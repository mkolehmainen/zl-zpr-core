//! The current user's identity, as the string both `ph` and `ph-cli` use to
//! derive the per-user control channel path (plan D9).
//!
//! * unix: the effective uid, in decimal (e.g. `"1000"`).
//! * Windows: the process token's user SID (e.g. `"S-1-5-21-...-1001"`).
//!   In this release `ph` and `ph-cli` both run elevated as the same user,
//!   so they agree on it.

use std::io;

/// The current user's id: see the module documentation.
#[cfg(unix)]
pub fn current_user_id() -> io::Result<String> {
    Ok(nix::unistd::geteuid().as_raw().to_string())
}

/// The current user's id: see the module documentation.
#[cfg(windows)]
pub fn current_user_id() -> io::Result<String> {
    windows_token::current_user_sid()
}

/// The SID, in `S-1-...` form, of the local group `name` on this machine
/// (zipline#154), or `None` when no such local group exists.
///
/// Local-only by construction: only the qualified names from
/// [local_group_lookup_candidates] are looked up — `<COMPUTERNAME>\name`
/// (administrator-created local groups) then `BUILTIN\name` (e.g.
/// `Users`) — so a same-named domain group can never stand in. The name
/// must be a group (`SidTypeAlias` or `SidTypeGroup`); a user or
/// well-known principal of that name gives `None`. The returned string is
/// produced only by `ConvertSidToStringSidW` from the binary SID the lookup
/// returned, which is what makes it safe to interpolate into SDDL.
///
/// `Err` is any lookup failure other than "no such account"
/// (`ERROR_NONE_MAPPED`); callers log it and treat the group as missing.
#[cfg(windows)]
pub fn local_group_sid(name: &str) -> io::Result<Option<String>> {
    windows_token::local_group_sid(name)
}

/// The qualified account names `local_group_sid` looks up, in order, for
/// group `name` on the computer whose NetBIOS name is `computer`
/// (zipline#154): the computer's own account domain, then `BUILTIN`. Both
/// are local SAM domains; an unqualified name would fall through to the
/// primary and trusted domains. Pure, so it is unit-tested on every OS.
#[cfg_attr(not(windows), allow(dead_code))]
fn local_group_lookup_candidates(computer: &str, name: &str) -> [String; 2] {
    [format!("{computer}\\{name}"), format!("BUILTIN\\{name}")]
}

/// Whether this process runs with elevated privileges: euid 0 on unix, an
/// elevated access token (UAC "run as administrator") on Windows.
///
/// ph-cli's browser pre-flight (zipline#46) consumes this: a browser
/// spawned from an elevated context fails inside the child (unix) or opens
/// as the wrong principal, so the login flow prints the URL instead
/// (zipline#131 step 4).
#[cfg(unix)]
pub fn is_elevated() -> io::Result<bool> {
    Ok(nix::unistd::geteuid().is_root())
}

/// Whether this process runs with elevated privileges: see the unix arm.
#[cfg(windows)]
pub fn is_elevated() -> io::Result<bool> {
    windows_token::current_token_elevated()
}

/// Reading the user SID out of this process's access token.
#[cfg(windows)]
mod windows_token {
    use std::io;
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetTokenInformation, LookupAccountNameW, PSID, SID_NAME_USE, SidTypeAlias, SidTypeGroup,
        TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;

    /// The SID of the local group `name`: see [super::local_group_sid].
    pub fn local_group_sid(name: &str) -> io::Result<Option<String>> {
        let computer = computer_name()?;
        for qualified in super::local_group_lookup_candidates(&computer, name) {
            match lookup_account(&qualified)? {
                None => continue,
                Some((sid_buf, use_)) => {
                    if use_ != SidTypeAlias && use_ != SidTypeGroup {
                        // e.g. a local user or a well-known principal with
                        // that name: not a group, so not a grant target.
                        return Ok(None);
                    }
                    return sid_to_string(sid_buf.as_ptr() as PSID).map(Some);
                }
            }
        }
        Ok(None)
    }

    /// This machine's NetBIOS name — the name of its local account domain.
    fn computer_name() -> io::Result<String> {
        // MAX_COMPUTERNAME_LENGTH is 15; leave generous room.
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` writable u16s; on success `len` is the
        // number written, excluding the terminating NUL.
        if unsafe { GetComputerNameW(buf.as_mut_ptr(), &mut len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        String::from_utf16(&buf[..len as usize])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// `LookupAccountNameW(NULL, qualified)` with the usual two-call buffer
    /// sizing. `Ok(None)` for ERROR_NONE_MAPPED (no such account); the SID
    /// is returned in a pointer-aligned buffer with its `SID_NAME_USE`.
    fn lookup_account(qualified: &str) -> io::Result<Option<(Vec<u64>, SID_NAME_USE)>> {
        let wide: Vec<u16> = qualified.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut use_: SID_NAME_USE = 0;
        // SAFETY: null buffers with zero lengths are the documented size
        // query; `wide` is NUL-terminated.
        let ok = unsafe {
            LookupAccountNameW(
                ptr::null(),
                wide.as_ptr(),
                ptr::null_mut(),
                &mut sid_len,
                ptr::null_mut(),
                &mut domain_len,
                &mut use_,
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error().map(|c| c as u32) {
                Some(ERROR_NONE_MAPPED) => return Ok(None),
                Some(ERROR_INSUFFICIENT_BUFFER) => {}
                _ => return Err(err),
            }
        }
        if sid_len == 0 {
            return Err(io::Error::other(format!(
                "LookupAccountNameW({qualified:?}) reported a zero-length SID"
            )));
        }
        let mut sid_buf = vec![0u64; (sid_len as usize).div_ceil(8)];
        let mut domain = vec![0u16; domain_len.max(1) as usize];
        // SAFETY: both buffers are at least the sizes the first call asked
        // for, and the length arguments say so.
        let ok = unsafe {
            LookupAccountNameW(
                ptr::null(),
                wide.as_ptr(),
                sid_buf.as_mut_ptr().cast(),
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut use_,
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error().map(|c| c as u32) == Some(ERROR_NONE_MAPPED) {
                return Ok(None);
            }
            return Err(err);
        }
        Ok(Some((sid_buf, use_)))
    }

    /// The SID of the user this process runs as, in `S-1-...` form.
    pub fn current_user_sid() -> io::Result<String> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; `token` is a valid out-pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid = token_user_sid(token);
        // SAFETY: `token` was opened above and is closed exactly once.
        unsafe { CloseHandle(token) };
        sid
    }

    /// Whether this process's access token is elevated (UAC "run as
    /// administrator"): the `TokenElevation` information class, which is a
    /// single `TOKEN_ELEVATION { TokenIsElevated: u32 }`.
    pub fn current_token_elevated() -> io::Result<bool> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing; `token` is a valid out-pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        // SAFETY: `elevation` is a valid out-buffer of exactly the size
        // this information class writes.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
        };
        let err = io::Error::last_os_error();
        // SAFETY: `token` was opened above and is closed exactly once.
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return Err(err);
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    /// The user SID recorded in the access token `token`.
    fn token_user_sid(token: HANDLE) -> io::Result<String> {
        // First call sizes the buffer; it fails with
        // ERROR_INSUFFICIENT_BUFFER and sets `len`.
        let mut len = 0u32;
        // SAFETY: a null buffer of length 0 is the documented size query.
        unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }

        // TOKEN_USER holds pointers, so the buffer must be pointer-aligned:
        // allocate it as u64s.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` is at least `len` writable bytes.
        if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success `buf` starts with a TOKEN_USER (whose SID
        // pointer points into `buf`), and `buf` is 8-byte aligned.
        let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
        sid_to_string(user.User.Sid)
    }

    /// A binary SID in `S-1-...` form, via `ConvertSidToStringSidW` — the
    /// only way a SID string reaching SDDL is produced (zipline#154).
    fn sid_to_string(sid: PSID) -> io::Result<String> {
        let mut wide = ptr::null_mut();
        // SAFETY: the caller guarantees `sid` is a valid SID for the
        // duration of this call; `wide` is a valid out-pointer.
        if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: on success `wide` is a NUL-terminated UTF-16 string
        // allocated with LocalAlloc; it is read here and freed exactly once.
        let sid = unsafe {
            let len = (0..).take_while(|&i| *wide.add(i) != 0).count();
            let sid = String::from_utf16(std::slice::from_raw_parts(wide, len));
            LocalFree(wide.cast());
            sid
        };
        sid.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// On unix the id is the effective uid in decimal, which is what `ph`
    /// formats a resolved `SUDO_UID` as, so the two sides agree.
    #[cfg(unix)]
    #[test]
    fn unix_user_id_is_decimal_euid() {
        assert_eq!(
            current_user_id().unwrap(),
            nix::unistd::geteuid().as_raw().to_string()
        );
    }

    /// On unix "elevated" means euid 0, exactly the old
    /// `geteuid().is_root()` check this helper replaces in ph-cli
    /// (zipline#131 step 4). Test runs unprivileged, so both sides are
    /// false; run as root both are true.
    #[cfg(unix)]
    #[test]
    fn unix_is_elevated_is_root_euid() {
        assert_eq!(is_elevated().unwrap(), nix::unistd::geteuid().is_root());
    }

    /// On Windows the elevation state comes from the process token; all
    /// this portable test can pin is that the call succeeds (CI runs both
    /// elevated and not).
    #[cfg(windows)]
    #[test]
    fn windows_is_elevated_reads_the_token() {
        let _ = is_elevated().unwrap();
    }

    /// On Windows the id is a SID string.
    #[cfg(windows)]
    #[test]
    fn windows_user_id_is_a_sid() {
        let sid = current_user_id().unwrap();
        assert!(sid.starts_with("S-1-"), "not a SID: {sid}");
    }

    /// zipline#154: only local-domain qualified names are ever looked up —
    /// the computer's account domain first, then BUILTIN — never the bare
    /// name, which LSA would resolve against domain controllers too.
    #[test]
    fn local_group_lookup_is_qualified_and_local_only() {
        assert_eq!(
            local_group_lookup_candidates("WIN11VM", "zipline"),
            [
                "WIN11VM\\zipline".to_string(),
                "BUILTIN\\zipline".to_string()
            ]
        );
    }

    /// zipline#154: a well-known local group resolves to its fixed SID
    /// (BUILTIN\Users is S-1-5-32-545 on every Windows host).
    #[cfg(windows)]
    #[test]
    fn windows_local_group_users_resolves() {
        assert_eq!(
            local_group_sid("Users").unwrap().as_deref(),
            Some("S-1-5-32-545")
        );
    }

    /// zipline#154: a group that does not exist is `None`, not an error.
    #[cfg(windows)]
    #[test]
    fn windows_local_group_missing_is_none() {
        assert_eq!(
            local_group_sid("zpr-no-such-group-7f3c2a9e4b1d4e0c").unwrap(),
            None
        );
    }

    /// zipline#154: a name that is not a local group — here the
    /// well-known SYSTEM account, which is not in either local domain as a
    /// group — is never reported as one.
    #[cfg(windows)]
    #[test]
    fn windows_local_group_non_group_is_none() {
        assert_eq!(local_group_sid("SYSTEM").unwrap(), None);
    }
}
