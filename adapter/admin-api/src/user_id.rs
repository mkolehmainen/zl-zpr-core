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

/// Reading the user SID out of this process's access token.
#[cfg(windows)]
mod windows_token {
    use std::io;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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

        let mut wide = ptr::null_mut();
        // SAFETY: `user.User.Sid` is a valid SID for as long as `buf` lives;
        // `wide` is a valid out-pointer.
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut wide) } == 0 {
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

    /// On Windows the id is a SID string.
    #[cfg(windows)]
    #[test]
    fn windows_user_id_is_a_sid() {
        let sid = current_user_id().unwrap();
        assert!(sid.starts_with("S-1-"), "not a SID: {sid}");
    }
}
