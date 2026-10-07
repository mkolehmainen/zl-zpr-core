//! Control channel transport, Windows arm: a named pipe with an explicit
//! DACL (zipline#130, plan D6).
//!
//! `admin_worker` serves Cap'n Proto RPC over whatever [ControlStream] this
//! module hands it, so the RPC code is transport-agnostic; the unix arm
//! (`sys/posix/control.rs`) provides the same two items over an AF_UNIX
//! socket.
//!
//! The pipe is created with `ServerOptions::create_with_security_attributes_raw`
//! and a DACL granting access **only** to `BUILTIN\Administrators`, the
//! owning user's SID and — when `control_group` names an existing local
//! group (zipline#154) — that group's SID. The default named-pipe DACL
//! (which lets Everyone read) is not acceptable for a control channel.
//!
//! Liveness contract: `admin_api::socket_is_live` probes by opening a pipe
//! client, which succeeds only while a server instance is waiting — so this
//! listener always keeps a free instance: `accept` creates the *next*
//! server instance before handing out the connected one.

use crate::logging::targets::STARTUP;
use crate::sys::control_access::{control_pipe_sddl, missing_group_warning};
use admin_api::SocketOwner;
use std::io;
use std::path::{Path, PathBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// One accepted control connection.
pub type ControlStream = NamedPipeServer;

/// Build the binary security descriptor for [control_pipe_sddl] and run
/// `f` with a `SECURITY_ATTRIBUTES` pointing at it, freeing the descriptor
/// afterwards whatever `f` returns.
fn with_control_pipe_security<T>(
    owner_sid: &str,
    group_sid: Option<&str>,
    f: impl FnOnce(*mut SECURITY_ATTRIBUTES) -> io::Result<T>,
) -> io::Result<T> {
    let sddl: Vec<u16> = control_pipe_sddl(owner_sid, group_sid)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: sddl is a valid NUL-terminated UTF-16 string; sd receives a
    // LocalAlloc'd descriptor that we free below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1, // SDDL_REVISION_1
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let result = f(&mut attrs);
    // SAFETY: sd was LocalAlloc'd by the conversion above and is no longer
    // referenced (the pipe holds its own copy of the descriptor).
    unsafe { LocalFree(sd as _) };
    result
}

/// Create one pipe server instance at `path` with the D6 DACL (plus the
/// control group's ACE when `group_sid` is set, zipline#154).
///
/// `first` maps to FILE_FLAG_FIRST_PIPE_INSTANCE: the first instance claims
/// the pipe name, so a second `ph` (or a squatter) cannot hijack it.
fn create_instance(
    path: &Path,
    owner_sid: &str,
    group_sid: Option<&str>,
    first: bool,
) -> io::Result<NamedPipeServer> {
    with_control_pipe_security(owner_sid, group_sid, |attrs| {
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first);
        // SAFETY: attrs points at a live SECURITY_ATTRIBUTES whose
        // descriptor outlives the create call (see with_control_pipe_security).
        unsafe { options.create_with_security_attributes_raw(path, attrs as *mut _) }
    })
}

/// Resolve the configured control group to its SID once, at startup
/// (zipline#154). A missing group — or a lookup that fails — logs one
/// warning and yields `None`, which keeps today's two-ACE DACL.
fn resolve_control_group(control_group: Option<&str>) -> Option<String> {
    let name = control_group?;
    match admin_api::local_group_sid(name) {
        Ok(Some(sid)) => {
            tracing::info!(
                target: STARTUP,
                "control pipe: granting local group '{name}' ({sid}) access"
            );
            Some(sid)
        }
        Ok(None) => {
            tracing::warn!(target: STARTUP, "{}", missing_group_warning(name));
            None
        }
        Err(e) => {
            tracing::warn!(
                target: STARTUP,
                "{} (lookup failed: {e})",
                missing_group_warning(name)
            );
            None
        }
    }
}

/// Listens for `ph-cli` control connections on the named pipe.
pub struct ControlListener {
    path: PathBuf,
    owner_sid: String,
    /// The configured control group's SID, resolved once in `bind`, so
    /// every pipe instance carries the same DACL (zipline#154).
    group_sid: Option<String>,
    /// The next server instance, already created and waiting — this is what
    /// keeps `socket_is_live`'s probe-connect working between accepts.
    next: Option<NamedPipeServer>,
}

impl ControlListener {
    /// Create the control pipe at `path`, restricted to Administrators,
    /// the owning user (plan D6) and, if configured and present, the local
    /// group `control_group` (zipline#154). `socket_owner` is accepted for
    /// signature parity with the posix arm and ignored (zipline#177):
    /// ownership/mode planning is unix-specific — chown/chmod have no
    /// meaning in the pipe namespace — and the DACL owner SID is taken from
    /// the current process token via [admin_api::current_user_id] instead.
    pub fn bind(
        path: &Path,
        _socket_owner: Option<&SocketOwner>,
        control_group: Option<&str>,
    ) -> io::Result<Self> {
        let owner_sid = admin_api::current_user_id()?;
        let group_sid = resolve_control_group(control_group);
        let first = create_instance(path, &owner_sid, group_sid.as_deref(), true)?;
        Ok(Self {
            path: path.to_path_buf(),
            owner_sid,
            group_sid,
            next: Some(first),
        })
    }

    /// Wait for the next control connection.
    ///
    /// `&mut self`: the waiting instance is consumed and its successor
    /// installed (see the liveness contract above). The unix arm shares the
    /// signature.
    pub async fn accept(&mut self) -> io::Result<ControlStream> {
        let server = self
            .next
            .take()
            .expect("ControlListener invariant: a waiting instance always exists");
        server.connect().await?;
        // Immediately stand up the next instance so the pipe name stays
        // alive (and probe-connectable) while this connection is served.
        self.next = Some(create_instance(
            &self.path,
            &self.owner_sid,
            self.group_sid.as_deref(),
            false,
        )?);
        Ok(server)
    }
}

#[cfg(test)]
mod tests {
    use crate::sys::control_access::control_pipe_sddl;

    /// The DACL grants exactly Administrators and the owner, protected
    /// from inheritance — plan D6 — when no control group is configured.
    /// (The SDDL builder moved to the cfg-free `sys::control_access` in
    /// zipline#154, where its group cases are tested on every OS; this
    /// Windows-side test pins that the arm still uses it unchanged.)
    #[test]
    fn sddl_grants_only_administrators_and_owner() {
        let sddl = control_pipe_sddl("S-1-5-21-1-2-3-1001", None);
        assert_eq!(sddl, "D:P(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1-2-3-1001)");
    }
}
