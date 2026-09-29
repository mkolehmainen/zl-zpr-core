//! Control channel transport, Windows arm: a named pipe with an explicit
//! DACL (zipline#130, plan D6).
//!
//! `admin_worker` serves Cap'n Proto RPC over whatever [ControlStream] this
//! module hands it, so the RPC code is transport-agnostic; the unix arm
//! (`sys/posix/control.rs`) provides the same two items over an AF_UNIX
//! socket.
//!
//! The pipe is created with `ServerOptions::create_with_security_attributes_raw`
//! and a DACL granting access **only** to `BUILTIN\Administrators` and the
//! owning user's SID — the default named-pipe DACL (which lets Everyone
//! read) is not acceptable for a control channel.
//!
//! Liveness contract: `admin_api::socket_is_live` probes by opening a pipe
//! client, which succeeds only while a server instance is waiting — so this
//! listener always keeps a free instance: `accept` creates the *next*
//! server instance before handing out the connected one.

use std::io;
use std::path::{Path, PathBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// One accepted control connection.
pub type ControlStream = NamedPipeServer;

/// The SDDL string for the control pipe's security descriptor: DACL with
/// exactly two ACEs — full access for `BUILTIN\Administrators` (`BA`) and
/// full access for the owning user's SID — and no inherited ACEs. `D:P` is
/// SE_DACL_PROTECTED: nothing is inherited into this DACL.
///
/// Pure string construction, unit-testable everywhere; the conversion to a
/// binary security descriptor below is Windows-only.
fn control_pipe_sddl(owner_sid: &str) -> String {
    format!("D:P(A;;GA;;;BA)(A;;GA;;;{owner_sid})")
}

/// Build the binary security descriptor for [control_pipe_sddl] and run
/// `f` with a `SECURITY_ATTRIBUTES` pointing at it, freeing the descriptor
/// afterwards whatever `f` returns.
fn with_control_pipe_security<T>(
    owner_sid: &str,
    f: impl FnOnce(*mut SECURITY_ATTRIBUTES) -> io::Result<T>,
) -> io::Result<T> {
    let sddl: Vec<u16> = control_pipe_sddl(owner_sid)
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

/// Create one pipe server instance at `path` with the D6 DACL.
///
/// `first` maps to FILE_FLAG_FIRST_PIPE_INSTANCE: the first instance claims
/// the pipe name, so a second `ph` (or a squatter) cannot hijack it.
fn create_instance(path: &Path, owner_sid: &str, first: bool) -> io::Result<NamedPipeServer> {
    with_control_pipe_security(owner_sid, |attrs| {
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first);
        // SAFETY: attrs points at a live SECURITY_ATTRIBUTES whose
        // descriptor outlives the create call (see with_control_pipe_security).
        unsafe { options.create_with_security_attributes_raw(path, attrs as *mut _) }
    })
}

/// Listens for `ph-cli` control connections on the named pipe.
pub struct ControlListener {
    path: PathBuf,
    owner_sid: String,
    /// The next server instance, already created and waiting — this is what
    /// keeps `socket_is_live`'s probe-connect working between accepts.
    next: Option<NamedPipeServer>,
}

impl ControlListener {
    /// Create the control pipe at `path`, restricted to Administrators and
    /// the owning user (plan D6). Ownership/mode planning is unix-specific
    /// (chown/chmod have no meaning in the pipe namespace); the DACL owner
    /// SID is taken from the current process token via
    /// [admin_api::current_user_id].
    pub fn bind(path: &Path) -> io::Result<Self> {
        let owner_sid = admin_api::current_user_id()?;
        let first = create_instance(path, &owner_sid, true)?;
        Ok(Self {
            path: path.to_path_buf(),
            owner_sid,
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
        self.next = Some(create_instance(&self.path, &self.owner_sid, false)?);
        Ok(server)
    }
}

#[cfg(test)]
mod tests {
    use super::control_pipe_sddl;

    /// The DACL grants exactly Administrators and the owner, protected
    /// from inheritance — plan D6. (DACL construction is compile-checked
    /// by the msvc gate now and exercised on a real Windows host by C5's
    /// CI; this test pins the SDDL string itself.)
    #[test]
    fn sddl_grants_only_administrators_and_owner() {
        let sddl = control_pipe_sddl("S-1-5-21-1-2-3-1001");
        assert_eq!(sddl, "D:P(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1-2-3-1001)");
    }
}
