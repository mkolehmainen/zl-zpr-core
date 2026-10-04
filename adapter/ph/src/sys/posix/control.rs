//! Control channel transport, unix arm: an AF_UNIX stream socket.
//!
//! `admin_worker` serves Cap'n Proto RPC over whatever [ControlStream]
//! this module hands it, so the RPC code is transport-agnostic; the
//! Windows arm (named pipe, zipline#130) provides the same two items.

use super::socket_access::{self, SocketAccess};
use crate::logging::targets::STARTUP;
use admin_api::SocketOwner;
use std::io;
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};
use tracing::warn;

/// One accepted control connection.
pub type ControlStream = UnixStream;

/// Listens for `ph-cli` control connections.
pub struct ControlListener {
    listener: UnixListener,
}

/// The socket-access plan for `owner`, from the real system lookups —
/// exactly the computation `main.rs` did before zipline#177 moved the
/// posix-only planning here. Separated from [ControlListener::bind] so the
/// decision stays unit-testable without binding anything.
fn access_plan(owner: Option<&SocketOwner>) -> SocketAccess {
    socket_access::plan_socket_access(
        owner,
        socket_access::system_user_primary_gid,
        socket_access::system_group_gid,
    )
}

impl ControlListener {
    /// Bind the control socket at `path` and hand it to whoever should
    /// drive `ph-cli` (zipline#39): the resolved `socket_owner` when there
    /// is one, else the `zpr` group, else leave it root-only and warn. The
    /// planning is posix-specific, which is why it lives here and not in
    /// `main.rs` (zipline#177); the Windows arm shares the signature and
    /// ignores `socket_owner` (named-pipe DACL is its access control).
    pub fn bind(path: &Path, socket_owner: Option<&SocketOwner>) -> io::Result<Self> {
        let plan = access_plan(socket_owner);
        if plan == SocketAccess::Unchanged && socket_owner.is_none() {
            warn!(
                target: STARTUP,
                "no invoking user resolved and no '{}' group on this host; the control socket \
                 stays root-only (ph-cli will need sudo or an explicit -p)",
                socket_access::FALLBACK_GROUP
            );
        }
        Ok(Self {
            listener: socket_access::bind_owned_listener("control", path, &plan)?,
        })
    }

    /// Wait for the next control connection.
    ///
    /// `&mut self` for parity with the Windows arm, whose accept must
    /// replace the consumed pipe instance (zipline#130).
    pub async fn accept(&mut self) -> io::Result<ControlStream> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use admin_api::SocketOwner;

    /// zipline#177: `bind` absorbs the access planning `main.rs` used to do
    /// — for a resolved owner (sudo: uid and gid known) it must compute the
    /// exact plan `plan_socket_access` produced there. Deterministic: with a
    /// gid supplied no system lookup is consulted.
    #[test]
    fn access_plan_matches_plan_socket_access_for_resolved_owner() {
        let owner = SocketOwner {
            uid: 1000,
            gid: Some(1001),
        };
        assert_eq!(
            access_plan(Some(&owner)),
            SocketAccess::OwnerOnly {
                uid: 1000,
                gid: Some(1001)
            }
        );
    }

    /// Same equivalence for the no-owner case, against whatever the real
    /// system lookups say on this host (GroupShared where a `zpr` group
    /// exists, Unchanged otherwise) — exactly main.rs's old computation.
    #[test]
    fn access_plan_matches_plan_socket_access_without_owner() {
        assert_eq!(
            access_plan(None),
            socket_access::plan_socket_access(
                None,
                socket_access::system_user_primary_gid,
                socket_access::system_group_gid,
            )
        );
    }

    /// The unified signature binds a working listener (zipline#177). A plan
    /// the process lacks privilege to apply is logged, not fatal, so this
    /// runs unprivileged whatever groups the host has.
    #[test]
    fn bind_succeeds_with_no_owner() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let dir = std::env::temp_dir().join(format!("ph-ctl-bind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("control.sock");
        ControlListener::bind(&path, None).unwrap();
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
