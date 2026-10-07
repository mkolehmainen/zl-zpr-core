//! Control channel transport, unix arm: an AF_UNIX stream socket.
//!
//! `admin_worker` serves Cap'n Proto RPC over whatever [ControlStream]
//! this module hands it, so the RPC code is transport-agnostic; the
//! Windows arm (named pipe, zipline#130) provides the same two items.

use super::socket_access::{self, SocketAccess};
use crate::logging::targets::STARTUP;
use crate::sys::control_access;
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

/// The socket-access plan for `owner` and the configured `control_group`,
/// from the real system lookups (zipline#177 moved this out of `main.rs`;
/// zipline#154 replaced the hard-coded `zpr` group with the setting).
/// Separated from [ControlListener::bind] so the decision stays
/// unit-testable without binding anything.
fn access_plan(owner: Option<&SocketOwner>, control_group: Option<&str>) -> SocketAccess {
    socket_access::plan_socket_access(
        owner,
        control_group,
        socket_access::system_user_primary_gid,
        socket_access::system_group_gid,
    )
}

/// The one startup warning, if any, for the plan `bind` is about to apply
/// (zipline#154). Only an ownerless `ph` that ends up `Unchanged` warns:
/// with a group configured but missing, in the wording shared with the
/// Windows arm; with no group configured, the root-only warning.
fn startup_warning(
    owner: Option<&SocketOwner>,
    control_group: Option<&str>,
    plan: &SocketAccess,
) -> Option<String> {
    if owner.is_some() || *plan != SocketAccess::Unchanged {
        return None;
    }
    Some(match control_group {
        Some(name) => control_access::missing_group_warning(name),
        None => "no invoking user resolved and no control_group configured; the control \
                 socket stays root-only (ph-cli will need sudo or an explicit -p)"
            .to_string(),
    })
}

impl ControlListener {
    /// Bind the control socket at `path` and hand it to whoever should
    /// drive `ph-cli` (zipline#39): the resolved `socket_owner` when there
    /// is one, else the configured `control_group` (zipline#154), else
    /// leave it root-only and warn. The planning is posix-specific, which
    /// is why it lives here and not in `main.rs` (zipline#177); the Windows
    /// arm shares the signature, ignores `socket_owner` and turns
    /// `control_group` into a DACL entry instead.
    pub fn bind(
        path: &Path,
        socket_owner: Option<&SocketOwner>,
        control_group: Option<&str>,
    ) -> io::Result<Self> {
        let plan = access_plan(socket_owner, control_group);
        if let Some(msg) = startup_warning(socket_owner, control_group, &plan) {
            warn!(target: STARTUP, "{msg}");
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
            access_plan(Some(&owner), Some("zipline")),
            SocketAccess::OwnerOnly {
                uid: 1000,
                gid: Some(1001)
            }
        );
    }

    /// Same equivalence for the no-owner case with a configured group,
    /// against whatever the real system lookups say on this host
    /// (GroupShared where the group exists, Unchanged otherwise).
    #[test]
    fn access_plan_matches_plan_socket_access_without_owner() {
        for group in [Some("root"), Some("zpr"), None] {
            assert_eq!(
                access_plan(None, group),
                socket_access::plan_socket_access(
                    None,
                    group,
                    socket_access::system_user_primary_gid,
                    socket_access::system_group_gid,
                ),
                "group {group:?}"
            );
        }
    }

    /// zipline#154: no owner and no group configured is `Unchanged` on
    /// every host — the `zpr` group is no longer looked up.
    #[test]
    fn access_plan_without_owner_or_group_is_unchanged() {
        assert_eq!(access_plan(None, None), SocketAccess::Unchanged);
    }

    /// zipline#154: the startup warning for each ownerless outcome. A
    /// configured-but-missing group gets the cross-platform wording; no
    /// group at all gets the root-only warning, which now points at
    /// `control_group` instead of a `zpr` group.
    #[test]
    fn startup_warning_cases() {
        let owner = SocketOwner {
            uid: 1000,
            gid: Some(1001),
        };
        let owner_plan = SocketAccess::OwnerOnly {
            uid: 1000,
            gid: Some(1001),
        };
        // An owner was resolved: nothing to warn about, group or not.
        assert_eq!(startup_warning(Some(&owner), None, &owner_plan), None);
        assert_eq!(
            startup_warning(Some(&owner), Some("zipline"), &owner_plan),
            None
        );
        // Ownerless, group found: shared access as configured.
        assert_eq!(
            startup_warning(
                None,
                Some("zipline"),
                &SocketAccess::GroupShared { gid: 990 }
            ),
            None
        );
        // Ownerless, group configured but missing.
        assert_eq!(
            startup_warning(None, Some("zipline"), &SocketAccess::Unchanged),
            Some(control_access::missing_group_warning("zipline"))
        );
        // Ownerless, no group configured.
        let msg = startup_warning(None, None, &SocketAccess::Unchanged).unwrap();
        assert!(msg.contains("control_group"), "{msg}");
        assert!(!msg.contains("'zpr'"), "{msg}");
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
        ControlListener::bind(&path, None, None).unwrap();
        assert!(path.exists());
        // A configured group that does not exist is a warning, not an error.
        ControlListener::bind(&path, None, Some("zpr-no-such-group-154")).unwrap();
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
