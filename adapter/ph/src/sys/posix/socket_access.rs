//! Ownership and mode applied to the control socket after bind
//! (zipline#39).
//!
//! `ph` usually runs as root, which used to leave both unix sockets root-only
//! and force every `ph-cli` invocation through sudo. After each successful
//! bind the socket is now handed to whoever should drive it:
//!
//! * Owner known (`sudo`/`pkexec` invocation): chown to that user, mode
//!   `0600`.
//! * Owner unknown (systemd, launchd, direct root login) and a
//!   `control_group` configured: chown to that group when it exists, mode
//!   `0660`, so its members can drive the adapter (zipline#154; before
//!   that the group was a hard-coded `zpr`).
//! * No owner and no usable group (none configured, or configured but
//!   missing): leave the socket exactly as before (the caller logs one
//!   warning) — packaging must not become a hard runtime dependency.
//!
//! [plan_socket_access] is the pure, unit-tested decision; [apply_socket_access]
//! is the thin syscall wrapper around it.

use std::io;
use std::os::unix::net::UnixListener;
use std::path::Path;

use crate::logging::targets::STARTUP;
use admin_api::SocketOwner;
use nix::unistd::{Gid, Uid, chown};

/// What to do to a control socket after binding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAccess {
    /// Chown to the resolved invoking user, mode `0600`. `gid: None` when
    /// the user's primary group could not be resolved (uid-only chown).
    OwnerOnly { uid: u32, gid: Option<u32> },

    /// No owner: chown to the configured control group, mode `0660`.
    GroupShared { gid: u32 },

    /// No owner and no usable control group: leave the socket untouched.
    Unchanged,
}

/// Decide the socket access plan from the resolved owner, the configured
/// `control_group` (zipline#154) and injected lookups (pass
/// [system_user_primary_gid] / [system_group_gid] for the real system;
/// tests inject tables). The group is consulted only when there is no
/// owner, and only the configured name is ever looked up.
pub fn plan_socket_access<U, G>(
    owner: Option<&SocketOwner>,
    control_group: Option<&str>,
    user_primary_gid: U,
    group_gid: G,
) -> SocketAccess
where
    U: Fn(u32) -> Option<u32>,
    G: Fn(&str) -> Option<u32>,
{
    match owner {
        Some(owner) => {
            // SUDO_GID gave us the gid directly; a PKEXEC_UID-only owner
            // needs the user's primary group resolved here.
            let gid = owner.gid.or_else(|| user_primary_gid(owner.uid));
            SocketAccess::OwnerOnly {
                uid: owner.uid,
                gid,
            }
        }
        None => match control_group.and_then(group_gid) {
            Some(gid) => SocketAccess::GroupShared { gid },
            None => SocketAccess::Unchanged,
        },
    }
}

/// Bind a listening unix socket at `path`, first removing any stale socket
/// file a previous run left behind. The listener is returned nonblocking so
/// the caller can hand it to tokio with `UnixListener::from_std`.
///
/// Every error names the socket and its path and says what to do about it:
/// the usual cause is running `ph` unprivileged while the socket directory
/// (`/var/run/zpr` by default) is root-owned, which used to surface as a bare
/// `PermissionDenied` panic with no path.
pub fn bind_socket(desc: &str, path: &Path) -> io::Result<UnixListener> {
    let explain = |what: &str, e: io::Error| {
        io::Error::new(
            e.kind(),
            format!(
                "{what} {desc} socket {path:?}: {e} \
                 (run ph as root, or set `{desc}_path` to a socket in a writable directory)"
            ),
        )
    };
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(explain("failed to remove stale", e)),
    }
    let listener = UnixListener::bind(path).map_err(|e| explain("failed to bind", e))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Bind `desc`'s socket at `path` (see [bind_socket]), hand it to tokio and
/// apply `plan` to it. A failure to apply the plan is logged, not fatal:
/// the socket still works for root (zipline#39). Must be called inside a
/// tokio runtime.
pub fn bind_owned_listener(
    desc: &str,
    path: &Path,
    plan: &SocketAccess,
) -> io::Result<tokio::net::UnixListener> {
    let listener = tokio::net::UnixListener::from_std(bind_socket(desc, path)?)?;
    tracing::info!(target: STARTUP, "{desc} socket bound to {path:?}");
    if let Err(e) = apply_socket_access(path, plan) {
        tracing::warn!(
            target: STARTUP,
            "failed to set ownership/mode on {desc} socket {path:?}: {e}"
        );
    }
    Ok(listener)
}

/// Apply the plan to a bound socket path. Thin syscall wrapper; the decision
/// logic lives in [plan_socket_access].
pub fn apply_socket_access(path: &Path, plan: &SocketAccess) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match plan {
        SocketAccess::OwnerOnly { uid, gid } => {
            chown(path, Some(Uid::from_raw(*uid)), gid.map(Gid::from_raw))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        SocketAccess::GroupShared { gid } => {
            chown(path, None, Some(Gid::from_raw(*gid)))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        }
        SocketAccess::Unchanged => {}
    }
    Ok(())
}

/// Real lookup: a user's primary gid, from the passwd database.
pub fn system_user_primary_gid(uid: u32) -> Option<u32> {
    nix::unistd::User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.gid.as_raw())
}

/// Real lookup: a group's gid, from the group database.
pub fn system_group_gid(name: &str) -> Option<u32> {
    nix::unistd::Group::from_name(name)
        .ok()
        .flatten()
        .map(|group| group.gid.as_raw())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fresh directory under the system temp dir, unique per test.
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ph-sock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    /// Binding twice at the same path works: the second bind removes the
    /// stale socket file the first one left behind.
    #[test]
    fn bind_socket_replaces_stale_socket_file() {
        let dir = scratch_dir("stale");
        let path = dir.join("control.sock");
        drop(bind_socket("control", &path).unwrap());
        assert!(path.exists(), "socket file should be left behind on drop");
        bind_socket("control", &path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A stale socket the process cannot remove yields a PermissionDenied
    /// error that names the socket, the path and the fix, not a bare EACCES.
    #[test]
    fn bind_socket_names_path_when_stale_socket_is_unremovable() {
        if nix::unistd::geteuid().is_root() {
            eprintln!("skipped: root can remove anything");
            return;
        }
        let dir = scratch_dir("denied");
        let path = dir.join("control.sock");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let err = bind_socket("control", &path).unwrap_err();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let msg = err.to_string();
        assert!(msg.contains("control socket"), "{msg}");
        assert!(msg.contains(path.to_str().unwrap()), "{msg}");
        assert!(msg.contains("control_path"), "{msg}");
    }

    // Lookups that must not be consulted for a given case.
    fn no_user_lookup(_uid: u32) -> Option<u32> {
        panic!("user primary gid lookup must not be consulted")
    }
    fn no_group_lookup(_name: &str) -> Option<u32> {
        panic!("fallback group lookup must not be consulted")
    }

    /// A sudo-resolved owner (uid and gid both known) is chowned as-is,
    /// mode 0600; no lookups run.
    #[test]
    fn sudo_owner_yields_owner_only_with_given_gid() {
        let owner = SocketOwner {
            uid: 1000,
            gid: Some(1001),
        };
        let plan = plan_socket_access(Some(&owner), None, no_user_lookup, no_group_lookup);
        assert_eq!(
            plan,
            SocketAccess::OwnerOnly {
                uid: 1000,
                gid: Some(1001)
            }
        );
    }

    /// A pkexec-resolved owner (uid only) gets its gid from the user's
    /// primary group.
    #[test]
    fn pkexec_owner_resolves_primary_gid() {
        let owner = SocketOwner {
            uid: 1000,
            gid: None,
        };
        let plan = plan_socket_access(
            Some(&owner),
            None,
            |uid| if uid == 1000 { Some(2000) } else { None },
            no_group_lookup,
        );
        assert_eq!(
            plan,
            SocketAccess::OwnerOnly {
                uid: 1000,
                gid: Some(2000)
            }
        );
    }

    /// When the primary-group lookup fails, the socket is still chowned to
    /// the uid (gid untouched) rather than falling back to the group path.
    #[test]
    fn pkexec_owner_with_failed_gid_lookup_still_owner_only() {
        let owner = SocketOwner {
            uid: 1000,
            gid: None,
        };
        let plan = plan_socket_access(Some(&owner), None, |_| None, no_group_lookup);
        assert_eq!(
            plan,
            SocketAccess::OwnerOnly {
                uid: 1000,
                gid: None
            }
        );
    }

    /// No owner (systemd start) and a configured group that exists: the
    /// group grants shared access, and exactly the configured name is
    /// looked up (zipline#154: no hard-coded fallback group).
    #[test]
    fn no_owner_with_configured_group_yields_group_shared() {
        let plan = plan_socket_access(None, Some("zipline"), no_user_lookup, |name| {
            assert_eq!(name, "zipline");
            Some(990)
        });
        assert_eq!(plan, SocketAccess::GroupShared { gid: 990 });
    }

    /// No owner and a configured group that does not exist: today's
    /// behaviour, untouched.
    #[test]
    fn no_owner_with_missing_configured_group_yields_unchanged() {
        let plan = plan_socket_access(None, Some("zipline"), no_user_lookup, |_| None);
        assert_eq!(plan, SocketAccess::Unchanged);
    }

    /// No owner and no group configured: `Unchanged`, and no group lookup
    /// is made at all — in particular `zpr` is no longer consulted
    /// (zipline#154 behaviour change).
    #[test]
    fn no_owner_without_configured_group_yields_unchanged_without_lookup() {
        let plan = plan_socket_access(None, None, no_user_lookup, no_group_lookup);
        assert_eq!(plan, SocketAccess::Unchanged);
    }

    /// A resolved owner wins over a configured group: the group is only the
    /// ownerless fallback, and it is not even looked up.
    #[test]
    fn owner_wins_over_configured_group() {
        let owner = SocketOwner {
            uid: 1000,
            gid: Some(1001),
        };
        let plan = plan_socket_access(
            Some(&owner),
            Some("zipline"),
            no_user_lookup,
            no_group_lookup,
        );
        assert_eq!(
            plan,
            SocketAccess::OwnerOnly {
                uid: 1000,
                gid: Some(1001)
            }
        );
    }

    /// Applying a plan really sets the mode (owner case, chown-to-self so
    /// the test does not need root).
    #[test]
    fn apply_owner_only_sets_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("zpr-test-sock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        std::fs::write(&path, b"").unwrap();
        let plan = SocketAccess::OwnerOnly {
            uid: nix::unistd::geteuid().as_raw(),
            gid: Some(nix::unistd::getegid().as_raw()),
        };
        apply_socket_access(&path, &plan).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
