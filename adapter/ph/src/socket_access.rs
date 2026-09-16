//! Ownership and mode applied to the control/capture sockets after bind
//! (zipline#39).
//!
//! `ph` usually runs as root, which used to leave both unix sockets root-only
//! and force every `ph-cli` invocation through sudo. After each successful
//! bind the socket is now handed to whoever should drive it:
//!
//! * Owner known (`sudo`/`pkexec` invocation): chown to that user, mode
//!   `0600`.
//! * Owner unknown (systemd, direct root login): chown group `zpr` when that
//!   group exists, mode `0660`, so `zpr` group members can drive the adapter.
//! * No owner and no `zpr` group: leave the socket exactly as before (the
//!   caller logs one warning) — packaging must not become a hard runtime
//!   dependency.
//!
//! [plan_socket_access] is the pure, unit-tested decision; [apply_socket_access]
//! is the thin syscall wrapper around it.

use std::path::Path;

use admin_api::SocketOwner;
use nix::unistd::{Gid, Uid, chown};

/// Group granted socket access when no owner is resolvable. Hardcoded by
/// design: the fallback must work with zero configuration, and a host
/// without the group degrades to today's root-only behaviour.
pub const FALLBACK_GROUP: &str = "zpr";

/// What to do to a control/capture socket after binding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAccess {
    /// Chown to the resolved invoking user, mode `0600`. `gid: None` when
    /// the user's primary group could not be resolved (uid-only chown).
    OwnerOnly { uid: u32, gid: Option<u32> },

    /// No owner: chown to the fallback group, mode `0660`.
    GroupShared { gid: u32 },

    /// No owner and no fallback group: leave the socket untouched.
    Unchanged,
}

/// Decide the socket access plan from the resolved owner and injected group
/// lookups (pass [system_user_primary_gid] / [system_group_gid] for the real
/// system; tests inject tables).
pub fn plan_socket_access<U, G>(
    owner: Option<&SocketOwner>,
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
        None => match group_gid(FALLBACK_GROUP) {
            Some(gid) => SocketAccess::GroupShared { gid },
            None => SocketAccess::Unchanged,
        },
    }
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
        let plan = plan_socket_access(Some(&owner), no_user_lookup, no_group_lookup);
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
        let plan = plan_socket_access(Some(&owner), |_| None, no_group_lookup);
        assert_eq!(
            plan,
            SocketAccess::OwnerOnly {
                uid: 1000,
                gid: None
            }
        );
    }

    /// No owner (systemd start): the zpr group grants shared access.
    #[test]
    fn no_owner_with_zpr_group_yields_group_shared() {
        let plan = plan_socket_access(None, no_user_lookup, |name| {
            assert_eq!(name, FALLBACK_GROUP);
            Some(990)
        });
        assert_eq!(plan, SocketAccess::GroupShared { gid: 990 });
    }

    /// No owner and no zpr group: today's behaviour, untouched.
    #[test]
    fn no_owner_without_zpr_group_yields_unchanged() {
        let plan = plan_socket_access(None, no_user_lookup, |_| None);
        assert_eq!(plan, SocketAccess::Unchanged);
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
