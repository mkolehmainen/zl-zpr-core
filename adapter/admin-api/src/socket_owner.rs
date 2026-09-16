//! Control/capture socket ownership and default path derivation (zipline#39).
//!
//! `ph` usually runs as root (it creates a TUN device) while `ph-cli` runs as
//! the invoking user. Both sides must agree on who "owns" the control and
//! capture sockets and, from that, where the sockets live:
//!
//! * Owner known (`ph` started via `sudo` or `pkexec`): the sockets live in a
//!   per-uid directory `<data_home>/<uid>/` and are chowned to that user.
//!   `ph-cli`, running as that user, derives the identical path from its own
//!   effective uid.
//! * Owner unknown (systemd, direct root login): the sockets live at the
//!   shared `<data_home>/` path as before; `ph` falls back to the `zpr` group
//!   for access control.
//!
//! Owner resolution here is pure environment-string parsing over an injected
//! lookup so it is unit-testable without mutating process environment; the
//! uid -> gid lookups and the chown/chmod syscalls live in `ph`, which already
//! depends on `nix`.

use std::path::PathBuf;

use crate::data_home::get_data_home;

/// The user a control/capture socket should belong to.
///
/// `gid` is `Some` when the environment supplied it directly (`SUDO_GID`);
/// `None` when only the uid is known (`PKEXEC_UID`) and the consumer must
/// resolve the user's primary group itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketOwner {
    pub uid: u32,
    pub gid: Option<u32>,
}

/// Resolve the socket owner from the environment, via an injected lookup
/// (pass `|k| std::env::var(k).ok()` for the real environment).
///
/// Rules:
/// * `SUDO_UID` + `SUDO_GID` (both valid, numeric): that owner.
/// * `SUDO_UID` present but either variable malformed or `SUDO_GID` absent:
///   `None` — a half-resolved owner is worse than none.
/// * Otherwise `PKEXEC_UID` (valid, numeric): that uid with `gid: None`.
/// * Neither: `None`.
///
/// `SUDO_*` wins over `PKEXEC_UID` when both are present.
pub fn resolve_socket_owner<F>(env: F) -> Option<SocketOwner>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(uid_str) = env("SUDO_UID") {
        let uid = uid_str.parse::<u32>().ok()?;
        let gid = env("SUDO_GID")?.parse::<u32>().ok()?;
        return Some(SocketOwner {
            uid,
            gid: Some(gid),
        });
    }
    if let Some(uid_str) = env("PKEXEC_UID") {
        let uid = uid_str.parse::<u32>().ok()?;
        return Some(SocketOwner { uid, gid: None });
    }
    None
}

/// The directory holding a known owner's sockets: `<data_home>/<uid>/`.
pub fn owner_socket_dir(uid: u32) -> PathBuf {
    get_data_home().join(uid.to_string())
}

/// Default control socket path for the given owner: per-uid when the owner
/// is known, the shared `<data_home>/control.sock` when it is not.
pub fn control_socket_path(owner_uid: Option<u32>) -> PathBuf {
    socket_path(owner_uid, "control.sock")
}

/// Default capture socket path; same derivation as [control_socket_path].
pub fn capture_socket_path(owner_uid: Option<u32>) -> PathBuf {
    socket_path(owner_uid, "capture.sock")
}

// Shared derivation for both sockets.
fn socket_path(owner_uid: Option<u32>, name: &str) -> PathBuf {
    match owner_uid {
        Some(uid) => owner_socket_dir(uid).join(name),
        None => get_data_home().join(name),
    }
}

/// Which socket path a client (`ph-cli`) should use, given an optional
/// explicit path (`-p` / `-c`) and an injected existence predicate.
///
/// * An explicit path short-circuits everything — it is used whether or not
///   it exists, so error reporting stays at the connect site.
/// * Otherwise the per-uid path for the caller's euid is preferred when it
///   exists, then the shared path when it exists.
/// * When neither exists the result is an error naming both paths tried.
pub fn choose_socket_path<F>(
    explicit: Option<PathBuf>,
    per_uid: PathBuf,
    shared: PathBuf,
    exists: F,
) -> Result<PathBuf, String>
where
    F: Fn(&std::path::Path) -> bool,
{
    if let Some(path) = explicit {
        return Ok(path);
    }
    if exists(&per_uid) {
        return Ok(per_uid);
    }
    if exists(&shared) {
        return Ok(shared);
    }
    Err(format!(
        "no packet handler socket found (tried {} and {}); is ph running? Use -p/-c to point at an explicit socket path",
        per_uid.display(),
        shared.display()
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::Path;

    // Build an env lookup over a table of (key, value) pairs.
    fn env_of<'vars>(
        vars: &'vars [(&'vars str, &'vars str)],
    ) -> impl Fn(&str) -> Option<String> + 'vars {
        move |key: &str| {
            vars.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    /// `SUDO_UID` + `SUDO_GID` resolve to that owner.
    #[test]
    fn sudo_uid_and_gid_resolve_owner() {
        let owner = resolve_socket_owner(env_of(&[("SUDO_UID", "1000"), ("SUDO_GID", "1001")]));
        assert_eq!(
            owner,
            Some(SocketOwner {
                uid: 1000,
                gid: Some(1001)
            })
        );
    }

    /// A valid `SUDO_UID` with a malformed or missing `SUDO_GID` yields no
    /// owner at all — never half an owner.
    #[test]
    fn sudo_gid_malformed_or_missing_yields_none() {
        for gid in ["abc", "", "-5", "4294967296"] {
            assert_eq!(
                resolve_socket_owner(env_of(&[("SUDO_UID", "1000"), ("SUDO_GID", gid)])),
                None,
                "SUDO_GID={gid:?} must not resolve"
            );
        }
        assert_eq!(
            resolve_socket_owner(env_of(&[("SUDO_UID", "1000")])),
            None,
            "absent SUDO_GID must not resolve"
        );
    }

    /// Malformed `SUDO_UID` values yield no owner and no panic.
    #[test]
    fn sudo_uid_malformed_yields_none() {
        for uid in ["abc", "", "-1", "12.5", "4294967296"] {
            assert_eq!(
                resolve_socket_owner(env_of(&[("SUDO_UID", uid), ("SUDO_GID", "1001")])),
                None,
                "SUDO_UID={uid:?} must not resolve"
            );
        }
    }

    /// `PKEXEC_UID` alone resolves to the uid with no gid; the consumer
    /// resolves the primary group itself.
    #[test]
    fn pkexec_uid_resolves_owner_without_gid() {
        let owner = resolve_socket_owner(env_of(&[("PKEXEC_UID", "1000")]));
        assert_eq!(
            owner,
            Some(SocketOwner {
                uid: 1000,
                gid: None
            })
        );
    }

    /// Malformed `PKEXEC_UID` yields no owner and no panic.
    #[test]
    fn pkexec_uid_malformed_yields_none() {
        for uid in ["abc", "", "-1"] {
            assert_eq!(
                resolve_socket_owner(env_of(&[("PKEXEC_UID", uid)])),
                None,
                "PKEXEC_UID={uid:?} must not resolve"
            );
        }
    }

    /// `SUDO_*` wins over `PKEXEC_UID` when both are present.
    #[test]
    fn sudo_wins_over_pkexec() {
        let owner = resolve_socket_owner(env_of(&[
            ("SUDO_UID", "1000"),
            ("SUDO_GID", "1001"),
            ("PKEXEC_UID", "2000"),
        ]));
        assert_eq!(
            owner,
            Some(SocketOwner {
                uid: 1000,
                gid: Some(1001)
            })
        );
    }

    /// No owner-identifying variables: no owner.
    #[test]
    fn no_env_yields_none() {
        assert_eq!(resolve_socket_owner(env_of(&[])), None);
    }

    /// Owner known: per-uid path `/var/run/zpr/<uid>/control.sock`.
    /// Owner unknown: today's shared `<data_home>/control.sock`.
    #[test]
    fn socket_paths_derive_from_owner() {
        let dh = get_data_home();
        assert_eq!(
            control_socket_path(Some(1000)),
            Path::new("/var/run/zpr/1000/control.sock")
        );
        assert_eq!(control_socket_path(None), dh.join("control.sock"));
        assert_eq!(
            capture_socket_path(Some(1000)),
            Path::new("/var/run/zpr/1000/capture.sock")
        );
        assert_eq!(capture_socket_path(None), dh.join("capture.sock"));
    }

    /// The per-uid base is a fixed location, never derived from the process
    /// environment: `ph` computes this path under root's `HOME`/
    /// `XDG_DATA_HOME` while `ph-cli` computes it under the invoking user's,
    /// so any environment-derived base makes the two sides disagree and the
    /// advertised sudo-to-unprivileged workflow cannot connect (zipline#39
    /// review).
    #[test]
    fn per_uid_base_is_environment_independent() {
        assert_eq!(owner_socket_dir(1000), Path::new("/var/run/zpr/1000"));
    }

    /// The drift regression this issue exists to prevent: the path `ph`
    /// derives for a resolved owner uid is identical to the path `ph-cli`
    /// derives for its own euid when they are the same user.
    #[test]
    fn ph_and_ph_cli_agree_on_per_uid_path() {
        let uid = 4321u32; // ph resolved SUDO_UID=4321; ph-cli geteuid()==4321
        let ph_side = control_socket_path(Some(uid));
        let cli_side = owner_socket_dir(uid).join("control.sock");
        assert_eq!(ph_side, cli_side);
        assert_eq!(
            capture_socket_path(Some(uid)),
            owner_socket_dir(uid).join("capture.sock")
        );
    }

    /// An explicit `-p` path short-circuits the search, even when it does
    /// not exist.
    #[test]
    fn explicit_path_short_circuits() {
        let chosen = choose_socket_path(
            Some(PathBuf::from("/explicit/control.sock")),
            PathBuf::from("/per-uid/control.sock"),
            PathBuf::from("/shared/control.sock"),
            |_: &Path| false,
        );
        assert_eq!(chosen, Ok(PathBuf::from("/explicit/control.sock")));
    }

    /// The per-uid path wins when it exists, even if the shared path also
    /// exists.
    #[test]
    fn per_uid_path_preferred_when_present() {
        let chosen = choose_socket_path(
            None,
            PathBuf::from("/per-uid/control.sock"),
            PathBuf::from("/shared/control.sock"),
            |_: &Path| true,
        );
        assert_eq!(chosen, Ok(PathBuf::from("/per-uid/control.sock")));
    }

    /// The shared path is the fallback when the per-uid path is absent.
    #[test]
    fn shared_path_used_when_per_uid_absent() {
        let chosen = choose_socket_path(
            None,
            PathBuf::from("/per-uid/control.sock"),
            PathBuf::from("/shared/control.sock"),
            |p: &Path| p == Path::new("/shared/control.sock"),
        );
        assert_eq!(chosen, Ok(PathBuf::from("/shared/control.sock")));
    }

    /// When nothing exists the error names both paths tried.
    #[test]
    fn error_names_both_paths_tried() {
        let err = choose_socket_path(
            None,
            PathBuf::from("/per-uid/control.sock"),
            PathBuf::from("/shared/control.sock"),
            |_: &Path| false,
        )
        .expect_err("no socket exists, the search must fail");
        assert!(err.contains("/per-uid/control.sock"), "err was: {err}");
        assert!(err.contains("/shared/control.sock"), "err was: {err}");
    }
}
