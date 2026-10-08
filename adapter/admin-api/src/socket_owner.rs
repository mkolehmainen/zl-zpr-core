//! Control socket ownership and default path derivation (zipline#39).
//!
//! `ph` usually runs as root (it creates a TUN device) while `ph-cli` runs as
//! the invoking user. Both sides must agree on who "owns" the control
//! socket and, from that, where the socket lives:
//!
//! * Owner known (`ph` started via `sudo` or `pkexec`): the socket lives in a
//!   per-uid directory `/var/run/zpr/<uid>/` and is chowned to that user.
//!   `ph-cli`, running as that user, derives the identical path from its own
//!   effective uid. The base is fixed, never environment-derived — see
//!   [PER_UID_SOCKET_BASE].
//! * Owner unknown (systemd, direct root login): the socket lives at the
//!   shared `<data_home>/` path as before; `ph` gives it to the configured
//!   `control_group`, if any, for access control (zipline#154).
//!
//! Owner resolution here is pure environment-string parsing over an injected
//! lookup so it is unit-testable without mutating process environment; the
//! uid -> gid lookups and the chown/chmod syscalls live in `ph`, which already
//! depends on `nix`.

use std::path::PathBuf;

#[cfg(unix)]
use crate::data_home::get_data_home;

/// The user a control socket should belong to.
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

/// Fixed base directory for per-uid socket directories.
///
/// Deliberately NOT derived from `HOME`/`XDG_DATA_HOME` (unlike the shared
/// path, which keeps its historical `get_data_home` derivation): `ph`
/// computes this path in root's environment while `ph-cli` computes it in
/// the invoking user's, so an environment-derived base makes the two sides
/// disagree for the same uid and the sudo-to-unprivileged workflow cannot
/// connect. `/var/run/zpr` is `get_data_home`'s own no-environment fallback,
/// is root-writable (ph creates `<base>/<uid>` chowned to the owner), and
/// being tmpfs-backed on modern hosts clears stale sockets on reboot.
#[cfg(unix)]
pub const PER_UID_SOCKET_BASE: &str = "/var/run/zpr";

/// The directory holding a known owner's sockets:
/// [`PER_UID_SOCKET_BASE`]`/<owner_id>/`. On unix `owner_id` is the
/// decimal uid (see [crate::current_user_id]).
#[cfg(unix)]
pub fn owner_socket_dir(owner_id: &str) -> PathBuf {
    PathBuf::from(PER_UID_SOCKET_BASE).join(owner_id)
}

/// Default control channel path for the given owner: per-owner when the
/// owner is known, the shared path when it is not. `owner_id` is what
/// [crate::current_user_id] returns for that user (a decimal uid on unix, a
/// SID string on Windows), so `ph` and `ph-cli` derive the same path.
///
/// * unix: `/var/run/zpr/<uid>/control.sock`, or `<data_home>/control.sock`.
/// * Windows: the named pipe `\\.\pipe\zpr-control-<sid>`, or
///   `\\.\pipe\zpr-control` (plan D6/D9).
pub fn control_socket_path(owner_id: Option<&str>) -> PathBuf {
    socket_path(owner_id, "control")
}

// Shared derivation for both sockets, unix arm: `<name>.sock` in the
// owner's directory or the data home.
#[cfg(unix)]
fn socket_path(owner_id: Option<&str>, name: &str) -> PathBuf {
    let file = format!("{name}.sock");
    match owner_id {
        Some(id) => owner_socket_dir(id).join(file),
        None => get_data_home().join(file),
    }
}

// Shared derivation for both sockets, Windows arm: a named pipe, which
// lives in the pipe namespace rather than the filesystem.
#[cfg(windows)]
fn socket_path(owner_id: Option<&str>, name: &str) -> PathBuf {
    match owner_id {
        Some(sid) => PathBuf::from(format!(r"\\.\pipe\zpr-{name}-{sid}")),
        None => PathBuf::from(format!(r"\\.\pipe\zpr-{name}")),
    }
}

/// Whether a live packet handler is accepting connections at `path`.
///
/// A socket pathname's existence is not proof of a live server: `ph` cannot
/// reliably unlink its sockets on shutdown (SIGKILL, crash), so a stale
/// file at the preferred per-uid path must not shadow a live server at the
/// shared path. This is the predicate `ph-cli` injects into
/// [choose_socket_path] — a probe connect, not an `exists()` check.
#[cfg(unix)]
pub fn socket_is_live(path: &std::path::Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

/// Whether a live packet handler is accepting connections on the named
/// pipe `path`: opening a pipe client succeeds only while a server
/// instance is listening. (A server whose every instance is busy also
/// probes not-live, so the named-pipe server in zipline#130 must always
/// keep a free instance waiting.)
#[cfg(windows)]
pub fn socket_is_live(path: &std::path::Path) -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .is_ok()
}

/// The control paths a client (`ph-cli`) running as `user_id` searches
/// when no `-p` is given, in priority order (see [choose_socket_path]):
///
/// 1. the per-owner path for `user_id` (a `sudo`/`pkexec`-started `ph`);
/// 2. the shared path, `control_socket_path(None)`;
/// 3. unix only: the fixed shared path `/var/run/zpr/control.sock`, unless
///    it is the same as 2 (zipline#77). A `ph` started by systemd or launchd
///    has no `HOME`, so it binds under `/var/run/zpr`; a non-root `ph-cli`
///    usually has `~/.local/share` or `XDG_DATA_HOME`, so its data home
///    (and hence path 2) points elsewhere. This is the same environment
///    mismatch [PER_UID_SOCKET_BASE] avoids for per-uid sockets.
///
/// Windows needs no third entry: pipe names do not depend on the environment.
pub fn control_socket_candidates(user_id: &str) -> Vec<PathBuf> {
    let per_owner = control_socket_path(Some(user_id));
    let shared = control_socket_path(None);
    #[cfg(unix)]
    {
        let fixed = PathBuf::from(PER_UID_SOCKET_BASE).join("control.sock");
        if fixed != shared {
            return vec![per_owner, shared, fixed];
        }
    }
    vec![per_owner, shared]
}

/// Which socket path a client (`ph-cli`) should use, given an optional
/// explicit path (`-p`), the candidate paths to search in priority order
/// (see [control_socket_candidates]) and an injected usability predicate
/// (see [socket_is_live]).
///
/// * An explicit path short-circuits everything. It is used whether or not
///   it is usable, so error reporting stays at the connect site.
/// * Otherwise the first usable candidate wins.
/// * When none is usable the result is an error naming every path tried.
pub fn choose_socket_path<F>(
    explicit: Option<PathBuf>,
    candidates: Vec<PathBuf>,
    exists: F,
) -> Result<PathBuf, String>
where
    F: Fn(&std::path::Path) -> bool,
{
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(path) = candidates.iter().find(|p| exists(p)) {
        return Ok(path.clone());
    }
    let tried: Vec<String> = candidates.iter().map(|p| p.display().to_string()).collect();
    Err(format!(
        "no live packet handler socket (tried {}); is ph running? Use -p to point at an explicit socket path",
        tried.join(", ")
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
    #[cfg(unix)]
    #[test]
    fn socket_paths_derive_from_owner() {
        let dh = get_data_home();
        assert_eq!(
            control_socket_path(Some("1000")),
            Path::new("/var/run/zpr/1000/control.sock")
        );
        assert_eq!(control_socket_path(None), dh.join("control.sock"));
    }

    /// Windows: owner known is a per-SID named pipe, owner unknown the
    /// shared pipe (plan D6/D9).
    #[cfg(windows)]
    #[test]
    fn socket_paths_derive_from_owner() {
        let sid = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            control_socket_path(Some(sid)),
            Path::new(r"\\.\pipe\zpr-control-S-1-5-21-1-2-3-1001")
        );
        assert_eq!(
            control_socket_path(None),
            Path::new(r"\\.\pipe\zpr-control")
        );
    }

    /// Nothing listens on a made-up pipe name.
    #[cfg(windows)]
    #[test]
    fn missing_pipe_is_not_live() {
        assert!(!socket_is_live(Path::new(r"\\.\pipe\zpr-test-nonexistent")));
    }

    /// The per-uid base is a fixed location, never derived from the process
    /// environment: `ph` computes this path under root's `HOME`/
    /// `XDG_DATA_HOME` while `ph-cli` computes it under the invoking user's,
    /// so any environment-derived base makes the two sides disagree and the
    /// advertised sudo-to-unprivileged workflow cannot connect (zipline#39
    /// review).
    #[cfg(unix)]
    #[test]
    fn per_uid_base_is_environment_independent() {
        assert_eq!(owner_socket_dir("1000"), Path::new("/var/run/zpr/1000"));
        assert_eq!(PER_UID_SOCKET_BASE, "/var/run/zpr");
    }

    /// The drift regression this issue exists to prevent: the path `ph`
    /// derives for a resolved owner uid is identical to the path `ph-cli`
    /// derives for its own euid when they are the same user.
    #[cfg(unix)]
    #[test]
    fn ph_and_ph_cli_agree_on_per_uid_path() {
        // ph resolved SUDO_UID=4321 and formats it; ph-cli's
        // current_user_id() is the same euid, formatted the same way.
        let ph_side = control_socket_path(Some(&4321u32.to_string()));
        let cli_side = owner_socket_dir("4321").join("control.sock");
        assert_eq!(ph_side, cli_side);
    }

    /// The three-candidate list the tests below search, in priority order.
    fn candidates() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/per-uid/control.sock"),
            PathBuf::from("/shared/control.sock"),
            PathBuf::from("/fixed/control.sock"),
        ]
    }

    /// An explicit `-p` path short-circuits the search, even when it does
    /// not exist.
    #[test]
    fn explicit_path_short_circuits() {
        let chosen = choose_socket_path(
            Some(PathBuf::from("/explicit/control.sock")),
            candidates(),
            |_: &Path| false,
        );
        assert_eq!(chosen, Ok(PathBuf::from("/explicit/control.sock")));
    }

    /// The per-uid path wins when it exists, even if the shared path also
    /// exists.
    #[test]
    fn per_uid_path_preferred_when_present() {
        let chosen = choose_socket_path(None, candidates(), |_: &Path| true);
        assert_eq!(chosen, Ok(PathBuf::from("/per-uid/control.sock")));
    }

    /// The shared path is the fallback when the per-uid path is absent.
    #[test]
    fn shared_path_used_when_per_uid_absent() {
        let chosen = choose_socket_path(None, candidates(), |p: &Path| {
            p == Path::new("/shared/control.sock")
        });
        assert_eq!(chosen, Ok(PathBuf::from("/shared/control.sock")));
    }

    /// The last candidate is still reached when every earlier one is
    /// absent (zipline#77: the fixed shared path behind a data home that
    /// `HOME`/`XDG_DATA_HOME` moved elsewhere).
    #[test]
    fn last_candidate_used_when_earlier_absent() {
        let chosen = choose_socket_path(None, candidates(), |p: &Path| {
            p == Path::new("/fixed/control.sock")
        });
        assert_eq!(chosen, Ok(PathBuf::from("/fixed/control.sock")));
    }

    /// When nothing exists the error names every path tried.
    #[test]
    fn error_names_every_path_tried() {
        let err = choose_socket_path(None, candidates(), |_: &Path| false)
            .expect_err("no socket exists, the search must fail");
        for path in candidates() {
            let path = path.to_str().unwrap().to_string();
            assert!(err.contains(&path), "err must name {path}: {err}");
        }
    }

    /// The failure diagnostic points at `-p` and ONLY `-p`: `ph-cli`
    /// retired its `-c` option (zipline#142 / zl-zpr-core#59 review), so a
    /// message telling the user to pass `-c` now leads straight into a
    /// clap unknown-option error. `ph`'s remaining `-c` is
    /// `--config-file`, unrelated to socket discovery, and `ph` never
    /// calls [choose_socket_path].
    #[test]
    fn error_recommends_only_dash_p() {
        let err = choose_socket_path(None, candidates(), |_: &Path| false)
            .expect_err("no socket exists, the search must fail");
        assert!(err.contains("-p"), "err must recommend -p: {err}");
        assert!(
            !err.contains("-c"),
            "err must not mention the retired -c option: {err}"
        );
    }

    /// zipline#77: a systemd/launchd-started `ph` has no `HOME`, so it binds
    /// the shared socket under `/var/run/zpr`; a non-root `ph-cli` usually
    /// has `~/.local/share`, so its data home differs. The candidates must
    /// therefore end with the fixed `/var/run/zpr/control.sock`, after the
    /// per-uid and data-home paths, and list it only once.
    #[cfg(unix)]
    #[test]
    fn candidates_end_with_fixed_shared_path() {
        let fixed = Path::new("/var/run/zpr/control.sock");
        let list = control_socket_candidates("1000");
        assert_eq!(list[0], control_socket_path(Some("1000")));
        assert_eq!(list[1], control_socket_path(None));
        assert_eq!(list.last().unwrap(), fixed);
        assert_eq!(list.iter().filter(|p| *p == fixed).count(), 1);
    }

    /// Windows: the shared pipe name is not environment-derived, so the
    /// search is just the per-SID pipe, then the shared pipe.
    #[cfg(windows)]
    #[test]
    fn candidates_are_per_sid_then_shared() {
        let sid = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            control_socket_candidates(sid),
            vec![control_socket_path(Some(sid)), control_socket_path(None)]
        );
    }

    /// A socket path with a live listener probes as live (zipline#39
    /// review: liveness, not existence, selects the socket).
    #[cfg(unix)]
    #[test]
    fn live_listener_probes_live() {
        let dir = temp_dir("live");
        let path = dir.join("control.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(socket_is_live(&path), "a bound listener must probe live");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A stale socket file — left behind by a dead ph that never got to
    /// unlink it — must NOT probe live, or it shadows a live server at the
    /// fallback path (zipline#39 review).
    #[cfg(unix)]
    #[test]
    fn stale_socket_file_is_not_live() {
        let dir = temp_dir("stale");
        let path = dir.join("control.sock");
        {
            // Bind and drop: the listener dies, the pathname stays — exactly
            // what a SIGKILLed ph leaves behind.
            let _dead = std::os::unix::net::UnixListener::bind(&path).unwrap();
        }
        assert!(path.exists(), "the stale pathname must still exist");
        assert!(
            !socket_is_live(&path),
            "a dead server's socket file must not probe live"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A missing path is not live.
    #[cfg(unix)]
    #[test]
    fn missing_path_is_not_live() {
        assert!(!socket_is_live(Path::new(
            "/nonexistent/zpr-test/control.sock"
        )));
    }

    #[cfg(unix)]
    // A unique temp dir for socket tests (paths must stay short: sun_path).
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zpr_sock_{tag}_{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
