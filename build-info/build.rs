//! Stamp a build-identity string into the binary (zipline#64).
//!
//! Emits `ZPR_BUILD_DESCRIBE` for `src/lib.rs` to compose into
//! `BUILD_VERSION` as `<pkg-version> (<describe>)`.
//!
//! Precedence:
//! 1. `ZPR_BUILD_ID` set in the environment — used verbatim, no git run.
//! 2. `git -c safe.directory=<repo root> describe --always --dirty --tags`
//!    run with the manifest directory as cwd. The `-c safe.directory` is
//!    load-bearing: the documented container build runs as root over a
//!    checkout owned by another uid, and without it git refuses ("dubious
//!    ownership") and every binary silently stamps `unknown`. The directory
//!    named must be the repository root — the nearest ancestor holding a
//!    `.git` entry — because git checks ownership of the repository, not of
//!    the cwd; for a workspace-member crate the manifest directory is a
//!    subdirectory and naming it alone does not lift the refusal.
//! 3. The literal `unknown`, with a `cargo:warning=` naming the reason.
//!    The build never fails for want of git metadata.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    println!("cargo:rerun-if-env-changed=ZPR_BUILD_ID");

    let describe = match std::env::var("ZPR_BUILD_ID") {
        Ok(id) => id,
        Err(_) => git_describe(&manifest_dir),
    };

    println!("cargo:rustc-env=ZPR_BUILD_DESCRIBE={describe}");
}

/// The nearest ancestor of `manifest_dir` (inclusive) containing a `.git`
/// entry — a directory in a normal clone, a file in a `git worktree`. This is
/// the directory `safe.directory` must name. Falls back to `manifest_dir`
/// when no `.git` exists anywhere above (the warned-`unknown` case).
fn repo_root(manifest_dir: &str) -> PathBuf {
    let mut dir = Path::new(manifest_dir);
    loop {
        if dir.join(".git").exists() {
            return dir.to_path_buf();
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return PathBuf::from(manifest_dir),
        }
    }
}

/// Run `git` in `manifest_dir` with the repository root marked safe.
fn git(
    manifest_dir: &str,
    safe_dir: &Path,
    args: &[&str],
) -> std::io::Result<std::process::Output> {
    Command::new("git")
        .arg("-c")
        .arg(format!("safe.directory={}", safe_dir.display()))
        .args(args)
        .current_dir(manifest_dir)
        .output()
}

/// Emit `cargo:rerun-if-changed=` for the path a `git` query reports,
/// resolved relative to the repository (git prints `--git-path` results
/// relative to the cwd it ran in). Skips a path that does not exist:
/// cargo treats a missing watched path as always-changed, which would
/// re-run this script (and rebuild every dependent crate) on every build.
/// The cost of skipping is that the path springing into existence later
/// (e.g. git creating `packed-refs`) is only noticed on the next re-run
/// triggered by some other input.
fn emit_rerun_path(manifest_dir: &str, safe_dir: &Path, args: &[&str]) {
    if let Ok(out) = git(manifest_dir, safe_dir, args)
        && out.status.success()
    {
        let path = String::from_utf8_lossy(&out.stdout);
        let path = path.trim();
        if !path.is_empty() {
            let abs = Path::new(manifest_dir).join(path);
            if abs.exists() {
                println!("cargo:rerun-if-changed={}", abs.display());
            }
        }
    }
}

/// Watch everything that can change the result of `git describe --dirty
/// --tags` without moving HEAD (zipline#64 review):
///
/// - **Every tracked file.** Editing one flips `--dirty`, and it is the one
///   change that touches no git bookkeeping file at all — the index records
///   the *staged* state, so a plain edit leaves it untouched. Watching the
///   tracked files themselves is the only way a build script can see it.
///   A deleted tracked file is deliberately still emitted (see below):
///   cargo treats the missing path as changed and re-runs, which is exactly
///   right — deletion is dirtiness.
/// - **The index**, for staged-only changes (`git add`, `git stash`,
///   `git checkout -- <path>`) that alter dirtiness without editing a file
///   after the last watch list was emitted.
/// - **`refs/tags` and `packed-refs`**, because creating, moving or deleting
///   a tag changes the describe name with no change to HEAD.
///
/// Honest limits: a watch list emitted at run N only covers what existed at
/// run N — a file becoming tracked is caught via the index (`git add`
/// re-runs us), but an edit whose mtime is deliberately restored, or git
/// internals not listed here, are not covered. This narrows the stale-stamp
/// window; it cannot eliminate it.
fn emit_dirty_rerun_inputs(manifest_dir: &str, safe_dir: &Path) {
    emit_rerun_path(
        manifest_dir,
        safe_dir,
        &["rev-parse", "--git-path", "index"],
    );
    emit_rerun_path(
        manifest_dir,
        safe_dir,
        &["rev-parse", "--git-path", "refs/tags"],
    );
    emit_rerun_path(
        manifest_dir,
        safe_dir,
        &["rev-parse", "--git-path", "packed-refs"],
    );

    // Tracked files, repo-wide: run from the repository root so a workspace
    // member's build sees edits to sibling crates too. `-z` for robustness
    // against unusual filenames. No existence filter here — missing means a
    // deleted tracked file, and always-re-run is the correct response.
    let root = safe_dir.to_str().unwrap_or(manifest_dir);
    if let Ok(out) = git(root, safe_dir, &["ls-files", "-z"])
        && out.status.success()
    {
        for name in out.stdout.split(|&b| b == 0) {
            if name.is_empty() {
                continue;
            }
            let name = String::from_utf8_lossy(name);
            println!("cargo:rerun-if-changed={}", safe_dir.join(&*name).display());
        }
    }
}

/// Run `git describe` in `manifest_dir`, falling back to `unknown` (with a
/// build-log warning quoting git's own stderr) if it cannot answer.
fn git_describe(manifest_dir: &str) -> String {
    let safe_dir = repo_root(manifest_dir);

    // Rebuild when HEAD moves. Ask git for the real paths: in a `git worktree`
    // `.git` is a file and the literal `.git/HEAD` does not exist. HEAD alone
    // is not enough — on a commit to the checked-out branch the HEAD file's
    // content (the branch name) does not change; the branch ref file does. So
    // watch both HEAD and, when HEAD is symbolic, the ref it points to.
    emit_rerun_path(
        manifest_dir,
        &safe_dir,
        &["rev-parse", "--git-path", "HEAD"],
    );

    // And rebuild when the describe result can change with HEAD unmoved:
    // worktree edits (--dirty), staged changes, tag creation or movement.
    emit_dirty_rerun_inputs(manifest_dir, &safe_dir);
    if let Ok(out) = git(manifest_dir, &safe_dir, &["symbolic-ref", "-q", "HEAD"])
        && out.status.success()
    {
        let refname = String::from_utf8_lossy(&out.stdout);
        let refname = refname.trim();
        if !refname.is_empty() {
            emit_rerun_path(
                manifest_dir,
                &safe_dir,
                &["rev-parse", "--git-path", refname],
            );
        }
    }

    let describe = git(
        manifest_dir,
        &safe_dir,
        &["describe", "--always", "--dirty", "--tags"],
    );

    match describe {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() {
                println!("cargo:warning=git describe printed nothing; version suffix is 'unknown'");
                "unknown".to_string()
            } else {
                s
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!(
                "cargo:warning=git describe failed ({}); version suffix is 'unknown': {}",
                out.status,
                stderr.trim().replace('\n', " ")
            );
            "unknown".to_string()
        }
        Err(e) => {
            println!("cargo:warning=could not run git ({e}); version suffix is 'unknown'");
            "unknown".to_string()
        }
    }
}
