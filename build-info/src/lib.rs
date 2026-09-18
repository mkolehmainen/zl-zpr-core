//! Build-identity string for every binary in this workspace (zipline#64).
//!
//! `build.rs` stamps `<workspace pkg-version> (<git describe>)` at build
//! time; each binary crate passes [`BUILD_VERSION`] to clap's `version`.

/// Build-identity string: `<pkg-version> (<git describe>)`, stamped by
/// `build.rs` at build time (zipline#64). The suffix is
/// `git describe --always --dirty --tags`, or the value of `ZPR_BUILD_ID`
/// verbatim, or the literal `unknown` when neither is available.
pub const BUILD_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("ZPR_BUILD_DESCRIBE"),
    ")"
);

#[cfg(test)]
mod tests {
    /// Runs inside the real git checkout, so it can only assert the normal
    /// (describe) case; the no-git-metadata outcomes are proven by scripted
    /// out-of-tree builds quoted in the PR.
    #[test]
    fn build_version_is_stamped() {
        let v = crate::BUILD_VERSION;
        assert!(!v.is_empty(), "BUILD_VERSION is empty");
        assert!(
            v.contains(env!("CARGO_PKG_VERSION")),
            "BUILD_VERSION does not contain the package version: {v}"
        );
        assert!(
            !v.ends_with("(unknown)"),
            "built inside a git checkout, yet the suffix is the fallback: {v}"
        );
    }
}
