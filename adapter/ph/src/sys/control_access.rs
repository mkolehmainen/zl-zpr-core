//! Platform-neutral pieces of control-channel access control
//! (zipline#154). Compiled on every OS so the Windows DACL string and the
//! warning wording stay unit-testable from Linux builds — the same pattern
//! as `macos_route` in `sys/mod.rs`.

/// The startup warning for a configured `control_group` that does not
/// exist on this host. One builder for both control arms (posix socket,
/// Windows pipe) so the wording is identical on every platform.
pub(crate) fn missing_group_warning(name: &str) -> String {
    format!(
        "control group '{name}' not found on this host; \
         the control channel keeps its default access"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wording is pinned: it is the one string an operator greps for
    /// on every platform.
    #[test]
    fn missing_group_warning_wording() {
        assert_eq!(
            missing_group_warning("zipline"),
            "control group 'zipline' not found on this host; \
             the control channel keeps its default access"
        );
    }
}
