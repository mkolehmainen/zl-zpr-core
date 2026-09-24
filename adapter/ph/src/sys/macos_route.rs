//! Decision logic for macOS `route add` reporting "File exists".
//!
//! When `route add` finds the destination prefix already in the table it
//! fails with "File exists" whether or not the existing route targets the
//! interface we asked for. This module decides, from `route -n get` output,
//! whether that existing route already points at our TUN (idempotent
//! success) or leads elsewhere and must be replaced.
//!
//! Platform-neutral on purpose: only `sys::macos::zprtun` calls it at
//! runtime, but keeping it compiled on every OS lets the logic be
//! unit-tested from a Linux build, where the macOS syscall path cannot run.

/// What to do about a route that `route add` reported as already existing.
#[derive(Debug, PartialEq, Eq)]
pub enum ExistingRouteAction {
    /// The existing route already targets our TUN: idempotent success.
    AlreadyOurs,
    /// The existing route points at another interface (or its target
    /// cannot be determined): it must be replaced with ours.
    Replace,
}

/// Decide whether the already-present route for a prefix targets our TUN.
///
/// `route_get_stdout` is the stdout of `route -n get -inet6 <prefix>`;
/// `our_ifname` is the name of the TUN the route must be on. Anything other
/// than an exact interface match — a different interface, or output with no
/// parseable `interface:` line — demands a replace: guessing "ours" is how
/// a stale route silently swallows every reply.
pub fn existing_route_action(route_get_stdout: &str, our_ifname: &str) -> ExistingRouteAction {
    for line in route_get_stdout.lines() {
        if let Some(value) = line.trim_start().strip_prefix("interface:") {
            let ifname = value.trim();
            if !ifname.is_empty() && ifname == our_ifname {
                return ExistingRouteAction::AlreadyOurs;
            }
            return ExistingRouteAction::Replace;
        }
    }
    ExistingRouteAction::Replace
}

/// Outcome of a `route add` / `route delete` invocation.
///
/// macOS `/sbin/route` exits **0** even when the operation failed — observed
/// on a real Mac (zipline#100): a duplicate `add` prints
/// `route: writing to routing socket: File exists` and exits 0, and a
/// `delete` of an absent route prints `... not in table` and exits 0.
/// Classification therefore reads stderr first and trusts the exit status
/// only when stderr is clean.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteCmdResult {
    /// Clean success: exit 0 and nothing on stderr.
    Ok,
    /// The destination prefix is already in the table (`File exists` /
    /// `already in table` on stderr), **whatever the exit status**.
    Exists,
    /// Anything else non-clean — including exit 0 with unexpected stderr
    /// text. Carries the stderr for the caller's error message.
    Failed(String),
}

/// Classify the result of a `route add` / `route delete` command from its
/// exit status and stderr.
pub fn classify_route_cmd(exit_success: bool, stderr: &str) -> RouteCmdResult {
    // RED stub: mirrors the pre-fix call sites, which trust the exit status
    // and read stderr only after a non-zero exit.
    if exit_success {
        return RouteCmdResult::Ok;
    }
    if stderr.contains("File exists") || stderr.contains("already in table") {
        return RouteCmdResult::Exists;
    }
    RouteCmdResult::Failed(stderr.to_string())
}

/// Classify `route -n get` output when probing whether a route is still
/// installed: `true` means the route is gone from the table.
///
/// A non-zero exit (macOS `route get` on an absent route) or a
/// `not in table` marker means gone; a resolved route — exit 0 with no
/// such marker — means present. Ambiguous output defaults to "present" so
/// an idempotent delete fails loudly rather than guessing.
pub fn route_gone(get_exit_success: bool, get_output: &str) -> bool {
    // RED stub: pre-fix semantics — only a non-zero exit means gone.
    let _ = get_output;
    !get_exit_success
}

#[cfg(test)]
mod test {
    use super::*;

    /// `route -n get` output when the route is on-link via our utun.
    const GET_ON_OUR_TUN: &str = "\
   route to: fd5a:5052::
destination: fd5a:5052::
       mask: ffff:ffff::
  interface: utun4
      flags: <UP,DONE,STATIC>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      2000         0
";

    /// `route -n get` output when the prefix routes via a gateway on en0.
    const GET_VIA_OTHER_IF: &str = "\
   route to: fd5a:5052::
destination: fd5a:5052::
       mask: ffff:ffff::
    gateway: fe80::1%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";

    #[test]
    fn route_on_our_tun_is_already_ours() {
        assert_eq!(
            existing_route_action(GET_ON_OUR_TUN, "utun4"),
            ExistingRouteAction::AlreadyOurs
        );
    }

    #[test]
    fn route_on_other_interface_demands_replace() {
        assert_eq!(
            existing_route_action(GET_VIA_OTHER_IF, "utun4"),
            ExistingRouteAction::Replace
        );
    }

    #[test]
    fn interface_match_is_exact_not_prefix() {
        // utun4 vs utun41: a prefix match would wrongly accept this.
        assert_eq!(
            existing_route_action(GET_ON_OUR_TUN, "utun41"),
            ExistingRouteAction::Replace
        );
    }

    #[test]
    fn unparseable_output_demands_replace() {
        // No `interface:` line at all — never assume the route is ours.
        assert_eq!(
            existing_route_action("not route output\n", "utun4"),
            ExistingRouteAction::Replace
        );
    }

    #[test]
    fn empty_interface_value_demands_replace() {
        assert_eq!(
            existing_route_action("  interface: \n", "utun4"),
            ExistingRouteAction::Replace
        );
    }

    // ---- classify_route_cmd ----
    //
    // The stderr fixtures below quote a real Mac verbatim (zipline#100,
    // operator run of 2026-09-24):
    //
    //   $ sudo route -n add -inet6 $P ::1;    echo "add#2 (exists) exit=$?"
    //   route: writing to routing socket: File exists
    //   add net fd00:6666:7777::/64: gateway ::1: File exists
    //   add#2 (exists) exit=0
    //
    //   $ sudo route -n delete -inet6 $P;     echo "del#2 (absent) exit=$?"
    //   route: writing to routing socket: not in table
    //   delete net fd00:6666:7777::/64: not in table
    //   del#2 (absent) exit=0
    //
    // Both failures exit 0 — that exit-0-on-failure is the whole bug.

    /// Mac add#2 output: duplicate add, exit 0.
    const ADD_EXISTS_STDERR: &str = "\
route: writing to routing socket: File exists
add net fd00:6666:7777::/64: gateway ::1: File exists
";

    /// Mac del#2 output: delete of an absent route, exit 0.
    const DEL_NOT_IN_TABLE_STDERR: &str = "\
route: writing to routing socket: not in table
delete net fd00:6666:7777::/64: not in table
";

    /// The field observation from the issue body (2026-09-24, exit 0).
    const FIELD_ADD_EXISTS_STDERR: &str = "\
route: writing to routing socket: File exists
add net fd5a:5052::/32: gateway utun5: File exists
";

    #[test]
    fn clean_exit_zero_is_ok() {
        // Mac add#1 / del#1: summary line goes to stdout, stderr is empty.
        assert_eq!(classify_route_cmd(true, ""), RouteCmdResult::Ok);
    }

    #[test]
    fn exit_zero_file_exists_is_exists() {
        // The bug: /sbin/route exits 0 on "File exists".
        assert_eq!(
            classify_route_cmd(true, ADD_EXISTS_STDERR),
            RouteCmdResult::Exists
        );
        assert_eq!(
            classify_route_cmd(true, FIELD_ADD_EXISTS_STDERR),
            RouteCmdResult::Exists
        );
    }

    #[test]
    fn nonzero_exit_file_exists_is_exists() {
        assert_eq!(
            classify_route_cmd(false, ADD_EXISTS_STDERR),
            RouteCmdResult::Exists
        );
    }

    #[test]
    fn already_in_table_is_exists_whatever_the_exit() {
        assert_eq!(
            classify_route_cmd(true, "add net fd5a:5052::/32: already in table\n"),
            RouteCmdResult::Exists
        );
        assert_eq!(
            classify_route_cmd(false, "add net fd5a:5052::/32: already in table\n"),
            RouteCmdResult::Exists
        );
    }

    #[test]
    fn nonzero_exit_other_stderr_is_failed_with_stderr() {
        let stderr = "route: bad address: nonsense\n";
        assert_eq!(
            classify_route_cmd(false, stderr),
            RouteCmdResult::Failed(stderr.to_string())
        );
    }

    #[test]
    fn exit_zero_unexpected_stderr_is_failed() {
        // Exit 0 with error text is never success: the classifier reports
        // "not in table" as non-clean; route_delete's route-gone probe is
        // what turns it into idempotent success.
        assert_eq!(
            classify_route_cmd(true, DEL_NOT_IN_TABLE_STDERR),
            RouteCmdResult::Failed(DEL_NOT_IN_TABLE_STDERR.to_string())
        );
    }

    #[test]
    fn nonzero_exit_not_in_table_is_failed() {
        assert_eq!(
            classify_route_cmd(false, DEL_NOT_IN_TABLE_STDERR),
            RouteCmdResult::Failed(DEL_NOT_IN_TABLE_STDERR.to_string())
        );
    }

    #[test]
    fn nonzero_exit_empty_stderr_is_failed() {
        assert_eq!(
            classify_route_cmd(false, ""),
            RouteCmdResult::Failed(String::new())
        );
    }

    // ---- route_gone ----

    #[test]
    fn get_nonzero_exit_means_gone() {
        // macOS `route -n get` on an absent route exits non-zero.
        assert!(route_gone(false, "route: route has not been found\n"));
    }

    #[test]
    fn not_in_table_at_exit_zero_means_gone() {
        // Mac del#2 verbatim: the marker arrives at exit 0.
        assert!(route_gone(true, DEL_NOT_IN_TABLE_STDERR));
    }

    #[test]
    fn not_in_table_at_nonzero_exit_means_gone() {
        assert!(route_gone(false, DEL_NOT_IN_TABLE_STDERR));
    }

    #[test]
    fn resolved_route_means_present() {
        assert!(!route_gone(true, GET_ON_OUR_TUN));
    }

    #[test]
    fn ambiguous_exit_zero_output_means_present() {
        // No gone-marker and exit 0: never guess "gone" — the idempotent
        // delete must fail loudly instead.
        assert!(!route_gone(true, ""));
    }
}
