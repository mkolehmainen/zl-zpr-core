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
    // Current behavior under test: "File exists" is unconditionally treated
    // as idempotent success, i.e. the existing route is assumed to be ours.
    let _ = (route_get_stdout, our_ifname);
    ExistingRouteAction::AlreadyOurs
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
}
