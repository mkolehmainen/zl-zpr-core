//! Deciding who owns the ZPR internal-network route (zipline#101).
//!
//! Only one adapter per host can own `fd5a:5052::/32`: a second adapter
//! whose route loses to another live interface docks, activates, and then
//! silently receives no traffic. This module holds the pure logic for the
//! refuse-to-start / refuse-to-activate check: a parser for Linux
//! `ip -6 route show <prefix>` output, and the platform-neutral conflict
//! decision shared with the macOS path (whose `route -n get` parsing lives
//! in [`super::macos_route`]).
//!
//! Platform-neutral on purpose: compiled on every OS so the logic stays
//! unit-testable from a Linux build, same pattern as `sys::macos_route`.

/// One route-table entry for the ZPR internal network: the interface it
/// routes via, and whether that interface is administratively present but
/// dead (`linkdown` — e.g. a Linux persistent TUN with nobody attached).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOwner {
    pub ifname: String,
    pub linkdown: bool,
}

/// The live interface found to already own the ZPR internal network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictingIf {
    pub ifname: String,
}

/// Which platform's liveness rule to apply in [`route_owner_conflict`].
///
/// One variant is inevitably never constructed at runtime on any given OS
/// (each platform builds only its own query path); the unit tests construct
/// both, hence the `allow(dead_code)`.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
}

/// Parse `ip -6 route show <prefix>` output into the interfaces carrying
/// the prefix.
///
/// Each line names one route; the interface is the token after `dev`, and
/// a `linkdown` token marks an interface that is present but has no
/// carrier. Lines without a parseable `dev <ifname>` pair are skipped —
/// this parser reports owners, and a route it cannot attribute to an
/// interface has no owner to report.
pub fn parse_route_show(_stdout: &str) -> Vec<RouteOwner> {
    todo!("zipline#101")
}

/// Decide whether any of `owners` conflicts with our TUN `our_ifname`.
///
/// - A route on our own interface is never a conflict (the `tun_if`
///   pre-provisioned case).
/// - macOS: any route on another interface is a conflict — a utun exists
///   only while its process holds it, so the owner is live by existence.
/// - Linux: another interface counts only when it is up with carrier; a
///   `linkdown` route (stale persistent TUN, nobody attached) must not
///   block startup.
/// - No route at all: no conflict.
pub fn route_owner_conflict(
    _owners: &[RouteOwner],
    _our_ifname: &str,
    _platform: Platform,
) -> Option<ConflictingIf> {
    todo!("zipline#101")
}

#[cfg(test)]
mod test {
    use super::*;

    // ---- parse_route_show fixtures ----
    //
    // `ip -6 route show fd5a:5052::/32` output shapes, from the zipline#101
    // issue body (kernel behavior checked with two TUNs in a container,
    // same `ip` commands ph runs): the kernel installs a
    // `proto kernel metric 256` /32 route when `addr add` assigns addr/32,
    // and ph's own `ip -6 route replace ... dev <tun>` installs an explicit
    // route at metric 1024.

    /// Route absent: `ip -6 route show <prefix>` prints nothing.
    const SHOW_NO_ROUTE: &str = "";

    /// Only our own TUN carries the prefix (kernel route from add_address).
    const SHOW_OWN_TUN_ONLY: &str = "fd5a:5052::/32 dev tun0 proto kernel metric 256 pref medium\n";

    /// Another TUN, up with carrier, owns the prefix.
    const SHOW_OTHER_TUN: &str = "fd5a:5052::/32 dev tun1 proto kernel metric 256 pref medium\n";

    /// Another TUN owns the prefix but is `linkdown` — a persistent TUN
    /// with nobody attached. Must not block startup.
    const SHOW_OTHER_TUN_LINKDOWN: &str =
        "fd5a:5052::/32 dev tun1 proto kernel metric 256 linkdown pref medium\n";

    /// Kernel route (metric 256) and explicit `route replace` route
    /// (metric 1024) both present on our own TUN.
    const SHOW_KERNEL_AND_EXPLICIT_OURS: &str = "\
fd5a:5052::/32 dev tun0 proto kernel metric 256 pref medium
fd5a:5052::/32 dev tun0 metric 1024 pref medium
";

    /// The two-adapter table from the issue: adapter A (tunA) and adapter B
    /// (tunB) both hold kernel routes, plus B's explicit metric-1024 route
    /// that the kernel routes shadow.
    const SHOW_TWO_ADAPTERS: &str = "\
fd5a:5052::/32 dev tunA proto kernel metric 256 pref medium
fd5a:5052::/32 dev tunB proto kernel metric 256 pref medium
fd5a:5052::/32 dev tunB metric 1024 pref medium
";

    #[test]
    fn parse_no_route_is_empty() {
        assert_eq!(parse_route_show(SHOW_NO_ROUTE), Vec::<RouteOwner>::new());
    }

    #[test]
    fn parse_own_tun_only() {
        assert_eq!(
            parse_route_show(SHOW_OWN_TUN_ONLY),
            vec![RouteOwner {
                ifname: "tun0".into(),
                linkdown: false
            }]
        );
    }

    #[test]
    fn parse_other_tun_with_carrier() {
        assert_eq!(
            parse_route_show(SHOW_OTHER_TUN),
            vec![RouteOwner {
                ifname: "tun1".into(),
                linkdown: false
            }]
        );
    }

    #[test]
    fn parse_other_tun_linkdown() {
        assert_eq!(
            parse_route_show(SHOW_OTHER_TUN_LINKDOWN),
            vec![RouteOwner {
                ifname: "tun1".into(),
                linkdown: true
            }]
        );
    }

    #[test]
    fn parse_kernel_and_explicit_routes_both_present() {
        assert_eq!(
            parse_route_show(SHOW_KERNEL_AND_EXPLICIT_OURS),
            vec![
                RouteOwner {
                    ifname: "tun0".into(),
                    linkdown: false
                },
                RouteOwner {
                    ifname: "tun0".into(),
                    linkdown: false
                },
            ]
        );
    }

    #[test]
    fn parse_skips_unattributable_lines() {
        // No `dev <ifname>` pair — nothing to report as an owner.
        assert_eq!(
            parse_route_show("unreachable fd5a:5052::/32 metric 1024\n"),
            Vec::<RouteOwner>::new()
        );
        assert_eq!(
            parse_route_show("fd5a:5052::/32 dev\n"),
            Vec::<RouteOwner>::new()
        );
    }

    // ---- route_owner_conflict ----

    fn owners(stdout: &str) -> Vec<RouteOwner> {
        parse_route_show(stdout)
    }

    #[test]
    fn no_route_is_no_conflict_on_both_platforms() {
        for platform in [Platform::Linux, Platform::MacOs] {
            assert_eq!(
                route_owner_conflict(&owners(SHOW_NO_ROUTE), "tun0", platform),
                None
            );
        }
    }

    #[test]
    fn own_interface_only_is_no_conflict_on_both_platforms() {
        // The `tun_if` pre-provisioned case: the route already sits on our
        // own TUN. Startup must pass.
        for platform in [Platform::Linux, Platform::MacOs] {
            assert_eq!(
                route_owner_conflict(&owners(SHOW_OWN_TUN_ONLY), "tun0", platform),
                None
            );
        }
    }

    #[test]
    fn own_kernel_and_explicit_routes_are_no_conflict() {
        assert_eq!(
            route_owner_conflict(
                &owners(SHOW_KERNEL_AND_EXPLICIT_OURS),
                "tun0",
                Platform::Linux
            ),
            None
        );
    }

    #[test]
    fn linux_other_interface_with_carrier_is_a_conflict() {
        assert_eq!(
            route_owner_conflict(&owners(SHOW_OTHER_TUN), "tun0", Platform::Linux),
            Some(ConflictingIf {
                ifname: "tun1".into()
            })
        );
    }

    #[test]
    fn linux_other_interface_linkdown_is_no_conflict() {
        // A stale route on an unattended persistent TUN must not block.
        assert_eq!(
            route_owner_conflict(&owners(SHOW_OTHER_TUN_LINKDOWN), "tun0", Platform::Linux),
            None
        );
    }

    #[test]
    fn linux_two_adapter_table_names_the_other_owner() {
        // Adapter B starting second: its own routes pass, A's live route
        // conflicts, and the reported owner is A's interface.
        assert_eq!(
            route_owner_conflict(&owners(SHOW_TWO_ADAPTERS), "tunB", Platform::Linux),
            Some(ConflictingIf {
                ifname: "tunA".into()
            })
        );
    }

    #[test]
    fn macos_any_other_interface_is_a_conflict_even_linkdown() {
        // A utun exists only while its process holds it: existence is
        // liveness, so the linkdown flag is irrelevant on macOS.
        assert_eq!(
            route_owner_conflict(&owners(SHOW_OTHER_TUN), "utun5", Platform::MacOs),
            Some(ConflictingIf {
                ifname: "tun1".into()
            })
        );
        assert_eq!(
            route_owner_conflict(
                &[RouteOwner {
                    ifname: "utun4".into(),
                    linkdown: true
                }],
                "utun5",
                Platform::MacOs
            ),
            Some(ConflictingIf {
                ifname: "utun4".into()
            })
        );
    }

    #[test]
    fn interface_match_is_exact_not_prefix() {
        // tun1 vs tun10: a prefix match would wrongly pass this.
        assert_eq!(
            route_owner_conflict(
                &[RouteOwner {
                    ifname: "tun10".into(),
                    linkdown: false
                }],
                "tun1",
                Platform::Linux
            ),
            Some(ConflictingIf {
                ifname: "tun10".into()
            })
        );
    }
}
