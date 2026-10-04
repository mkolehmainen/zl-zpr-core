//! The manual add-address hint: the one command line `ph` tells an operator
//! to run when a node ZPR address could not be applied to — or is missing
//! from — the TUN device (zipline#161).
//!
//! Compiled on every OS so the per-platform strings stay unit-testable from
//! Linux builds, same pattern and reason as `macos_route`: the decision of
//! *which* command to print is pure, only the caller is platform-specific.

use std::net::IpAddr;

/// The platform whose command syntax the hint uses. Separated from the
/// `cfg` so every arm is testable on every build host.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Platform {
    Linux,
    MacOs,
    Windows,
}

/// The current platform's arm.
const CURRENT: Platform = if cfg!(target_os = "linux") {
    Platform::Linux
} else if cfg!(target_os = "macos") {
    Platform::MacOs
} else {
    Platform::Windows
};

/// The hint in `platform`'s command syntax.
fn hint_for(platform: Platform, addr: &IpAddr, prefix_len: usize, ifname: &str) -> String {
    match platform {
        Platform::Linux => format!("ip -6 addr add {addr}/{prefix_len} dev {ifname}"),
        Platform::MacOs => format!("ifconfig {ifname} inet6 {addr}/{prefix_len} alias"),
        // netsh's add-address form takes no prefix length, and the
        // interface comes before the address.
        Platform::Windows => format!("netsh interface ipv6 add address {ifname} {addr}"),
    }
}

/// The command an operator runs to put `addr/prefix_len` on `ifname` by
/// hand, in the current platform's syntax.
pub fn manual_add_address_hint(addr: &IpAddr, prefix_len: usize, ifname: &str) -> String {
    hint_for(CURRENT, addr, prefix_len, ifname)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn addr() -> IpAddr {
        "fd5a:5052::a:b:c".parse().unwrap()
    }

    #[test]
    fn linux_hint_is_ip_addr_add() {
        assert_eq!(
            hint_for(Platform::Linux, &addr(), 32, "zpr0"),
            "ip -6 addr add fd5a:5052::a:b:c/32 dev zpr0"
        );
    }

    #[test]
    fn macos_hint_is_ifconfig_inet6_alias() {
        assert_eq!(
            hint_for(Platform::MacOs, &addr(), 32, "utun4"),
            "ifconfig utun4 inet6 fd5a:5052::a:b:c/32 alias"
        );
    }

    #[test]
    fn windows_hint_is_netsh_add_address() {
        // netsh takes no prefix length in this form; the interface name
        // comes before the address.
        assert_eq!(
            hint_for(Platform::Windows, &addr(), 32, "zpr0"),
            "netsh interface ipv6 add address zpr0 fd5a:5052::a:b:c"
        );
    }

    #[test]
    fn public_fn_uses_the_current_platform_arm() {
        let expected = if cfg!(target_os = "linux") {
            hint_for(Platform::Linux, &addr(), 32, "zpr0")
        } else if cfg!(target_os = "macos") {
            hint_for(Platform::MacOs, &addr(), 32, "zpr0")
        } else {
            hint_for(Platform::Windows, &addr(), 32, "zpr0")
        };
        assert_eq!(manual_add_address_hint(&addr(), 32, "zpr0"), expected);
    }

    // --- route hint (zipline#177): the manual add-route command printed
    // when the visa-service host route could not be installed. Only
    // Windows needs one — `netsh add address` ignores the prefix, so the
    // /128 route is a separate step there; on Linux and macOS the route
    // failure message carries no command today, and None keeps it that way.

    #[test]
    fn windows_route_hint_is_netsh_add_route() {
        // Exact current main.rs string, including the quotes around the
        // interface name (Wintun adapter names may contain spaces).
        assert_eq!(
            route_hint_for(Platform::Windows, &addr(), "zpr0").as_deref(),
            Some("netsh interface ipv6 add route fd5a:5052::a:b:c/128 \"zpr0\"")
        );
    }

    #[test]
    fn linux_route_hint_is_none() {
        assert_eq!(route_hint_for(Platform::Linux, &addr(), "zpr0"), None);
    }

    #[test]
    fn macos_route_hint_is_none() {
        assert_eq!(route_hint_for(Platform::MacOs, &addr(), "utun4"), None);
    }

    #[test]
    fn public_route_fn_uses_the_current_platform_arm() {
        let expected = if cfg!(target_os = "linux") {
            route_hint_for(Platform::Linux, &addr(), "zpr0")
        } else if cfg!(target_os = "macos") {
            route_hint_for(Platform::MacOs, &addr(), "zpr0")
        } else {
            route_hint_for(Platform::Windows, &addr(), "zpr0")
        };
        assert_eq!(manual_add_route_hint(&addr(), "zpr0"), expected);
    }
}
