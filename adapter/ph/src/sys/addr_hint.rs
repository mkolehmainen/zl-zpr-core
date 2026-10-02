//! The manual add-address hint: the one command line `ph` tells an operator
//! to run when a node ZPR address could not be applied to — or is missing
//! from — the TUN device (zipline#161).
//!
//! Compiled on every OS so the per-platform strings stay unit-testable from
//! Linux builds, same pattern and reason as `macos_route`: the decision of
//! *which* command to print is pure, only the caller is platform-specific.

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
}
