//! Substrate socket helpers shared by every platform.

use std::io;
use std::net::{SocketAddr, UdpSocket};

/// Ask the OS which local address it would use to send to `peer`.
///
/// Binds a throwaway UDP socket to `bind_addr` exactly as configured, then
/// `connect`s it to `peer`. A UDP connect sends nothing on the wire; it
/// only runs route selection and fixes the socket's source address, which
/// `local_addr` then reports, including the IPv6 scope id. The probe is
/// dropped on return.
///
/// The port is kept (and, when `bind_addr`'s is 0, the OS-chosen one is
/// reported) because route selection may depend on the source port --
/// source-port policy rules, L4-hash ECMP -- so the probe must ask with the
/// same 5-tuple the substrate sockets will use (PR #72 review). Callers
/// therefore run this before any substrate socket holds the port.
///
/// Used when an adapter is configured with a wildcard `self_addr`
/// (zipline#175): the substrate sockets are then bound to the returned
/// address directly, so no socket ever has to be connected and disconnected
/// again (which behaves differently on Linux, macOS and Windows).
pub fn resolve_local_addr(bind_addr: SocketAddr, peer: SocketAddr) -> io::Result<SocketAddr> {
    let probe = UdpSocket::bind(bind_addr)?;
    probe.connect(peer)?;
    probe.local_addr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    /// A loopback peer is reached from loopback, so the probe must report
    /// a loopback source address (and the OS-chosen ephemeral port, which
    /// callers ignore).
    #[test]
    fn test_resolve_local_addr_loopback_v4() {
        let wildcard = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let local = resolve_local_addr(wildcard, peer).unwrap();
        assert_eq!(local.ip(), Ipv4Addr::LOCALHOST);
    }

    /// Same as above over IPv6. Skipped (passes) when the host has no IPv6
    /// loopback, which some CI containers lack.
    #[test]
    fn test_resolve_local_addr_loopback_v6() {
        if std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).is_err() {
            return;
        }
        let wildcard = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
        let peer = SocketAddr::from((Ipv6Addr::LOCALHOST, 9));
        let local = resolve_local_addr(wildcard, peer).unwrap();
        assert_eq!(local.ip(), Ipv6Addr::LOCALHOST);
    }

    /// A configured port is kept: routing may depend on the source port
    /// (source-port policy rules, L4-hash ECMP), so the probe must ask with
    /// the same 5-tuple the substrate sockets will use (PR #72 review).
    #[test]
    fn test_resolve_local_addr_keeps_configured_port() {
        // Find a free port, then release it for the probe to bind.
        let port = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let wildcard = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let local = resolve_local_addr(wildcard, peer).unwrap();
        assert_eq!(local, SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    }

    /// With no configured port the OS picks one; the caller adopts it so the
    /// substrate sockets use the port the route was chosen for.
    #[test]
    fn test_resolve_local_addr_reports_chosen_port() {
        let wildcard = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let local = resolve_local_addr(wildcard, peer).unwrap();
        assert_ne!(local.port(), 0);
    }
}
