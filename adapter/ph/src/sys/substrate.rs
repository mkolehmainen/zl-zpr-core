//! Substrate socket helpers shared by every platform.

use std::io;
use std::net::{SocketAddr, UdpSocket};

/// Ask the OS which local address it would use to send to `peer`.
///
/// Binds a throwaway UDP socket to the IP of `bind_addr` (its port is
/// ignored: the probe takes an ephemeral one, so a port already held by the
/// real substrate sockets is not disturbed), then `connect`s it to `peer`.
/// A UDP connect sends nothing on the wire; it only runs route selection
/// and fixes the socket's source address, which `local_addr` then reports,
/// including the IPv6 scope id. The probe is dropped on return.
///
/// Used when an adapter is configured with a wildcard `self_addr`
/// (zipline#175): the substrate sockets are then bound to the returned IP
/// directly, so no socket ever has to be connected and disconnected again
/// (which behaves differently on Linux, macOS and Windows).
pub fn resolve_local_addr(bind_addr: SocketAddr, peer: SocketAddr) -> io::Result<SocketAddr> {
    let mut probe_bind = bind_addr;
    probe_bind.set_port(0);
    let probe = UdpSocket::bind(probe_bind)?;
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

    /// The probe binds only to the IP of `bind_addr`; a fixed port there
    /// (e.g. the tether port a node already holds) must not be required to
    /// be free.
    #[test]
    fn test_resolve_local_addr_ignores_bind_port() {
        let held = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let wildcard = held.local_addr().unwrap();
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let local = resolve_local_addr(wildcard, peer).unwrap();
        assert_eq!(local.ip(), Ipv4Addr::LOCALHOST);
    }
}
