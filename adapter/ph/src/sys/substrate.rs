//! Substrate socket helpers shared by every platform.

use std::io;
use std::net::{SocketAddr, UdpSocket};

// The per-platform "create, set options, bind, check" arm of substrate
// socket setup (zipline#176), re-exported here so `main.rs` calls one
// portable `sys::substrate::open` — the same split as `control`/`notify`.
#[cfg(unix)]
pub use super::posix::substrate::open;
#[cfg(windows)]
pub use super::windows::substrate::open;

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

    /// `open` returns a socket already bound to the requested address and
    /// nonblocking: a `recv` on the empty socket must fail with
    /// `WouldBlock` immediately instead of blocking the thread, which is
    /// what the batch I/O engines rely on.
    #[test]
    fn test_open_binds_nonblocking() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let socket = open(addr).unwrap();
        let local = socket.local_addr().unwrap().as_socket().unwrap();
        assert_eq!(local.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(local.port(), 0);
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 16];
        let err = socket.recv(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    /// The substrate loop opens `fastpath_concurrency` sockets on the SAME
    /// concrete addr+port, which on unix relies on `open` setting
    /// SO_REUSEPORT before the bind: a second `open` on the first one's
    /// bound address must succeed, and the option must read back set.
    #[cfg(unix)]
    #[test]
    fn test_open_same_addr_twice_reuse_port() {
        let first = open(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        assert!(first.reuse_port().unwrap());
        let bound = first.local_addr().unwrap().as_socket().unwrap();
        let second = open(bound).unwrap();
        assert_eq!(
            second.local_addr().unwrap().as_socket().unwrap(),
            bound,
            "second socket must share the first one's 5-tuple"
        );
    }

    /// The posix arm enables pktinfo reception (`IP_PKTINFO`), which
    /// `try_recv_buf_from_to_batch` needs to report each datagram's
    /// destination address.
    #[cfg(unix)]
    #[test]
    fn test_open_enables_pktinfo() {
        let socket = open(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let enabled =
            nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::Ipv4PacketInfo)
                .unwrap();
        assert!(enabled);
    }

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
