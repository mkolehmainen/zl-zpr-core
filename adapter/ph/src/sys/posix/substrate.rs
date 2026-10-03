//! Substrate socket creation, unix arm (zipline#176).
//!
//! The windows arm (`sys/windows/substrate.rs`) provides the same `open`,
//! so the socket loop in `main.rs` has no platform branches left.

use crate::batch_io;
use std::io;
use std::net::SocketAddr;

/// Create, configure and bind one substrate UDP socket on `addr`.
///
/// The socket is nonblocking (the batch I/O engines poll it), receives
/// per-datagram packet info (`IP_PKTINFO`/`IPV6_RECVPKTINFO`, which
/// `try_recv_buf_from_to_batch` needs to report each datagram's
/// destination address), and has `SO_REUSEPORT` set before the bind so
/// the fastpath can open several sockets for the same 5-tuple.
///
/// If `addr`'s port is 0 the OS picks one; the caller reads it back via
/// `local_addr` and adopts it so every later socket binds the same port.
///
/// Any failure — including the bind — is an `Err`, not a panic: the
/// caller logs it and exits cleanly (zipline#160 semantics, extended to
/// unix with zipline#176).
pub fn open(addr: SocketAddr) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        None,
    )?;
    socket.set_nonblocking(true)?;
    batch_io::set_recv_packet_info(&socket, true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&socket2::SockAddr::from(addr))?;
    Ok(socket)
}
