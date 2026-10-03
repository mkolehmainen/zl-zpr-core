//! Substrate socket creation, Windows arm (zipline#176).
//!
//! The unix arm (`sys/posix/substrate.rs`) provides the same `open`, so
//! the socket loop in `main.rs` has no platform branches left.

use crate::batch_io;
use crate::logging::targets::STARTUP;
use std::io;
use std::net::SocketAddr;
use tracing::warn;

/// Create, configure and bind one substrate UDP socket on `addr`.
///
/// The socket is nonblocking (the batch I/O engines poll it). The Windows
/// datapath (zipline#131, plan D5) is single-socket/single-homed, so
/// there is no pktinfo or `SO_REUSEPORT` here; the Windows-specific setup
/// is instead:
///
/// - [`batch_io::windows_substrate_bind_check`] after the bind: a socket
///   still wildcard-bound — a node with a wildcard `self_addr`, which the
///   adapter-only probe in `main.rs` never rebinds — would record
///   `0.0.0.0`/`::` as every packet's interface address and trip the
///   fastpath's unspecified-address assertion on the first response.
///   Rejected here with the fix in the error message; the caller logs it
///   and exits cleanly, not a panic (zipline#160).
/// - [`disable_udp_connreset`] (zipline#160, plan N4): without it, a peer
///   that departs — its host answering our sends with ICMP
///   port-unreachable — makes a later `recvfrom` on this unconnected UDP
///   socket fail with `WSAECONNRESET`, and the substrate socket talks to
///   many peers that may leave at any time. Failure is non-fatal and
///   logged here (a `warn!`): the `ConnectionReset` mapping in the
///   receive path (`connreset_as_wouldblock`) is the fallback, so the
///   socket still works, just with a trace-level note per swallowed
///   reset.
///
/// If `addr`'s port is 0 the OS picks one; the caller reads it back via
/// `local_addr` and adopts it so every later socket binds the same port.
pub fn open(addr: SocketAddr) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        None,
    )?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(addr))?;
    let bound = socket
        .local_addr()?
        .as_socket()
        .expect("substrate socket bound to a non-IP address");
    batch_io::windows_substrate_bind_check(bound)?;
    if let Err(err) = disable_udp_connreset(&socket) {
        warn!(
            target: STARTUP,
            "unable to disable SIO_UDP_CONNRESET on the substrate \
             socket (continuing; resets are tolerated in the \
             receive path): {err}"
        );
    }
    Ok(socket)
}

/// Disable `SIO_UDP_CONNRESET` on a UDP socket (zipline#160, plan N4).
///
/// On Windows, a datagram sent to a peer that answers with ICMP
/// port-unreachable (it exited, or nothing ever listened there) is recorded
/// against the socket and surfaces as `WSAECONNRESET` (10054) on a LATER
/// `recvfrom` — on an unconnected socket, where no reset semantics are
/// wanted: a node's substrate socket talks to many adapters and any of them
/// may leave at any time. This ioctl turns the behavior off so the reset is
/// never reported; the `ConnectionReset` mapping in
/// `batch_io`'s `std_udp::connreset_as_wouldblock` remains as the
/// belt-and-braces fallback should the ioctl ever be absent.
///
/// Moved here from `batch_io.rs` (zipline#176): it is socket setup, not
/// I/O, and only [`open`] calls it.
fn disable_udp_connreset(socket: &socket2::Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, SOCKET, WSAIoctl};

    // FALSE as the BOOL input argument: new behavior = do not report resets.
    let enable: u32 = 0;
    let mut bytes_returned: u32 = 0;
    // SAFETY: the socket is live (borrowed for this call); the input buffer
    // is a readable u32 of the size passed; no output buffer is requested;
    // no OVERLAPPED/completion routine (synchronous call).
    let rc = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as SOCKET,
            SIO_UDP_CONNRESET,
            &enable as *const u32 as *const core::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
