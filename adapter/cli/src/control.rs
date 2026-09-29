//! Control channel transport to `ph`, unix arm: an AF_UNIX stream socket.
//!
//! The admin RPC runs over whatever [ControlStream] [connect] returns, so
//! the RPC code is transport-agnostic; the Windows arm (named pipe,
//! zipline#130) provides the same two items. Mirrors `ph`'s
//! `sys::control` on the server side.

use std::io;
use std::path::Path;

/// A connected control channel.
pub type ControlStream = tokio::net::UnixStream;

/// Connect to `ph`'s control socket at `path`.
pub async fn connect(path: &Path) -> io::Result<ControlStream> {
    tokio::net::UnixStream::connect(path).await
}
