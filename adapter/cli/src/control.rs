//! Control channel transport to `ph`.
//!
//! The admin RPC runs over whatever [ControlStream] [connect] returns, so
//! the RPC code is transport-agnostic. Unix arm: an AF_UNIX stream socket.
//! Windows arm (zipline#130): a named-pipe client. Mirrors `ph`'s
//! `sys::control` on the server side.

use std::io;
use std::path::Path;

/// A connected control channel.
#[cfg(unix)]
pub type ControlStream = tokio::net::UnixStream;

/// A connected control channel.
#[cfg(windows)]
pub type ControlStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// Connect to `ph`'s control socket at `path`.
#[cfg(unix)]
pub async fn connect(path: &Path) -> io::Result<ControlStream> {
    tokio::net::UnixStream::connect(path).await
}

/// Connect to `ph`'s control pipe at `path` (e.g.
/// `\\.\pipe\zpr-control-<sid>`).
///
/// A pipe whose every server instance is momentarily busy answers
/// ERROR_PIPE_BUSY rather than connecting; `ph`'s listener always keeps a
/// spare instance waiting (see its `sys::control`), so a short retry
/// cycle is enough to bridge the gap between an accept and the next
/// instance standing up.
#[cfg(windows)]
pub async fn connect(path: &Path) -> io::Result<ControlStream> {
    use tokio::net::windows::named_pipe::ClientOptions;

    /// winerror.h ERROR_PIPE_BUSY: all pipe instances are busy.
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut attempts = 0;
    loop {
        match ClientOptions::new().open(path) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 50 => {
                attempts += 1;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e),
        }
    }
}
