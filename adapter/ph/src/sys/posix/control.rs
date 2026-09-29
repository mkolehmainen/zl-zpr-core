//! Control channel transport, unix arm: an AF_UNIX stream socket.
//!
//! `admin_worker` serves Cap'n Proto RPC over whatever [ControlStream]
//! this module hands it, so the RPC code is transport-agnostic; the
//! Windows arm (named pipe, zipline#130) provides the same two items.

use crate::socket_access::{self, SocketAccess};
use std::io;
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};

/// One accepted control connection.
pub type ControlStream = UnixStream;

/// Listens for `ph-cli` control connections.
pub struct ControlListener {
    listener: UnixListener,
}

impl ControlListener {
    /// Bind the control socket at `path` and give it the ownership/mode in
    /// `access` (zipline#39). See [socket_access::bind_owned_listener].
    pub fn bind(path: &Path, access: &SocketAccess) -> io::Result<Self> {
        Ok(Self {
            listener: socket_access::bind_owned_listener("control", path, access)?,
        })
    }

    /// Wait for the next control connection.
    pub async fn accept(&self) -> io::Result<ControlStream> {
        let (stream, _addr) = self.listener.accept().await?;
        Ok(stream)
    }
}
