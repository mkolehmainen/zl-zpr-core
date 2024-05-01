use std::{io, sync::Arc};

use tracing::{error, info};

use tokio::{
    io::{
        //BufReader,
        AsyncBufReadExt,
        //AsyncReadExt,
        AsyncWriteExt,
    },
    net::UnixListener,
};

pub use crate::cd::config::Config;

// TODO: How to signal when this server exits.
// TODO: How to stop this server.
pub async fn command_server(config: Arc<Config>) -> io::Result<()> {
    info!("starting command server on {}", config.socket_path);
    let listener = UnixListener::bind(config.socket_path.clone())?;
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                info!("accepted command connection");
                tokio::spawn(async move {
                    if let Err(e) = handle_command_connection(stream).await {
                        error!("Error handling command connection: {}", e);
                    }
                });
            }
            Err(e) => {
                //error!({error = e}, "Error accepting command connection");
                // error!("Error accepting command connection: {}", e);
                // break;
                return Err(e);
            }
        }
    }
}

// A command message is one line of text terminated with "\n".
// A response is multi line with the first line just being the integer number of lines to follow.
// Also, line 2 is always OK or ERR.
//
// For example:
//
//      2
//      OK
//      explanatory message here
//
async fn handle_command_connection(stream: tokio::net::UnixStream) -> io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            error!("empty line received");
            break;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "status" => {
                writer.write_all(b"2\nOK\nstatus unknown\n").await?;
            }
            "connect" => {
                writer
                    .write_all(b"2\nERR\nconnect not implemented\n")
                    .await?;
            }
            "disconnect" => {
                writer
                    .write_all(b"2\nERR\ndisconnect not implemented\n")
                    .await?;
            }
            _ => {
                writer.write_all(b"2\nERR\nunknown command\n").await?;
            }
        }
        break;
    }
    Ok(())
}
