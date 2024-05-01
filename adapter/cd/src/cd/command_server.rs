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
pub use crate::cd::zpr::{Zpr, load_configuration};



// TODO: How to signal when this server exits.
// TODO: How to stop this server.
pub async fn command_server(config: Arc<Config>, zpr: Zpr) -> io::Result<()> {
    info!("starting command server on {}", config.socket_path);
    let listener = UnixListener::bind(config.socket_path.clone())?;
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                info!("accepted command connection");
                let zpr = zpr.clone();                                    
                tokio::spawn(async move {
                    if let Err(e) = handle_command_connection(stream, zpr).await {
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
async fn handle_command_connection(stream: tokio::net::UnixStream, zpr: Zpr) -> io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut line = String::new();
    'readline: loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break 'readline;
        }
        let line = line.trim();
        if line.is_empty() {
            error!("empty line received");
            break 'readline;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "status" => {
                let stats = zpr.get_status();
                if stats.len() == 0 {
                    writer.write_all(b"2\nOK\nno configurations\n").await?;
                    break 'readline;
                }
                writer.write_all(format!("{}\nOK\n", stats.len() + 1).as_bytes()).await?;
                for (cpath, cstat) in &stats {
                    writer.write_all(format!("{} - {}\n", cpath, cstat).as_bytes()).await?;
                }
            }
            "connect" => {
                // Connect takes a single argument - the path to a ZPR configuration file.
                //
                // TODO: Need to manage some state here.  We should only allow a single connection
                // at a time to a given ZPR endpoint/configuration.  Somewhere there is a table 
                // of [configuration | endpoint | status] rows.
                if parts.len() < 2 {
                    writer
                        .write_all(b"2\nERR\nconnect requires a path\n")
                        .await?;
                    break 'readline;
                }

                let configuration = match load_configuration(parts[1]) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Error loading configuration {}: {}", parts[1], e);
                        let emsg = e.to_string().replace("\n", " ");
                        writer
                            .write_all(format!("2\nERR\n{}\n", emsg).as_bytes())
                            .await?;
                        break 'readline;
                    }
                };

                // install the configuration
                match zpr.add_configuration(configuration) {
                    Ok(()) => (),
                    Err(e) => {
                        let emsg = e.to_string().replace("\n", " ");                        
                        writer
                            .write_all(format!("2\nERR\n{}\n", emsg).as_bytes())
                            .await?;
                        break 'readline;
                    }
                }

                // TODO: Kick off start me up.
                info!("(TODO) kick off start-me-up for configuration just loaded");

                writer
                    .write_all(b"2\nOK\nconnect starting\n")
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
        break 'readline;
    }
    Ok(())
}
