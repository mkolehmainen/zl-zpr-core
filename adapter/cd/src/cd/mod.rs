use std::{
    fs, io,
    sync::Arc,
};

use tracing::{error, info};
use tracing_subscriber;


use tokio::{
    net::UnixListener,
    io::{
        //AsyncReadExt,
        AsyncWriteExt,
        //BufReader,
        AsyncBufReadExt
    },
    sync::oneshot,
    signal::unix::{signal, SignalKind},
    select,
};


pub struct Config {
    pub socket_path: String,
}



#[tokio::main]
pub async fn tokio_main(config: Arc<Config>) -> io::Result<()> {
    tracing_subscriber::fmt::init();

    info!("cd starts");

    // Watch for SIGINT and SIGTERM
    let (sig_shutdown_tx, mut sig_shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        loop {
            select! {
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                    break;
                },
                _ = sigint.recv() => {
                    info!("received SIGINT");
                    break;
                }
            }
        }
        let _ = sig_shutdown_tx.send(());        
    });

    let (cs_shutdown_tx, mut cs_shutdown_rx) = oneshot::channel();
    let cs_config = config.clone();
    tokio::spawn(async move {
        match command_server(cs_config).await {
            Ok(()) => {
                info!("command server shut down");
            }
            Err(e) => {
                error!("command server shut down with error: {}", e);
            }
        }
        let _ = cs_shutdown_tx.send(());
    });

    // Now just waiting for an exit condition:
    loop {
        tokio::select! {
            _ = &mut cs_shutdown_rx => {
                info!("exiting due to command server shutdown");
                break;
            },
            _ = &mut sig_shutdown_rx => {
                info!("exiting due to signal");
                // TODO: Do I need to stop the command server?
                break;
            }
        }
    }

    // cleanup
    info!("cd preparing for exit");
    match fs::remove_file(&config.socket_path) {        
        Ok(()) => (),
        Err(_) => (),
    };

    info!("cd shuts down");
    Ok(())
}



// TODO: How to signal when this server exits.
// TODO: How to stop this server.
async fn command_server(config: Arc<Config>) -> io::Result<()> {
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
                writer.write_all(b"OK status unknown\n").await?;
            },
            "connect" => {
                writer.write_all(b"ERR connect not implemented\n").await?;                
            },
            "disconnect" => {
                writer.write_all(b"ERR disconnect not implemented\n").await?;                                
            },
            _ => {
                writer.write_all(b"ERR unknown command\n").await?;
            }
        }
        break;
    }
    Ok(())
}