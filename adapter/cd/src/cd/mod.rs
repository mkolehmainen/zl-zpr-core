mod command_server;
pub use crate::cd::command_server::command_server;

mod config;
pub use crate::cd::config::Config;

mod zpr;
pub use crate::cd::zpr::Zpr;

use std::{fs, io, sync::Arc};

use tracing::{error, info};
use tracing_subscriber;

use tokio::{
    select,
    signal::unix::{signal, SignalKind},
    //io::{
    //AsyncReadExt,
    //AsyncWriteExt,
    //BufReader,
    //AsyncBufReadExt
    //},
    sync::oneshot,
};

#[tokio::main]
pub async fn tokio_main(config: Arc<Config>) -> io::Result<()> {
    tracing_subscriber::fmt::init();

    info!("cd starts");

    let zpr = Zpr::new();

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
        match command_server(cs_config, zpr.clone()).await {
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
