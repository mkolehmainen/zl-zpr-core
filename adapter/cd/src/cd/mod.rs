use std::io;
use tracing::info;
use tracing_subscriber;

#[tokio::main]
pub async fn tokio_main() -> io::Result<()> {
    tracing_subscriber::fmt::init();

    info!("cd starts");

    // ...


    info!("cd shuts down");
    Ok(())
}