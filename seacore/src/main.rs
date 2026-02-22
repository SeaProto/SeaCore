use clap::{Parser, Subcommand};
use eyre::Result;

mod client;
mod server;
mod router;
mod sniffer;

#[derive(Parser)]
#[command(name = "seacore")]
#[command(about = "SeaCore Proxy - combined client and server", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a SeaCore server
    Server {
        /// Path to the server JSON config file
        #[arg(short, long, default_value = "server.json")]
        config: String,
    },
    /// Run as a SeaCore client
    Client {
        /// Path to the client JSON config file
        #[arg(short, long, default_value = "client.json")]
        config: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { config } => {
            tracing::info!("Starting SeaCore in server mode");
            server::run_server(&config).await
        }
        Commands::Client { config } => {
            tracing::info!("Starting SeaCore in client mode");
            client::run_client(&config).await
        }
    }
}
