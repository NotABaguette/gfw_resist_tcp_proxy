use clap::Parser;
use gfw_resist_tcp_proxy::config::Config;
use gfw_resist_tcp_proxy::quic::run_quic_server;
use gfw_resist_tcp_proxy::vio::run_vio_server;
use log::info;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "gfw-server", about = "TCP violation server (vio + quic)")]
struct Cli {
    /// Path to configuration file (TOML)
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let config = Config::load(cli.config.as_deref())?;

    info!("starting TCP violation server");

    let vio_task = tokio::spawn(run_vio_server(config.clone()));
    let quic_task = tokio::spawn(run_quic_server(config.clone()));

    let _ = tokio::try_join!(vio_task, quic_task)?;
    Ok(())
}
