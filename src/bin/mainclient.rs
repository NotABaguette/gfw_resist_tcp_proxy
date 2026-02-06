use anyhow::Result;
use clap::Parser;
use std::process::{Child, Command};
use std::time::Duration;
use std::{thread, vec};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "mainclient")]
struct Args {
    #[arg(long)]
    config: Option<String>,
}

fn run_child(bin: &str, config: &Option<String>) -> std::io::Result<Child> {
    let mut cmd = Command::new(bin);
    if let Some(cfg) = config {
        cmd.arg("--config").arg(cfg);
    }
    cmd.spawn()
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let mut processes = vec![
        run_child("vio-client", &args.config)?,
        run_child("quic-client", &args.config)?,
    ];

    ctrlc::set_handler(|| {
        info!("shutdown signal received");
        std::process::exit(0);
    })?;

    loop {
        thread::sleep(Duration::from_millis(500));
        let mut alive = true;
        for process in processes.iter_mut() {
            if let Some(status) = process.try_wait()? {
                warn!("child exited with status: {status}");
                alive = false;
                break;
            }
        }
        if !alive {
            break;
        }
    }

    for process in processes.iter_mut() {
        let _ = process.kill();
    }

    Ok(())
}
