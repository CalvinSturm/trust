use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "mcp-gateway")]
struct Cli {
    #[arg(long)]
    mounts: PathBuf,
    #[arg(long)]
    views: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    gateway_core::run_stdio(&cli.mounts, &cli.views)
}
