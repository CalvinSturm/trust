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
    #[arg(long)]
    auth_pubkey: Option<PathBuf>,
    #[arg(long)]
    auth_keys: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    gateway_core::run_stdio(
        &cli.mounts,
        &cli.views,
        cli.auth_pubkey.as_deref(),
        cli.auth_keys.as_deref(),
    )
}
