use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "toolfw")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Proxy {
        #[command(subcommand)]
        command: ProxyCommands,
    },
    Approve {
        #[arg(long)]
        approval_store: PathBuf,
        approval_request_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ProxyCommands {
    Stdio {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        approval_store: PathBuf,
        #[arg(trailing_var_arg = true, required = true)]
        upstream: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Proxy {
            command:
                ProxyCommands::Stdio {
                    policy,
                    approval_store,
                    upstream,
                },
        } => toolfw_core::run_proxy_stdio(&policy, &approval_store, &upstream),
        Commands::Approve {
            approval_store,
            approval_request_id,
        } => {
            let token = toolfw_core::issue_approval_token(&approval_store, &approval_request_id)?;
            println!("{token}");
            Ok(())
        }
    }
}
