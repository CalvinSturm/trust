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
        #[arg(long)]
        audit: Option<PathBuf>,
        #[arg(long)]
        audit_checkpoint: Option<PathBuf>,
        #[arg(long)]
        redact: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        audit_payload_sample_bytes: usize,
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
                    audit,
                    audit_checkpoint,
                    redact,
                    audit_payload_sample_bytes,
                    upstream,
                },
        } => toolfw_core::run_proxy_stdio(
            &policy,
            &approval_store,
            audit.as_deref(),
            audit_checkpoint.as_deref(),
            redact.as_deref(),
            audit_payload_sample_bytes,
            &upstream,
        ),
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
