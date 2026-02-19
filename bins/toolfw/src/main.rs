use std::path::PathBuf;
use std::process::ExitCode;

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
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
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
        audit_signing_key: Option<PathBuf>,
        #[arg(long)]
        redact: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        audit_payload_sample_bytes: usize,
        #[arg(trailing_var_arg = true, required = true)]
        upstream: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommands {
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    Verify {
        #[arg(long)]
        audit: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        pubkey: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Proxy {
            command:
                ProxyCommands::Stdio {
                    policy,
                    approval_store,
                    audit,
                    audit_checkpoint,
                    audit_signing_key,
                    redact,
                    audit_payload_sample_bytes,
                    upstream,
                },
        } => toolfw_core::run_proxy_stdio(
            &policy,
            &approval_store,
            audit.as_deref(),
            audit_checkpoint.as_deref(),
            audit_signing_key.as_deref(),
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
        Commands::Audit { command } => match command {
            AuditCommands::Keygen { out } => {
                let pubkey = toolfw_core::audit_keygen(&out)?;
                println!("{pubkey}");
                Ok(())
            }
            AuditCommands::Verify {
                audit,
                checkpoint,
                pubkey,
            } => toolfw_core::audit_verify(&audit, &checkpoint, &pubkey),
        },
    }
}
