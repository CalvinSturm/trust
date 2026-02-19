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
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    Doctor {
        #[command(subcommand)]
        command: DoctorCommands,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
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
        auth_pubkey: Option<PathBuf>,
        #[arg(long)]
        auth_keys: Option<PathBuf>,
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

#[derive(Debug, Subcommand)]
enum DoctorCommands {
    ProxyStdio {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        approval_store: Option<PathBuf>,
        #[arg(long)]
        audit: Option<PathBuf>,
        #[arg(long)]
        audit_checkpoint: Option<PathBuf>,
        #[arg(long)]
        audit_signing_key: Option<PathBuf>,
        #[arg(long)]
        auth_pubkey: Option<PathBuf>,
        #[arg(long)]
        auth_keys: Option<PathBuf>,
        #[arg(long)]
        redact: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        audit_payload_sample_bytes: usize,
        #[arg(long)]
        gateway_mounts: Option<PathBuf>,
        #[arg(long)]
        gateway_views: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    Explain {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        request: String,
    },
    Lint {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Compile {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommands {
    Keyring {
        #[command(subcommand)]
        command: AuthKeyringCommands,
    },
    Issue {
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        client: String,
        #[arg(long)]
        tools: String,
        #[arg(long)]
        views: Option<String>,
        #[arg(long)]
        mounts: Option<String>,
        #[arg(long)]
        ttl_seconds: Option<u64>,
    },
    Verify {
        #[arg(long)]
        pubkey: Option<PathBuf>,
        #[arg(long)]
        keys: Option<PathBuf>,
        #[arg(long)]
        token: String,
    },
    Rotate {
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        out_signing_key: PathBuf,
        #[arg(long)]
        note: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AuthKeyringCommands {
    Init {
        #[arg(long)]
        out: PathBuf,
    },
    Add {
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        pubkey: PathBuf,
        #[arg(long)]
        note: Option<String>,
    },
    Revoke {
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        note: Option<String>,
    },
    List {
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        json: bool,
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
                    auth_pubkey,
                    auth_keys,
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
            auth_pubkey.as_deref(),
            auth_keys.as_deref(),
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
        Commands::Auth { command } => match command {
            AuthCommands::Keyring { command } => match command {
                AuthKeyringCommands::Init { out } => toolfw_core::keyring_init(&out),
                AuthKeyringCommands::Add { keys, pubkey, note } => {
                    toolfw_core::keyring_add(&keys, &pubkey, note)
                }
                AuthKeyringCommands::Revoke { keys, key_id, note } => {
                    toolfw_core::keyring_revoke(&keys, &key_id, note)
                }
                AuthKeyringCommands::List { keys, json } => {
                    let summary = toolfw_core::keyring_list(&keys)?;
                    if json {
                        println!("{}", serde_json::to_string(&summary)?);
                    } else {
                        println!("{}", serde_json::to_string_pretty(&summary)?);
                    }
                    Ok(())
                }
            },
            AuthCommands::Issue {
                signing_key,
                client,
                tools,
                views,
                mounts,
                ttl_seconds,
            } => {
                let tools = split_csv(&tools);
                let views = views.map(|v| split_csv(&v)).unwrap_or_default();
                let mounts = mounts.map(|m| split_csv(&m)).unwrap_or_default();
                let token = toolfw_core::auth_issue(
                    &signing_key,
                    &client,
                    tools,
                    views,
                    mounts,
                    ttl_seconds,
                )?;
                println!("{token}");
                Ok(())
            }
            AuthCommands::Verify {
                pubkey,
                keys,
                token,
            } => {
                let summary = toolfw_core::auth_verify(pubkey.as_deref(), keys.as_deref(), &token)?;
                println!("{}", serde_json::to_string(&summary)?);
                Ok(())
            }
            AuthCommands::Rotate {
                keys,
                out_signing_key,
                note,
            } => {
                let key_id = toolfw_core::auth_rotate(&keys, &out_signing_key, note)?;
                println!("{key_id}");
                Ok(())
            }
        },
        Commands::Doctor { command } => match command {
            DoctorCommands::ProxyStdio {
                policy,
                approval_store,
                audit,
                audit_checkpoint,
                audit_signing_key,
                auth_pubkey,
                auth_keys,
                redact,
                audit_payload_sample_bytes,
                gateway_mounts,
                gateway_views,
            } => {
                let report =
                    toolfw_core::doctor_proxy_stdio(&toolfw_core::DoctorProxyStdioOptions {
                        policy: &policy,
                        approval_store: approval_store.as_deref(),
                        audit: audit.as_deref(),
                        audit_checkpoint: audit_checkpoint.as_deref(),
                        audit_signing_key: audit_signing_key.as_deref(),
                        auth_pubkey: auth_pubkey.as_deref(),
                        auth_keys: auth_keys.as_deref(),
                        redact: redact.as_deref(),
                        audit_payload_sample_bytes,
                        gateway_mounts: gateway_mounts.as_deref(),
                        gateway_views: gateway_views.as_deref(),
                    })?;
                println!("{}", serde_json::to_string(&report)?);
                if report.ok {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("doctor found issues"))
                }
            }
        },
        Commands::Policy { command } => match command {
            PolicyCommands::Explain { policy, request } => {
                let out = toolfw_core::policy_explain(&policy, &request)?;
                println!("{}", serde_json::to_string(&out)?);
                Ok(())
            }
            PolicyCommands::Lint { policy, json } => {
                let out = toolfw_core::policy_lint(&policy)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("{}", serde_json::to_string(&out)?);
                }
                let ok = out.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                if ok {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("policy lint errors"))
                }
            }
            PolicyCommands::Compile { policy, json } => {
                let out = toolfw_core::policy_compile(&policy)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("{}", serde_json::to_string(&out)?);
                }
                Ok(())
            }
        },
    }
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(ToString::to_string)
        .collect()
}
