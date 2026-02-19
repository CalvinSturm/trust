use std::path::PathBuf;
use std::process::ExitCode;

use c2pa_inspector_core::{inspect_path, parse_trust_mode, InspectOptions};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "c2pa-inspect")]
struct Cli {
    path: PathBuf,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    pretty: bool,
    #[arg(long, default_value = "off")]
    trust: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
        Err(CliError::Operational(msg)) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

enum CliError {
    Usage(String),
    Operational(String),
}

fn run() -> Result<(), CliError> {
    let cli = Cli::try_parse().map_err(|e| CliError::Usage(e.to_string()))?;
    let trust = parse_trust_mode(&cli.trust).map_err(|e| CliError::Usage(e.to_string()))?;
    let opts = InspectOptions {
        trust,
        ..InspectOptions::default()
    };
    let report =
        inspect_path(&cli.path, &opts).map_err(|e| CliError::Operational(e.to_string()))?;

    if cli.pretty {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| CliError::Operational(e.to_string()))?
        );
        return Ok(());
    }

    if cli.json {
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| CliError::Operational(e.to_string()))?
        );
        return Ok(());
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| CliError::Operational(e.to_string()))?
    );
    Ok(())
}
