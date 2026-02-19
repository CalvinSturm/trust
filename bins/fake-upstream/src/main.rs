use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use serde_json::{json, Value};

#[derive(Debug, Parser)]
#[command(name = "fake-upstream")]
struct Cli {
    #[arg(long)]
    log: PathBuf,
    #[arg(long)]
    tools: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let tools_payload = load_tools_payload(cli.tools.as_deref())?;

    let mut stdin = io::stdin().lock();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut partial = Vec::new();

    while let Some(msg) = mcp_wire::read_json_line_streaming(&mut stdin, &mut partial)? {
        if let Some(resp) = handle_message(&cli.log, tools_payload.as_ref(), &msg)? {
            mcp_wire::write_json_line(&mut out, &resp)?;
        }
    }

    Ok(())
}

fn handle_message(
    log_path: &PathBuf,
    tools_payload: Option<&Value>,
    msg: &Value,
) -> Result<Option<Value>> {
    let method = msg
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    let line = json!({
        "method": method,
        "id": id,
        "params": params,
    });
    append_log(log_path, &line)?;

    if id.is_null() {
        return Ok(None);
    }

    let resp = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "fake-upstream", "version": "0.1.0"},
                "capabilities": {}
            }
        }),
        "tools/call" => {
            let name = params.get("name").cloned().unwrap_or(Value::Null);
            let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "seen_name": name,
                    "seen_arguments": arguments
                }
            })
        }
        "tools/list" => {
            let result = tools_payload
                .cloned()
                .unwrap_or_else(|| json!({ "tools": [] }));
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            })
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"ok": true}
        }),
    };

    Ok(Some(resp))
}

fn append_log(path: &PathBuf, value: &Value) -> Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let s = serde_json::to_string(value)?;
    f.write_all(s.as_bytes())?;
    f.write_all(b"\n")?;
    f.flush()?;
    Ok(())
}

fn load_tools_payload(path: Option<&std::path::Path>) -> Result<Option<Value>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let txt = std::fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&txt)?;
    Ok(Some(value))
}
