use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use tempfile::tempdir;

fn bin_path(name: &str) -> Option<String> {
    std::env::var(format!("CARGO_BIN_EXE_{name}")).ok()
}

fn write_json_line(stdin: &mut impl Write, value: &Value) {
    let s = serde_json::to_string(value).unwrap();
    assert!(!s.contains('\n'));
    stdin.write_all(s.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

fn read_json_line(reader: &mut BufReader<impl std::io::Read>) -> Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).unwrap();
    assert!(n > 0, "expected a response line");
    serde_json::from_str(line.trim_end()).unwrap()
}

#[test]
fn policy_trace_can_be_written_to_audit_without_leaking_values() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let store = root.join("approval-store.json");
    let log = root.join("upstream.log.jsonl");
    let audit = root.join("audit.jsonl");

    fs::write(
        &policy,
        r#"
protocol_version: "2025-06-18"
defaults: { decision: allow }
rules:
  - id: deny_view
    match:
      mcp_method: "tools/call"
      tool: "views.query"
    decision: deny
"#,
    )
    .unwrap();

    let mut child =
        if let (Some(toolfw), Some(fake)) = (bin_path("toolfw"), bin_path("fake-upstream")) {
            Command::new(toolfw)
                .arg("proxy")
                .arg("stdio")
                .arg("--policy")
                .arg(&policy)
                .arg("--approval-store")
                .arg(&store)
                .arg("--audit")
                .arg(&audit)
                .arg("--policy-trace-to-audit")
                .arg("deny")
                .arg("--")
                .arg(fake)
                .arg("--log")
                .arg(&log)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap()
        } else {
            Command::new("cargo")
                .arg("run")
                .arg("-q")
                .arg("-p")
                .arg("toolfw")
                .arg("--")
                .arg("proxy")
                .arg("stdio")
                .arg("--policy")
                .arg(&policy)
                .arg("--approval-store")
                .arg(&store)
                .arg("--audit")
                .arg(&audit)
                .arg("--policy-trace-to-audit")
                .arg("deny")
                .arg("--")
                .arg("cargo")
                .arg("run")
                .arg("-q")
                .arg("-p")
                .arg("fake-upstream")
                .arg("--")
                .arg("--log")
                .arg(&log)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap()
        };

    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    let _ = read_json_line(&mut reader);

    write_json_line(
        &mut stdin,
        &json!({
          "jsonrpc":"2.0",
          "id":2,
          "method":"tools/call",
          "params":{"name":"views.query","arguments":{"view":"notes_recent","secret":"SUPER_SECRET_SHOULD_NOT_APPEAR"}}
        }),
    );
    let deny = read_json_line(&mut reader);
    assert_eq!(deny["error"]["code"], -32040);

    let _ = child.kill();
    let _ = child.wait();

    let audit_txt = fs::read_to_string(&audit).unwrap();
    assert!(audit_txt.contains("\"trace\""));
    assert!(!audit_txt.contains("SUPER_SECRET_SHOULD_NOT_APPEAR"));
}
