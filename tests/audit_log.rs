use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use audit_log::verify_file;
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
fn audit_log_chain_and_privacy_smoke() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let approval_store = root.join("approval-store.json");
    let upstream_log = root.join("upstream.log.jsonl");
    let audit_path = root.join("audit.jsonl");

    fs::write(
        &policy,
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n      args:\n        path_glob: \"**/.env\"\n    decision: deny\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.write\"\n    decision: allow\n",
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
                .arg(&approval_store)
                .arg("--audit")
                .arg(&audit_path)
                .arg("--")
                .arg(fake)
                .arg("--log")
                .arg(&upstream_log)
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
                .arg(&approval_store)
                .arg("--audit")
                .arg(&audit_path)
                .arg("--")
                .arg("cargo")
                .arg("run")
                .arg("-q")
                .arg("-p")
                .arg("fake-upstream")
                .arg("--")
                .arg("--log")
                .arg(&upstream_log)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap()
        };

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    let _ = read_json_line(&mut reader);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
    );

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files.read","arguments":{"mount":"notes","path":".env"}}}),
    );
    let denied = read_json_line(&mut reader);
    assert_eq!(denied["error"]["code"], -32040);

    let secret = "hello world secret";
    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files.write","arguments":{"mount":"notes","path":"x.txt","content":secret}}}),
    );
    let allowed = read_json_line(&mut reader);
    assert_eq!(allowed["id"], 3);
    assert!(allowed["result"].is_object());

    let _ = child.kill();
    let _ = child.wait();

    assert!(audit_path.exists());
    let txt = fs::read_to_string(&audit_path).unwrap();
    assert!(!txt.trim().is_empty());
    assert!(!txt.contains(secret));
    verify_file(&audit_path).unwrap();
}
