use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use audit_log::{generate_signing_key, write_signing_key_atomic};
use cap_token::{issue_token, AllowSpecV1, CapabilityTokenPayloadV1};
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

fn line_count(path: &Path) -> usize {
    if !path.exists() {
        return 0;
    }
    fs::read_to_string(path).unwrap().lines().count()
}

fn start_proxy(
    policy: &Path,
    store: &Path,
    log: &Path,
    keyfile: &Path,
    trace_mode: &str,
) -> std::process::Child {
    if let (Some(toolfw), Some(fake)) = (bin_path("toolfw"), bin_path("fake-upstream")) {
        Command::new(toolfw)
            .arg("proxy")
            .arg("stdio")
            .arg("--policy")
            .arg(policy)
            .arg("--approval-store")
            .arg(store)
            .arg("--auth-pubkey")
            .arg(keyfile)
            .arg("--policy-trace")
            .arg(trace_mode)
            .arg("--")
            .arg(fake)
            .arg("--log")
            .arg(log)
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
            .arg(policy)
            .arg("--approval-store")
            .arg(store)
            .arg("--auth-pubkey")
            .arg(keyfile)
            .arg("--policy-trace")
            .arg(trace_mode)
            .arg("--")
            .arg("cargo")
            .arg("run")
            .arg("-q")
            .arg("-p")
            .arg("fake-upstream")
            .arg("--")
            .arg("--log")
            .arg(log)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    }
}

#[test]
fn proxy_policy_trace_deny_and_rate_limit_are_bounded() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let store = root.join("approval-store.json");
    let log = root.join("upstream.log.jsonl");
    let keyfile = root.join("auth.key.json");

    fs::write(
        &policy,
        r#"
protocol_version: "2025-06-18"
defaults: { decision: deny }
rules:
  - id: deny_bob
    priority: 100
    match:
      client_id: "bob"
      auth_verified: true
      mcp_method: "tools/call"
      tool: "views.query"
    decision: deny
  - id: allow_alice_rl
    priority: 50
    match:
      client_id: "alice"
      auth_verified: true
      mcp_method: "tools/call"
      tool: "views.query"
      args:
        view: "notes_recent"
    limit:
      per_client:
        capacity: 1
        refill_per_sec: 0.000001
    decision: allow
"#,
    )
    .unwrap();

    let key = generate_signing_key();
    write_signing_key_atomic(&keyfile, &key).unwrap();
    let alice = issue_token(
        &key,
        CapabilityTokenPayloadV1 {
            version: 1,
            key_id: String::new(),
            client_id: "alice".to_string(),
            issued_at_ms: 1,
            expires_at_ms: None,
            allow: AllowSpecV1 {
                tools: vec!["views.query".to_string()],
                views: vec!["notes_recent".to_string()],
                mounts: vec![],
            },
        },
    )
    .unwrap();
    let bob = issue_token(
        &key,
        CapabilityTokenPayloadV1 {
            version: 1,
            key_id: String::new(),
            client_id: "bob".to_string(),
            issued_at_ms: 1,
            expires_at_ms: None,
            allow: AllowSpecV1 {
                tools: vec!["views.query".to_string()],
                views: vec!["notes_recent".to_string()],
                mounts: vec![],
            },
        },
    )
    .unwrap();

    let mut child = start_proxy(&policy, &store, &log, &keyfile, "deny");
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    let _ = read_json_line(&mut reader);
    let baseline = line_count(&log);

    write_json_line(
        &mut stdin,
        &json!({
          "jsonrpc":"2.0",
          "id":2,
          "method":"tools/call",
          "params":{
            "name":"views.query",
            "arguments":{"view":"notes_recent","note":"SUPER_SECRET_SHOULD_NOT_APPEAR"},
            "auth":{"token": bob}
          }
        }),
    );
    let denied = read_json_line(&mut reader);
    assert_eq!(denied["error"]["code"], -32040);
    assert!(denied["error"]["data"]["trace"].is_object());
    let deny_str = serde_json::to_string(&denied).unwrap();
    assert!(!deny_str.contains("SUPER_SECRET_SHOULD_NOT_APPEAR"));
    assert_eq!(line_count(&log), baseline);

    write_json_line(
        &mut stdin,
        &json!({
          "jsonrpc":"2.0",
          "id":3,
          "method":"tools/call",
          "params":{
            "name":"views.query",
            "arguments":{"view":"notes_recent"},
            "auth":{"token": alice}
          }
        }),
    );
    let ok = read_json_line(&mut reader);
    assert!(ok.get("error").is_none() || ok["error"].is_null());
    assert_eq!(line_count(&log), baseline + 1);

    write_json_line(
        &mut stdin,
        &json!({
          "jsonrpc":"2.0",
          "id":4,
          "method":"tools/call",
          "params":{
            "name":"views.query",
            "arguments":{"view":"notes_recent"},
            "auth":{"token": alice}
          }
        }),
    );
    let limited = read_json_line(&mut reader);
    assert_eq!(limited["error"]["code"], -32042);
    assert!(limited["error"]["data"]["trace"].is_object());
    assert_eq!(line_count(&log), baseline + 1);

    let _ = child.kill();
    let _ = child.wait();

    let log2 = root.join("upstream2.log.jsonl");
    let store2 = root.join("approval-store2.json");
    let mut child2 = start_proxy(&policy, &store2, &log2, &keyfile, "off");
    let mut stdin2 = child2.stdin.take().unwrap();
    let mut reader2 = BufReader::new(child2.stdout.take().unwrap());

    write_json_line(
        &mut stdin2,
        &json!({"jsonrpc":"2.0","id":11,"method":"initialize","params":{}}),
    );
    let _ = read_json_line(&mut reader2);
    write_json_line(
        &mut stdin2,
        &json!({
          "jsonrpc":"2.0",
          "id":12,
          "method":"tools/call",
          "params":{
            "name":"views.query",
            "arguments":{"view":"notes_recent"},
            "auth":{"token": bob}
          }
        }),
    );
    let denied2 = read_json_line(&mut reader2);
    assert_eq!(denied2["error"]["code"], -32040);
    assert!(denied2["error"]["data"].get("trace").is_none());

    let _ = child2.kill();
    let _ = child2.wait();
}
