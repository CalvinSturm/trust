use std::fs;
use std::io::{BufRead, BufReader, Write};
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

#[test]
fn audit_includes_auth_attribution_without_raw_token() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let store = root.join("approval-store.json");
    let keyfile = root.join("auth.key.json");
    let upstream_log = root.join("upstream.log.jsonl");
    let audit = root.join("audit.jsonl");

    fs::write(
        &policy,
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: allow\nrules: []\n",
    )
    .unwrap();

    let key = generate_signing_key();
    write_signing_key_atomic(&keyfile, &key).unwrap();
    let token = issue_token(
        &key,
        CapabilityTokenPayloadV1 {
            version: 1,
            key_id: "".to_string(),
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
                .arg("--auth-pubkey")
                .arg(&keyfile)
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
                .arg(&store)
                .arg("--audit")
                .arg(&audit)
                .arg("--auth-pubkey")
                .arg(&keyfile)
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
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    let _ = read_json_line(&mut reader);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"},"auth":{"token":token}}}),
    );
    let _ = read_json_line(&mut reader);

    let _ = child.kill();
    let _ = child.wait();

    let audit_txt = fs::read_to_string(&audit).unwrap();
    assert!(audit_txt.contains("\"client_id\":\"alice\""));
    assert!(audit_txt.contains("\"token_digest\""));
    assert!(!audit_txt.contains(&token));
}
