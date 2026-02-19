use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use audit_log::generate_signing_key;
use auth_keyring::{add_key, empty_keyring, revoke_key, write_keyring_atomic};
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
    keys: &Path,
    upstream_log: &Path,
) -> std::process::Child {
    if let (Some(toolfw), Some(fake)) = (bin_path("toolfw"), bin_path("fake-upstream")) {
        Command::new(toolfw)
            .arg("proxy")
            .arg("stdio")
            .arg("--policy")
            .arg(policy)
            .arg("--approval-store")
            .arg(store)
            .arg("--auth-keys")
            .arg(keys)
            .arg("--")
            .arg(fake)
            .arg("--log")
            .arg(upstream_log)
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
            .arg("--auth-keys")
            .arg(keys)
            .arg("--")
            .arg("cargo")
            .arg("run")
            .arg("-q")
            .arg("-p")
            .arg("fake-upstream")
            .arg("--")
            .arg("--log")
            .arg(upstream_log)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    }
}

fn handshake(stdin: &mut impl Write, reader: &mut BufReader<impl std::io::Read>) {
    write_json_line(
        stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    let _ = read_json_line(reader);
    write_json_line(
        stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
    );
}

#[test]
fn revoked_key_token_is_denied_without_upstream_contact() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let store = root.join("approval-store.json");
    let keys_path = root.join("keys.json");
    let upstream_log = root.join("upstream.log.jsonl");

    fs::write(
        &policy,
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - match:\n      client_id: \"alice\"\n      auth_verified: true\n      mcp_method: \"tools/call\"\n      tool: \"views.query\"\n      args:\n        view: \"notes_recent\"\n    decision: allow\n",
    )
    .unwrap();

    let k1 = generate_signing_key();
    let mut ring = empty_keyring(1);
    add_key(
        &mut ring,
        k1.key_id.clone(),
        k1.public_key_b64.clone(),
        None,
        1,
    )
    .unwrap();
    write_keyring_atomic(&keys_path, &ring).unwrap();

    let token = issue_token(
        &k1,
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

    let mut child = start_proxy(&policy, &store, &keys_path, &upstream_log);
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    handshake(&mut stdin, &mut reader);
    let baseline = line_count(&upstream_log);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"},"auth":{"token":token}}}),
    );
    let first = read_json_line(&mut reader);
    assert!(first.get("error").is_none() || first["error"].is_null());
    assert_eq!(line_count(&upstream_log), baseline + 1);

    let _ = child.kill();
    let _ = child.wait();

    revoke_key(&mut ring, &k1.key_id, Some("compromised".to_string()), 2).unwrap();
    write_keyring_atomic(&keys_path, &ring).unwrap();

    let mut child = start_proxy(&policy, &store, &keys_path, &upstream_log);
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    handshake(&mut stdin, &mut reader);
    let baseline = line_count(&upstream_log);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"},"auth":{"token":token}}}),
    );
    let denied = read_json_line(&mut reader);
    assert_eq!(denied["error"]["code"], -32040);
    assert_eq!(line_count(&upstream_log), baseline);

    let _ = child.kill();
    let _ = child.wait();
}
