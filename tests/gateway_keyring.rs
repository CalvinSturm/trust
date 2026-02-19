use std::fs;
use std::io::{BufRead, BufReader, Write};
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

fn start_gateway(
    mounts: &std::path::Path,
    views: &std::path::Path,
    keys: &std::path::Path,
) -> std::process::Child {
    if let Some(gateway) = bin_path("mcp-gateway") {
        Command::new(gateway)
            .arg("--mounts")
            .arg(mounts)
            .arg("--views")
            .arg(views)
            .arg("--auth-keys")
            .arg(keys)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    } else {
        Command::new("cargo")
            .args(["run", "-q", "-p", "mcp-gateway", "--"])
            .arg("--mounts")
            .arg(mounts)
            .arg("--views")
            .arg(views)
            .arg("--auth-keys")
            .arg(keys)
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
fn gateway_auth_keyring_supports_rotation_and_revocation() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let mount_root = root.join("notes");
    fs::create_dir_all(&mount_root).unwrap();
    fs::write(mount_root.join("a.txt"), "hello world").unwrap();

    let mounts = root.join("mounts.yaml");
    let views = root.join("views.yaml");
    let keys_path = root.join("keys.json");
    fs::write(
        &mounts,
        format!(
            "mounts:\n  - name: notes\n    root: \"{}\"\n    read_only: true\n",
            mount_root.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .unwrap();
    fs::write(
        &views,
        "views:\n  - name: notes_recent\n    tool: files.search\n    args:\n      mount: notes\n      query: \"hello\"\n      max_results: 10\n      max_bytes: 20000\n",
    )
    .unwrap();

    let k1 = generate_signing_key();
    let k2 = generate_signing_key();
    let mut ring = empty_keyring(1);
    add_key(
        &mut ring,
        k1.key_id.clone(),
        k1.public_key_b64.clone(),
        Some("k1".to_string()),
        1,
    )
    .unwrap();
    add_key(
        &mut ring,
        k2.key_id.clone(),
        k2.public_key_b64.clone(),
        Some("k2".to_string()),
        2,
    )
    .unwrap();
    write_keyring_atomic(&keys_path, &ring).unwrap();

    let token1 = issue_token(
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
    let token2 = issue_token(
        &k2,
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

    let mut child = start_gateway(&mounts, &views, &keys_path);
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    handshake(&mut stdin, &mut reader);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"},"auth":{"token":token1}}}),
    );
    let r1 = read_json_line(&mut reader);
    assert!(r1.get("error").is_none() || r1["error"].is_null());

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"},"auth":{"token":token2}}}),
    );
    let r2 = read_json_line(&mut reader);
    assert!(r2.get("error").is_none() || r2["error"].is_null());

    let _ = child.kill();
    let _ = child.wait();

    revoke_key(&mut ring, &k1.key_id, Some("compromised".to_string()), 3).unwrap();
    write_keyring_atomic(&keys_path, &ring).unwrap();

    let mut child = start_gateway(&mounts, &views, &keys_path);
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    handshake(&mut stdin, &mut reader);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"},"auth":{"token":token1}}}),
    );
    let revoked = read_json_line(&mut reader);
    assert_eq!(revoked["error"]["code"], -32060);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"},"auth":{"token":token2}}}),
    );
    let still_ok = read_json_line(&mut reader);
    assert!(still_ok.get("error").is_none() || still_ok["error"].is_null());

    let _ = child.kill();
    let _ = child.wait();
}
