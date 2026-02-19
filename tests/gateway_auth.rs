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
fn gateway_enforces_auth_and_scopes() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let mount_root = root.join("notes");
    fs::create_dir_all(&mount_root).unwrap();
    fs::write(mount_root.join("a.txt"), "hello world").unwrap();
    fs::write(mount_root.join(".env"), "secret").unwrap();

    let mounts = root.join("mounts.yaml");
    let views = root.join("views.yaml");
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

    let keyfile = root.join("auth.key.json");
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

    let mut child = if let Some(gateway) = bin_path("mcp-gateway") {
        Command::new(gateway)
            .arg("--mounts")
            .arg(&mounts)
            .arg("--views")
            .arg(&views)
            .arg("--auth-pubkey")
            .arg(&keyfile)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    } else {
        Command::new("cargo")
            .args(["run", "-q", "-p", "mcp-gateway", "--"])
            .arg("--mounts")
            .arg(&mounts)
            .arg("--views")
            .arg(&views)
            .arg("--auth-pubkey")
            .arg(&keyfile)
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
        &json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
    );

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"}}}),
    );
    let unauthorized = read_json_line(&mut reader);
    assert_eq!(unauthorized["error"]["code"], -32060);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files.read","arguments":{"mount":"notes","path":".env"},"auth":{"token":token}}}),
    );
    let forbidden = read_json_line(&mut reader);
    assert_eq!(forbidden["error"]["code"], -32061);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"},"auth":{"token":token}}}),
    );
    let ok = read_json_line(&mut reader);
    assert_eq!(ok["id"], 4);
    assert!(ok.get("error").is_none() || ok["error"].is_null());

    let _ = child.kill();
    let _ = child.wait();
}
