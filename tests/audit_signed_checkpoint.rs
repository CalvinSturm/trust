use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use audit_log::{generate_signing_key, verify_with_signed_checkpoint, write_signing_key_atomic};
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
fn signed_audit_checkpoint_detects_truncation_tamper_and_key_mismatch() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let store = root.join("approval-store.json");
    let upstream_log = root.join("upstream.log.jsonl");
    let audit = root.join("audit.jsonl");
    let checkpoint = root.join("audit.checkpoint.json");
    let keyfile = root.join("audit.key.json");
    let other_keyfile = root.join("other.key.json");

    fs::write(
        &policy,
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n      args:\n        path_glob: \"**/.env\"\n    decision: deny\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.write\"\n    decision: allow\n",
    )
    .unwrap();

    let keygen = if let Some(toolfw) = bin_path("toolfw") {
        Command::new(toolfw)
            .arg("audit")
            .arg("keygen")
            .arg("--out")
            .arg(&keyfile)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    } else {
        Command::new("cargo")
            .args(["run", "-q", "-p", "toolfw", "--"])
            .arg("audit")
            .arg("keygen")
            .arg("--out")
            .arg(&keyfile)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let keygen_out = keygen.wait_with_output().unwrap();
    assert!(
        keygen_out.status.success(),
        "{}",
        String::from_utf8_lossy(&keygen_out.stderr)
    );
    assert!(!String::from_utf8_lossy(&keygen_out.stdout)
        .trim()
        .is_empty());
    assert!(keyfile.exists());

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
                .arg("--audit-checkpoint")
                .arg(&checkpoint)
                .arg("--audit-signing-key")
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
                .arg("--audit-checkpoint")
                .arg(&checkpoint)
                .arg("--audit-signing-key")
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
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files.read","arguments":{"mount":"notes","path":".env"}}}),
    );
    let denied = read_json_line(&mut reader);
    assert_eq!(denied["error"]["code"], -32040);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files.write","arguments":{"mount":"notes","path":"x.txt","content":"hello"}}}),
    );
    let allowed = read_json_line(&mut reader);
    assert_eq!(allowed["id"], 3);

    let _ = child.kill();
    let _ = child.wait();

    assert!(checkpoint.exists());
    verify_with_signed_checkpoint(&audit, &checkpoint, &keyfile).unwrap();

    let original_audit = fs::read_to_string(&audit).unwrap();
    let original_checkpoint = fs::read_to_string(&checkpoint).unwrap();

    let mut trunc_lines = original_audit
        .lines()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    trunc_lines.pop();
    fs::write(&audit, trunc_lines.join("\n") + "\n").unwrap();
    assert!(verify_with_signed_checkpoint(&audit, &checkpoint, &keyfile).is_err());

    fs::write(&audit, &original_audit).unwrap();
    let mut tampered_lines = original_audit
        .lines()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let mut line0: Value = serde_json::from_str(&tampered_lines[0]).unwrap();
    line0.as_object_mut().unwrap().insert(
        "method".to_string(),
        Value::String("tampered.method".to_string()),
    );
    tampered_lines[0] = serde_json::to_string(&line0).unwrap();
    fs::write(&audit, tampered_lines.join("\n") + "\n").unwrap();
    assert!(verify_with_signed_checkpoint(&audit, &checkpoint, &keyfile).is_err());

    fs::write(&audit, &original_audit).unwrap();
    fs::write(&checkpoint, &original_checkpoint).unwrap();
    let other = generate_signing_key();
    write_signing_key_atomic(&other_keyfile, &other).unwrap();
    assert!(verify_with_signed_checkpoint(&audit, &checkpoint, &other_keyfile).is_err());
}
