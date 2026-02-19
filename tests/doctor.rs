use std::fs;
use std::process::Command;

use audit_log::{generate_signing_key, write_signing_key_atomic};
use auth_keyring::{add_key, empty_keyring, write_keyring_atomic};
use serde_json::Value;
use tempfile::tempdir;

fn toolfw_cmd() -> Command {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_toolfw") {
        Command::new(path)
    } else {
        let mut cmd = Command::new("cargo");
        cmd.args(["run", "-q", "-p", "toolfw", "--"]);
        cmd
    }
}

#[test]
fn doctor_proxy_stdio_succeeds_on_valid_inputs() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let redact = root.join("redact.yaml");
    let mounts = root.join("mounts.yaml");
    let views = root.join("views.yaml");
    let keyfile = root.join("auth.key.json");
    let keyring = root.join("keys.json");
    let audit = root.join("audit.jsonl");
    let checkpoint = root.join("audit.checkpoint.json");
    let approval_store = root.join("approval-store.json");

    fs::write(
        &policy,
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: allow\nrules: []\n",
    )
    .unwrap();
    fs::write(
        &redact,
        "patterns:\n  - name: token\n    regex: \"token\\\\s*[:=]\\\\s*\\\\S+\"\n    replacement: \"token=REDACTED\"\n",
    )
    .unwrap();
    fs::write(
        &mounts,
        format!(
            "mounts:\n  - name: notes\n    root: \"{}\"\n    read_only: true\n",
            root.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .unwrap();
    fs::write(
        &views,
        "views:\n  - name: notes_recent\n    tool: files.search\n    args:\n      mount: notes\n      query: hello\n      max_results: 10\n      max_bytes: 2000\n",
    )
    .unwrap();

    let key = generate_signing_key();
    write_signing_key_atomic(&keyfile, &key).unwrap();
    let mut ring = empty_keyring(1);
    add_key(
        &mut ring,
        key.key_id.clone(),
        key.public_key_b64.clone(),
        None,
        1,
    )
    .unwrap();
    write_keyring_atomic(&keyring, &ring).unwrap();

    let output = toolfw_cmd()
        .args([
            "doctor",
            "proxy-stdio",
            "--policy",
            policy.to_str().unwrap(),
            "--approval-store",
            approval_store.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--audit-checkpoint",
            checkpoint.to_str().unwrap(),
            "--audit-signing-key",
            keyfile.to_str().unwrap(),
            "--auth-keys",
            keyring.to_str().unwrap(),
            "--redact",
            redact.to_str().unwrap(),
            "--gateway-mounts",
            mounts.to_str().unwrap(),
            "--gateway-views",
            views.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["summary"]["auth"], "keyring");
    assert_eq!(report["summary"]["audit"], "signed_checkpoint");
}

#[test]
fn doctor_proxy_stdio_fails_on_mutually_exclusive_auth_flags() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let keyfile = root.join("auth.key.json");
    let keyring = root.join("keys.json");
    fs::write(
        &policy,
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: allow\nrules: []\n",
    )
    .unwrap();
    let key = generate_signing_key();
    write_signing_key_atomic(&keyfile, &key).unwrap();
    let mut ring = empty_keyring(1);
    add_key(
        &mut ring,
        key.key_id.clone(),
        key.public_key_b64.clone(),
        None,
        1,
    )
    .unwrap();
    write_keyring_atomic(&keyring, &ring).unwrap();

    let output = toolfw_cmd()
        .args([
            "doctor",
            "proxy-stdio",
            "--policy",
            policy.to_str().unwrap(),
            "--auth-pubkey",
            keyfile.to_str().unwrap(),
            "--auth-keys",
            keyring.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
}

#[test]
fn doctor_proxy_stdio_fails_on_missing_audit_dependency_and_invalid_yaml() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let bad_policy = root.join("policy.yaml");
    let checkpoint = root.join("checkpoint.json");
    fs::write(&bad_policy, "not: [valid").unwrap();

    let output = toolfw_cmd()
        .args([
            "doctor",
            "proxy-stdio",
            "--policy",
            bad_policy.to_str().unwrap(),
            "--audit-checkpoint",
            checkpoint.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    let issues = report["issues"].as_array().unwrap();
    assert!(issues.iter().any(|i| i
        .as_str()
        .unwrap()
        .contains("--audit-checkpoint requires --audit")));
    assert!(issues
        .iter()
        .any(|i| i.as_str().unwrap().contains("invalid policy yaml")));
}
