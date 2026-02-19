use std::fs;
use std::process::Command;

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
fn policy_lint_fails_on_invalid_regex() {
    let temp = tempdir().unwrap();
    let p = temp.path().join("bad.yaml");
    fs::write(
        &p,
        r#"
protocol_version: "2025-06-18"
defaults: { decision: deny }
rules:
  - id: bad
    match:
      tool: "files.search"
      args:
        query: { regex: "[" }
    decision: allow
"#,
    )
    .unwrap();

    let output = toolfw_cmd()
        .args(["policy", "lint", "--policy", p.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert!(report["errors"].is_array());
}

#[test]
fn policy_lint_warns_with_zero_exit() {
    let temp = tempdir().unwrap();
    let p = temp.path().join("warn.yaml");
    fs::write(
        &p,
        r#"
protocol_version: "2025-06-18"
defaults: { decision: deny }
rules:
  - match:
      tool: "views.query"
      args:
        view: "notes_recent"
    decision: deny
"#,
    )
    .unwrap();

    let output = toolfw_cmd()
        .args(["policy", "lint", "--policy", p.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert!(report["warnings"].is_array());
}
