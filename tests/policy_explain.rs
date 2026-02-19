use std::process::Command;

use serde_json::Value;

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
fn policy_explain_outputs_stable_fields() {
    let request = r#"{
      "client_id":"alice",
      "auth_verified":true,
      "mcp_method":"tools/call",
      "tool":"views.query",
      "args":{"view":"notes_recent"}
    }"#;

    let output = toolfw_cmd()
        .args([
            "policy",
            "explain",
            "--policy",
            "configs/examples/toolfw.policy.yaml",
            "--request",
            request,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(v.get("decision").is_some());
    assert!(v.get("rule_id").is_some());
    assert!(v.get("rule_index").is_some());
    assert!(v.get("reasons").is_some());
    assert!(v.get("matched").is_some());
}
