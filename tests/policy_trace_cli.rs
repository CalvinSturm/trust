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
fn policy_trace_outputs_stable_bounded_fields() {
    let request = r#"{
      "client_id":"alice",
      "auth_verified":true,
      "mcp_method":"tools/call",
      "tool":"views.query",
      "args":{"z":"1","a":"SUPER_SECRET_SHOULD_NOT_APPEAR"}
    }"#;

    let output = toolfw_cmd()
        .args([
            "policy",
            "trace",
            "--policy",
            "configs/examples/toolfw.policy.yaml",
            "--request",
            request,
            "--max-steps",
            "200",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("SUPER_SECRET_SHOULD_NOT_APPEAR"));

    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert!(v.get("decision").is_some());
    assert!(v.get("rule_id").is_some());
    assert!(v.get("rule_index").is_some());
    let trace = v.get("trace").and_then(Value::as_object).unwrap();
    assert_eq!(trace.get("version").and_then(Value::as_u64), Some(1));
    let args_keys = trace
        .get("request_summary")
        .and_then(|x| x.get("args_keys"))
        .and_then(Value::as_array)
        .unwrap();
    let keys: Vec<String> = args_keys
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert_eq!(keys, vec!["a".to_string(), "z".to_string()]);
}
