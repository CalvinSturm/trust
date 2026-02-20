use std::process::Command;

use serde_json::Value;

#[test]
fn trust_up_plan_json_is_stable() {
    let output = run_plan_json();
    assert!(
        output.status.success(),
        "status={:?} stderr={} stdout={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    let value: Value = serde_json::from_slice(&output.stdout).expect("valid plan json");
    assert_eq!(value["mode"], "plan");
    assert!(value["security_mode"].is_string());
    assert!(value["run_dir"].is_string());
    assert_eq!(value["approvals_schema_version"], "toolfw.approvals.v1");
    assert!(value["paths"]["data_dir"].is_string());
    assert!(value["paths"].get("sandbox_dir").is_none());
    assert!(value["paths"]["policy_path"].is_string());
    assert!(value["paths"]["approvals_path"].is_string());
    assert!(value["commands"]["stack_argv"].is_array());
    assert!(value["commands"]["console_argv"].is_array());
    assert_eq!(value["agent"]["requested"], "none");
    assert!(value["agent"]["config_write_status"].is_string());
}

fn run_plan_json() -> std::process::Output {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_trust-up") {
        let p = std::path::PathBuf::from(path);
        if p.is_file() {
            return Command::new(p)
                .arg("plan")
                .arg("--agent")
                .arg("none")
                .arg("--json")
                .output()
                .expect("run trust-up plan --json");
        }
    }

    Command::new("cargo")
        .arg("run")
        .arg("-q")
        .arg("-p")
        .arg("trust-up")
        .arg("--target-dir")
        .arg("target/trust-up-test-plan")
        .arg("--")
        .arg("plan")
        .arg("--agent")
        .arg("none")
        .arg("--json")
        .output()
        .expect("run cargo run -p trust-up -- plan --json")
}
