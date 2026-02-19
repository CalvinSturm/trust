use std::process::Command;

use serde_json::Value;
use tempfile::tempdir;

mod c2pa_test_support;

fn run_cli(args: &[&str]) -> (bool, String, String) {
    if let Ok(bin) = std::env::var("CARGO_BIN_EXE_c2pa-inspect") {
        let out = Command::new(bin).args(args).output().unwrap();
        return (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        );
    }
    let out = Command::new("cargo")
        .args(["run", "-q", "-p", "c2pa-inspect", "--"])
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn c2pa_cli_reports_stable_schema_and_presence() {
    let temp = tempdir().unwrap();
    let (unsigned, signed) = c2pa_test_support::make_unsigned_and_signed_assets(temp.path());

    let (ok_unsigned, stdout_unsigned, stderr_unsigned) =
        run_cli(&[unsigned.to_string_lossy().as_ref(), "--json", "--trust=off"]);
    assert!(ok_unsigned, "{stderr_unsigned}");
    let unsigned_report: Value = serde_json::from_str(stdout_unsigned.trim()).unwrap();
    assert_eq!(unsigned_report["tool"]["name"], "c2pa-inspect");
    assert_eq!(unsigned_report["tool"]["schema_version"], 1);
    assert_eq!(unsigned_report["credentials"]["present"], false);
    assert!(unsigned_report["actions"].as_array().is_some());
    assert!(unsigned_report["ingredients"].as_array().is_some());

    let (ok_signed, stdout_signed, stderr_signed) =
        run_cli(&[signed.to_string_lossy().as_ref(), "--json", "--trust=off"]);
    assert!(ok_signed, "{stderr_signed}");
    let signed_report: Value = serde_json::from_str(stdout_signed.trim()).unwrap();
    assert_eq!(signed_report["tool"]["schema_version"], 1);
    assert_eq!(signed_report["credentials"]["present"], true);
    assert!(signed_report["credentials"]["active_manifest_label"].is_string());

    let (ok_default, _stdout_default, stderr_default) = run_cli(&[
        signed.to_string_lossy().as_ref(),
        "--json",
        "--trust=default",
    ]);
    assert!(ok_default, "{stderr_default}");
}
