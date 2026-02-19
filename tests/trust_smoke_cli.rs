use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

#[test]
fn trust_smoke_stdio_json_ok() {
    let exe = trust_smoke_bin_path();
    let out = Command::new(exe)
        .arg("stdio")
        .arg("--json")
        .arg("--timeout-ms")
        .arg("30000")
        .output()
        .expect("run trust-smoke");

    assert!(
        out.status.success(),
        "trust-smoke failed: status={:?} stderr={} stdout={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    let value: Value = serde_json::from_slice(&out.stdout).expect("parse trust-smoke json output");
    assert_eq!(value["ok"], Value::Bool(true));
    assert!(value["steps"].as_array().is_some_and(|s| !s.is_empty()));
}

fn trust_smoke_bin_path() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_trust-smoke") {
        let p = PathBuf::from(path);
        if p.is_file() {
            return p;
        }
    }

    let current = std::env::current_exe().expect("resolve current exe");
    let test_bin_dir = current.parent().expect("test exe parent");
    let target_debug = test_bin_dir.parent().expect("target/debug directory");
    let file = if cfg!(windows) {
        "trust-smoke.exe"
    } else {
        "trust-smoke"
    };
    let candidate = target_debug.join(file);
    assert!(
        candidate.is_file(),
        "trust-smoke binary not found at {}",
        candidate.display()
    );
    candidate
}
