use std::fs;
use std::process::Command;

#[test]
fn trust_up_policy_set_writes_preset_policy() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let run_dir = tmp.path().join("run");

    let out = run_policy_set(&run_dir, "guarded");
    assert!(
        out.status.success(),
        "status={:?} stderr={} stdout={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    let policy_path = run_dir.join("out").join("toolfw.policy.yaml");
    let txt = fs::read_to_string(&policy_path).expect("read generated policy");
    assert!(txt.contains("id: require_approval_for_writes"));
    assert!(txt.contains("id: deny_secret_env_reads"));
}

fn run_policy_set(run_dir: &std::path::Path, mode: &str) -> std::process::Output {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_trust-up") {
        let p = std::path::PathBuf::from(path);
        if p.is_file() {
            return Command::new(p)
                .arg("policy")
                .arg("set")
                .arg("--dir")
                .arg(run_dir)
                .arg(mode)
                .output()
                .expect("run trust-up policy set");
        }
    }

    Command::new("cargo")
        .arg("run")
        .arg("-q")
        .arg("-p")
        .arg("trust-up")
        .arg("--target-dir")
        .arg("target/trust-up-test-policy")
        .arg("--")
        .arg("policy")
        .arg("set")
        .arg("--dir")
        .arg(run_dir)
        .arg(mode)
        .output()
        .expect("run cargo run -p trust-up -- policy set")
}
