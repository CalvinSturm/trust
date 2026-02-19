use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use tempfile::tempdir;

fn bin_path(name: &str) -> Option<String> {
    std::env::var(format!("CARGO_BIN_EXE_{name}")).ok()
}

fn has_git() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git command failed: {:?}", args);
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
fn git_tools_are_bounded_and_safe() {
    if !has_git() {
        return;
    }
    let temp = tempdir().unwrap();
    let root = temp.path();
    let mount_root = root.join("mount");
    let repo = mount_root.join("repo");
    let outside = root.join("outside-repo");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&outside).unwrap();

    run_git(&repo, &["init"]);
    run_git(&repo, &["config", "user.email", "test@example.com"]);
    run_git(&repo, &["config", "user.name", "Test User"]);
    fs::write(
        repo.join("a.txt"),
        "hello\nneedle one\nneedle two\nanother line\n",
    )
    .unwrap();
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-m", "initial"]);
    fs::write(repo.join("b.txt"), "second\n").unwrap();
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-m", "second"]);
    fs::write(
        repo.join("a.txt"),
        "hello\nneedle one\nneedle two\nanother line\nmore edits\n",
    )
    .unwrap();
    fs::write(repo.join("u.txt"), "untracked\n").unwrap();

    run_git(&outside, &["init"]);
    run_git(&outside, &["config", "user.email", "test@example.com"]);
    run_git(&outside, &["config", "user.name", "Test User"]);
    fs::write(outside.join("x.txt"), "x\n").unwrap();
    run_git(&outside, &["add", "."]);
    run_git(&outside, &["commit", "-m", "outside"]);

    let mounts = root.join("mounts.yaml");
    let views = root.join("views.yaml");
    fs::write(
        &mounts,
        format!(
            "mounts:\n  - name: notes\n    root: \"{}\"\n    read_only: false\n",
            mount_root.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .unwrap();
    fs::write(
        &views,
        "views:\n  - name: repo_commits\n    tool: git.log\n    args:\n      mount: notes\n      repo: repo\n      max_commits: 2\n      max_bytes: 50000\n      max_lines: 200\n",
    )
    .unwrap();

    let mut child = if let Some(gateway) = bin_path("mcp-gateway") {
        Command::new(gateway)
            .arg("--mounts")
            .arg(&mounts)
            .arg("--views")
            .arg(&views)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    } else {
        Command::new("cargo")
            .arg("run")
            .arg("-q")
            .arg("-p")
            .arg("mcp-gateway")
            .arg("--")
            .arg("--mounts")
            .arg(&mounts)
            .arg("--views")
            .arg(&views)
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
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    let list = read_json_line(&mut reader);
    let names = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    for n in ["git.status", "git.log", "git.diff", "git.show", "git.grep"] {
        assert!(names.contains(&n));
    }

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"git.status","arguments":{"mount":"notes","repo":"repo","porcelain":true}}}),
    );
    let status = read_json_line(&mut reader);
    assert_eq!(status["id"], 3);
    assert_eq!(status["result"]["tool"], "git.status");
    let stdout = status["result"]["stdout"].as_str().unwrap();
    assert!(stdout.contains("a.txt"));
    assert!(stdout.contains("u.txt"));

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"git.log","arguments":{"mount":"notes","repo":"repo","max_commits":1}}}),
    );
    let log = read_json_line(&mut reader);
    assert_eq!(log["result"]["tool"], "git.log");
    let lines = log["result"]["stdout"].as_str().unwrap().lines().count();
    assert!(lines <= 1);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"git.diff","arguments":{"mount":"notes","repo":"repo","max_bytes":40,"max_lines":100}}}),
    );
    let diff = read_json_line(&mut reader);
    assert_eq!(diff["result"]["tool"], "git.diff");
    assert_eq!(diff["result"]["truncated"], true);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"git.grep","arguments":{"mount":"notes","repo":"repo","query":"needle","max_matches":1}}}),
    );
    let grep = read_json_line(&mut reader);
    assert_eq!(grep["result"]["tool"], "git.grep");
    let grep_lines = grep["result"]["stdout"].as_str().unwrap().lines().count();
    assert!(grep_lines <= 1);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"git.log","arguments":{"mount":"notes","repo":"repo","ref":"--help"}}}),
    );
    let bad_ref = read_json_line(&mut reader);
    assert_eq!(bad_ref["error"]["code"], -32602);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"git.log","arguments":{"mount":"notes","repo":"../outside-repo"}}}),
    );
    let bad_repo = read_json_line(&mut reader);
    assert_eq!(bad_repo["error"]["code"], -32602);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"repo_commits"}}}),
    );
    let view = read_json_line(&mut reader);
    assert_eq!(view["result"]["view"], "repo_commits");
    assert_eq!(view["result"]["data"]["tool"], "git.log");

    let _ = child.kill();
    let _ = child.wait();
}
