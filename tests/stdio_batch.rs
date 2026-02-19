use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use tempfile::tempdir;

fn bin_path(name: &str) -> Option<String> {
    let key = format!("CARGO_BIN_EXE_{name}");
    std::env::var(&key).ok()
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
fn stdio_batch_mixed_allow_and_deny() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let notes_root = root.join("notes");
    fs::create_dir_all(&notes_root).unwrap();
    fs::write(notes_root.join("seed.txt"), "hello world from trust stack").unwrap();
    fs::write(notes_root.join(".env"), "SECRET=1").unwrap();

    let mounts = root.join("gateway.mounts.yaml");
    let views = root.join("gateway.views.yaml");
    let policy = root.join("toolfw.policy.yaml");
    let approval_store = root.join("approval-store.json");

    fs::write(
        &mounts,
        format!(
            "mounts:\n  - name: notes\n    root: \"{}\"\n    read_only: false\n",
            notes_root.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .unwrap();
    fs::write(
        &views,
        "views:\n  - name: notes_recent\n    tool: files.search\n    args:\n      mount: notes\n      query: \"hello\"\n      max_results: 10\n      max_bytes: 20000\n",
    )
    .unwrap();
    fs::write(
        &policy,
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"views.query\"\n      args:\n        view: \"notes_recent\"\n    decision: allow\n\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n      args:\n        path_glob: \"**/.env\"\n    decision: deny\n",
    )
    .unwrap();

    let mut child =
        if let (Some(toolfw), Some(gateway)) = (bin_path("toolfw"), bin_path("mcp-gateway")) {
            Command::new(toolfw)
                .arg("proxy")
                .arg("stdio")
                .arg("--policy")
                .arg(&policy)
                .arg("--approval-store")
                .arg(&approval_store)
                .arg("--")
                .arg(gateway)
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
                .arg("toolfw")
                .arg("--")
                .arg("proxy")
                .arg("stdio")
                .arg("--policy")
                .arg(&policy)
                .arg("--approval-store")
                .arg(&approval_store)
                .arg("--")
                .arg("cargo")
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
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    let _ = read_json_line(&mut reader);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
    );

    write_json_line(
        &mut stdin,
        &json!([
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"}}},
            {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files.read","arguments":{"mount":"notes","path":".env"}}}
        ]),
    );

    let batch_resp = read_json_line(&mut reader);
    let arr = batch_resp.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    let mut saw_allow = false;
    let mut saw_deny = false;
    for item in arr {
        if item["id"] == 2 {
            assert!(item.get("result").is_some());
            saw_allow = true;
        }
        if item["id"] == 3 {
            assert_eq!(item["error"]["code"], -32040);
            saw_deny = true;
        }
    }
    assert!(saw_allow && saw_deny);

    let _ = child.kill();
    let _ = child.wait();
}
