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
fn stdio_proxy_end_to_end() {
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
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"views.query\"\n      args:\n        view: \"notes_recent\"\n    decision: allow\n\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n      args:\n        path_glob: \"**/.env\"\n    decision: deny\n\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.write\"\n    decision: require_approval\n",
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
    let init_resp = read_json_line(&mut reader);
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["protocolVersion"], "2025-06-18");

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
    );

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"views.query","arguments":{"view":"notes_recent"}}}),
    );
    let allow_resp = read_json_line(&mut reader);
    assert_eq!(allow_resp["id"], 2);
    assert!(allow_resp.get("result").is_some());

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files.read","arguments":{"mount":"notes","path":".env"}}}),
    );
    let deny_resp = read_json_line(&mut reader);
    assert_eq!(deny_resp["id"], 3);
    assert_eq!(deny_resp["error"]["code"], -32040);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"files.write","arguments":{"mount":"notes","path":"out.txt","content":"hello"}}}),
    );
    let approval_resp = read_json_line(&mut reader);
    assert_eq!(approval_resp["id"], 4);
    assert_eq!(approval_resp["error"]["code"], -32041);
    let approval_request_id = approval_resp["error"]["data"]["approval_request_id"]
        .as_str()
        .unwrap()
        .to_string();

    let approve_out = if let Some(toolfw) = bin_path("toolfw") {
        Command::new(toolfw)
            .arg("approve")
            .arg("--approval-store")
            .arg(&approval_store)
            .arg(&approval_request_id)
            .output()
            .unwrap()
    } else {
        Command::new("cargo")
            .arg("run")
            .arg("-q")
            .arg("-p")
            .arg("toolfw")
            .arg("--")
            .arg("approve")
            .arg("--approval-store")
            .arg(&approval_store)
            .arg(&approval_request_id)
            .output()
            .unwrap()
    };
    assert!(approve_out.status.success());
    let token = String::from_utf8(approve_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(!token.is_empty());

    write_json_line(
        &mut stdin,
        &json!({
            "jsonrpc":"2.0",
            "id":5,
            "method":"tools/call",
            "params":{
                "name":"files.write",
                "arguments":{
                    "__toolfw":{"approvalToken":token},
                    "mount":"notes",
                    "path":"out.txt",
                    "content":"hello"
                }
            }
        }),
    );
    let replay_resp = read_json_line(&mut reader);
    assert_eq!(replay_resp["id"], 5);
    assert_eq!(replay_resp["result"]["ok"], true);

    let wrote = fs::read_to_string(notes_root.join("out.txt")).unwrap();
    assert_eq!(wrote, "hello");

    let _ = child.kill();
    let _ = child.wait();
}
