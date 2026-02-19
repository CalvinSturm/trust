use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use tempfile::tempdir;

fn bin_path(name: &str) -> Option<String> {
    std::env::var(format!("CARGO_BIN_EXE_{name}")).ok()
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

fn line_count(path: &Path) -> usize {
    if !path.exists() {
        return 0;
    }
    fs::read_to_string(path).unwrap().lines().count()
}

#[test]
fn schema_validation_blocks_invalid_and_strips_reserved() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let policy = root.join("policy.yaml");
    let approval_store = root.join("approval-store.json");
    let log = root.join("upstream.log.jsonl");
    let tools = root.join("tools.json");

    fs::write(
        &policy,
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.write\"\n    decision: allow\n",
    )
    .unwrap();

    fs::write(
        &tools,
        serde_json::to_string_pretty(&json!({
            "tools": [
                {
                    "name": "files.write",
                    "inputSchema": {
                        "type": "object",
                        "required": ["mount", "path", "content"],
                        "additionalProperties": false,
                        "properties": {
                            "mount": {"type": "string"},
                            "path": {"type": "string"},
                            "content": {"type": "string"}
                        }
                    }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let mut child =
        if let (Some(toolfw), Some(fake)) = (bin_path("toolfw"), bin_path("fake-upstream")) {
            Command::new(toolfw)
                .arg("proxy")
                .arg("stdio")
                .arg("--policy")
                .arg(&policy)
                .arg("--approval-store")
                .arg(&approval_store)
                .arg("--")
                .arg(fake)
                .arg("--log")
                .arg(&log)
                .arg("--tools")
                .arg(&tools)
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
                .arg("fake-upstream")
                .arg("--")
                .arg("--log")
                .arg(&log)
                .arg("--tools")
                .arg(&tools)
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
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    let list = read_json_line(&mut reader);
    assert_eq!(list["id"], 2);

    let baseline = line_count(&log);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files.write","arguments":{"mount":"notes","path":"x.txt"}}}),
    );
    let invalid = read_json_line(&mut reader);
    assert_eq!(invalid["error"]["code"], -32602);
    assert_eq!(line_count(&log), baseline);

    write_json_line(
        &mut stdin,
        &json!({
            "jsonrpc":"2.0",
            "id":4,
            "method":"tools/call",
            "params":{
                "name":"files.write",
                "arguments":{
                    "__toolfw":{"approvalToken":"junk"},
                    "mount":"notes",
                    "path":"x.txt",
                    "content":"hello"
                }
            }
        }),
    );
    let ok = read_json_line(&mut reader);
    assert_eq!(ok["id"], 4);
    assert_eq!(ok["result"]["seen_name"], "files.write");
    let seen_args = &ok["result"]["seen_arguments"];
    assert!(seen_args.get("__toolfw").is_none());
    assert_eq!(seen_args["mount"], "notes");
    assert_eq!(seen_args["path"], "x.txt");
    assert_eq!(seen_args["content"], "hello");

    let _ = child.kill();
    let _ = child.wait();
}
