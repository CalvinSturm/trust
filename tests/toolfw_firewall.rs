use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};

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

struct ProxyHarness {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl ProxyHarness {
    fn start(policy_path: &Path, approval_store: &Path, log_path: &Path) -> Self {
        let mut child =
            if let (Some(toolfw), Some(fake)) = (bin_path("toolfw"), bin_path("fake-upstream")) {
                Command::new(toolfw)
                    .arg("proxy")
                    .arg("stdio")
                    .arg("--policy")
                    .arg(policy_path)
                    .arg("--approval-store")
                    .arg(approval_store)
                    .arg("--")
                    .arg(fake)
                    .arg("--log")
                    .arg(log_path)
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
                    .arg(policy_path)
                    .arg("--approval-store")
                    .arg(approval_store)
                    .arg("--")
                    .arg("cargo")
                    .arg("run")
                    .arg("-q")
                    .arg("-p")
                    .arg("fake-upstream")
                    .arg("--")
                    .arg("--log")
                    .arg(log_path)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap()
            };

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
        }
    }

    fn handshake(&mut self) {
        write_json_line(
            &mut self.stdin,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        );
        let init = read_json_line(&mut self.reader);
        assert_eq!(init["id"], 1);

        write_json_line(
            &mut self.stdin,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
        );
    }
}

impl Drop for ProxyHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn approve_token(store: &Path, approval_request_id: &str) -> String {
    let out = if let Some(toolfw) = bin_path("toolfw") {
        Command::new(toolfw)
            .arg("approve")
            .arg("--approval-store")
            .arg(store)
            .arg(approval_request_id)
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
            .arg(store)
            .arg(approval_request_id)
            .output()
            .unwrap()
    };
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn toolfw_firewall_behaviors() {
    let temp = tempdir().unwrap();

    // 1) deny without upstream contact for denied call
    {
        let log = temp.path().join("deny.log.jsonl");
        let policy = temp.path().join("deny.policy.yaml");
        let store = temp.path().join("deny.approval.json");
        fs::write(
            &policy,
            "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: allow\nrules:\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n      args:\n        path_glob: \"**/.env\"\n    decision: deny\n",
        )
        .unwrap();

        let mut h = ProxyHarness::start(&policy, &store, &log);
        h.handshake();
        let baseline = line_count(&log);

        write_json_line(
            &mut h.stdin,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files.read","arguments":{"mount":"notes","path":".env"}}}),
        );
        let deny = read_json_line(&mut h.reader);
        assert_eq!(deny["error"]["code"], -32040);
        assert_eq!(line_count(&log), baseline);
    }

    // 2) reserved __toolfw is stripped before forwarding
    {
        let log = temp.path().join("strip.log.jsonl");
        let policy = temp.path().join("strip.policy.yaml");
        let store = temp.path().join("strip.approval.json");
        fs::write(
            &policy,
            "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: allow\nrules: []\n",
        )
        .unwrap();

        let mut h = ProxyHarness::start(&policy, &store, &log);
        h.handshake();

        write_json_line(
            &mut h.stdin,
            &json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{
                    "name":"files.write",
                    "arguments":{
                        "__toolfw":{"approvalToken":"junk"},
                        "mount":"notes",
                        "path":"x.txt",
                        "content":"hi"
                    }
                }
            }),
        );
        let resp = read_json_line(&mut h.reader);
        let args = &resp["result"]["seen_arguments"];
        assert!(args.get("__toolfw").is_none());
        assert_eq!(args["mount"], "notes");
        assert_eq!(args["path"], "x.txt");
        assert_eq!(args["content"], "hi");
    }

    // 3) approval binding positive and negative replay
    {
        let log = temp.path().join("approval.log.jsonl");
        let policy = temp.path().join("approval.policy.yaml");
        let store = temp.path().join("approval.store.json");
        fs::write(
            &policy,
            "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: allow\nrules:\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.write\"\n    decision: require_approval\n",
        )
        .unwrap();

        let mut h = ProxyHarness::start(&policy, &store, &log);
        h.handshake();
        let baseline = line_count(&log);

        write_json_line(
            &mut h.stdin,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files.write","arguments":{"mount":"notes","path":"x.txt","content":"hi"}}}),
        );
        let approval_needed = read_json_line(&mut h.reader);
        assert_eq!(approval_needed["error"]["code"], -32041);
        let approval_request_id = approval_needed["error"]["data"]["approval_request_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(line_count(&log), baseline);

        let token = approve_token(&store, &approval_request_id);
        assert!(!token.is_empty());

        write_json_line(
            &mut h.stdin,
            &json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"tools/call",
                "params":{
                    "name":"files.write",
                    "arguments":{
                        "__toolfw":{"approvalToken": token},
                        "mount":"notes",
                        "path":"x.txt",
                        "content":"hi"
                    }
                }
            }),
        );
        let approved = read_json_line(&mut h.reader);
        assert_eq!(approved["id"], 3);
        assert!(approved["error"].is_null());
        let seen = &approved["result"]["seen_arguments"];
        assert!(seen.get("__toolfw").is_none());
        assert_eq!(seen["content"], "hi");
        assert_eq!(line_count(&log), baseline + 1);

        write_json_line(
            &mut h.stdin,
            &json!({
                "jsonrpc":"2.0",
                "id":4,
                "method":"tools/call",
                "params":{
                    "name":"files.write",
                    "arguments":{
                        "__toolfw":{"approvalToken": token},
                        "mount":"notes",
                        "path":"x.txt",
                        "content":"bye"
                    }
                }
            }),
        );
        let mutated = read_json_line(&mut h.reader);
        assert_eq!(mutated["error"]["code"], -32041);
        assert_eq!(line_count(&log), baseline + 1);
    }
}
