use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use tempfile::tempdir;

mod c2pa_test_support;

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
    assert!(n > 0, "expected response line");
    serde_json::from_str(line.trim_end()).unwrap()
}

#[test]
fn gateway_c2pa_inspect_reports_and_confines_paths() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let mount_root = root.join("mount");
    fs::create_dir_all(&mount_root).unwrap();
    let (unsigned, signed) = c2pa_test_support::make_unsigned_and_signed_assets(&mount_root);
    let signed_name = signed.file_name().unwrap().to_string_lossy().to_string();
    let unsigned_name = unsigned.file_name().unwrap().to_string_lossy().to_string();

    let mounts = root.join("mounts.yaml");
    let views = root.join("views.yaml");
    fs::write(
        &mounts,
        format!(
            "mounts:\n  - name: notes\n    root: \"{}\"\n    read_only: true\n",
            mount_root.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .unwrap();
    fs::write(&views, "views: []\n").unwrap();

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
            .args(["run", "-q", "-p", "mcp-gateway", "--"])
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
    let _init = read_json_line(&mut reader);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"c2pa.inspect","arguments":{"mount":"notes","path":signed_name,"trust":"off"}}}),
    );
    let signed_resp = read_json_line(&mut reader);
    assert_eq!(signed_resp["id"], 2);
    assert_eq!(signed_resp["result"]["tool"]["schema_version"], 1);
    assert_eq!(signed_resp["result"]["credentials"]["present"], true);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"c2pa.inspect","arguments":{"mount":"notes","path":unsigned_name,"trust":"off"}}}),
    );
    let unsigned_resp = read_json_line(&mut reader);
    assert_eq!(unsigned_resp["id"], 3);
    assert_eq!(unsigned_resp["result"]["credentials"]["present"], false);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"c2pa.inspect","arguments":{"mount":"notes","path":"../escape.png","trust":"off"}}}),
    );
    let confined = read_json_line(&mut reader);
    assert_eq!(confined["id"], 4);
    assert!(confined.get("error").is_some());

    let _ = child.kill();
    let _ = child.wait();
}
