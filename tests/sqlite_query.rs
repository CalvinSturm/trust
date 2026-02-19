use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use rusqlite::Connection;
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

#[test]
fn sqlite_query_select_only_and_caps() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let mount_root = root.join("notes");
    fs::create_dir_all(&mount_root).unwrap();

    let db_path = mount_root.join("notes.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)", [])
        .unwrap();
    conn.execute("INSERT INTO t(name) VALUES('a')", []).unwrap();
    conn.execute("INSERT INTO t(name) VALUES('b')", []).unwrap();

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
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sqlite.query","arguments":{"mount":"notes","path":"notes.db","query":"SELECT id, name FROM t ORDER BY id","max_rows":10,"max_bytes":50000}}}),
    );
    let ok = read_json_line(&mut reader);
    assert_eq!(ok["id"], 2);
    assert_eq!(ok["result"]["rows"].as_array().unwrap().len(), 2);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sqlite.query","arguments":{"mount":"notes","path":"notes.db","query":"PRAGMA user_version"}}}),
    );
    let pragma = read_json_line(&mut reader);
    assert!(pragma.get("error").is_some());

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sqlite.query","arguments":{"mount":"notes","path":"notes.db","query":"select 1; drop table t;"}}}),
    );
    let multi = read_json_line(&mut reader);
    assert!(multi.get("error").is_some());

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sqlite.query","arguments":{"mount":"notes","path":"notes.db","query":"SELECT id, name FROM t ORDER BY id","max_rows":1,"max_bytes":50000}}}),
    );
    let trunc_rows = read_json_line(&mut reader);
    assert_eq!(trunc_rows["result"]["rows"].as_array().unwrap().len(), 1);
    assert_eq!(trunc_rows["result"]["truncated"], true);

    write_json_line(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"sqlite.query","arguments":{"mount":"notes","path":"notes.db","query":"SELECT id, name FROM t ORDER BY id","max_rows":10,"max_bytes":20}}}),
    );
    let trunc_bytes = read_json_line(&mut reader);
    assert_eq!(trunc_bytes["result"]["truncated"], true);

    let _ = child.kill();
    let _ = child.wait();
}
