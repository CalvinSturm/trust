use std::process::{Command, Stdio};

use native_messaging::{read_frame, write_frame, DEFAULT_MAX_FRAME_BYTES};
use serde_json::{json, Value};
use tempfile::tempdir;

mod c2pa_test_support;

fn host_cmd() -> Command {
    if let Ok(bin) = std::env::var("CARGO_BIN_EXE_c2pa-native-host") {
        return Command::new(bin);
    }
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "-q", "-p", "c2pa-native-host", "--"]);
    cmd
}

#[test]
fn native_host_path_source_protocol_and_validation() {
    let temp = tempdir().unwrap();
    let (unsigned, signed) = c2pa_test_support::make_unsigned_and_signed_assets(temp.path());

    let mut child = host_cmd()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    write_frame(
        &mut stdin,
        &json!({
            "id":"req_signed",
            "v":1,
            "trust":"off",
            "source":{"path": signed.to_string_lossy()}
        }),
    )
    .unwrap();
    let resp1 = read_frame(&mut stdout, DEFAULT_MAX_FRAME_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(resp1["id"], "req_signed");
    assert_eq!(resp1["ok"], true);
    assert_eq!(resp1["report"]["tool"]["schema_version"], 1);
    assert_eq!(resp1["report"]["credentials"]["present"], true);

    write_frame(
        &mut stdin,
        &json!({
            "id":"req_unsigned",
            "v":1,
            "trust":"default",
            "source":{"path": unsigned.to_string_lossy(), "page_url":"https://example.org/page", "detect_reason":"largest_img"}
        }),
    )
    .unwrap();
    let resp2 = read_frame(&mut stdout, DEFAULT_MAX_FRAME_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(resp2["id"], "req_unsigned");
    assert_eq!(resp2["ok"], true);
    assert_eq!(resp2["report"]["credentials"]["present"], false);

    write_frame(
        &mut stdin,
        &json!({
            "id":"req_bad_trust",
            "v":1,
            "trust":"custom:/tmp/ca.pem",
            "source":{"path": signed.to_string_lossy()}
        }),
    )
    .unwrap();
    let resp3 = read_frame(&mut stdout, DEFAULT_MAX_FRAME_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(resp3["id"], "req_bad_trust");
    assert_eq!(resp3["ok"], false);
    assert_eq!(resp3["error"]["code"], "invalid_request");

    write_frame(
        &mut stdin,
        &json!({
            "id":"req_too_large",
            "v":1,
            "trust":"off",
            "source":{"path": signed.to_string_lossy()},
            "caps":{"max_download_bytes":1}
        }),
    )
    .unwrap();
    let resp4 = read_frame(&mut stdout, DEFAULT_MAX_FRAME_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(resp4["id"], "req_too_large");
    assert_eq!(resp4["ok"], false);
    assert_eq!(resp4["error"]["code"], "too_large");

    drop(stdin);
    let _ = child.wait();
}

#[test]
fn native_host_invalid_json_request_returns_invalid_request() {
    let mut child = host_cmd()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    write_frame(
        &mut stdin,
        &json!({"id":"bad","v":1,"trust":"off","source":{"url":123}}),
    )
    .unwrap();
    let resp: Value = read_frame(&mut stdout, DEFAULT_MAX_FRAME_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(resp["ok"], false);
    assert_eq!(resp["error"]["code"], "invalid_request");
    drop(stdin);
    let _ = child.wait();
}
