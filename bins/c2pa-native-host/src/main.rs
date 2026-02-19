use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

use c2pa_inspector_core::{inspect_path, parse_trust_mode, InspectOptions, TrustMode};
use native_messaging::{read_frame, write_frame, DEFAULT_MAX_FRAME_BYTES};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 50_000_000;
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MAX_ERROR_MSG_LEN: usize = 240;

#[derive(Debug, Deserialize)]
struct HostRequest {
    id: String,
    v: u32,
    trust: String,
    source: Source,
    #[serde(default)]
    caps: Option<Caps>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Source {
    Url { url: String },
    Path { path: String },
}

#[derive(Debug, Deserialize, Default)]
struct Caps {
    max_download_bytes: Option<u64>,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct HostResponse {
    id: String,
    v: u32,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<HostError>,
}

#[derive(Debug, Serialize)]
struct HostError {
    code: String,
    message: String,
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let in_msg = match read_frame(&mut reader, DEFAULT_MAX_FRAME_BYTES) {
            Ok(Some(v)) => v,
            Ok(None) => break,
            Err(e) => {
                let resp = error_response("unknown".to_string(), "invalid_request", e.to_string());
                let _ = write_frame(
                    &mut writer,
                    &serde_json::to_value(resp).unwrap_or(json!({})),
                );
                break;
            }
        };
        let resp = handle_request_value(in_msg);
        let _ = write_frame(
            &mut writer,
            &serde_json::to_value(resp).unwrap_or_else(|_| {
                json!({
                    "id":"unknown","v":1,"ok":false,
                    "error":{"code":"invalid_request","message":"failed to serialize response"}
                })
            }),
        );
    }
}

fn handle_request_value(v: Value) -> HostResponse {
    match serde_json::from_value::<HostRequest>(v) {
        Ok(req) => match handle_request(req) {
            Ok(report) => HostResponse {
                id: report.0,
                v: 1,
                ok: true,
                report: Some(report.1),
                error: None,
            },
            Err((id, code, msg)) => error_response(id, code, msg),
        },
        Err(e) => error_response("unknown".to_string(), "invalid_request", e.to_string()),
    }
}

fn handle_request(
    req: HostRequest,
) -> std::result::Result<(String, Value), (String, &'static str, String)> {
    if req.v != 1 {
        return Err((
            req.id,
            "invalid_request",
            "unsupported request version".to_string(),
        ));
    }
    let trust = match parse_trust_mode(&req.trust) {
        Ok(TrustMode::Off) => TrustMode::Off,
        Ok(TrustMode::Default) => TrustMode::Default,
        Ok(TrustMode::CustomPem { .. }) => {
            return Err((
                req.id,
                "invalid_request",
                "only trust off/default is allowed".to_string(),
            ))
        }
        Err(e) => return Err((req.id, "invalid_request", e.to_string())),
    };
    let caps = req.caps.unwrap_or_default();
    let max_download_bytes = caps
        .max_download_bytes
        .unwrap_or(DEFAULT_MAX_DOWNLOAD_BYTES);
    let timeout_ms = caps.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    let opts = InspectOptions {
        trust,
        ..InspectOptions::default()
    };

    let report = match req.source {
        Source::Path { path } => inspect_from_path(&path, &opts, max_download_bytes),
        Source::Url { url } => inspect_from_url(&url, &opts, max_download_bytes, timeout_ms),
    }
    .map_err(|(code, msg)| (req.id.clone(), code, msg))?;

    Ok((req.id, report))
}

fn inspect_from_path(
    path: &str,
    opts: &InspectOptions,
    max_bytes: u64,
) -> std::result::Result<Value, (&'static str, String)> {
    let p = Path::new(path);
    let meta = fs::metadata(p).map_err(|e| ("invalid_request", format!("read metadata: {e}")))?;
    if meta.is_dir() {
        return Err((
            "invalid_request",
            "path source cannot be a directory".to_string(),
        ));
    }
    if meta.len() > max_bytes {
        return Err(("too_large", "input exceeds max_download_bytes".to_string()));
    }
    let report = inspect_path(p, opts).map_err(|e| ("inspect_failed", e.to_string()))?;
    serde_json::to_value(report).map_err(|e| ("inspect_failed", format!("serialize report: {e}")))
}

fn inspect_from_url(
    url: &str,
    opts: &InspectOptions,
    max_bytes: u64,
    timeout_ms: u64,
) -> std::result::Result<Value, (&'static str, String)> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err((
            "invalid_request",
            "only http/https URLs are allowed".to_string(),
        ));
    }
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let client = Client::builder()
        .redirect(Policy::limited(5))
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
        .map_err(|e| ("fetch_failed", format!("build client: {e}")))?;

    let mut resp = client
        .get(url)
        .send()
        .map_err(|e| map_fetch_error(&e.to_string()))?;
    if !resp.status().is_success() {
        return Err((
            "fetch_failed",
            format!("http status {}", resp.status().as_u16()),
        ));
    }

    let mut tmp = NamedTempFile::new().map_err(|e| ("fetch_failed", format!("temp file: {e}")))?;
    let mut total: u64 = 0;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = resp
            .read(&mut buf)
            .map_err(|e| ("fetch_failed", format!("read response: {e}")))?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err((
                "too_large",
                "download exceeds max_download_bytes".to_string(),
            ));
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(tmp.as_file_mut(), &buf[..n])
            .map_err(|e| ("fetch_failed", format!("write temp file: {e}")))?;
    }

    let mut report =
        inspect_path(tmp.path(), opts).map_err(|e| ("inspect_failed", e.to_string()))?;
    report.input.path = url.to_string();
    report.input.size_bytes = total;
    report.input.sha256 = hex::encode(hasher.finalize());

    serde_json::to_value(report).map_err(|e| ("inspect_failed", format!("serialize report: {e}")))
}

fn map_fetch_error(msg: &str) -> (&'static str, String) {
    if msg.contains("timed out") {
        ("timeout", msg.to_string())
    } else {
        ("fetch_failed", msg.to_string())
    }
}

fn error_response(id: String, code: &'static str, message: String) -> HostResponse {
    HostResponse {
        id,
        v: 1,
        ok: false,
        report: None,
        error: Some(HostError {
            code: code.to_string(),
            message: truncate_message(&message),
        }),
    }
}

fn truncate_message(s: &str) -> String {
    let clean = s.replace(['\n', '\r'], " ");
    if clean.len() <= MAX_ERROR_MSG_LEN {
        clean
    } else {
        format!("{}...", &clean[..MAX_ERROR_MSG_LEN])
    }
}
