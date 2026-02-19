use std::io::{self, BufRead, Write};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Id {
    Number(i64),
    String(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: Id,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: Id,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Message {
    Request(Request),
    Notification(Notification),
    Response(Response),
}

pub fn write_json_line<W: Write>(writer: &mut W, value: &Value) -> anyhow::Result<()> {
    let s = serde_json::to_string(value).context("serialize json")?;
    if s.contains('\n') || s.contains('\r') {
        bail!("serialized JSON contains literal newline")
    }
    writer.write_all(s.as_bytes()).context("write json")?;
    writer.write_all(b"\n").context("write newline")?;
    writer.flush().context("flush json line")?;
    Ok(())
}

pub fn read_json_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> anyhow::Result<Option<Value>> {
    buf.clear();
    let n = reader.read_until(b'\n', buf).context("read json line")?;
    if n == 0 {
        return Ok(None);
    }
    if let Some(b'\n') = buf.last().copied() {
        buf.pop();
    }
    if let Some(b'\r') = buf.last().copied() {
        buf.pop();
    }
    if buf.is_empty() {
        return Ok(None);
    }
    let v = serde_json::from_slice::<Value>(buf).context("parse json line")?;
    Ok(Some(v))
}

pub fn read_json_line_streaming<R: io::Read>(
    reader: &mut R,
    partial: &mut Vec<u8>,
) -> anyhow::Result<Option<Value>> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(pos) = partial.iter().position(|b| *b == b'\n') {
            let mut line = partial.drain(..=pos).collect::<Vec<u8>>();
            if let Some(b'\n') = line.last().copied() {
                line.pop();
            }
            if let Some(b'\r') = line.last().copied() {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }
            let v = serde_json::from_slice::<Value>(&line).context("parse json line")?;
            return Ok(Some(v));
        }
        let n = reader.read(&mut chunk).context("read stream")?;
        if n == 0 {
            if partial.is_empty() {
                return Ok(None);
            }
            bail!("unexpected EOF with partial JSON line")
        }
        partial.extend_from_slice(&chunk[..n]);
    }
}

pub fn success(id: Id, result: Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

pub fn error(id: Id, code: i64, message: &str, data: Option<Value>) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
            "data": data
        }
    })
}
