use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToUpstream,
    UpstreamToClient,
    LocalError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts_unix_ms: u128,
    pub direction: Direction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i64>,
}

impl AuditEvent {
    pub fn now(direction: Direction) -> Self {
        Self {
            ts_unix_ms: now_ms(),
            direction,
            id: None,
            method: None,
            tool: None,
            decision: None,
            args_digest: None,
            args_bytes: None,
            result_digest: None,
            result_bytes: None,
            error_code: None,
        }
    }
}

struct State {
    file: File,
    prev_hash: String,
}

pub struct AuditLogger {
    state: Mutex<State>,
}

impl AuditLogger {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create audit directory {}", parent.display()))?;
        }

        let prev_hash = load_last_hash(path).unwrap_or_else(|| "0".repeat(64));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open audit log {}", path.display()))?;

        Ok(Self {
            state: Mutex::new(State { file, prev_hash }),
        })
    }

    pub fn append(&self, event: AuditEvent) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow!("audit log mutex poisoned"))?;
        let payload = serde_json::to_value(&event).context("serialize audit event")?;
        let payload_canon = canonicalize(&payload);
        let payload_str =
            serde_json::to_string(&payload_canon).context("serialize canonical event")?;

        let hash = hash_entry(&guard.prev_hash, payload_str.as_bytes());
        let mut entry = payload
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow!("audit event payload was not an object"))?;
        entry.insert(
            "prev_hash".to_string(),
            Value::String(guard.prev_hash.clone()),
        );
        entry.insert("hash".to_string(), Value::String(hash.clone()));

        let line = serde_json::to_string(&Value::Object(entry)).context("serialize audit line")?;
        guard
            .file
            .write_all(line.as_bytes())
            .context("write audit line")?;
        guard.file.write_all(b"\n").context("write audit newline")?;
        guard.file.flush().context("flush audit log")?;

        guard.prev_hash = hash;
        Ok(())
    }
}

pub fn verify_file(path: &Path) -> Result<()> {
    let f = File::open(path).with_context(|| format!("open audit log {}", path.display()))?;
    let mut prev = "0".repeat(64);
    for (idx, line) in BufReader::new(f).lines().enumerate() {
        let line = line.with_context(|| format!("read line {}", idx + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let mut v: Value =
            serde_json::from_str(&line).with_context(|| format!("parse line {}", idx + 1))?;
        let obj = v
            .as_object_mut()
            .ok_or_else(|| anyhow!("line {} was not an object", idx + 1))?;

        let prev_hash = obj
            .remove("prev_hash")
            .and_then(|x| x.as_str().map(|s| s.to_string()))
            .ok_or_else(|| anyhow!("line {} missing prev_hash", idx + 1))?;
        let hash = obj
            .remove("hash")
            .and_then(|x| x.as_str().map(|s| s.to_string()))
            .ok_or_else(|| anyhow!("line {} missing hash", idx + 1))?;

        if prev_hash != prev {
            return Err(anyhow!("line {} prev_hash mismatch", idx + 1));
        }

        let payload = canonicalize(&Value::Object(obj.clone()));
        let payload_str = serde_json::to_string(&payload).context("serialize canonical payload")?;
        let expected = hash_entry(&prev, payload_str.as_bytes());
        if expected != hash {
            return Err(anyhow!("line {} hash mismatch", idx + 1));
        }
        prev = hash;
    }
    Ok(())
}

pub fn digest_and_size(value: &Value) -> Result<(String, usize)> {
    let bytes = serde_json::to_vec(value).context("serialize digest payload")?;
    let digest = hash_bytes(&bytes);
    Ok((digest, bytes.len()))
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn load_last_hash(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let txt = fs::read_to_string(path).ok()?;
    let last = txt.lines().last()?;
    let v: Value = serde_json::from_str(last).ok()?;
    v.get("hash")?.as_str().map(|s| s.to_string())
}

fn hash_entry(prev_hash: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(payload);
    hash_to_hex(hasher.finalize().as_slice())
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hash_to_hex(hasher.finalize().as_slice())
}

fn hash_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

fn canonicalize(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                if let Some(val) = map.get(&k) {
                    out.insert(k, canonicalize(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        _ => v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn hash_chain_verify_passes_and_detects_tamper() {
        let temp = tempdir().unwrap();
        let p = temp.path().join("audit.jsonl");
        let logger = AuditLogger::open(&p).unwrap();

        let mut e1 = AuditEvent::now(Direction::ClientToUpstream);
        e1.method = Some("tools/call".to_string());
        logger.append(e1).unwrap();

        let mut e2 = AuditEvent::now(Direction::LocalError);
        e2.error_code = Some(-32040);
        logger.append(e2).unwrap();

        verify_file(&p).unwrap();

        let mut lines = fs::read_to_string(&p)
            .unwrap()
            .lines()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let mut v: Value = serde_json::from_str(&lines[0]).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("method".to_string(), Value::String("tampered".to_string()));
        lines[0] = serde_json::to_string(&v).unwrap();
        fs::write(&p, lines.join("\n") + "\n").unwrap();

        assert!(verify_file(&p).is_err());
    }
}
