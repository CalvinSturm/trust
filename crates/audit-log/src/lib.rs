use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_sample: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_sample: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_data_sample: Option<Value>,
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
            args_sample: None,
            result_sample: None,
            error_data_sample: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: String,
    pub updated_at: u128,
    pub entry_count: u64,
    pub head_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKeyFile {
    pub version: u32,
    pub key_type: String,
    pub public_key_b64: String,
    pub secret_key_b64: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub version: u32,
    pub updated_at: u128,
    pub entry_count: u64,
    pub head_hash: String,
    pub key_id: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedCheckpointPayload {
    version: u32,
    updated_at: u128,
    entry_count: u64,
    head_hash: String,
    key_id: String,
}

struct State {
    file: File,
    prev_hash: String,
    entries: u64,
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

        let (prev_hash, entries) = compute_chain_state(path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open audit log {}", path.display()))?;

        Ok(Self {
            state: Mutex::new(State {
                file,
                prev_hash,
                entries,
            }),
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
        guard.entries = guard.entries.saturating_add(1);
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<Checkpoint> {
        let guard = self
            .state
            .lock()
            .map_err(|_| anyhow!("audit log mutex poisoned"))?;
        Ok(Checkpoint {
            version: "v1".to_string(),
            updated_at: now_ms(),
            entry_count: guard.entries,
            head_hash: guard.prev_hash.clone(),
        })
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

pub fn write_checkpoint(path: &Path, checkpoint: &Checkpoint) -> Result<()> {
    write_json_atomic(
        path,
        &serde_json::to_vec_pretty(checkpoint).context("serialize checkpoint")?,
    )
}

pub fn generate_signing_key() -> SigningKeyFile {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let public = verifying_key.to_bytes();

    SigningKeyFile {
        version: 1,
        key_type: "ed25519".to_string(),
        public_key_b64: BASE64_STANDARD.encode(public),
        secret_key_b64: BASE64_STANDARD.encode(signing_key.to_bytes()),
        key_id: hash_bytes(public.as_ref()),
    }
}

pub fn load_signing_key(path: &Path) -> Result<SigningKeyFile> {
    let txt = fs::read_to_string(path)
        .with_context(|| format!("read signing key file {}", path.display()))?;
    let key: SigningKeyFile = serde_json::from_str(&txt)
        .with_context(|| format!("parse signing key file {}", path.display()))?;
    validate_signing_key(&key)?;
    Ok(key)
}

pub fn write_signing_key_atomic(path: &Path, key: &SigningKeyFile) -> Result<()> {
    validate_signing_key(key)?;
    write_json_atomic(
        path,
        &serde_json::to_vec_pretty(key).context("serialize signing key")?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn sign_checkpoint(payload: &Checkpoint, key: &SigningKeyFile) -> Result<SignedCheckpoint> {
    validate_signing_key(key)?;
    let signing_key = signing_key_from_file(key)?;
    let cp_payload = SignedCheckpointPayload {
        version: 1,
        updated_at: payload.updated_at,
        entry_count: payload.entry_count,
        head_hash: payload.head_hash.clone(),
        key_id: key.key_id.clone(),
    };
    let to_sign = serde_json::to_vec(&cp_payload).context("serialize checkpoint payload")?;
    let sig = signing_key.sign(&to_sign);
    Ok(SignedCheckpoint {
        version: cp_payload.version,
        updated_at: cp_payload.updated_at,
        entry_count: cp_payload.entry_count,
        head_hash: cp_payload.head_hash,
        key_id: cp_payload.key_id,
        signature_b64: BASE64_STANDARD.encode(sig.to_bytes()),
    })
}

pub fn verify_signed_checkpoint(cp: &SignedCheckpoint, public_key_b64: &str) -> Result<()> {
    let public = BASE64_STANDARD
        .decode(public_key_b64.as_bytes())
        .context("decode public key base64")?;
    if public.len() != 32 {
        bail!("public key must be 32 bytes");
    }
    let mut public_arr = [0u8; 32];
    public_arr.copy_from_slice(&public);
    let verifying_key = VerifyingKey::from_bytes(&public_arr).context("parse public key")?;
    let expected_key_id = hash_bytes(&public);
    if cp.key_id != expected_key_id {
        bail!("checkpoint key_id does not match verification key");
    }

    let sig_bytes = BASE64_STANDARD
        .decode(cp.signature_b64.as_bytes())
        .context("decode checkpoint signature")?;
    if sig_bytes.len() != 64 {
        bail!("signature must be 64 bytes");
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    let payload = SignedCheckpointPayload {
        version: cp.version,
        updated_at: cp.updated_at,
        entry_count: cp.entry_count,
        head_hash: cp.head_hash.clone(),
        key_id: cp.key_id.clone(),
    };
    let signed = serde_json::to_vec(&payload).context("serialize signed checkpoint payload")?;
    verifying_key
        .verify(&signed, &sig)
        .context("verify checkpoint signature")?;
    Ok(())
}

pub fn write_signed_checkpoint_atomic(path: &Path, cp: &SignedCheckpoint) -> Result<()> {
    write_json_atomic(
        path,
        &serde_json::to_vec_pretty(cp).context("serialize signed checkpoint")?,
    )
}

pub fn read_signed_checkpoint(path: &Path) -> Result<SignedCheckpoint> {
    let txt = fs::read_to_string(path)
        .with_context(|| format!("read signed checkpoint file {}", path.display()))?;
    serde_json::from_str::<SignedCheckpoint>(&txt)
        .with_context(|| format!("parse signed checkpoint file {}", path.display()))
}

pub fn verify_with_signed_checkpoint(
    audit_path: &Path,
    signed_checkpoint_path: &Path,
    public_key_path: &Path,
) -> Result<()> {
    verify_file(audit_path)?;
    let (head_hash, entries) = compute_chain_state(audit_path)?;
    let cp = read_signed_checkpoint(signed_checkpoint_path)?;
    if cp.head_hash != head_hash || cp.entry_count != entries {
        return Err(anyhow!("checkpoint mismatch"));
    }
    let public_key_b64 = load_public_key_b64(public_key_path)?;
    verify_signed_checkpoint(&cp, &public_key_b64)?;
    Ok(())
}

fn write_json_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create checkpoint directory {}", parent.display()))?;
    }

    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("open checkpoint temp {}", tmp.display()))?;
        f.write_all(&bytes)
            .with_context(|| format!("write checkpoint temp {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("sync checkpoint temp {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("replace checkpoint {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn read_checkpoint(path: &Path) -> Result<Checkpoint> {
    let txt = fs::read_to_string(path)
        .with_context(|| format!("read checkpoint file {}", path.display()))?;
    let c = serde_json::from_str::<Checkpoint>(&txt)
        .with_context(|| format!("parse checkpoint file {}", path.display()))?;
    Ok(c)
}

pub fn verify_with_checkpoint(audit_path: &Path, checkpoint_path: &Path) -> Result<()> {
    let cp = read_checkpoint(checkpoint_path)?;
    verify_file(audit_path)?;
    let (head_hash, entries) = compute_chain_state(audit_path)?;
    if cp.head_hash != head_hash || cp.entry_count != entries {
        return Err(anyhow!("checkpoint mismatch"));
    }
    Ok(())
}

fn load_public_key_b64(path: &Path) -> Result<String> {
    let txt = fs::read_to_string(path)
        .with_context(|| format!("read public key file {}", path.display()))?;
    let trimmed = txt.trim();
    if trimmed.starts_with('{') {
        if let Ok(keyfile) = serde_json::from_str::<SigningKeyFile>(trimmed) {
            validate_signing_key(&keyfile)?;
            return Ok(keyfile.public_key_b64);
        }
        let v: Value = serde_json::from_str(trimmed)
            .with_context(|| format!("parse public key json {}", path.display()))?;
        if let Some(pk) = v.get("public_key_b64").and_then(Value::as_str) {
            return Ok(pk.to_string());
        }
        bail!("public key json missing public_key_b64");
    }
    Ok(trimmed.to_string())
}

fn validate_signing_key(key: &SigningKeyFile) -> Result<()> {
    if key.version != 1 {
        bail!("unsupported signing key version {}", key.version);
    }
    if key.key_type != "ed25519" {
        bail!("unsupported signing key type {}", key.key_type);
    }
    let public = BASE64_STANDARD
        .decode(key.public_key_b64.as_bytes())
        .context("decode public_key_b64")?;
    if public.len() != 32 {
        bail!("public key must be 32 bytes");
    }
    let secret = BASE64_STANDARD
        .decode(key.secret_key_b64.as_bytes())
        .context("decode secret_key_b64")?;
    if secret.len() != 32 {
        bail!("secret key must be 32 bytes");
    }
    if hash_bytes(&public) != key.key_id {
        bail!("key_id does not match public key");
    }
    Ok(())
}

fn signing_key_from_file(key: &SigningKeyFile) -> Result<SigningKey> {
    let secret = BASE64_STANDARD
        .decode(key.secret_key_b64.as_bytes())
        .context("decode secret key")?;
    if secret.len() != 32 {
        bail!("secret key must be 32 bytes");
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&secret);
    Ok(SigningKey::from_bytes(&sk))
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

fn compute_chain_state(path: &Path) -> Result<(String, u64)> {
    if !path.exists() {
        return Ok(("0".repeat(64), 0));
    }
    let txt =
        fs::read_to_string(path).with_context(|| format!("read audit log {}", path.display()))?;
    let mut head = "0".repeat(64);
    let mut count: u64 = 0;
    for line in txt.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line).context("parse audit line for state")?;
        if let Some(h) = v.get("hash").and_then(Value::as_str) {
            head = h.to_string();
            count = count.saturating_add(1);
        }
    }
    Ok((head, count))
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

    #[test]
    fn signed_checkpoint_roundtrip_and_deterministic() {
        let key = generate_signing_key();
        let cp = Checkpoint {
            version: "v1".to_string(),
            updated_at: 123,
            entry_count: 2,
            head_hash: "ab".repeat(32),
        };
        let s1 = sign_checkpoint(&cp, &key).unwrap();
        let s2 = sign_checkpoint(&cp, &key).unwrap();
        assert_eq!(s1.signature_b64, s2.signature_b64);
        verify_signed_checkpoint(&s1, &key.public_key_b64).unwrap();
    }

    #[test]
    fn signed_checkpoint_tamper_fails_verification() {
        let key = generate_signing_key();
        let cp = Checkpoint {
            version: "v1".to_string(),
            updated_at: 123,
            entry_count: 2,
            head_hash: "ab".repeat(32),
        };
        let mut signed = sign_checkpoint(&cp, &key).unwrap();
        signed.head_hash = "cd".repeat(32);
        assert!(verify_signed_checkpoint(&signed, &key.public_key_b64).is_err());
    }
}
