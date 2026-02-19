use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LOCK_RETRIES: usize = 200;
const LOCK_SLEEP_MS: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthKeyringV1 {
    pub version: u32,
    pub updated_at_ms: u64,
    pub keys: Vec<AuthKeyEntryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthKeyEntryV1 {
    pub key_id: String,
    pub public_key_b64: String,
    pub status: KeyStatusV1,
    pub added_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatusV1 {
    Active,
    Revoked,
}

pub fn empty_keyring(now_ms: u64) -> AuthKeyringV1 {
    AuthKeyringV1 {
        version: 1,
        updated_at_ms: now_ms,
        keys: Vec::new(),
    }
}

pub fn load_keyring(path: &Path) -> Result<AuthKeyringV1> {
    let txt =
        fs::read_to_string(path).with_context(|| format!("read keyring {}", path.display()))?;
    let ring: AuthKeyringV1 =
        serde_json::from_str(&txt).with_context(|| format!("parse keyring {}", path.display()))?;
    validate_keyring(&ring)?;
    Ok(ring)
}

pub fn write_keyring_atomic(path: &Path, ring: &AuthKeyringV1) -> Result<()> {
    validate_keyring(ring)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create keyring dir {}", parent.display()))?;
    }

    let tmp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(ring).context("serialize keyring")?;
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("open keyring temp {}", tmp.display()))?;
        f.write_all(&bytes)
            .with_context(|| format!("write keyring temp {}", tmp.display()))?;
        let _ = f.sync_all();
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("replace keyring {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

pub fn with_keyring_lock<T, F>(path: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let _guard = acquire_lock(path)?;
    f()
}

pub fn find_active_key<'a>(ring: &'a AuthKeyringV1, key_id: &str) -> Option<&'a AuthKeyEntryV1> {
    ring.keys
        .iter()
        .find(|k| k.key_id == key_id && k.status == KeyStatusV1::Active)
}

pub fn active_public_key_bytes(entry: &AuthKeyEntryV1) -> Result<[u8; 32]> {
    if entry.status != KeyStatusV1::Active {
        bail!("key {} is not active", entry.key_id);
    }
    let public = BASE64_STANDARD
        .decode(entry.public_key_b64.as_bytes())
        .context("decode public key")?;
    if public.len() != 32 {
        bail!("public key must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&public);
    Ok(out)
}

pub fn key_id_from_public_b64(public_key_b64: &str) -> Result<String> {
    let public = BASE64_STANDARD
        .decode(public_key_b64.as_bytes())
        .context("decode public key")?;
    if public.len() != 32 {
        bail!("public key must be 32 bytes");
    }
    let mut hasher = Sha256::new();
    hasher.update(&public);
    Ok(hex::encode(hasher.finalize()))
}

pub fn add_key(
    ring: &mut AuthKeyringV1,
    key_id: String,
    public_key_b64: String,
    note: Option<String>,
    now_ms: u64,
) -> Result<()> {
    if ring.keys.iter().any(|k| k.key_id == key_id) {
        bail!("key_id already exists");
    }
    let derived = key_id_from_public_b64(&public_key_b64)?;
    if derived != key_id {
        bail!("key_id does not match public key");
    }
    ring.keys.push(AuthKeyEntryV1 {
        key_id,
        public_key_b64,
        status: KeyStatusV1::Active,
        added_at_ms: now_ms,
        revoked_at_ms: None,
        note,
    });
    ring.updated_at_ms = now_ms;
    Ok(())
}

pub fn revoke_key(
    ring: &mut AuthKeyringV1,
    key_id: &str,
    note: Option<String>,
    now_ms: u64,
) -> Result<()> {
    let Some(entry) = ring.keys.iter_mut().find(|k| k.key_id == key_id) else {
        bail!("unknown key_id");
    };
    entry.status = KeyStatusV1::Revoked;
    entry.revoked_at_ms = Some(now_ms);
    if note.is_some() {
        entry.note = note;
    }
    ring.updated_at_ms = now_ms;
    Ok(())
}

fn validate_keyring(ring: &AuthKeyringV1) -> Result<()> {
    if ring.version != 1 {
        bail!("unsupported keyring version {}", ring.version);
    }
    let mut seen = HashSet::new();
    for key in &ring.keys {
        if !seen.insert(key.key_id.clone()) {
            bail!("duplicate key_id {}", key.key_id);
        }
        let derived = key_id_from_public_b64(&key.public_key_b64)?;
        if derived != key.key_id {
            bail!("key_id does not match public key for {}", key.key_id);
        }
    }
    Ok(())
}

fn lock_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.lock", path.display()))
}

struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn acquire_lock(path: &Path) -> Result<LockGuard> {
    let lock = lock_path(path);
    for _ in 0..LOCK_RETRIES {
        match OpenOptions::new().create_new(true).write(true).open(&lock) {
            Ok(_) => return Ok(LockGuard { path: lock }),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                thread::sleep(Duration::from_millis(LOCK_SLEEP_MS))
            }
            Err(e) => {
                return Err(e).with_context(|| format!("create lock file {}", lock.display()));
            }
        }
    }
    Err(anyhow!("timed out acquiring keyring lock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn lock_and_atomic_write_roundtrip() {
        let temp = tempdir().unwrap();
        let p = temp.path().join("keys.json");
        let mut ring = empty_keyring(1);
        add_key(
            &mut ring,
            "f".repeat(64),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            None,
            1,
        )
        .unwrap_err();

        let pubkey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=".to_string();
        let key_id = key_id_from_public_b64(&pubkey).unwrap();
        add_key(&mut ring, key_id.clone(), pubkey.clone(), None, 2).unwrap();
        with_keyring_lock(&p, || write_keyring_atomic(&p, &ring)).unwrap();
        let loaded = load_keyring(&p).unwrap();
        assert_eq!(loaded.keys.len(), 1);
        assert!(find_active_key(&loaded, &key_id).is_some());
    }

    #[test]
    fn revoke_changes_status() {
        let pubkey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=".to_string();
        let key_id = key_id_from_public_b64(&pubkey).unwrap();
        let mut ring = empty_keyring(1);
        add_key(&mut ring, key_id.clone(), pubkey, None, 2).unwrap();
        revoke_key(&mut ring, &key_id, Some("compromised".to_string()), 3).unwrap();
        assert!(find_active_key(&ring, &key_id).is_none());
    }
}
