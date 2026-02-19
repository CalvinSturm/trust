use anyhow::{anyhow, bail, Context, Result};
use audit_log::SigningKeyFile;
use auth_keyring::{active_public_key_bytes, find_active_key, AuthKeyringV1};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityTokenPayloadV1 {
    pub version: u32,
    pub key_id: String,
    pub client_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub allow: AllowSpecV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowSpecV1 {
    pub tools: Vec<String>,
    pub views: Vec<String>,
    pub mounts: Vec<String>,
}

pub fn issue_token(
    signing_key: &SigningKeyFile,
    mut payload: CapabilityTokenPayloadV1,
) -> Result<String> {
    validate_signing_key(signing_key)?;
    if payload.version != 1 {
        bail!("token payload version must be 1");
    }
    if payload.allow.tools.is_empty() {
        bail!("token allow.tools must not be empty");
    }
    payload.key_id = signing_key.key_id.clone();

    let bytes = serde_json::to_vec(&payload).context("serialize token payload")?;
    let signing_key = signing_key_from_file(signing_key)?;
    let sig = signing_key.sign(&bytes);

    Ok(format!(
        "v1.{}.{}",
        URL_SAFE_NO_PAD.encode(bytes),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    ))
}

pub fn verify_token(
    token: &str,
    pubkey_file: &SigningKeyFile,
    now_ms: u64,
) -> Result<CapabilityTokenPayloadV1> {
    validate_signing_key(pubkey_file)?;
    let parts: Vec<&str> = token.split('.').collect();
    let (payload_bytes, sig) = decode_token_parts(&parts)?;

    let verifying = verifying_key_from_file(pubkey_file)?;
    verifying
        .verify(&payload_bytes, &sig)
        .context("token signature verification failed")?;

    let payload: CapabilityTokenPayloadV1 =
        serde_json::from_slice(&payload_bytes).context("parse token payload")?;
    if payload.version != 1 {
        bail!("unsupported token payload version {}", payload.version);
    }
    if payload.allow.tools.is_empty() {
        bail!("token allow.tools must not be empty");
    }
    if payload.key_id != pubkey_file.key_id {
        bail!("token key_id mismatch");
    }
    if let Some(expires) = payload.expires_at_ms {
        if now_ms > expires {
            bail!("token expired");
        }
    }
    Ok(payload)
}

pub fn verify_token_with_keyring(
    token: &str,
    ring: &AuthKeyringV1,
    now_ms: u64,
) -> Result<CapabilityTokenPayloadV1> {
    let parts: Vec<&str> = token.split('.').collect();
    let (payload_bytes, sig) = decode_token_parts(&parts)?;
    let payload: CapabilityTokenPayloadV1 =
        serde_json::from_slice(&payload_bytes).context("parse token payload")?;
    if payload.version != 1 {
        bail!("unsupported token payload version {}", payload.version);
    }
    if payload.allow.tools.is_empty() {
        bail!("token allow.tools must not be empty");
    }
    if let Some(expires) = payload.expires_at_ms {
        if now_ms > expires {
            bail!("token expired");
        }
    }

    let Some(entry) = find_active_key(ring, &payload.key_id) else {
        bail!("token key_id is missing or revoked");
    };
    let public = active_public_key_bytes(entry)?;
    let verifying = VerifyingKey::from_bytes(&public).context("parse keyring public key")?;
    verifying
        .verify(&payload_bytes, &sig)
        .context("token signature verification failed")?;
    Ok(payload)
}

pub fn token_digest_hex(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn validate_signing_key(key: &SigningKeyFile) -> Result<()> {
    if key.version != 1 {
        bail!("unsupported key version {}", key.version);
    }
    if key.key_type != "ed25519" {
        bail!("unsupported key type {}", key.key_type);
    }
    let public = URL_SAFE_NO_PAD
        .decode(normalize_b64(&key.public_key_b64).as_bytes())
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD.decode(key.public_key_b64.as_bytes())
        })
        .map_err(|_| anyhow!("invalid public key encoding"))?;
    if public.len() != 32 {
        bail!("public key must be 32 bytes");
    }
    Ok(())
}

fn normalize_b64(s: &str) -> String {
    s.replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

fn decode_token_parts(parts: &[&str]) -> Result<(Vec<u8>, Signature)> {
    if parts.len() != 3 || parts[0] != "v1" {
        bail!("invalid token format");
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .context("decode token payload")?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .context("decode token signature")?;
    if sig_bytes.len() != 64 {
        bail!("invalid token signature length");
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    Ok((payload_bytes, Signature::from_bytes(&sig_arr)))
}

fn signing_key_from_file(key: &SigningKeyFile) -> Result<SigningKey> {
    let secret = base64::engine::general_purpose::STANDARD
        .decode(key.secret_key_b64.as_bytes())
        .context("decode secret key")?;
    if secret.len() != 32 {
        bail!("secret key must be 32 bytes");
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&secret);
    Ok(SigningKey::from_bytes(&sk))
}

fn verifying_key_from_file(key: &SigningKeyFile) -> Result<VerifyingKey> {
    let public = base64::engine::general_purpose::STANDARD
        .decode(key.public_key_b64.as_bytes())
        .context("decode public key")?;
    if public.len() != 32 {
        bail!("public key must be 32 bytes");
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&public);
    VerifyingKey::from_bytes(&pk).context("parse public key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use audit_log::generate_signing_key;
    use auth_keyring::{add_key, empty_keyring, revoke_key};

    #[test]
    fn issue_and_verify_roundtrip() {
        let key = generate_signing_key();
        let payload = CapabilityTokenPayloadV1 {
            version: 1,
            key_id: "".to_string(),
            client_id: "alice".to_string(),
            issued_at_ms: 1000,
            expires_at_ms: Some(2000),
            allow: AllowSpecV1 {
                tools: vec!["views.query".to_string()],
                views: vec!["notes_recent".to_string()],
                mounts: vec![],
            },
        };
        let token = issue_token(&key, payload).unwrap();
        let verified = verify_token(&token, &key, 1500).unwrap();
        assert_eq!(verified.client_id, "alice");
    }

    #[test]
    fn expired_token_fails() {
        let key = generate_signing_key();
        let payload = CapabilityTokenPayloadV1 {
            version: 1,
            key_id: "".to_string(),
            client_id: "alice".to_string(),
            issued_at_ms: 1000,
            expires_at_ms: Some(1001),
            allow: AllowSpecV1 {
                tools: vec!["views.query".to_string()],
                views: vec![],
                mounts: vec![],
            },
        };
        let token = issue_token(&key, payload).unwrap();
        assert!(verify_token(&token, &key, 2000).is_err());
    }

    #[test]
    fn tampered_token_fails() {
        let key = generate_signing_key();
        let payload = CapabilityTokenPayloadV1 {
            version: 1,
            key_id: "".to_string(),
            client_id: "alice".to_string(),
            issued_at_ms: 1000,
            expires_at_ms: None,
            allow: AllowSpecV1 {
                tools: vec!["views.query".to_string()],
                views: vec![],
                mounts: vec![],
            },
        };
        let token = issue_token(&key, payload).unwrap();
        let mut parts: Vec<String> = token.split('.').map(ToString::to_string).collect();
        parts[1].push('x');
        let bad = parts.join(".");
        assert!(verify_token(&bad, &key, 1000).is_err());
    }

    #[test]
    fn keyring_verification_respects_revocation() {
        let key = generate_signing_key();
        let payload = CapabilityTokenPayloadV1 {
            version: 1,
            key_id: "".to_string(),
            client_id: "alice".to_string(),
            issued_at_ms: 1000,
            expires_at_ms: None,
            allow: AllowSpecV1 {
                tools: vec!["views.query".to_string()],
                views: vec![],
                mounts: vec![],
            },
        };
        let token = issue_token(&key, payload).unwrap();
        let mut ring = empty_keyring(1);
        add_key(
            &mut ring,
            key.key_id.clone(),
            key.public_key_b64.clone(),
            None,
            1,
        )
        .unwrap();
        assert!(verify_token_with_keyring(&token, &ring, 1000).is_ok());
        revoke_key(&mut ring, &key.key_id, None, 2).unwrap();
        assert!(verify_token_with_keyring(&token, &ring, 1000).is_err());
    }
}
