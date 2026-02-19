use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use audit_log::{
    digest_and_size, generate_signing_key, load_signing_key, sign_checkpoint,
    verify_with_checkpoint, verify_with_signed_checkpoint, write_checkpoint,
    write_signed_checkpoint_atomic, AuditEvent, AuditLogger, Direction, SigningKeyFile,
};
use auth_keyring::{
    add_key, empty_keyring, load_keyring, revoke_key, with_keyring_lock, write_keyring_atomic,
    AuthKeyringV1, KeyStatusV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use cap_token::{
    issue_token as issue_capability_token, token_digest_hex,
    verify_token as verify_capability_token, verify_token_with_keyring as verify_with_keyring,
    AllowSpecV1, CapabilityTokenPayloadV1,
};
use hmac::{Hmac, Mac};
use jsonschema::JSONSchema;
use mcp_wire::{error, read_json_line_streaming, Id};
use policy_engine::{
    compile_and_lint, evaluate_with_context, lint_policy, parse_policy, request_from_params,
    CompiledPolicy, Decision, DecisionTrace, RequestContext, TraceConfig, TraceStep,
};
use rand::{distributions::Alphanumeric, Rng};
use redaction::Redactor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const TOOLFW_DENIED: i64 = -32040;
pub const TOOLFW_APPROVAL_REQUIRED: i64 = -32041;
pub const TOOLFW_RATE_LIMITED: i64 = -32042;
const RESERVED_ARG_NS: &str = "__toolfw";
const INVALID_PARAMS: i64 = -32602;
const MAX_VALIDATION_ERRORS: usize = 5;
const MAX_VALIDATION_MSG_LEN: usize = 160;
const STORE_LOCK_RETRIES: usize = 200;
const STORE_LOCK_SLEEP_MS: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovalRecord {
    request_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApprovalStore {
    secret_hex: String,
    requests: HashMap<String, ApprovalRecord>,
}

impl ApprovalStore {
    fn load_or_init_nolock(path: &Path) -> Result<Self> {
        if path.exists() {
            let txt = fs::read_to_string(path)
                .with_context(|| format!("read approval store {}", path.display()))?;
            let s =
                serde_json::from_str::<ApprovalStore>(&txt).context("parse approval store json")?;
            return Ok(s);
        }

        let mut secret = [0u8; 32];
        rand::thread_rng().fill(&mut secret);
        let s = ApprovalStore {
            secret_hex: to_hex(&secret),
            requests: HashMap::new(),
        };
        s.save_nolock(path)?;
        Ok(s)
    }

    fn save_nolock(&self, path: &Path) -> Result<()> {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(dir)
            .with_context(|| format!("create store directory {}", dir.display()))?;

        let rand_tail: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(8)
            .map(char::from)
            .collect();
        let tmp = dir.join(format!(".{}.{}.tmp", file_stem_safe(path), rand_tail));

        let bytes = serde_json::to_vec_pretty(self).context("serialize approval store")?;
        {
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp)
                .with_context(|| format!("open temp store {}", tmp.display()))?;
            f.write_all(&bytes)
                .with_context(|| format!("write temp store {}", tmp.display()))?;
            f.sync_all()
                .with_context(|| format!("sync temp store {}", tmp.display()))?;
        }

        fs::rename(&tmp, path).with_context(|| {
            format!(
                "atomic replace approval store {} -> {}",
                tmp.display(),
                path.display()
            )
        })?;
        Ok(())
    }

    fn secret(&self) -> Result<Vec<u8>> {
        from_hex(&self.secret_hex)
    }
}

struct ProxyConfig {
    redactor: Redactor,
    audit_sample_bytes: usize,
    audit_signing_key: Option<SigningKeyFile>,
    auth_keyring: Option<AuthKeyringV1>,
    policy_trace: PolicyTraceMode,
    policy_trace_to_audit: PolicyTraceMode,
    policy_trace_max_steps: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTraceMode {
    Off,
    Deny,
    All,
}

impl PolicyTraceMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "off" => Ok(Self::Off),
            "deny" => Ok(Self::Deny),
            "all" => Ok(Self::All),
            _ => bail!("invalid trace mode '{value}', expected one of: off, deny, all"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DoctorProxyStdioOptions<'a> {
    pub policy: &'a Path,
    pub approval_store: Option<&'a Path>,
    pub audit: Option<&'a Path>,
    pub audit_checkpoint: Option<&'a Path>,
    pub audit_signing_key: Option<&'a Path>,
    pub auth_pubkey: Option<&'a Path>,
    pub auth_keys: Option<&'a Path>,
    pub redact: Option<&'a Path>,
    pub audit_payload_sample_bytes: usize,
    pub policy_trace: Option<&'a str>,
    pub gateway_mounts: Option<&'a Path>,
    pub gateway_views: Option<&'a Path>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub issues: Vec<String>,
    pub warnings: Vec<String>,
    pub summary: DoctorSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorSummary {
    pub policy_rules: usize,
    pub policy_lint_errors: usize,
    pub policy_lint_warnings: usize,
    pub auth: String,
    pub audit: String,
    pub policy_trace: String,
}

pub fn issue_approval_token(store_path: &Path, approval_request_id: &str) -> Result<String> {
    with_store_lock(store_path, || {
        let store = ApprovalStore::load_or_init_nolock(store_path)?;
        let rec = store
            .requests
            .get(approval_request_id)
            .ok_or_else(|| anyhow!("unknown approval_request_id"))?;
        let secret = store.secret()?;
        let mac = compute_mac(&secret, approval_request_id, &rec.request_digest)?;
        let mac_b64 = URL_SAFE_NO_PAD.encode(mac);
        Ok(format!("v1:{approval_request_id}:{mac_b64}"))
    })
}

pub fn audit_keygen(out_path: &Path) -> Result<String> {
    let key = generate_signing_key();
    audit_log::write_signing_key_atomic(out_path, &key)?;
    Ok(key.public_key_b64)
}

pub fn audit_verify(audit_path: &Path, checkpoint_path: &Path, pubkey_path: &Path) -> Result<()> {
    let txt = fs::read_to_string(checkpoint_path)
        .with_context(|| format!("read checkpoint {}", checkpoint_path.display()))?;
    let v: Value = serde_json::from_str(&txt)
        .with_context(|| format!("parse checkpoint {}", checkpoint_path.display()))?;
    let is_signed = v.get("signature_b64").and_then(Value::as_str).is_some();
    if is_signed {
        verify_with_signed_checkpoint(audit_path, checkpoint_path, pubkey_path)
    } else {
        verify_with_checkpoint(audit_path, checkpoint_path)
    }
}

#[derive(Debug, Deserialize)]
struct ExplainRequestInput {
    client_id: Option<String>,
    auth_verified: Option<bool>,
    token_key_id: Option<String>,
    mcp_method: String,
    tool: Option<String>,
    #[serde(default)]
    args: Value,
}

pub fn policy_explain(policy_path: &Path, request_json: &str) -> Result<Value> {
    let txt = fs::read_to_string(policy_path)
        .with_context(|| format!("read policy file {}", policy_path.display()))?;
    let policy = parse_policy(&txt)?;
    let req: ExplainRequestInput =
        serde_json::from_str(request_json).context("parse explain request json")?;
    let auth_verified = req.auth_verified.unwrap_or(false);
    let eval = evaluate_with_context(
        &policy,
        &policy_engine::PolicyRequest {
            mcp_method: req.mcp_method,
            tool: req.tool,
            args: req.args,
        },
        &RequestContext {
            client_id: if auth_verified { req.client_id } else { None },
            auth_verified: Some(auth_verified),
            token_key_id: if auth_verified {
                req.token_key_id
            } else {
                None
            },
        },
    );

    Ok(json!({
        "decision": eval.decision,
        "rule_id": eval.matched_rule_id,
        "rule_index": eval.matched_rule_index,
        "reasons": eval.reasons.into_iter().take(5).map(|r| r.message).collect::<Vec<_>>(),
        "matched": eval.matched,
    }))
}

pub fn policy_trace(policy_path: &Path, request_json: &str, max_steps: usize) -> Result<Value> {
    let txt = fs::read_to_string(policy_path)
        .with_context(|| format!("read policy file {}", policy_path.display()))?;
    let policy = parse_policy(&txt)?;
    let compiled = policy.compile()?;
    let req: ExplainRequestInput =
        serde_json::from_str(request_json).context("parse trace request json")?;
    let auth_verified = req.auth_verified.unwrap_or(false);
    let (eval, trace) = compiled.evaluate_with_context_traced(
        &policy_engine::PolicyRequest {
            mcp_method: req.mcp_method,
            tool: req.tool,
            args: req.args,
        },
        &RequestContext {
            client_id: if auth_verified { req.client_id } else { None },
            auth_verified: Some(auth_verified),
            token_key_id: if auth_verified {
                req.token_key_id
            } else {
                None
            },
        },
        &TraceConfig {
            enabled: true,
            max_steps: max_steps.max(1),
            max_reasons: 10,
        },
    );

    Ok(json!({
        "decision": eval.decision,
        "rule_id": eval.matched_rule_id,
        "rule_index": eval.matched_rule_index,
        "trace": trace,
    }))
}

pub fn policy_lint(policy_path: &Path) -> Result<Value> {
    let txt = fs::read_to_string(policy_path)
        .with_context(|| format!("read policy file {}", policy_path.display()))?;
    let policy = parse_policy(&txt)?;
    serde_json::to_value(lint_policy(&policy)).context("serialize lint report")
}

pub fn policy_compile(policy_path: &Path) -> Result<Value> {
    let txt = fs::read_to_string(policy_path)
        .with_context(|| format!("read policy file {}", policy_path.display()))?;
    let policy = parse_policy(&txt)?;
    let _ = policy.compile()?;
    let rules = policy
        .rules
        .iter()
        .enumerate()
        .map(|(idx, r)| {
            json!({
                "id": r.id,
                "index": idx,
                "priority": r.priority.unwrap_or(0),
                "hard": r.hard,
                "decision": r.decision,
                "has_not": r.matcher.not.is_some(),
                "has_args": r.matcher.args.as_ref().map(|a| !a.is_empty()).unwrap_or(false),
                "limit_per_client": r.limit.as_ref().and_then(|l| l.per_client.as_ref()).map(|p| json!({"capacity": p.capacity, "refill_per_sec": p.refill_per_sec})),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "compiled": true,
        "rule_count": rules.len(),
        "rules": rules,
    }))
}

pub fn doctor_proxy_stdio(opts: &DoctorProxyStdioOptions<'_>) -> Result<DoctorReport> {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut policy_rules = 0usize;
    let mut lint_errors = 0usize;
    let mut lint_warnings = 0usize;
    let mut policy_trace = "off".to_string();

    if opts.auth_pubkey.is_some() && opts.auth_keys.is_some() {
        issues.push("--auth-pubkey and --auth-keys are mutually exclusive".to_string());
    }
    if opts.audit_checkpoint.is_some() && opts.audit.is_none() {
        issues.push("--audit-checkpoint requires --audit".to_string());
    }
    if opts.audit_signing_key.is_some() && (opts.audit_checkpoint.is_none() || opts.audit.is_none())
    {
        issues.push("--audit-signing-key requires --audit-checkpoint and --audit".to_string());
    }
    if let Some(mode) = opts.policy_trace {
        match PolicyTraceMode::parse(mode) {
            Ok(_) => policy_trace = mode.to_string(),
            Err(e) => issues.push(format!("invalid --policy-trace: {e}")),
        }
    }

    match fs::read_to_string(opts.policy) {
        Ok(txt) => match parse_policy(&txt) {
            Ok(policy) => {
                policy_rules = policy.rules.len();
                let lint = lint_policy(&policy);
                lint_errors = lint.summary.error_count;
                lint_warnings = lint.summary.warning_count;
                for d in lint.errors.into_iter().take(20) {
                    issues.push(format!("policy lint error {}: {}", d.code, d.message));
                }
                for d in lint.warnings.into_iter().take(20) {
                    warnings.push(format!("policy lint warning {}: {}", d.code, d.message));
                }
            }
            Err(e) => issues.push(format!("invalid policy yaml: {e}")),
        },
        Err(e) => issues.push(format!("policy file unreadable: {e}")),
    }

    if let Some(path) = opts.redact {
        if let Err(e) = Redactor::from_yaml(path) {
            issues.push(format!("invalid redaction config: {e}"));
        }
    }

    if let Some(path) = opts.auth_pubkey {
        if let Err(e) = load_signing_key(path) {
            issues.push(format!("invalid auth pubkey: {e}"));
        }
    }
    if let Some(path) = opts.auth_keys {
        if let Err(e) = with_keyring_lock(path, || load_keyring(path)) {
            issues.push(format!("invalid auth keyring: {e}"));
        }
    }
    if let Some(path) = opts.audit_signing_key {
        if let Err(e) = load_signing_key(path) {
            issues.push(format!("invalid audit signing key: {e}"));
        }
    }

    if let Some(path) = opts.gateway_mounts {
        if let Err(e) = parse_mounts_yaml(path) {
            issues.push(format!("invalid gateway mounts yaml: {e}"));
        }
    }
    if let Some(path) = opts.gateway_views {
        if let Err(e) = parse_views_yaml(path) {
            issues.push(format!("invalid gateway views yaml: {e}"));
        }
    }

    if let Some(path) = opts.approval_store {
        check_writable_target(path, "approval store", &mut issues, &mut warnings);
    }
    if let Some(path) = opts.audit {
        check_writable_target(path, "audit log", &mut issues, &mut warnings);
    }
    if let Some(path) = opts.audit_checkpoint {
        check_writable_target(path, "audit checkpoint", &mut issues, &mut warnings);
    }

    if opts.audit_payload_sample_bytes > 0 && opts.redact.is_none() {
        warnings
            .push("audit payload sampling is enabled with default redaction patterns".to_string());
    }

    let auth = if opts.auth_keys.is_some() {
        "keyring".to_string()
    } else if opts.auth_pubkey.is_some() {
        "pubkey".to_string()
    } else {
        "none".to_string()
    };
    let audit = if opts.audit_signing_key.is_some() {
        "signed_checkpoint".to_string()
    } else if opts.audit_checkpoint.is_some() {
        "checkpoint".to_string()
    } else if opts.audit.is_some() {
        "audit_only".to_string()
    } else {
        "none".to_string()
    };

    Ok(DoctorReport {
        ok: issues.is_empty(),
        issues,
        warnings,
        summary: DoctorSummary {
            policy_rules,
            policy_lint_errors: lint_errors,
            policy_lint_warnings: lint_warnings,
            auth,
            audit,
            policy_trace,
        },
    })
}

pub fn auth_issue(
    signing_key_path: &Path,
    client_id: &str,
    tools: Vec<String>,
    views: Vec<String>,
    mounts: Vec<String>,
    ttl_seconds: Option<u64>,
) -> Result<String> {
    let key = load_signing_key(signing_key_path)?;
    let now_ms = now_ms();
    let payload = CapabilityTokenPayloadV1 {
        version: 1,
        key_id: key.key_id.clone(),
        client_id: client_id.to_string(),
        issued_at_ms: now_ms,
        expires_at_ms: ttl_seconds.map(|t| now_ms.saturating_add(t.saturating_mul(1000))),
        allow: AllowSpecV1 {
            tools,
            views,
            mounts,
        },
    };
    issue_capability_token(&key, payload)
}

#[derive(Debug, Deserialize)]
struct DoctorMountsConfig {
    mounts: Vec<DoctorMountSpec>,
}

#[derive(Debug, Deserialize)]
struct DoctorMountSpec {
    name: String,
    root: String,
}

#[derive(Debug, Deserialize)]
struct DoctorViewsConfig {
    views: Vec<DoctorViewSpec>,
}

#[derive(Debug, Deserialize)]
struct DoctorViewSpec {
    name: String,
    tool: String,
}

fn parse_mounts_yaml(path: &Path) -> Result<()> {
    let txt = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let parsed: DoctorMountsConfig =
        serde_yaml::from_str(&txt).with_context(|| format!("parse {}", path.display()))?;
    for mount in parsed.mounts {
        if mount.name.trim().is_empty() {
            bail!("mount name must not be empty");
        }
        if mount.root.trim().is_empty() {
            bail!("mount root must not be empty");
        }
    }
    Ok(())
}

fn parse_views_yaml(path: &Path) -> Result<()> {
    let txt = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let parsed: DoctorViewsConfig =
        serde_yaml::from_str(&txt).with_context(|| format!("parse {}", path.display()))?;
    for view in parsed.views {
        if view.name.trim().is_empty() {
            bail!("view name must not be empty");
        }
        if view.tool.trim().is_empty() {
            bail!("view tool must not be empty");
        }
    }
    Ok(())
}

fn check_writable_target(
    path: &Path,
    label: &str,
    issues: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    if path.exists() {
        if OpenOptions::new().write(true).open(path).is_err() {
            issues.push(format!("{label} is not writable: {}", path.display()));
        }
        return;
    }

    let Some(parent) = path.parent() else {
        warnings.push(format!(
            "cannot determine parent directory writability for {label}: {}",
            path.display()
        ));
        return;
    };

    match fs::metadata(parent) {
        Ok(meta) => {
            if !meta.is_dir() {
                issues.push(format!(
                    "parent for {label} is not a directory: {}",
                    parent.display()
                ));
            } else if meta.permissions().readonly() {
                issues.push(format!(
                    "parent directory for {label} is read-only: {}",
                    parent.display()
                ));
            }
        }
        Err(e) => issues.push(format!(
            "parent directory for {label} is not accessible: {} ({e})",
            parent.display()
        )),
    }
}

pub fn auth_verify(
    pubkey_path: Option<&Path>,
    keyring_path: Option<&Path>,
    token: &str,
) -> Result<Value> {
    if pubkey_path.is_some() && keyring_path.is_some() {
        bail!("--pubkey and --keys are mutually exclusive");
    }
    let payload = if let Some(path) = keyring_path {
        let ring = with_keyring_lock(path, || load_keyring(path))?;
        verify_with_keyring(token, &ring, now_ms())?
    } else if let Some(path) = pubkey_path {
        let key = load_signing_key(path)?;
        verify_capability_token(token, &key, now_ms())?
    } else {
        bail!("one of --pubkey or --keys is required");
    };
    serde_json::to_value(json!({
        "client_id": payload.client_id,
        "key_id": payload.key_id,
        "expires_at_ms": payload.expires_at_ms,
        "allow": payload.allow,
    }))
    .context("serialize auth verify summary")
}

pub fn keyring_init(out_path: &Path) -> Result<()> {
    let ring = empty_keyring(now_ms());
    with_keyring_lock(out_path, || write_keyring_atomic(out_path, &ring))
}

pub fn keyring_add(keys_path: &Path, pubkey_path: &Path, note: Option<String>) -> Result<()> {
    let key = load_signing_key(pubkey_path)?;
    with_keyring_lock(keys_path, || {
        let mut ring = if keys_path.exists() {
            load_keyring(keys_path)?
        } else {
            empty_keyring(now_ms())
        };
        add_key(
            &mut ring,
            key.key_id.clone(),
            key.public_key_b64.clone(),
            note,
            now_ms(),
        )?;
        write_keyring_atomic(keys_path, &ring)
    })
}

pub fn keyring_revoke(keys_path: &Path, key_id: &str, note: Option<String>) -> Result<()> {
    with_keyring_lock(keys_path, || {
        let mut ring = load_keyring(keys_path)?;
        revoke_key(&mut ring, key_id, note, now_ms())?;
        write_keyring_atomic(keys_path, &ring)
    })
}

pub fn keyring_list(keys_path: &Path) -> Result<Value> {
    let ring = with_keyring_lock(keys_path, || load_keyring(keys_path))?;
    Ok(json!({
        "version": ring.version,
        "updated_at_ms": ring.updated_at_ms,
        "keys": ring.keys.into_iter().map(|k| {
            json!({
                "key_id": k.key_id,
                "status": match k.status {
                    KeyStatusV1::Active => "active",
                    KeyStatusV1::Revoked => "revoked",
                },
                "added_at_ms": k.added_at_ms,
                "revoked_at_ms": k.revoked_at_ms,
                "note": k.note,
            })
        }).collect::<Vec<_>>()
    }))
}

pub fn auth_rotate(
    keys_path: &Path,
    out_signing_key: &Path,
    note: Option<String>,
) -> Result<String> {
    let key = generate_signing_key();
    audit_log::write_signing_key_atomic(out_signing_key, &key)?;
    with_keyring_lock(keys_path, || {
        let mut ring = if keys_path.exists() {
            load_keyring(keys_path)?
        } else {
            empty_keyring(now_ms())
        };
        add_key(
            &mut ring,
            key.key_id.clone(),
            key.public_key_b64.clone(),
            note,
            now_ms(),
        )?;
        write_keyring_atomic(keys_path, &ring)?;
        Ok(())
    })?;
    Ok(key.key_id)
}

#[allow(clippy::too_many_arguments)]
pub fn run_proxy_stdio(
    policy_path: &Path,
    approval_store_path: &Path,
    audit_path: Option<&Path>,
    audit_checkpoint_path: Option<&Path>,
    audit_signing_key_path: Option<&Path>,
    auth_pubkey_path: Option<&Path>,
    auth_keys_path: Option<&Path>,
    redact_path: Option<&Path>,
    audit_payload_sample_bytes: usize,
    policy_trace_mode: PolicyTraceMode,
    policy_trace_max_steps: usize,
    policy_trace_to_audit: PolicyTraceMode,
    upstream_cmd: &[String],
) -> Result<()> {
    if upstream_cmd.is_empty() {
        bail!("upstream command is required");
    }
    if audit_checkpoint_path.is_some() && audit_path.is_none() {
        bail!("--audit-checkpoint requires --audit");
    }
    if audit_signing_key_path.is_some() && audit_checkpoint_path.is_none() {
        bail!("--audit-signing-key requires --audit-checkpoint");
    }
    if auth_pubkey_path.is_some() && auth_keys_path.is_some() {
        bail!("--auth-pubkey and --auth-keys are mutually exclusive");
    }

    let compiled_policy = {
        let txt = fs::read_to_string(policy_path)
            .with_context(|| format!("read policy file {}", policy_path.display()))?;
        let policy = parse_policy(&txt)?;
        let (compiled, lint) = compile_and_lint(&policy)?;
        if !lint.ok {
            let first = lint
                .errors
                .first()
                .map(|d| format!("{}: {}", d.code, d.message))
                .unwrap_or_else(|| "unknown policy lint error".to_string());
            bail!("policy lint errors present: {first}");
        }
        compiled
    };

    let config = ProxyConfig {
        redactor: if let Some(path) = redact_path {
            Redactor::from_yaml(path)?
        } else {
            Redactor::new_default()
        },
        audit_sample_bytes: audit_payload_sample_bytes,
        audit_signing_key: if let Some(path) = audit_signing_key_path {
            Some(load_signing_key(path)?)
        } else {
            None
        },
        auth_keyring: if let Some(path) = auth_keys_path {
            Some(with_keyring_lock(path, || load_keyring(path))?)
        } else if let Some(path) = auth_pubkey_path {
            let key = load_signing_key(path)?;
            Some(single_key_keyring(&key)?)
        } else {
            None
        },
        policy_trace: policy_trace_mode,
        policy_trace_to_audit,
        policy_trace_max_steps: policy_trace_max_steps.max(1),
    };

    let audit = if let Some(path) = audit_path {
        Some(AuditLogger::open(path)?)
    } else {
        None
    };

    let mut child = Command::new(&upstream_cmd[0])
        .args(&upstream_cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn upstream {}", upstream_cmd[0]))?;

    let mut child_in = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("missing upstream stdin"))?;
    let mut child_out = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("missing upstream stdout"))?;

    let mut stdin = io::stdin().lock();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut client_partial = Vec::new();
    let mut upstream_partial = Vec::new();
    let mut schema_cache: HashMap<String, Value> = HashMap::new();
    let rate_limiter = RateLimiter::default();

    while let Some(client_msg) = read_json_line_streaming(&mut stdin, &mut client_partial)? {
        if let Some(resp) = process_client_message(
            &compiled_policy,
            approval_store_path,
            &mut child_in,
            &mut child_out,
            &mut upstream_partial,
            &mut schema_cache,
            &rate_limiter,
            audit.as_ref(),
            audit_checkpoint_path,
            &config,
            client_msg,
        )? {
            mcp_wire::write_json_line(&mut out, &resp)?;
        }
    }

    let _ = child.wait();
    Ok(())
}

enum ProxyAction {
    Forward(Value),
    Respond(Value),
}

struct EvalMeta {
    id: Option<Value>,
    method: Option<String>,
    tool: Option<String>,
    decision: Option<String>,
    args_digest: Option<String>,
    args_bytes: Option<usize>,
    args_sample: Option<Value>,
    client_id: Option<String>,
    auth_verified: Option<bool>,
    token_key_id: Option<String>,
    token_digest: Option<String>,
    rule_id: Option<String>,
    rule_index: Option<usize>,
    policy_reasons: Option<Vec<String>>,
    policy_trace: Option<Value>,
}

struct EvalOutcome {
    action: ProxyAction,
    meta: EvalMeta,
}

#[derive(Debug, Clone)]
struct AuthInfo {
    client_id: Option<String>,
    auth_verified: bool,
    token_key_id: Option<String>,
    token_digest: Option<String>,
}

#[derive(Debug, Default)]
struct RateLimiter {
    buckets: Mutex<HashMap<String, BucketState>>,
}

#[derive(Debug, Clone)]
struct BucketState {
    tokens: f64,
    last_ms: u64,
}

impl AuthInfo {
    fn unknown() -> Self {
        Self {
            client_id: Some("<unknown>".to_string()),
            auth_verified: false,
            token_key_id: None,
            token_digest: None,
        }
    }
}

impl RateLimiter {
    fn check(
        &self,
        client_key: &str,
        tool_key: &str,
        capacity: f64,
        refill_per_sec: f64,
        now_ms: u64,
    ) -> Option<u64> {
        if capacity <= 0.0 {
            return Some(0);
        }
        let key = format!("{client_key}:{tool_key}");
        let mut guard = match self.buckets.lock() {
            Ok(g) => g,
            Err(_) => return Some(0),
        };
        let bucket = guard.entry(key).or_insert(BucketState {
            tokens: capacity,
            last_ms: now_ms,
        });

        let elapsed_ms = now_ms.saturating_sub(bucket.last_ms);
        if refill_per_sec > 0.0 {
            let refill = (elapsed_ms as f64 / 1000.0) * refill_per_sec;
            bucket.tokens = (bucket.tokens + refill).min(capacity);
        }
        bucket.last_ms = now_ms;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            None
        } else if refill_per_sec <= 0.0 {
            Some(u64::MAX)
        } else {
            let needed = 1.0 - bucket.tokens;
            let retry_after_ms = ((needed / refill_per_sec) * 1000.0).ceil().max(0.0) as u64;
            Some(retry_after_ms)
        }
    }
}

fn trace_enabled(config: &ProxyConfig) -> bool {
    config.policy_trace != PolicyTraceMode::Off
        || config.policy_trace_to_audit != PolicyTraceMode::Off
}

fn should_attach_trace_to_error(config: &ProxyConfig, code: i64) -> bool {
    match config.policy_trace {
        PolicyTraceMode::Off => false,
        PolicyTraceMode::Deny | PolicyTraceMode::All => {
            matches!(
                code,
                TOOLFW_DENIED | TOOLFW_APPROVAL_REQUIRED | TOOLFW_RATE_LIMITED
            )
        }
    }
}

fn should_attach_trace_to_audit(
    config: &ProxyConfig,
    direction: Direction,
    error_code: Option<i64>,
) -> bool {
    match config.policy_trace_to_audit {
        PolicyTraceMode::Off => false,
        PolicyTraceMode::All => true,
        PolicyTraceMode::Deny => {
            direction == Direction::LocalError
                && matches!(
                    error_code,
                    Some(TOOLFW_DENIED | TOOLFW_APPROVAL_REQUIRED | TOOLFW_RATE_LIMITED)
                )
        }
    }
}

fn attach_trace_to_error_data(base: Value, trace: Option<&Value>) -> Value {
    if trace.is_none() {
        return base;
    }
    let mut obj = base.as_object().cloned().unwrap_or_default();
    obj.insert("trace".to_string(), trace.cloned().unwrap_or(Value::Null));
    Value::Object(obj)
}

#[allow(clippy::too_many_arguments)]
fn process_client_message(
    policy: &CompiledPolicy,
    approval_store_path: &Path,
    child_in: &mut std::process::ChildStdin,
    child_out: &mut std::process::ChildStdout,
    upstream_partial: &mut Vec<u8>,
    schema_cache: &mut HashMap<String, Value>,
    rate_limiter: &RateLimiter,
    audit: Option<&AuditLogger>,
    audit_checkpoint_path: Option<&Path>,
    config: &ProxyConfig,
    client_msg: Value,
) -> Result<Option<Value>> {
    match client_msg {
        Value::Array(batch) => {
            let mut responses = Vec::new();
            for item in batch {
                if !item.is_object() {
                    let resp = invalid_request(Value::Null, "Invalid Request");
                    log_local_error(
                        audit,
                        audit_checkpoint_path,
                        config,
                        None,
                        None,
                        None,
                        None,
                        None,
                        -32600,
                        None,
                        Some("<unknown>".to_string()),
                        Some(false),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    );
                    responses.push(resp);
                    continue;
                }
                if let Some(resp) = process_single_message(
                    policy,
                    approval_store_path,
                    child_in,
                    child_out,
                    upstream_partial,
                    schema_cache,
                    rate_limiter,
                    audit,
                    audit_checkpoint_path,
                    config,
                    &item,
                )? {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                Ok(None)
            } else {
                Ok(Some(Value::Array(responses)))
            }
        }
        Value::Object(_) => process_single_message(
            policy,
            approval_store_path,
            child_in,
            child_out,
            upstream_partial,
            schema_cache,
            rate_limiter,
            audit,
            audit_checkpoint_path,
            config,
            &client_msg,
        ),
        _ => {
            log_local_error(
                audit,
                audit_checkpoint_path,
                config,
                None,
                None,
                None,
                None,
                None,
                -32600,
                None,
                Some("<unknown>".to_string()),
                Some(false),
                None,
                None,
                None,
                None,
                None,
                None,
            );
            Ok(Some(invalid_request(Value::Null, "Invalid Request")))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_single_message(
    policy: &CompiledPolicy,
    approval_store_path: &Path,
    child_in: &mut std::process::ChildStdin,
    child_out: &mut std::process::ChildStdout,
    upstream_partial: &mut Vec<u8>,
    schema_cache: &mut HashMap<String, Value>,
    rate_limiter: &RateLimiter,
    audit: Option<&AuditLogger>,
    audit_checkpoint_path: Option<&Path>,
    config: &ProxyConfig,
    request: &Value,
) -> Result<Option<Value>> {
    let outcome = evaluate_request(
        policy,
        approval_store_path,
        request,
        schema_cache,
        config,
        rate_limiter,
    )?;
    log_client_request(audit, audit_checkpoint_path, config, &outcome.meta);

    match outcome.action {
        ProxyAction::Respond(resp) => {
            let error_code = resp
                .get("error")
                .and_then(|v| v.get("code"))
                .and_then(Value::as_i64)
                .unwrap_or(-32000);
            let error_data_sample = sample_error_data(&resp, config);
            log_local_error(
                audit,
                audit_checkpoint_path,
                config,
                outcome.meta.id,
                outcome.meta.method,
                outcome.meta.tool,
                outcome.meta.decision,
                outcome.meta.args_digest,
                error_code,
                error_data_sample,
                outcome.meta.client_id,
                outcome.meta.auth_verified,
                outcome.meta.token_key_id,
                outcome.meta.token_digest,
                outcome.meta.rule_id,
                outcome.meta.rule_index,
                outcome.meta.policy_reasons,
                outcome.meta.policy_trace,
            );
            Ok(Some(resp))
        }
        ProxyAction::Forward(forward_msg) => {
            mcp_wire::write_json_line(child_in, &forward_msg)?;
            if forward_msg.get("id").is_some() {
                let upstream_resp = read_json_line_streaming(child_out, upstream_partial)?
                    .ok_or_else(|| anyhow!("upstream closed while awaiting response"))?;

                if outcome.meta.method.as_deref() == Some("tools/list") {
                    cache_tool_schemas(&upstream_resp, schema_cache);
                }

                log_upstream_response(
                    audit,
                    audit_checkpoint_path,
                    config,
                    outcome.meta.id,
                    outcome.meta.method,
                    outcome.meta.tool,
                    outcome.meta.decision,
                    outcome.meta.client_id,
                    outcome.meta.auth_verified,
                    outcome.meta.token_key_id,
                    outcome.meta.token_digest,
                    outcome.meta.rule_id,
                    outcome.meta.rule_index,
                    outcome.meta.policy_reasons,
                    outcome.meta.policy_trace,
                    &upstream_resp,
                );

                Ok(Some(upstream_resp))
            } else {
                Ok(None)
            }
        }
    }
}

fn evaluate_request(
    policy: &CompiledPolicy,
    approval_store_path: &Path,
    request: &Value,
    schema_cache: &HashMap<String, Value>,
    config: &ProxyConfig,
    rate_limiter: &RateLimiter,
) -> Result<EvalOutcome> {
    if !request.is_object() {
        return Ok(EvalOutcome {
            action: ProxyAction::Respond(invalid_request(Value::Null, "Invalid Request")),
            meta: EvalMeta {
                id: None,
                method: None,
                tool: None,
                decision: Some("invalid_request".to_string()),
                args_digest: None,
                args_bytes: None,
                args_sample: None,
                client_id: Some("<unknown>".to_string()),
                auth_verified: Some(false),
                token_key_id: None,
                token_digest: None,
                rule_id: None,
                rule_index: None,
                policy_reasons: None,
                policy_trace: None,
            },
        });
    }

    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let id_value = request.get("id").cloned();

    if method != "tools/call" {
        return Ok(EvalOutcome {
            action: ProxyAction::Forward(request.clone()),
            meta: EvalMeta {
                id: id_value,
                method: Some(method),
                tool: None,
                decision: Some("allow".to_string()),
                args_digest: None,
                args_bytes: None,
                args_sample: None,
                client_id: Some("<unknown>".to_string()),
                auth_verified: Some(false),
                token_key_id: None,
                token_digest: None,
                rule_id: None,
                rule_index: None,
                policy_reasons: None,
                policy_trace: None,
            },
        });
    }

    let auth_info = auth_info_from_request(request, config);

    let id = request.get("id").and_then(parse_id);
    let Some(id) = id else {
        let mut stripped = request.clone();
        let _ = strip_reserved_metadata(&mut stripped)?;
        return Ok(EvalOutcome {
            action: ProxyAction::Forward(stripped),
            meta: EvalMeta {
                id: id_value,
                method: Some(method),
                tool: request
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .map(|s| s.to_string()),
                decision: Some("allow".to_string()),
                args_digest: None,
                args_bytes: None,
                args_sample: None,
                client_id: auth_info.client_id.clone(),
                auth_verified: Some(auth_info.auth_verified),
                token_key_id: auth_info.token_key_id.clone(),
                token_digest: auth_info.token_digest.clone(),
                rule_id: None,
                rule_index: None,
                policy_reasons: None,
                policy_trace: None,
            },
        });
    };

    let mut stripped = request.clone();
    let approval_token = strip_reserved_metadata(&mut stripped)?;

    let params = stripped
        .get("params")
        .cloned()
        .unwrap_or_else(|| json!({ "name": "", "arguments": {} }));
    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    let args_value = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let (args_digest, args_bytes) = digest_and_size(&args_value)
        .map(|(d, b)| (Some(d), Some(b)))
        .unwrap_or((None, None));
    let args_sample = sample_for_audit(&args_value, config);
    let policy_req = request_from_params(&method, &params);
    let policy_ctx = RequestContext {
        client_id: if auth_info.auth_verified {
            auth_info.client_id.clone()
        } else {
            None
        },
        auth_verified: Some(auth_info.auth_verified),
        token_key_id: if auth_info.auth_verified {
            auth_info.token_key_id.clone()
        } else {
            None
        },
    };
    let (eval, mut trace_obj): (policy_engine::EvalResult, Option<DecisionTrace>) =
        if trace_enabled(config) {
            policy.evaluate_with_context_traced(
                &policy_req,
                &policy_ctx,
                &TraceConfig {
                    enabled: true,
                    max_steps: config.policy_trace_max_steps,
                    max_reasons: 10,
                },
            )
        } else {
            (policy.evaluate_with_context(&policy_req, &policy_ctx), None)
        };
    let decision = eval.decision.clone();
    let rule_id = eval.matched_rule_id.clone();
    let rule_index = eval.matched_rule_index;
    let explain_reasons: Vec<String> = eval
        .reasons
        .into_iter()
        .take(5)
        .map(|r| r.message)
        .collect();

    if decision != Decision::Deny {
        if let Some(limit) = eval.rate_limit {
            let client_key = if auth_info.auth_verified {
                auth_info
                    .client_id
                    .clone()
                    .unwrap_or_else(|| "<anon>".to_string())
            } else {
                "<anon>".to_string()
            };
            let tool_key = tool_name.clone().unwrap_or_else(|| "<unknown>".to_string());
            let now_ms = now_ms();
            if let Some(retry_after_ms) = rate_limiter.check(
                &client_key,
                &tool_key,
                limit.capacity,
                limit.refill_per_sec,
                now_ms,
            ) {
                if let (Some(trace), Some(rule_idx)) = (trace_obj.as_mut(), rule_index) {
                    if trace.steps.len() < config.policy_trace_max_steps {
                        trace.steps.push(TraceStep::RateLimitChecked {
                            rule_index: rule_idx,
                            rule_id: rule_id.clone(),
                            key: if auth_info.auth_verified {
                                "client".to_string()
                            } else {
                                "<anon>".to_string()
                            },
                            allowed: false,
                            retry_after_ms: Some(retry_after_ms),
                        });
                    } else {
                        trace.truncated = true;
                    }
                }
                let trace_json = trace_obj
                    .as_ref()
                    .and_then(|t| serde_json::to_value(t).ok());
                let err_data = attach_trace_to_error_data(
                    json!({
                        "retry_after_ms": retry_after_ms,
                        "rule_id": rule_id,
                    }),
                    if should_attach_trace_to_error(config, TOOLFW_RATE_LIMITED) {
                        trace_json.as_ref()
                    } else {
                        None
                    },
                );
                return Ok(EvalOutcome {
                    action: ProxyAction::Respond(error(
                        id,
                        TOOLFW_RATE_LIMITED,
                        "Rate limited",
                        Some(err_data),
                    )),
                    meta: EvalMeta {
                        id: id_value,
                        method: Some(method),
                        tool: tool_name,
                        decision: Some("rate_limited".to_string()),
                        args_digest,
                        args_bytes,
                        args_sample,
                        client_id: auth_info.client_id.clone(),
                        auth_verified: Some(auth_info.auth_verified),
                        token_key_id: auth_info.token_key_id.clone(),
                        token_digest: auth_info.token_digest.clone(),
                        rule_id,
                        rule_index,
                        policy_reasons: Some(explain_reasons),
                        policy_trace: trace_json,
                    },
                });
            }
            if let (Some(trace), Some(rule_idx)) = (trace_obj.as_mut(), rule_index) {
                if trace.steps.len() < config.policy_trace_max_steps {
                    trace.steps.push(TraceStep::RateLimitChecked {
                        rule_index: rule_idx,
                        rule_id: rule_id.clone(),
                        key: if auth_info.auth_verified {
                            "client".to_string()
                        } else {
                            "<anon>".to_string()
                        },
                        allowed: true,
                        retry_after_ms: None,
                    });
                } else {
                    trace.truncated = true;
                }
            }
        }
    }

    let trace_json = trace_obj
        .as_ref()
        .and_then(|t| serde_json::to_value(t).ok());

    match decision {
        Decision::Allow => {
            if let Some(resp) =
                validate_tool_arguments(id.clone(), &tool_name, &params, schema_cache, config)?
            {
                return Ok(EvalOutcome {
                    action: ProxyAction::Respond(resp),
                    meta: EvalMeta {
                        id: id_value,
                        method: Some(method),
                        tool: tool_name,
                        decision: Some("invalid_params".to_string()),
                        args_digest,
                        args_bytes,
                        args_sample,
                        client_id: auth_info.client_id.clone(),
                        auth_verified: Some(auth_info.auth_verified),
                        token_key_id: auth_info.token_key_id.clone(),
                        token_digest: auth_info.token_digest.clone(),
                        rule_id: rule_id.clone(),
                        rule_index,
                        policy_reasons: Some(explain_reasons.clone()),
                        policy_trace: trace_json.clone(),
                    },
                });
            }
            Ok(EvalOutcome {
                action: ProxyAction::Forward(stripped),
                meta: EvalMeta {
                    id: id_value,
                    method: Some(method),
                    tool: tool_name,
                    decision: Some("allow".to_string()),
                    args_digest,
                    args_bytes,
                    args_sample,
                    client_id: auth_info.client_id.clone(),
                    auth_verified: Some(auth_info.auth_verified),
                    token_key_id: auth_info.token_key_id.clone(),
                    token_digest: auth_info.token_digest.clone(),
                    rule_id,
                    rule_index,
                    policy_reasons: Some(explain_reasons),
                    policy_trace: trace_json,
                },
            })
        }
        Decision::Deny => Ok(EvalOutcome {
            action: ProxyAction::Respond(error(
                id,
                TOOLFW_DENIED,
                "Denied by policy",
                Some(attach_trace_to_error_data(
                    json!({
                        "rule_id": rule_id,
                        "rule_index": rule_index,
                        "reasons": explain_reasons.clone(),
                    }),
                    if should_attach_trace_to_error(config, TOOLFW_DENIED) {
                        trace_json.as_ref()
                    } else {
                        None
                    },
                )),
            )),
            meta: EvalMeta {
                id: id_value,
                method: Some(method),
                tool: tool_name,
                decision: Some("deny".to_string()),
                args_digest,
                args_bytes,
                args_sample,
                client_id: auth_info.client_id.clone(),
                auth_verified: Some(auth_info.auth_verified),
                token_key_id: auth_info.token_key_id.clone(),
                token_digest: auth_info.token_digest.clone(),
                rule_id,
                rule_index,
                policy_reasons: Some(explain_reasons),
                policy_trace: trace_json,
            },
        }),
        Decision::RequireApproval => {
            let digest = request_digest("tools/call", &params)?;
            if let Some(token) = approval_token {
                if verify_token(approval_store_path, &token, &digest)? {
                    if let Some(resp) = validate_tool_arguments(
                        id.clone(),
                        &tool_name,
                        &params,
                        schema_cache,
                        config,
                    )? {
                        return Ok(EvalOutcome {
                            action: ProxyAction::Respond(resp),
                            meta: EvalMeta {
                                id: id_value,
                                method: Some(method),
                                tool: tool_name,
                                decision: Some("invalid_params".to_string()),
                                args_digest,
                                args_bytes,
                                args_sample,
                                client_id: auth_info.client_id.clone(),
                                auth_verified: Some(auth_info.auth_verified),
                                token_key_id: auth_info.token_key_id.clone(),
                                token_digest: auth_info.token_digest.clone(),
                                rule_id: rule_id.clone(),
                                rule_index,
                                policy_reasons: Some(explain_reasons.clone()),
                                policy_trace: trace_json.clone(),
                            },
                        });
                    }
                    return Ok(EvalOutcome {
                        action: ProxyAction::Forward(stripped),
                        meta: EvalMeta {
                            id: id_value,
                            method: Some(method),
                            tool: tool_name,
                            decision: Some("allowed_with_token".to_string()),
                            args_digest,
                            args_bytes,
                            args_sample,
                            client_id: auth_info.client_id.clone(),
                            auth_verified: Some(auth_info.auth_verified),
                            token_key_id: auth_info.token_key_id.clone(),
                            token_digest: auth_info.token_digest.clone(),
                            rule_id: rule_id.clone(),
                            rule_index,
                            policy_reasons: Some(explain_reasons.clone()),
                            policy_trace: trace_json.clone(),
                        },
                    });
                }
            }

            let approval_request_id = create_approval_request(approval_store_path, &digest)?;
            Ok(EvalOutcome {
                action: ProxyAction::Respond(error(
                    id,
                    TOOLFW_APPROVAL_REQUIRED,
                    "Approval required",
                    Some(attach_trace_to_error_data(
                        json!({
                            "approval_request_id": approval_request_id,
                            "rule_id": rule_id,
                            "rule_index": rule_index,
                            "reasons": explain_reasons.clone(),
                        }),
                        if should_attach_trace_to_error(config, TOOLFW_APPROVAL_REQUIRED) {
                            trace_json.as_ref()
                        } else {
                            None
                        },
                    )),
                )),
                meta: EvalMeta {
                    id: id_value,
                    method: Some(method),
                    tool: tool_name,
                    decision: Some("approval_required".to_string()),
                    args_digest,
                    args_bytes,
                    args_sample,
                    client_id: auth_info.client_id.clone(),
                    auth_verified: Some(auth_info.auth_verified),
                    token_key_id: auth_info.token_key_id.clone(),
                    token_digest: auth_info.token_digest.clone(),
                    rule_id,
                    rule_index,
                    policy_reasons: Some(explain_reasons),
                    policy_trace: trace_json,
                },
            })
        }
    }
}

fn auth_info_from_request(request: &Value, config: &ProxyConfig) -> AuthInfo {
    let token = request
        .get("params")
        .and_then(|p| p.get("auth"))
        .and_then(|a| a.get("token"))
        .and_then(Value::as_str);
    let Some(token) = token else {
        return AuthInfo::unknown();
    };

    let digest = token_digest_hex(token);
    let Some(keyring) = config.auth_keyring.as_ref() else {
        return AuthInfo {
            client_id: Some("<unknown>".to_string()),
            auth_verified: false,
            token_key_id: None,
            token_digest: Some(digest),
        };
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    match verify_with_keyring(token, keyring, now_ms) {
        Ok(payload) => AuthInfo {
            client_id: Some(payload.client_id),
            auth_verified: true,
            token_key_id: Some(payload.key_id),
            token_digest: Some(digest),
        },
        Err(_) => AuthInfo {
            client_id: Some("<unknown>".to_string()),
            auth_verified: false,
            token_key_id: None,
            token_digest: Some(digest),
        },
    }
}

fn validate_tool_arguments(
    id: Id,
    tool_name: &Option<String>,
    params: &Value,
    schema_cache: &HashMap<String, Value>,
    config: &ProxyConfig,
) -> Result<Option<Value>> {
    let Some(tool_name) = tool_name else {
        return Ok(None);
    };
    let Some(schema) = schema_cache.get(tool_name) else {
        return Ok(None);
    };

    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let validator = match JSONSchema::compile(schema) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let errors = match validator.validate(&args) {
        Ok(_) => Vec::new(),
        Err(errs) => bounded_validation_errors(errs, &config.redactor),
    };
    if errors.is_empty() {
        return Ok(None);
    }

    Ok(Some(error(
        id,
        INVALID_PARAMS,
        "Invalid params",
        Some(json!({
            "tool": tool_name,
            "errors": errors,
        })),
    )))
}

fn bounded_validation_errors<I, E>(errors: I, redactor: &Redactor) -> Vec<String>
where
    I: IntoIterator<Item = E>,
    E: ToString,
{
    errors
        .into_iter()
        .take(MAX_VALIDATION_ERRORS)
        .map(|e| {
            let s = redactor.redact_str(&e.to_string());
            if s.len() > MAX_VALIDATION_MSG_LEN {
                format!("{}...", &s[..MAX_VALIDATION_MSG_LEN])
            } else {
                s
            }
        })
        .collect()
}

fn cache_tool_schemas(upstream_response: &Value, schema_cache: &mut HashMap<String, Value>) {
    let Some(result) = upstream_response.get("result") else {
        return;
    };
    let Some(tools) = result.get("tools").and_then(Value::as_array) else {
        return;
    };

    for tool in tools {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(input_schema) = tool.get("inputSchema") else {
            continue;
        };
        schema_cache.insert(name.to_string(), input_schema.clone());
    }
}

fn log_client_request(
    audit: Option<&AuditLogger>,
    audit_checkpoint_path: Option<&Path>,
    config: &ProxyConfig,
    meta: &EvalMeta,
) {
    let Some(audit) = audit else {
        return;
    };
    let mut event = AuditEvent::now(Direction::ClientToUpstream);
    event.id = meta.id.clone();
    event.method = meta.method.clone();
    event.tool = meta.tool.clone();
    event.args_digest = meta.args_digest.clone();
    event.args_bytes = meta.args_bytes;
    event.args_sample = meta.args_sample.clone();
    event.client_id = meta.client_id.clone();
    event.auth_verified = meta.auth_verified;
    event.token_key_id = meta.token_key_id.clone();
    event.token_digest = meta.token_digest.clone();
    event.rule_id = meta.rule_id.clone();
    event.policy_reasons = meta.policy_reasons.clone();
    if should_attach_trace_to_audit(config, Direction::ClientToUpstream, None) {
        event.policy_trace = meta.policy_trace.clone();
    }
    if audit.append(event).is_ok() {
        maybe_write_checkpoint_with_signing(audit, audit_checkpoint_path, config);
    }
}

#[allow(clippy::too_many_arguments)]
fn log_local_error(
    audit: Option<&AuditLogger>,
    audit_checkpoint_path: Option<&Path>,
    config: &ProxyConfig,
    id: Option<Value>,
    method: Option<String>,
    tool: Option<String>,
    decision: Option<String>,
    args_digest: Option<String>,
    error_code: i64,
    error_data_sample: Option<Value>,
    client_id: Option<String>,
    auth_verified: Option<bool>,
    token_key_id: Option<String>,
    token_digest: Option<String>,
    rule_id: Option<String>,
    _rule_index: Option<usize>,
    policy_reasons: Option<Vec<String>>,
    policy_trace: Option<Value>,
) {
    let Some(audit) = audit else {
        return;
    };
    let mut event = AuditEvent::now(Direction::LocalError);
    event.id = id;
    event.method = method;
    event.tool = tool;
    event.decision = decision;
    event.args_digest = args_digest;
    event.error_code = Some(error_code);
    event.error_data_sample = error_data_sample;
    event.client_id = client_id;
    event.auth_verified = auth_verified;
    event.token_key_id = token_key_id;
    event.token_digest = token_digest;
    event.rule_id = rule_id;
    event.policy_reasons = policy_reasons;
    if should_attach_trace_to_audit(config, Direction::LocalError, Some(error_code)) {
        event.policy_trace = policy_trace;
    }
    if audit.append(event).is_ok() {
        maybe_write_checkpoint_with_signing(audit, audit_checkpoint_path, config);
    }
}

#[allow(clippy::too_many_arguments)]
fn log_upstream_response(
    audit: Option<&AuditLogger>,
    audit_checkpoint_path: Option<&Path>,
    config: &ProxyConfig,
    id: Option<Value>,
    method: Option<String>,
    tool: Option<String>,
    decision: Option<String>,
    client_id: Option<String>,
    auth_verified: Option<bool>,
    token_key_id: Option<String>,
    token_digest: Option<String>,
    rule_id: Option<String>,
    _rule_index: Option<usize>,
    policy_reasons: Option<Vec<String>>,
    policy_trace: Option<Value>,
    upstream_resp: &Value,
) {
    let Some(audit) = audit else {
        return;
    };

    let result = upstream_resp.get("result").cloned().unwrap_or(Value::Null);
    let (result_digest, result_bytes) = digest_and_size(&result).ok().unwrap_or_default();

    let mut event = AuditEvent::now(Direction::UpstreamToClient);
    event.id = id;
    event.method = method;
    event.tool = tool;
    event.decision = decision;
    event.client_id = client_id;
    event.auth_verified = auth_verified;
    event.token_key_id = token_key_id;
    event.token_digest = token_digest;
    event.rule_id = rule_id;
    event.policy_reasons = policy_reasons;
    if should_attach_trace_to_audit(config, Direction::UpstreamToClient, None) {
        event.policy_trace = policy_trace;
    }
    if !result_digest.is_empty() {
        event.result_digest = Some(result_digest);
    }
    if result_bytes > 0 {
        event.result_bytes = Some(result_bytes);
    }
    if config.audit_sample_bytes > 0 {
        event.result_sample = if let Some(r) = upstream_resp.get("result") {
            sample_for_audit(r, config)
        } else if let Some(err_data) = upstream_resp.get("error").and_then(|e| e.get("data")) {
            sample_for_audit(err_data, config)
        } else {
            None
        };
    }
    if audit.append(event).is_ok() {
        maybe_write_checkpoint_with_signing(audit, audit_checkpoint_path, config);
    }
}

fn maybe_write_checkpoint_with_signing(
    audit: &AuditLogger,
    audit_checkpoint_path: Option<&Path>,
    config: &ProxyConfig,
) {
    let Some(path) = audit_checkpoint_path else {
        return;
    };
    let Ok(cp) = audit.checkpoint() else {
        return;
    };
    if let Some(key) = &config.audit_signing_key {
        let Ok(signed) = sign_checkpoint(&cp, key) else {
            return;
        };
        let _ = write_signed_checkpoint_atomic(path, &signed);
    } else {
        let _ = write_checkpoint(path, &cp);
    }
}

fn sample_for_audit(value: &Value, config: &ProxyConfig) -> Option<Value> {
    if config.audit_sample_bytes == 0 {
        return None;
    }
    let redacted = config.redactor.redact_json(value);
    let mut s = serde_json::to_string(&redacted).ok()?;
    if s.len() > config.audit_sample_bytes {
        s.truncate(config.audit_sample_bytes);
        s.push_str("...");
    }
    Some(Value::String(s))
}

fn sample_error_data(resp: &Value, config: &ProxyConfig) -> Option<Value> {
    let data = resp.get("error").and_then(|e| e.get("data"))?;
    sample_for_audit(data, config)
}

fn invalid_request(id: Value, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32600,
            "message": message
        }
    })
}

pub fn strip_reserved_metadata(request: &mut Value) -> Result<Option<String>> {
    let params = request
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("missing params for tools/call"))?;

    let args = params
        .entry("arguments")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow!("arguments must be object"))?;

    let approval_token = args
        .get(RESERVED_ARG_NS)
        .and_then(Value::as_object)
        .and_then(|meta| meta.get("approvalToken"))
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    args.remove(RESERVED_ARG_NS);
    Ok(approval_token)
}

fn create_approval_request(store_path: &Path, digest: &str) -> Result<String> {
    with_store_lock(store_path, || {
        let mut store = ApprovalStore::load_or_init_nolock(store_path)?;
        let rand_tail: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();
        let approval_request_id = format!("apr_{rand_tail}");
        store.requests.insert(
            approval_request_id.clone(),
            ApprovalRecord {
                request_digest: digest.to_string(),
                created_at: None,
            },
        );
        store.save_nolock(store_path)?;
        Ok(approval_request_id)
    })
}

fn verify_token(store_path: &Path, token: &str, digest: &str) -> Result<bool> {
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return Ok(false);
    }
    let approval_request_id = parts[1];
    let mac_bytes = match URL_SAFE_NO_PAD.decode(parts[2].as_bytes()) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };

    with_store_lock(store_path, || {
        let store = ApprovalStore::load_or_init_nolock(store_path)?;
        let Some(rec) = store.requests.get(approval_request_id) else {
            return Ok(false);
        };
        if rec.request_digest != digest {
            return Ok(false);
        }

        let secret = store.secret()?;
        let expected = compute_mac(&secret, approval_request_id, &rec.request_digest)?;
        Ok(constant_time_eq(&expected, &mac_bytes))
    })
}

fn compute_mac(secret: &[u8], approval_request_id: &str, digest: &str) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(secret).context("hmac init")?;
    mac.update(approval_request_id.as_bytes());
    mac.update(digest.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut x = 0u8;
    for (aa, bb) in a.iter().zip(b.iter()) {
        x |= aa ^ bb;
    }
    x == 0
}

fn request_digest(method: &str, params: &Value) -> Result<String> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing tool name"))?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let canonical = canonicalize(&json!({
        "method": method,
        "name": name,
        "arguments": args,
    }));
    let s = serde_json::to_string(&canonical).context("serialize canonical request")?;
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let out = hasher.finalize();
    Ok(to_hex(&out))
}

fn canonicalize(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, val) in map {
                sorted.insert(k.clone(), canonicalize(val));
            }
            let mut out = Map::new();
            for (k, val) in sorted {
                out.insert(k, val);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        _ => v.clone(),
    }
}

fn parse_id(v: &Value) -> Option<Id> {
    match v {
        Value::Number(n) => n.as_i64().map(Id::Number),
        Value::String(s) => Some(Id::String(s.clone())),
        _ => None,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn single_key_keyring(key: &SigningKeyFile) -> Result<AuthKeyringV1> {
    let mut ring = empty_keyring(now_ms());
    add_key(
        &mut ring,
        key.key_id.clone(),
        key.public_key_b64.clone(),
        Some("wrapped from --auth-pubkey".to_string()),
        now_ms(),
    )?;
    Ok(ring)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("invalid hex length")
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16).context("decode hex")?;
        out.push(b);
    }
    Ok(out)
}

fn file_stem_safe(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("approval_store")
        .replace(['/', '\\', ':'], "_")
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
    for _ in 0..STORE_LOCK_RETRIES {
        match OpenOptions::new().create_new(true).write(true).open(&lock) {
            Ok(_) => return Ok(LockGuard { path: lock }),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                thread::sleep(Duration::from_millis(STORE_LOCK_SLEEP_MS));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("create lock file {}", lock.display()))
            }
        }
    }
    Err(anyhow!("timed out acquiring approval store lock"))
}

fn with_store_lock<T, F>(path: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let _guard = acquire_lock(path)?;
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_error_messages_are_bounded() {
        let schema = json!({
            "type": "object",
            "required": ["a", "b", "c", "d", "e", "f"],
            "additionalProperties": false
        });
        let args = json!({ "unexpected": true });
        let validator = JSONSchema::compile(&schema).unwrap();
        let errs = match validator.validate(&args) {
            Ok(_) => Vec::new(),
            Err(errs) => bounded_validation_errors(errs, &Redactor::new_default()),
        };
        assert!(!errs.is_empty());
        assert!(errs.len() <= MAX_VALIDATION_ERRORS);
        assert!(errs.iter().all(|e| e.len() <= MAX_VALIDATION_MSG_LEN + 3));
    }
}
