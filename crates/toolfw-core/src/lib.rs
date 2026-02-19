use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use audit_log::{digest_and_size, write_checkpoint, AuditEvent, AuditLogger, Direction};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use jsonschema::JSONSchema;
use mcp_wire::{error, read_json_line_streaming, Id};
use policy_engine::{evaluate, parse_policy, Decision, Policy};
use rand::{distributions::Alphanumeric, Rng};
use redaction::Redactor;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const TOOLFW_DENIED: i64 = -32040;
pub const TOOLFW_APPROVAL_REQUIRED: i64 = -32041;
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

pub fn run_proxy_stdio(
    policy_path: &Path,
    approval_store_path: &Path,
    audit_path: Option<&Path>,
    audit_checkpoint_path: Option<&Path>,
    redact_path: Option<&Path>,
    audit_payload_sample_bytes: usize,
    upstream_cmd: &[String],
) -> Result<()> {
    if upstream_cmd.is_empty() {
        bail!("upstream command is required");
    }
    if audit_checkpoint_path.is_some() && audit_path.is_none() {
        bail!("--audit-checkpoint requires --audit");
    }

    let policy = {
        let txt = fs::read_to_string(policy_path)
            .with_context(|| format!("read policy file {}", policy_path.display()))?;
        parse_policy(&txt)?
    };

    let config = ProxyConfig {
        redactor: if let Some(path) = redact_path {
            Redactor::from_yaml(path)?
        } else {
            Redactor::new_default()
        },
        audit_sample_bytes: audit_payload_sample_bytes,
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

    while let Some(client_msg) = read_json_line_streaming(&mut stdin, &mut client_partial)? {
        if let Some(resp) = process_client_message(
            &policy,
            approval_store_path,
            &mut child_in,
            &mut child_out,
            &mut upstream_partial,
            &mut schema_cache,
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
}

struct EvalOutcome {
    action: ProxyAction,
    meta: EvalMeta,
}

fn process_client_message(
    policy: &Policy,
    approval_store_path: &Path,
    child_in: &mut std::process::ChildStdin,
    child_out: &mut std::process::ChildStdout,
    upstream_partial: &mut Vec<u8>,
    schema_cache: &mut HashMap<String, Value>,
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
                        None,
                        None,
                        None,
                        None,
                        None,
                        -32600,
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
            audit,
            audit_checkpoint_path,
            config,
            &client_msg,
        ),
        _ => {
            log_local_error(
                audit,
                audit_checkpoint_path,
                None,
                None,
                None,
                None,
                None,
                -32600,
                None,
            );
            Ok(Some(invalid_request(Value::Null, "Invalid Request")))
        }
    }
}

fn process_single_message(
    policy: &Policy,
    approval_store_path: &Path,
    child_in: &mut std::process::ChildStdin,
    child_out: &mut std::process::ChildStdout,
    upstream_partial: &mut Vec<u8>,
    schema_cache: &mut HashMap<String, Value>,
    audit: Option<&AuditLogger>,
    audit_checkpoint_path: Option<&Path>,
    config: &ProxyConfig,
    request: &Value,
) -> Result<Option<Value>> {
    let outcome = evaluate_request(policy, approval_store_path, request, schema_cache, config)?;
    log_client_request(audit, audit_checkpoint_path, &outcome.meta);

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
                outcome.meta.id,
                outcome.meta.method,
                outcome.meta.tool,
                outcome.meta.decision,
                outcome.meta.args_digest,
                error_code,
                error_data_sample,
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
                    outcome.meta.id,
                    outcome.meta.method,
                    outcome.meta.tool,
                    outcome.meta.decision,
                    &upstream_resp,
                    config,
                );

                Ok(Some(upstream_resp))
            } else {
                Ok(None)
            }
        }
    }
}

fn evaluate_request(
    policy: &Policy,
    approval_store_path: &Path,
    request: &Value,
    schema_cache: &HashMap<String, Value>,
    config: &ProxyConfig,
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
            },
        });
    }

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

    let decision = evaluate(policy, &method, &params);

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
                },
            })
        }
        Decision::Deny => Ok(EvalOutcome {
            action: ProxyAction::Respond(error(id, TOOLFW_DENIED, "Denied by policy", None)),
            meta: EvalMeta {
                id: id_value,
                method: Some(method),
                tool: tool_name,
                decision: Some("deny".to_string()),
                args_digest,
                args_bytes,
                args_sample,
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
                    Some(json!({ "approval_request_id": approval_request_id })),
                )),
                meta: EvalMeta {
                    id: id_value,
                    method: Some(method),
                    tool: tool_name,
                    decision: Some("approval_required".to_string()),
                    args_digest,
                    args_bytes,
                    args_sample,
                },
            })
        }
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
    if audit.append(event).is_ok() {
        maybe_write_checkpoint(audit, audit_checkpoint_path);
    }
}

#[allow(clippy::too_many_arguments)]
fn log_local_error(
    audit: Option<&AuditLogger>,
    audit_checkpoint_path: Option<&Path>,
    id: Option<Value>,
    method: Option<String>,
    tool: Option<String>,
    decision: Option<String>,
    args_digest: Option<String>,
    error_code: i64,
    error_data_sample: Option<Value>,
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
    if audit.append(event).is_ok() {
        maybe_write_checkpoint(audit, audit_checkpoint_path);
    }
}

#[allow(clippy::too_many_arguments)]
fn log_upstream_response(
    audit: Option<&AuditLogger>,
    audit_checkpoint_path: Option<&Path>,
    id: Option<Value>,
    method: Option<String>,
    tool: Option<String>,
    decision: Option<String>,
    upstream_resp: &Value,
    config: &ProxyConfig,
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
        maybe_write_checkpoint(audit, audit_checkpoint_path);
    }
}

fn maybe_write_checkpoint(audit: &AuditLogger, audit_checkpoint_path: Option<&Path>) {
    let Some(path) = audit_checkpoint_path else {
        return;
    };
    if let Ok(cp) = audit.checkpoint() {
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

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
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
