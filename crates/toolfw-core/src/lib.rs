use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, BufWriter};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use mcp_wire::{error, read_json_line_streaming, Id};
use policy_engine::{evaluate, parse_policy, Decision, Policy};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const TOOLFW_DENIED: i64 = -32040;
pub const TOOLFW_APPROVAL_REQUIRED: i64 = -32041;
const RESERVED_ARG_NS: &str = "__toolfw";

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
    fn load_or_init(path: &Path) -> Result<Self> {
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
        s.save(path)?;
        Ok(s)
    }

    fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(self).context("serialize approval store")?;
        fs::write(&tmp, bytes).with_context(|| format!("write tmp store {}", tmp.display()))?;
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

pub fn issue_approval_token(store_path: &Path, approval_request_id: &str) -> Result<String> {
    let store = ApprovalStore::load_or_init(store_path)?;
    let rec = store
        .requests
        .get(approval_request_id)
        .ok_or_else(|| anyhow!("unknown approval_request_id"))?;
    let secret = store.secret()?;
    let mac = compute_mac(&secret, approval_request_id, &rec.request_digest)?;
    let mac_b64 = URL_SAFE_NO_PAD.encode(mac);
    Ok(format!("v1:{approval_request_id}:{mac_b64}"))
}

pub fn run_proxy_stdio(
    policy_path: &Path,
    approval_store_path: &Path,
    upstream_cmd: &[String],
) -> Result<()> {
    if upstream_cmd.is_empty() {
        bail!("upstream command is required");
    }

    let policy = {
        let txt = fs::read_to_string(policy_path)
            .with_context(|| format!("read policy file {}", policy_path.display()))?;
        parse_policy(&txt)?
    };

    let mut child = Command::new(&upstream_cmd[0])
        .args(&upstream_cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
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

    while let Some(client_msg) = read_json_line_streaming(&mut stdin, &mut client_partial)? {
        if let Some(resp) = process_client_message(
            &policy,
            approval_store_path,
            &mut child_in,
            &mut child_out,
            &mut upstream_partial,
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

fn process_client_message(
    policy: &Policy,
    approval_store_path: &Path,
    child_in: &mut std::process::ChildStdin,
    child_out: &mut std::process::ChildStdout,
    upstream_partial: &mut Vec<u8>,
    client_msg: Value,
) -> Result<Option<Value>> {
    match client_msg {
        Value::Array(batch) => {
            let mut responses = Vec::new();
            for item in batch {
                if !item.is_object() {
                    responses.push(invalid_request(Value::Null, "Invalid Request"));
                    continue;
                }
                if let Some(resp) = process_single_message(
                    policy,
                    approval_store_path,
                    child_in,
                    child_out,
                    upstream_partial,
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
            &client_msg,
        ),
        _ => Ok(Some(invalid_request(Value::Null, "Invalid Request"))),
    }
}

fn process_single_message(
    policy: &Policy,
    approval_store_path: &Path,
    child_in: &mut std::process::ChildStdin,
    child_out: &mut std::process::ChildStdout,
    upstream_partial: &mut Vec<u8>,
    request: &Value,
) -> Result<Option<Value>> {
    match evaluate_request(policy, approval_store_path, request)? {
        ProxyAction::Respond(resp) => Ok(Some(resp)),
        ProxyAction::Forward(forward_msg) => {
            mcp_wire::write_json_line(child_in, &forward_msg)?;
            if forward_msg.get("id").is_some() {
                let upstream_resp = read_json_line_streaming(child_out, upstream_partial)?
                    .ok_or_else(|| anyhow!("upstream closed while awaiting response"))?;
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
) -> Result<ProxyAction> {
    if !request.is_object() {
        return Ok(ProxyAction::Respond(invalid_request(
            Value::Null,
            "Invalid Request",
        )));
    }

    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if method != "tools/call" {
        return Ok(ProxyAction::Forward(request.clone()));
    }

    let id = request.get("id").and_then(parse_id);
    let Some(id) = id else {
        let mut stripped = request.clone();
        let _ = strip_reserved_metadata(&mut stripped)?;
        return Ok(ProxyAction::Forward(stripped));
    };

    let mut stripped = request.clone();
    let approval_token = strip_reserved_metadata(&mut stripped)?;

    let params = stripped
        .get("params")
        .cloned()
        .unwrap_or_else(|| json!({ "name": "", "arguments": {} }));
    let decision = evaluate(policy, method, &params);

    match decision {
        Decision::Allow => Ok(ProxyAction::Forward(stripped)),
        Decision::Deny => Ok(ProxyAction::Respond(error(
            id,
            TOOLFW_DENIED,
            "Denied by policy",
            None,
        ))),
        Decision::RequireApproval => {
            let digest = request_digest(method, &params)?;
            if let Some(token) = approval_token {
                if verify_token(approval_store_path, &token, &digest)? {
                    return Ok(ProxyAction::Forward(stripped));
                }
            }

            let approval_request_id = create_approval_request(approval_store_path, &digest)?;
            Ok(ProxyAction::Respond(error(
                id,
                TOOLFW_APPROVAL_REQUIRED,
                "Approval required",
                Some(json!({ "approval_request_id": approval_request_id })),
            )))
        }
    }
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
    let mut store = ApprovalStore::load_or_init(store_path)?;
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
    store.save(store_path)?;
    Ok(approval_request_id)
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

    let store = ApprovalStore::load_or_init(store_path)?;
    let Some(rec) = store.requests.get(approval_request_id) else {
        return Ok(false);
    };
    if rec.request_digest != digest {
        return Ok(false);
    }

    let secret = store.secret()?;
    let expected = compute_mac(&secret, approval_request_id, &rec.request_digest)?;
    Ok(constant_time_eq(&expected, &mac_bytes))
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
