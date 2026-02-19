use std::collections::HashMap;
use std::fs;
use std::io::{self, BufWriter};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use audit_log::load_signing_key;
use auth_keyring::{add_key, empty_keyring, load_keyring, with_keyring_lock, AuthKeyringV1};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use c2pa_inspector_core::{inspect_path, parse_trust_mode, InspectOptions, TrustMode};
use cap_token::verify_token_with_keyring as verify_capability_token;
use mcp_wire::{error, read_json_line_streaming, success, Id};
use rusqlite::types::ValueRef;
use rusqlite::OpenFlags;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlparser::ast::Statement;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub const GATEWAY_UNAUTHORIZED: i64 = -32060;
pub const GATEWAY_FORBIDDEN: i64 = -32061;
pub const GATEWAY_INVALID_PARAMS: i64 = -32602;

#[derive(Debug, Clone, Deserialize)]
pub struct MountsConfig {
    pub mounts: Vec<MountSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MountSpec {
    pub name: String,
    pub root: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ViewsConfig {
    pub views: Vec<ViewSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ViewSpec {
    pub name: String,
    pub tool: String,
    pub args: Value,
}

#[derive(Debug, Clone)]
struct Mount {
    root: PathBuf,
    read_only: bool,
}

#[derive(Debug, Clone, Copy)]
enum ResolvePurpose {
    Read,
    Write,
}

#[derive(Clone)]
struct AuthConfig {
    keyring: AuthKeyringV1,
}

pub fn run_stdio(
    mounts_path: &Path,
    views_path: &Path,
    auth_pubkey: Option<&Path>,
    auth_keys: Option<&Path>,
) -> Result<()> {
    if auth_pubkey.is_some() && auth_keys.is_some() {
        return Err(anyhow!(
            "--auth-pubkey and --auth-keys are mutually exclusive"
        ));
    }
    let mounts = load_mounts(mounts_path)?;
    let views = load_views(views_path)?;
    let auth = if let Some(path) = auth_keys {
        let ring = with_keyring_lock(path, || load_keyring(path))?;
        Some(AuthConfig { keyring: ring })
    } else if let Some(path) = auth_pubkey {
        let key = load_signing_key(path)?;
        Some(AuthConfig {
            keyring: keyring_from_signing_key(&key)?,
        })
    } else {
        None
    };

    let mut stdin = io::stdin().lock();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut partial = Vec::new();

    while let Some(msg) = read_json_line_streaming(&mut stdin, &mut partial)? {
        if let Some(resp) = handle_input(&mounts, &views, auth.as_ref(), msg) {
            mcp_wire::write_json_line(&mut out, &resp)?;
        }
    }

    Ok(())
}

fn load_mounts(path: &Path) -> Result<HashMap<String, Mount>> {
    let txt =
        fs::read_to_string(path).with_context(|| format!("read mounts file {}", path.display()))?;
    let cfg: MountsConfig = serde_yaml::from_str(&txt).context("parse mounts yaml")?;
    let mut out = HashMap::new();
    for m in cfg.mounts {
        let root = PathBuf::from(&m.root);
        fs::create_dir_all(&root)
            .with_context(|| format!("create mount root {}", root.display()))?;
        let canonical = root
            .canonicalize()
            .with_context(|| format!("canonicalize mount root {}", root.display()))?;
        out.insert(
            m.name,
            Mount {
                root: canonical,
                read_only: m.read_only,
            },
        );
    }
    Ok(out)
}

fn load_views(path: &Path) -> Result<HashMap<String, ViewSpec>> {
    let txt =
        fs::read_to_string(path).with_context(|| format!("read views file {}", path.display()))?;
    let cfg: ViewsConfig = serde_yaml::from_str(&txt).context("parse views yaml")?;
    let mut out = HashMap::new();
    for v in cfg.views {
        out.insert(v.name.clone(), v);
    }
    Ok(out)
}

fn handle_input(
    mounts: &HashMap<String, Mount>,
    views: &HashMap<String, ViewSpec>,
    auth: Option<&AuthConfig>,
    msg: Value,
) -> Option<Value> {
    match msg {
        Value::Array(batch) => {
            let mut responses = Vec::new();
            for item in batch {
                if !item.is_object() {
                    responses.push(invalid_request(Value::Null, "Invalid Request"));
                    continue;
                }
                if let Some(resp) = handle_message(mounts, views, auth, item) {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                None
            } else {
                Some(Value::Array(responses))
            }
        }
        Value::Object(_) => handle_message(mounts, views, auth, msg),
        _ => Some(invalid_request(Value::Null, "Invalid Request")),
    }
}

fn handle_message(
    mounts: &HashMap<String, Mount>,
    views: &HashMap<String, ViewSpec>,
    auth: Option<&AuthConfig>,
    msg: Value,
) -> Option<Value> {
    let method = msg.get("method")?.as_str()?.to_string();
    let id = msg.get("id").and_then(parse_id);

    match method.as_str() {
        "notifications/initialized" => None,
        "initialize" => {
            let id = id?;
            Some(success(
                id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": "mcp-gateway",
                        "version": "0.1.0"
                    },
                    "capabilities": {}
                }),
            ))
        }
        "tools/list" => {
            let id = id?;
            Some(success(
                id,
                json!({
                    "tools": [
                        {"name": "files.read"},
                        {"name": "files.search"},
                        {"name": "files.write"},
                        {"name": "views.query"},
                        {"name": "sqlite.query"},
                        {
                            "name": "git.status",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "mount": {"type": "string"},
                                    "repo": {"type": "string"},
                                    "porcelain": {"type": "boolean"},
                                    "include_untracked": {"type": "boolean"},
                                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
                                    "max_lines": {"type": "integer", "minimum": 1, "maximum": 20_000}
                                },
                                "required": ["mount", "repo"],
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "git.log",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "mount": {"type": "string"},
                                    "repo": {"type": "string"},
                                    "max_commits": {"type": "integer", "minimum": 1, "maximum": 200},
                                    "ref": {"type": "string"},
                                    "path": {"type": "string"},
                                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
                                    "max_lines": {"type": "integer", "minimum": 1, "maximum": 20_000}
                                },
                                "required": ["mount", "repo"],
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "git.diff",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "mount": {"type": "string"},
                                    "repo": {"type": "string"},
                                    "base": {"type": "string"},
                                    "head": {"type": "string"},
                                    "path": {"type": "string"},
                                    "staged": {"type": "boolean"},
                                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
                                    "max_lines": {"type": "integer", "minimum": 1, "maximum": 20_000}
                                },
                                "required": ["mount", "repo"],
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "git.show",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "mount": {"type": "string"},
                                    "repo": {"type": "string"},
                                    "object": {"type": "string"},
                                    "patch": {"type": "boolean"},
                                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
                                    "max_lines": {"type": "integer", "minimum": 1, "maximum": 20_000}
                                },
                                "required": ["mount", "repo", "object"],
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "git.grep",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "mount": {"type": "string"},
                                    "repo": {"type": "string"},
                                    "query": {"type": "string"},
                                    "path": {"type": "string"},
                                    "ignore_case": {"type": "boolean"},
                                    "max_matches": {"type": "integer", "minimum": 1, "maximum": 1000},
                                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1_000_000},
                                    "max_lines": {"type": "integer", "minimum": 1, "maximum": 20_000}
                                },
                                "required": ["mount", "repo", "query"],
                                "additionalProperties": false
                            }
                        },
                        {
                            "name": "c2pa.inspect",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "mount": {"type": "string"},
                                    "path": {"type": "string"},
                                    "trust": {"type": "string", "enum": ["off", "default"]}
                                },
                                "required": ["mount", "path"],
                                "additionalProperties": false
                            }
                        }
                    ]
                }),
            ))
        }
        "tools/call" => {
            let id = id?;
            let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
            if let Some(auth) = auth {
                match authorize_tools_call(&params, auth) {
                    Ok(()) => {}
                    Err(AuthzError::Unauthorized) => {
                        return Some(error(id, GATEWAY_UNAUTHORIZED, "Unauthorized", None));
                    }
                    Err(AuthzError::Forbidden) => {
                        return Some(error(id, GATEWAY_FORBIDDEN, "Forbidden", None));
                    }
                }
            }
            match call_tool(mounts, views, &params) {
                Ok(result) => Some(success(id, result)),
                Err(ToolCallError::InvalidParams(e)) => Some(error(
                    id,
                    GATEWAY_INVALID_PARAMS,
                    "Invalid params",
                    Some(json!({"error": truncate_text(&e.to_string(), 200)})),
                )),
                Err(ToolCallError::Operational(e)) => Some(error(id, -32000, &e.to_string(), None)),
            }
        }
        _ => {
            let id = id?;
            Some(error(id, -32601, "Method not found", None))
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

fn parse_id(v: &Value) -> Option<Id> {
    match v {
        Value::Number(n) => n.as_i64().map(Id::Number),
        Value::String(s) => Some(Id::String(s.clone())),
        _ => None,
    }
}

enum ToolCallError {
    InvalidParams(anyhow::Error),
    Operational(anyhow::Error),
}

impl From<anyhow::Error> for ToolCallError {
    fn from(value: anyhow::Error) -> Self {
        Self::Operational(value)
    }
}

fn invalid_params(msg: impl Into<String>) -> ToolCallError {
    ToolCallError::InvalidParams(anyhow!(msg.into()))
}

fn call_tool(
    mounts: &HashMap<String, Mount>,
    views: &HashMap<String, ViewSpec>,
    params: &Value,
) -> std::result::Result<Value, ToolCallError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params("missing tool name"))?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "files.read" => files_read(mounts, &args).map_err(ToolCallError::Operational),
        "files.write" => files_write(mounts, &args).map_err(ToolCallError::Operational),
        "files.search" => files_search(mounts, &args).map_err(ToolCallError::Operational),
        "sqlite.query" => sqlite_query(mounts, &args).map_err(ToolCallError::Operational),
        "c2pa.inspect" => c2pa_inspect(mounts, &args).map_err(ToolCallError::Operational),
        "git.status" => git_status(mounts, &args),
        "git.log" => git_log(mounts, &args),
        "git.diff" => git_diff(mounts, &args),
        "git.show" => git_show(mounts, &args),
        "git.grep" => git_grep(mounts, &args),
        "views.query" => views_query(mounts, views, &args).map_err(ToolCallError::Operational),
        _ => Err(ToolCallError::Operational(anyhow!("unknown tool"))),
    }
}

enum AuthzError {
    Unauthorized,
    Forbidden,
}

fn authorize_tools_call(params: &Value, auth: &AuthConfig) -> std::result::Result<(), AuthzError> {
    let token = params
        .get("auth")
        .and_then(|a| a.get("token"))
        .and_then(Value::as_str)
        .ok_or(AuthzError::Unauthorized)?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let payload = verify_capability_token(token, &auth.keyring, now_ms)
        .map_err(|_| AuthzError::Unauthorized)?;

    let tool = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or(AuthzError::Unauthorized)?;
    if !payload.allow.tools.iter().any(|t| t == tool) {
        return Err(AuthzError::Forbidden);
    }

    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if tool == "views.query" && !payload.allow.views.is_empty() {
        let view = args
            .get("view")
            .and_then(Value::as_str)
            .ok_or(AuthzError::Forbidden)?;
        if !payload.allow.views.iter().any(|v| v == view) {
            return Err(AuthzError::Forbidden);
        }
    }

    let needs_mount_scope = matches!(
        tool,
        "files.read"
            | "files.write"
            | "files.search"
            | "sqlite.query"
            | "git.status"
            | "git.log"
            | "git.diff"
            | "git.show"
            | "git.grep"
    );
    if needs_mount_scope && !payload.allow.mounts.is_empty() {
        let mount = args
            .get("mount")
            .and_then(Value::as_str)
            .ok_or(AuthzError::Forbidden)?;
        if !payload.allow.mounts.iter().any(|m| m == mount) {
            return Err(AuthzError::Forbidden);
        }
    }

    Ok(())
}

fn keyring_from_signing_key(key: &audit_log::SigningKeyFile) -> Result<AuthKeyringV1> {
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn mount_and_path<'a>(
    mounts: &'a HashMap<String, Mount>,
    args: &Value,
) -> Result<(&'a Mount, String)> {
    let mount_name = args
        .get("mount")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing mount"))?;
    let rel = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing path"))?
        .to_string();
    let mount = mounts
        .get(mount_name)
        .ok_or_else(|| anyhow!("unknown mount {mount_name}"))?;
    Ok((mount, rel))
}

fn ensure_under_root(root: &Path, candidate: &Path) -> Result<()> {
    if !candidate.starts_with(root) {
        return Err(anyhow!("path escapes mount root"));
    }
    Ok(())
}

fn normalize_rel_segments(rel: &str) -> Result<Vec<String>> {
    let normalized = rel.replace('\\', "/");
    let path = Path::new(&normalized);
    if path.is_absolute() {
        return Err(anyhow!("absolute paths are not allowed"));
    }
    let mut out = Vec::new();
    for comp in path.components() {
        match comp {
            Component::Normal(s) => out.push(s.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir => return Err(anyhow!("parent segments are not allowed")),
            Component::RootDir | Component::Prefix(_) => {
                return Err(anyhow!("absolute paths are not allowed"))
            }
        }
    }
    if out.is_empty() {
        return Err(anyhow!("empty relative path is not allowed"));
    }
    Ok(out)
}

fn resolve_mount_path(root: &Path, rel: &str, purpose: ResolvePurpose) -> Result<PathBuf> {
    let segments = normalize_rel_segments(rel)?;
    let mut cursor = root.to_path_buf();

    for (idx, seg) in segments.iter().enumerate() {
        let is_last = idx + 1 == segments.len();
        let candidate = cursor.join(seg);

        match fs::symlink_metadata(&candidate) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(anyhow!("symlinks are not allowed in mount paths"));
                }
                if !is_last && !meta.is_dir() {
                    return Err(anyhow!("path component is not a directory"));
                }
                if !is_last {
                    cursor = candidate;
                    continue;
                }

                let canonical = candidate
                    .canonicalize()
                    .with_context(|| format!("canonicalize {}", candidate.display()))?;
                ensure_under_root(root, &canonical)?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match purpose {
                ResolvePurpose::Read => {
                    return Err(anyhow!("path does not exist"));
                }
                ResolvePurpose::Write => {
                    if !is_last {
                        fs::create_dir(&candidate).with_context(|| {
                            format!("create directory segment {}", candidate.display())
                        })?;
                        cursor = candidate;
                        continue;
                    }
                    ensure_under_root(root, &candidate)?;
                    return Ok(candidate);
                }
            },
            Err(e) => return Err(e).with_context(|| format!("stat {}", candidate.display())),
        }
    }

    Err(anyhow!("failed to resolve path"))
}

fn files_read(mounts: &HashMap<String, Mount>, args: &Value) -> Result<Value> {
    let (mount, rel) = mount_and_path(mounts, args)?;
    let path = resolve_mount_path(&mount.root, &rel, ResolvePurpose::Read)?;
    let content =
        fs::read_to_string(&path).with_context(|| format!("read file {}", path.display()))?;
    Ok(json!({ "content": content }))
}

fn files_write(mounts: &HashMap<String, Mount>, args: &Value) -> Result<Value> {
    let (mount, rel) = mount_and_path(mounts, args)?;
    if mount.read_only {
        return Err(anyhow!("mount is read_only"));
    }
    let content = args
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing content"))?;
    let dst = resolve_mount_path(&mount.root, &rel, ResolvePurpose::Write)?;
    fs::write(&dst, content).with_context(|| format!("write file {}", dst.display()))?;
    Ok(json!({ "ok": true, "bytes_written": content.len() }))
}

fn files_search(mounts: &HashMap<String, Mount>, args: &Value) -> Result<Value> {
    let mount_name = args
        .get("mount")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing mount"))?;
    let mount = mounts
        .get(mount_name)
        .ok_or_else(|| anyhow!("unknown mount {mount_name}"))?;
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing query"))?;
    let max_results = args
        .get("max_results")
        .and_then(Value::as_u64)
        .unwrap_or(10) as usize;
    let max_bytes = args
        .get("max_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(20_000) as usize;

    let mut pending = vec![mount.root.clone()];
    let mut results = Vec::new();
    let mut used_bytes = 0usize;
    let mut truncated = false;

    while let Some(dir) = pending.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in rd {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let p = entry.path();
            let meta = match fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if p.is_dir() {
                pending.push(p);
                continue;
            }
            if !p.is_file() {
                continue;
            }
            let content = match fs::read_to_string(&p) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let Some(idx) = content.find(query) else {
                continue;
            };

            let start = idx.saturating_sub(20);
            let end = (idx + query.len() + 20).min(content.len());
            let snippet = content[start..end].to_string();
            let rel = p
                .strip_prefix(&mount.root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");

            let add = rel.len() + snippet.len();
            if used_bytes + add > max_bytes {
                truncated = true;
                break;
            }

            results.push(json!({ "path": rel, "snippet": snippet }));
            used_bytes += add;

            if results.len() >= max_results {
                truncated = true;
                break;
            }
        }
        if truncated {
            break;
        }
    }

    Ok(json!({ "results": results, "truncated": truncated }))
}

#[derive(Debug, Clone)]
struct OutputCaps {
    max_bytes: usize,
    max_lines: usize,
    max_entries: usize,
}

#[derive(Debug, Clone)]
struct GitContext {
    repo_root: PathBuf,
    repo_root_display: String,
}

#[derive(Debug, Clone)]
struct BoundedText {
    text: String,
    truncated: bool,
    reason: Option<String>,
}

#[derive(Debug, Clone)]
struct GitExecResult {
    stdout: String,
    stderr: String,
    exit_code: i32,
    truncated: bool,
    truncated_reason: Option<String>,
}

fn parse_output_caps(args: &Value) -> std::result::Result<OutputCaps, ToolCallError> {
    let max_bytes = args
        .get("max_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(200_000) as usize;
    let max_lines = args
        .get("max_lines")
        .and_then(Value::as_u64)
        .unwrap_or(5_000) as usize;
    if max_bytes == 0 || max_lines == 0 {
        return Err(invalid_params("max_bytes/max_lines must be > 0"));
    }
    Ok(OutputCaps {
        max_bytes: max_bytes.min(1_000_000),
        max_lines: max_lines.min(20_000),
        max_entries: 200,
    })
}

fn validate_safe_ref(s: &str) -> bool {
    if s.is_empty() || s.starts_with('-') || s.contains("..") || s.contains("@{") {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '/' || c == '-')
}

fn validate_rel_path(s: &str) -> bool {
    if s.is_empty() || s.contains('\0') {
        return false;
    }
    let normalized = s.replace('\\', "/");
    if normalized.starts_with('/') || normalized.starts_with('\\') {
        return false;
    }
    let p = Path::new(&normalized);
    if p.is_absolute() {
        return false;
    }
    !p.components().any(|c| matches!(c, Component::ParentDir))
}

fn arg_str<'a>(
    args: &'a Value,
    key: &str,
    required: bool,
) -> std::result::Result<Option<&'a str>, ToolCallError> {
    match args.get(key) {
        Some(v) => v
            .as_str()
            .map(Some)
            .ok_or_else(|| invalid_params(format!("{key} must be a string"))),
        None if required => Err(invalid_params(format!("missing {key}"))),
        None => Ok(None),
    }
}

fn mount_from_args<'a>(
    mounts: &'a HashMap<String, Mount>,
    args: &Value,
) -> std::result::Result<&'a Mount, ToolCallError> {
    let mount_name = arg_str(args, "mount", true)?.expect("required");
    mounts
        .get(mount_name)
        .ok_or_else(|| invalid_params(format!("unknown mount {mount_name}")))
}

fn resolve_git_context(
    mounts: &HashMap<String, Mount>,
    args: &Value,
) -> std::result::Result<GitContext, ToolCallError> {
    let mount = mount_from_args(mounts, args)?;
    let repo = arg_str(args, "repo", true)?.expect("required");
    if !validate_rel_path(repo) {
        return Err(invalid_params("repo must be a safe relative path"));
    }

    let start = if repo == "." {
        mount.root.clone()
    } else {
        resolve_mount_path(&mount.root, repo, ResolvePurpose::Read)
            .map_err(ToolCallError::Operational)?
    };
    let start_str = start.to_string_lossy().to_string();
    let out = run_git_raw(
        &start,
        &["rev-parse", "--show-toplevel"],
        &OutputCaps {
            max_bytes: 20_000,
            max_lines: 200,
            max_entries: 200,
        },
    )?;
    if out.exit_code != 0 {
        return Err(ToolCallError::Operational(anyhow!(
            "not a git repository: {}",
            truncate_text(&out.stderr, 200)
        )));
    }
    let top = out.stdout.trim();
    if top.is_empty() {
        return Err(ToolCallError::Operational(anyhow!(
            "failed to resolve git repo root from {}",
            start_str
        )));
    }
    let top_path = PathBuf::from(top)
        .canonicalize()
        .with_context(|| format!("canonicalize git repo root {top}"))
        .map_err(ToolCallError::Operational)?;
    if !top_path.starts_with(&mount.root) {
        return Err(ToolCallError::Operational(anyhow!(
            "git repo root escapes mount root"
        )));
    }
    let display = top_path
        .strip_prefix(&mount.root)
        .ok()
        .map(|p| {
            let s = p.to_string_lossy().replace('\\', "/");
            if s.is_empty() {
                ".".to_string()
            } else {
                s
            }
        })
        .unwrap_or_else(|| top_path.to_string_lossy().to_string());
    Ok(GitContext {
        repo_root: top_path,
        repo_root_display: display,
    })
}

fn run_git_raw(
    repo_root: &Path,
    args: &[&str],
    caps: &OutputCaps,
) -> std::result::Result<GitExecResult, ToolCallError> {
    let mut cmd = Command::new("git");
    cmd.arg("--no-pager")
        .arg("-c")
        .arg("core.pager=cat")
        .arg("-c")
        .arg("color.ui=false")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("GIT_PAGER", "cat")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_EXEC_PATH")
        .env_remove("GIT_CONFIG")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_SYSTEM")
        .env_remove("GIT_SSH_COMMAND")
        .env_remove("SSH_ASKPASS");

    let output = cmd
        .output()
        .with_context(|| format!("run git in {}", repo_root.display()))
        .map_err(ToolCallError::Operational)?;
    let out = bounded_text(
        &output.stdout,
        caps.max_bytes,
        caps.max_lines,
        caps.max_entries,
    );
    let err = bounded_text(
        &output.stderr,
        (caps.max_bytes / 2).max(1),
        (caps.max_lines / 2).max(1),
        caps.max_entries,
    );
    let mut truncated = out.truncated || err.truncated;
    let mut truncated_reason = out.reason.or(err.reason);
    if truncated_reason.is_none() && truncated {
        truncated_reason = Some("truncated".to_string());
    }
    if !output.status.success() && truncated_reason.is_none() {
        truncated = false;
    }
    Ok(GitExecResult {
        stdout: out.text,
        stderr: err.text,
        exit_code: output.status.code().unwrap_or(-1),
        truncated,
        truncated_reason,
    })
}

fn bounded_text(
    input: &[u8],
    max_bytes: usize,
    max_lines: usize,
    max_entries: usize,
) -> BoundedText {
    let s = String::from_utf8_lossy(input);
    let mut out = String::new();
    let mut truncated = false;
    let mut reason = None;
    for (idx, line) in s.lines().enumerate() {
        if idx >= max_lines {
            truncated = true;
            reason = Some("max_lines".to_string());
            break;
        }
        if idx >= max_entries {
            truncated = true;
            reason = Some("max_entries".to_string());
            break;
        }
        let next_len = out.len() + line.len() + 1;
        if next_len > max_bytes {
            truncated = true;
            reason = Some("max_bytes".to_string());
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    if s.len() > max_bytes && reason.is_none() {
        truncated = true;
        reason = Some("max_bytes".to_string());
    }
    BoundedText {
        text: out,
        truncated,
        reason,
    }
}

fn truncate_text(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    format!("{}...", &s[..max_len])
}

fn git_response(tool: &str, ctx: &GitContext, out: GitExecResult) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("ok".to_string(), Value::Bool(out.exit_code == 0));
    obj.insert("tool".to_string(), Value::String(tool.to_string()));
    obj.insert(
        "repo_root".to_string(),
        Value::String(ctx.repo_root_display.clone()),
    );
    obj.insert("stdout".to_string(), Value::String(out.stdout));
    obj.insert("stderr".to_string(), Value::String(out.stderr));
    obj.insert("exit_code".to_string(), json!(out.exit_code));
    obj.insert("truncated".to_string(), Value::Bool(out.truncated));
    if let Some(r) = out.truncated_reason {
        obj.insert("truncated_reason".to_string(), Value::String(r));
    }
    Value::Object(obj)
}

fn git_status(
    mounts: &HashMap<String, Mount>,
    args: &Value,
) -> std::result::Result<Value, ToolCallError> {
    let ctx = resolve_git_context(mounts, args)?;
    let caps = parse_output_caps(args)?;
    let porcelain = args
        .get("porcelain")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let include_untracked = args
        .get("include_untracked")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut argv = vec!["status"];
    if porcelain {
        argv.push("--porcelain=v1");
    }
    if !include_untracked {
        argv.push("--untracked-files=no");
    }
    let out = run_git_raw(&ctx.repo_root, &argv, &caps)?;
    Ok(git_response("git.status", &ctx, out))
}

fn git_log(
    mounts: &HashMap<String, Mount>,
    args: &Value,
) -> std::result::Result<Value, ToolCallError> {
    let ctx = resolve_git_context(mounts, args)?;
    let caps = parse_output_caps(args)?;
    let max_commits = args
        .get("max_commits")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .min(200);

    let mut owned: Vec<String> = vec![
        "log".to_string(),
        format!("--max-count={max_commits}"),
        "--date=iso-strict".to_string(),
        "--pretty=format:%H %ad %an %s".to_string(),
    ];
    if let Some(r) = arg_str(args, "ref", false)? {
        if !validate_safe_ref(r) {
            return Err(invalid_params("invalid ref"));
        }
        owned.push(r.to_string());
    }
    if let Some(path) = arg_str(args, "path", false)? {
        if !validate_rel_path(path) {
            return Err(invalid_params("invalid path"));
        }
        owned.push("--".to_string());
        owned.push(path.replace('\\', "/"));
    }
    let argv = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let out = run_git_raw(&ctx.repo_root, &argv, &caps)?;
    Ok(git_response("git.log", &ctx, out))
}

fn git_diff(
    mounts: &HashMap<String, Mount>,
    args: &Value,
) -> std::result::Result<Value, ToolCallError> {
    let ctx = resolve_git_context(mounts, args)?;
    let caps = parse_output_caps(args)?;
    let staged = args.get("staged").and_then(Value::as_bool).unwrap_or(false);
    let base = arg_str(args, "base", false)?;
    let head = arg_str(args, "head", false)?;
    let path = arg_str(args, "path", false)?;
    if let Some(r) = base {
        if !validate_safe_ref(r) {
            return Err(invalid_params("invalid base ref"));
        }
    }
    if let Some(r) = head {
        if !validate_safe_ref(r) {
            return Err(invalid_params("invalid head ref"));
        }
    }
    if let Some(p) = path {
        if !validate_rel_path(p) {
            return Err(invalid_params("invalid path"));
        }
    }

    let mut owned = vec!["diff".to_string(), "--no-color".to_string()];
    if staged {
        owned.push("--cached".to_string());
    } else if let (Some(b), Some(h)) = (base, head) {
        owned.push(format!("{b}..{h}"));
    } else if base.is_some() || head.is_some() {
        return Err(invalid_params("base and head must be provided together"));
    }
    if let Some(p) = path {
        owned.push("--".to_string());
        owned.push(p.replace('\\', "/"));
    }
    let argv = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let out = run_git_raw(&ctx.repo_root, &argv, &caps)?;
    Ok(git_response("git.diff", &ctx, out))
}

fn git_show(
    mounts: &HashMap<String, Mount>,
    args: &Value,
) -> std::result::Result<Value, ToolCallError> {
    let ctx = resolve_git_context(mounts, args)?;
    let caps = parse_output_caps(args)?;
    let object = arg_str(args, "object", true)?.expect("required");
    if !validate_safe_ref(object) {
        return Err(invalid_params("invalid object"));
    }
    let patch = args.get("patch").and_then(Value::as_bool).unwrap_or(true);
    let mut owned = vec!["show".to_string(), "--no-color".to_string()];
    if patch {
        owned.push("--pretty=medium".to_string());
    } else {
        owned.push("--pretty=medium".to_string());
        owned.push("--stat".to_string());
        owned.push("--no-patch".to_string());
    }
    owned.push(object.to_string());
    let argv = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let out = run_git_raw(&ctx.repo_root, &argv, &caps)?;
    Ok(git_response("git.show", &ctx, out))
}

fn git_grep(
    mounts: &HashMap<String, Mount>,
    args: &Value,
) -> std::result::Result<Value, ToolCallError> {
    let ctx = resolve_git_context(mounts, args)?;
    let mut caps = parse_output_caps(args)?;
    let query = arg_str(args, "query", true)?.expect("required");
    let path = arg_str(args, "path", false)?;
    let ignore_case = args
        .get("ignore_case")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let max_matches = args
        .get("max_matches")
        .and_then(Value::as_u64)
        .unwrap_or(200)
        .min(1000) as usize;
    caps.max_entries = max_matches;
    if let Some(p) = path {
        if !validate_rel_path(p) {
            return Err(invalid_params("invalid path"));
        }
    }
    let mut owned = vec!["grep".to_string(), "-n".to_string()];
    if ignore_case {
        owned.push("-i".to_string());
    }
    owned.push(query.to_string());
    if let Some(p) = path {
        owned.push("--".to_string());
        owned.push(p.replace('\\', "/"));
    }
    let argv = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let out = run_git_raw(&ctx.repo_root, &argv, &caps)?;
    Ok(git_response("git.grep", &ctx, out))
}

fn tool_err_anyhow(e: ToolCallError) -> anyhow::Error {
    match e {
        ToolCallError::InvalidParams(e) | ToolCallError::Operational(e) => e,
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolve_rejects_absolute_path() {
        let t = tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let abs = root.join("x.txt").to_string_lossy().to_string();
        let r = resolve_mount_path(&root, &abs, ResolvePurpose::Read);
        assert!(r.is_err());
    }

    #[test]
    fn resolve_rejects_parent_segments() {
        let t = tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let r = resolve_mount_path(&root, "../escape.txt", ResolvePurpose::Read);
        assert!(r.is_err());
    }

    #[test]
    fn resolve_write_new_file_under_root_succeeds() {
        let t = tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let p = resolve_mount_path(&root, "a/b/new.txt", ResolvePurpose::Write).unwrap();
        assert!(p.starts_with(&root));
        assert!(p.ends_with(Path::new("new.txt")));
    }

    #[test]
    fn resolve_rejects_symlink_escape_read_and_write() {
        let t = tempdir().unwrap();
        let root = t.path().join("root");
        let outside = t.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let root = root.canonicalize().unwrap();
        let outside = outside.canonicalize().unwrap();
        let link = root.join("link");

        #[cfg(windows)]
        let symlink_ok = std::os::windows::fs::symlink_dir(&outside, &link).is_ok();
        #[cfg(not(windows))]
        let symlink_ok = std::os::unix::fs::symlink(&outside, &link).is_ok();
        if !symlink_ok {
            return;
        }

        let read = resolve_mount_path(&root, "link/file.txt", ResolvePurpose::Read);
        let write = resolve_mount_path(&root, "link/file.txt", ResolvePurpose::Write);
        assert!(read.is_err());
        assert!(write.is_err());
    }

    #[test]
    fn safe_ref_validation_works() {
        assert!(validate_safe_ref("main"));
        assert!(validate_safe_ref("feature/x-1.2"));
        assert!(validate_safe_ref("a1b2c3d4"));
        assert!(!validate_safe_ref("--help"));
        assert!(!validate_safe_ref("HEAD@{1}"));
        assert!(!validate_safe_ref("../evil"));
    }

    #[test]
    fn rel_path_validation_works() {
        assert!(validate_rel_path("src/lib.rs"));
        assert!(validate_rel_path("./"));
        assert!(!validate_rel_path("/abs/path"));
        assert!(!validate_rel_path("../escape"));
        assert!(!validate_rel_path("a/../../b"));
    }

    #[test]
    fn bounded_text_truncates_deterministically() {
        let bt = bounded_text("a\nb\nc\n".as_bytes(), 4, 10, 10);
        assert!(bt.truncated);
        assert_eq!(bt.reason.as_deref(), Some("max_bytes"));
        let bt2 = bounded_text("a\nb\nc\n".as_bytes(), 100, 2, 10);
        assert!(bt2.truncated);
        assert_eq!(bt2.reason.as_deref(), Some("max_lines"));
    }
}

fn views_query(
    mounts: &HashMap<String, Mount>,
    views: &HashMap<String, ViewSpec>,
    args: &Value,
) -> Result<Value> {
    let view_name = args
        .get("view")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing view"))?;
    let view = views
        .get(view_name)
        .ok_or_else(|| anyhow!("unknown view {view_name}"))?;
    let data = match view.tool.as_str() {
        "files.search" => files_search(mounts, &view.args)?,
        "files.read" => files_read(mounts, &view.args)?,
        "sqlite.query" => sqlite_query(mounts, &view.args)?,
        "c2pa.inspect" => c2pa_inspect(mounts, &view.args)?,
        "git.status" => git_status(mounts, &view.args).map_err(tool_err_anyhow)?,
        "git.log" => git_log(mounts, &view.args).map_err(tool_err_anyhow)?,
        "git.diff" => git_diff(mounts, &view.args).map_err(tool_err_anyhow)?,
        "git.show" => git_show(mounts, &view.args).map_err(tool_err_anyhow)?,
        "git.grep" => git_grep(mounts, &view.args).map_err(tool_err_anyhow)?,
        _ => return Err(anyhow!("unsupported view tool")),
    };
    Ok(json!({ "view": view_name, "data": data }))
}

fn c2pa_inspect(mounts: &HashMap<String, Mount>, args: &Value) -> Result<Value> {
    let (mount, rel) = mount_and_path(mounts, args)?;
    let asset_path = resolve_mount_path(&mount.root, &rel, ResolvePurpose::Read)?;
    let trust = args.get("trust").and_then(Value::as_str).unwrap_or("off");
    let trust = parse_trust_mode(trust)?;
    if matches!(trust, TrustMode::CustomPem { .. }) {
        return Err(anyhow!(
            "custom trust mode is not allowed for c2pa.inspect via MCP"
        ));
    }
    let opts = InspectOptions {
        trust,
        ..InspectOptions::default()
    };
    let report = inspect_path(&asset_path, &opts)?;
    serde_json::to_value(report).context("serialize c2pa report")
}

fn sqlite_query(mounts: &HashMap<String, Mount>, args: &Value) -> Result<Value> {
    const DEFAULT_MAX_ROWS: usize = 200;
    const DEFAULT_MAX_BYTES: usize = 200_000;
    const MAX_BLOB_BYTES: usize = 4096;

    let mount_name = args
        .get("mount")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing mount"))?;
    let rel = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing path"))?;
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing query"))?;
    let max_rows = args
        .get("max_rows")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_MAX_ROWS as u64) as usize;
    let max_bytes = args
        .get("max_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_MAX_BYTES as u64) as usize;

    let mount = mounts
        .get(mount_name)
        .ok_or_else(|| anyhow!("unknown mount {mount_name}"))?;
    let db_path = resolve_mount_path(&mount.root, rel, ResolvePurpose::Read)?;

    enforce_select_only(query)?;

    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open sqlite db {}", db_path.display()))?;

    let mut stmt = conn
        .prepare(query)
        .with_context(|| format!("prepare sqlite query in {}", db_path.display()))?;
    let columns = stmt
        .column_names()
        .into_iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>();

    let mut rows_out = Vec::new();
    let mut bytes_used = columns.iter().map(|c| c.len()).sum::<usize>();
    let mut truncated = false;

    let mut rows = stmt.query([]).context("execute sqlite query")?;
    while let Some(row) = rows.next().context("iterate sqlite rows")? {
        if rows_out.len() >= max_rows {
            truncated = true;
            break;
        }

        let mut row_map = serde_json::Map::new();
        for (idx, col) in columns.iter().enumerate() {
            let v = match row.get_ref(idx).context("read sqlite column")? {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(i) => json!(i),
                ValueRef::Real(f) => json!(f),
                ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).to_string()),
                ValueRef::Blob(b) => {
                    if b.len() > MAX_BLOB_BYTES {
                        truncated = true;
                        let encoded = BASE64_STANDARD.encode(&b[..MAX_BLOB_BYTES]);
                        Value::String(format!("{encoded}..."))
                    } else {
                        Value::String(BASE64_STANDARD.encode(b))
                    }
                }
            };
            row_map.insert(col.clone(), v);
        }

        let row_value = Value::Object(row_map);
        let row_bytes = serde_json::to_vec(&row_value)
            .map(|b| b.len())
            .context("measure sqlite row size")?;
        if bytes_used + row_bytes > max_bytes {
            truncated = true;
            break;
        }
        bytes_used += row_bytes;
        rows_out.push(row_value);
    }

    Ok(json!({
        "columns": columns,
        "rows": rows_out,
        "truncated": truncated
    }))
}

fn enforce_select_only(query: &str) -> Result<()> {
    let dialect = GenericDialect {};
    let statements = Parser::parse_sql(&dialect, query).context("parse SQL query")?;
    if statements.len() != 1 {
        return Err(anyhow!("exactly one SQL statement is required"));
    }
    match &statements[0] {
        Statement::Query(_) => Ok(()),
        _ => Err(anyhow!("only SELECT-style queries are allowed")),
    }
}
