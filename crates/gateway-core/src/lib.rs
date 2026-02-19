use std::collections::HashMap;
use std::fs;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use mcp_wire::{error, read_json_line_streaming, success, Id};
use serde::Deserialize;
use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

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

pub fn run_stdio(mounts_path: &Path, views_path: &Path) -> Result<()> {
    let mounts = load_mounts(mounts_path)?;
    let views = load_views(views_path)?;

    let mut stdin = io::stdin().lock();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut partial = Vec::new();

    while let Some(msg) = read_json_line_streaming(&mut stdin, &mut partial)? {
        if let Some(resp) = handle_input(&mounts, &views, msg) {
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
                if let Some(resp) = handle_message(mounts, views, item) {
                    responses.push(resp);
                }
            }
            if responses.is_empty() {
                None
            } else {
                Some(Value::Array(responses))
            }
        }
        Value::Object(_) => handle_message(mounts, views, msg),
        _ => Some(invalid_request(Value::Null, "Invalid Request")),
    }
}

fn handle_message(
    mounts: &HashMap<String, Mount>,
    views: &HashMap<String, ViewSpec>,
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
                        {"name": "views.query"}
                    ]
                }),
            ))
        }
        "tools/call" => {
            let id = id?;
            let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
            match call_tool(mounts, views, &params) {
                Ok(result) => Some(success(id, result)),
                Err(e) => Some(error(id, -32000, &e.to_string(), None)),
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

fn call_tool(
    mounts: &HashMap<String, Mount>,
    views: &HashMap<String, ViewSpec>,
    params: &Value,
) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing tool name"))?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "files.read" => files_read(mounts, &args),
        "files.write" => files_write(mounts, &args),
        "files.search" => files_search(mounts, &args),
        "views.query" => views_query(mounts, views, &args),
        _ => Err(anyhow!("unknown tool")),
    }
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

fn safe_join_existing(root: &Path, rel: &str) -> Result<PathBuf> {
    let rel_path = PathBuf::from(rel);
    if rel_path.is_absolute() {
        return Err(anyhow!("absolute paths are not allowed"));
    }
    let joined = root.join(&rel_path);
    let canonical = joined
        .canonicalize()
        .with_context(|| format!("canonicalize {}", joined.display()))?;
    ensure_under_root(root, &canonical)?;
    Ok(canonical)
}

fn safe_join_for_write(root: &Path, rel: &str) -> Result<PathBuf> {
    let rel_path = PathBuf::from(rel);
    if rel_path.is_absolute() {
        return Err(anyhow!("absolute paths are not allowed"));
    }
    let full = root.join(&rel_path);
    let parent = full
        .parent()
        .ok_or_else(|| anyhow!("invalid destination path"))?;
    fs::create_dir_all(parent).with_context(|| format!("create parent {}", parent.display()))?;
    let parent_canonical = parent
        .canonicalize()
        .with_context(|| format!("canonicalize parent {}", parent.display()))?;
    ensure_under_root(root, &parent_canonical)?;
    Ok(full)
}

fn files_read(mounts: &HashMap<String, Mount>, args: &Value) -> Result<Value> {
    let (mount, rel) = mount_and_path(mounts, args)?;
    let path = safe_join_existing(&mount.root, &rel)?;
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
    let dst = safe_join_for_write(&mount.root, &rel)?;
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
        _ => return Err(anyhow!("unsupported view tool")),
    };
    Ok(json!({ "view": view_name, "data": data }))
}
