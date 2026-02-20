use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use toml_edit::{value, DocumentMut, Item, Table};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentKind {
    ClaudeCode,
    CodexCli,
    OpenClaw,
    OtherMcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedAgent {
    pub kind: AgentKind,
    pub display_name: String,
    pub detected: bool,
    pub exe_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RoutingPaths {
    pub policy_path: PathBuf,
    pub approval_store_path: PathBuf,
    pub audit_path: PathBuf,
    pub checkpoint_path: PathBuf,
    pub mounts_path: PathBuf,
    pub views_path: PathBuf,
    pub toolfw_bin: String,
    pub gateway_bin: String,
}

#[derive(Debug, Clone)]
pub struct AgentConfigWriteResult {
    pub path: PathBuf,
    pub backup_path: Option<PathBuf>,
}

pub fn detect_agents() -> Vec<DetectedAgent> {
    [
        profile(
            AgentKind::ClaudeCode,
            "Claude Code (MCP)",
            &["claude", "claude-code"],
        ),
        profile(
            AgentKind::CodexCli,
            "Codex CLI (MCP)",
            &["codex", "openai-codex"],
        ),
        profile(AgentKind::OpenClaw, "OpenClaw (MCP)", &["openclaw", "claw"]),
        profile(AgentKind::OtherMcp, "Other MCP Client (Manual)", &[]),
    ]
    .to_vec()
}

pub fn default_config_path(kind: AgentKind, project_root: &Path) -> Option<PathBuf> {
    let home = home_dir();
    match kind {
        AgentKind::CodexCli => {
            let project = project_root.join(".codex").join("config.toml");
            Some(project)
        }
        AgentKind::ClaudeCode => Some(project_root.join(".mcp.json")),
        AgentKind::OpenClaw => home.map(|h| h.join(".openclaw").join("config.json")),
        AgentKind::OtherMcp => None,
    }
}

pub fn write_config(
    kind: AgentKind,
    target: &Path,
    paths: &RoutingPaths,
    project_root: &Path,
) -> Result<AgentConfigWriteResult> {
    match kind {
        AgentKind::CodexCli => write_codex_config(target, paths, project_root),
        AgentKind::ClaudeCode => write_claude_config(target, paths),
        AgentKind::OpenClaw => bail!("OpenClaw auto-write is not implemented; use manual snippet"),
        AgentKind::OtherMcp => {
            bail!("Other MCP Client auto-write is not implemented; use manual snippet")
        }
    }
}

pub fn generate_mcp_server_snippet(_agent: AgentKind, paths: &RoutingPaths) -> String {
    let value = json!({
        "command": paths.toolfw_bin,
        "args": mcp_args(paths),
    });

    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
}

pub fn generate_manual_command_line(paths: &RoutingPaths) -> String {
    format!(
        "{} proxy stdio --policy {} --approval-store {} --audit {} --audit-checkpoint {} -- {} --mounts {} --views {}",
        paths.toolfw_bin,
        quote(&display(&paths.policy_path)),
        quote(&display(&paths.approval_store_path)),
        quote(&display(&paths.audit_path)),
        quote(&display(&paths.checkpoint_path)),
        paths.gateway_bin,
        quote(&display(&paths.mounts_path)),
        quote(&display(&paths.views_path))
    )
}

fn mcp_args(paths: &RoutingPaths) -> Vec<String> {
    vec![
        "proxy".to_string(),
        "stdio".to_string(),
        "--policy".to_string(),
        display(&paths.policy_path),
        "--approval-store".to_string(),
        display(&paths.approval_store_path),
        "--audit".to_string(),
        display(&paths.audit_path),
        "--audit-checkpoint".to_string(),
        display(&paths.checkpoint_path),
        "--".to_string(),
        paths.gateway_bin.clone(),
        "--mounts".to_string(),
        display(&paths.mounts_path),
        "--views".to_string(),
        display(&paths.views_path),
    ]
}

fn write_codex_config(
    target: &Path,
    paths: &RoutingPaths,
    project_root: &Path,
) -> Result<AgentConfigWriteResult> {
    let mut doc = if target.exists() {
        let txt =
            fs::read_to_string(target).with_context(|| format!("read {}", target.display()))?;
        txt.parse::<DocumentMut>()
            .context("parse codex config toml")?
    } else {
        DocumentMut::new()
    };

    if !doc.as_table().contains_key("mcp_servers") {
        doc["mcp_servers"] = Item::Table(Table::new());
    }
    if !doc["mcp_servers"].is_table() {
        doc["mcp_servers"] = Item::Table(Table::new());
    }
    doc["mcp_servers"]["trust-stack"]["command"] = value(paths.toolfw_bin.clone());
    doc["mcp_servers"]["trust-stack"]["cwd"] = value(display(project_root));

    let args = mcp_args(paths);
    let toml_args = args.iter().map(|x| value(x.clone())).collect::<Vec<_>>();
    let mut arr = toml_edit::Array::default();
    for v in toml_args {
        if let Some(s) = v.as_str() {
            arr.push(s);
        }
    }
    doc["mcp_servers"]["trust-stack"]["args"] = Item::Value(toml_edit::Value::Array(arr));
    doc["mcp_servers"]["trust-stack"]["startup_timeout_sec"] = value(20);
    doc["mcp_servers"]["trust-stack"]["tool_timeout_sec"] = value(30);

    let bytes = doc.to_string().into_bytes();
    write_with_backup_atomic(target, &bytes)
}

fn write_claude_config(target: &Path, paths: &RoutingPaths) -> Result<AgentConfigWriteResult> {
    let mut doc = if target.exists() {
        let txt =
            fs::read_to_string(target).with_context(|| format!("read {}", target.display()))?;
        serde_json::from_str::<serde_json::Value>(&txt).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };
    if !doc.is_object() {
        doc = json!({});
    }
    let root = doc
        .as_object_mut()
        .ok_or_else(|| anyhow!("claude config root must be object"))?;
    let entry = root
        .entry("mcpServers".to_string())
        .or_insert_with(|| json!({}));
    if !entry.is_object() {
        *entry = json!({});
    }
    let servers = entry
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcpServers must be object"))?;
    servers.insert(
        "trust-stack".to_string(),
        json!({
            "command": paths.toolfw_bin,
            "args": mcp_args(paths),
            "env": {}
        }),
    );

    let bytes = serde_json::to_vec_pretty(&doc).context("serialize claude config json")?;
    write_with_backup_atomic(target, &bytes)
}

fn write_with_backup_atomic(target: &Path, bytes: &[u8]) -> Result<AgentConfigWriteResult> {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;

    let backup_path = if target.exists() {
        let backup = PathBuf::from(format!("{}.bak.{}", target.display(), now_ts()));
        fs::copy(target, &backup)
            .with_context(|| format!("backup {} -> {}", target.display(), backup.display()))?;
        Some(backup)
    } else {
        None
    };

    let tmp = parent.join(format!(".{}.tmp", now_ts()));
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, target)
        .with_context(|| format!("atomic replace {} -> {}", tmp.display(), target.display()))?;

    Ok(AgentConfigWriteResult {
        path: target.to_path_buf(),
        backup_path,
    })
}

fn profile(kind: AgentKind, name: &str, candidates: &[&str]) -> DetectedAgent {
    let exe_path = candidates.iter().find_map(|n| find_executable(n));
    let config_path = detect_config_path(kind);
    let mut notes = Vec::new();

    if let Some(path) = &exe_path {
        notes.push(format!("found executable: {}", path.display()));
    } else {
        notes.push("executable not found on PATH".to_string());
    }

    if let Some(path) = &config_path {
        notes.push(format!("config file detected: {}", path.display()));
    } else {
        notes.push("config file not auto-detected".to_string());
    }

    notes.truncate(6);

    DetectedAgent {
        kind,
        display_name: name.to_string(),
        detected: exe_path.is_some(),
        exe_path,
        config_path,
        notes,
    }
}

fn detect_config_path(kind: AgentKind) -> Option<PathBuf> {
    let home = home_dir()?;
    let guesses = match kind {
        AgentKind::ClaudeCode => vec![
            home.join(".mcp.json"),
            home.join(".claude").join("config.json"),
            home.join(".config").join("claude").join("config.json"),
        ],
        AgentKind::CodexCli => vec![
            home.join(".codex").join("config.toml"),
            home.join(".config").join("codex").join("config.toml"),
        ],
        AgentKind::OpenClaw => vec![
            home.join(".openclaw").join("config.json"),
            home.join(".config").join("openclaw").join("config.json"),
        ],
        AgentKind::OtherMcp => vec![],
    };

    guesses.into_iter().find(|p| p.is_file())
}

fn home_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        env::var_os("HOME").map(PathBuf::from)
    }
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    let paths = env::split_paths(&path_var);
    let names = candidate_names(name);

    for dir in paths {
        for candidate in &names {
            let p = dir.join(candidate);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn candidate_names(name: &str) -> Vec<String> {
    if cfg!(windows) {
        let mut out = vec![name.to_string()];
        let exts = env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT".to_string());
        for ext in exts.split(';') {
            if ext.is_empty() {
                continue;
            }
            out.push(format!("{}{}", name, ext.to_ascii_lowercase()));
            out.push(format!("{}{}", name, ext.to_ascii_uppercase()));
        }
        out
    } else {
        vec![name.to_string()]
    }
}

fn display(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn quote(v: &str) -> String {
    if v.contains(' ') {
        format!("\"{}\"", v)
    } else {
        v.to_string()
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routing() -> RoutingPaths {
        RoutingPaths {
            policy_path: PathBuf::from(".trust/run/out/toolfw.policy.yaml"),
            approval_store_path: PathBuf::from(".trust/run/approvals.json"),
            audit_path: PathBuf::from(".trust/run/audit/audit.jsonl"),
            checkpoint_path: PathBuf::from(".trust/run/audit/audit.checkpoint.json"),
            mounts_path: PathBuf::from(".trust/run/out/gateway.mounts.yaml"),
            views_path: PathBuf::from(".trust/run/out/gateway.views.yaml"),
            toolfw_bin: "toolfw".to_string(),
            gateway_bin: "mcp-gateway".to_string(),
        }
    }

    #[test]
    fn codex_toml_merge_keeps_other_servers() {
        let temp = tempfile::tempdir().unwrap();
        let p = temp.path().join("config.toml");
        fs::write(&p, "[mcp_servers.other]\ncommand='x'\nargs=['a']\n").unwrap();
        write_codex_config(&p, &routing(), temp.path()).unwrap();
        let txt = fs::read_to_string(&p).unwrap();
        assert!(txt.contains("[mcp_servers.other]"));
        let parsed = txt.parse::<DocumentMut>().unwrap();
        assert!(parsed["mcp_servers"]["trust-stack"].is_table_like());
        assert_eq!(
            parsed["mcp_servers"]["trust-stack"]["command"]
                .as_str()
                .unwrap(),
            "toolfw"
        );
    }

    #[test]
    fn claude_json_merge_keeps_other_servers() {
        let temp = tempfile::tempdir().unwrap();
        let p = temp.path().join(".mcp.json");
        fs::write(&p, r#"{"mcpServers":{"other":{"command":"x","args":[]}}}"#).unwrap();
        write_claude_config(&p, &routing()).unwrap();
        let txt = fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
        assert!(v["mcpServers"]["other"].is_object());
        assert!(v["mcpServers"]["trust-stack"].is_object());
    }
}
