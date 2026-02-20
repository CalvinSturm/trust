use std::collections::VecDeque;
use std::fs;
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_profiles::{
    default_config_path, detect_agents, generate_manual_command_line, generate_mcp_server_snippet,
    write_config, AgentKind, DetectedAgent, RoutingPaths,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{Local, TimeZone};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Text};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::{Frame, Terminal};
use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_REFRESH_MS: u64 = 250;
const DEFAULT_MAX_EVENTS: usize = 2000;
const DEFAULT_MAX_DETAIL_BYTES: usize = 200_000;
const MAX_MODAL_TEXT: usize = 2000;
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(name = "trust-console")]
struct Cli {
    #[arg(
        long,
        conflicts_with_all = [
            "audit",
            "approval_store",
            "policy",
            "checkpoint",
            "mounts",
            "views"
        ]
    )]
    run_dir: Option<PathBuf>,
    #[arg(long)]
    audit: Option<PathBuf>,
    #[arg(long)]
    approval_store: Option<PathBuf>,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    checkpoint: Option<PathBuf>,
    #[arg(long)]
    mounts: Option<PathBuf>,
    #[arg(long)]
    views: Option<PathBuf>,
    #[arg(long)]
    toolfw_bin: Option<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_REFRESH_MS)]
    refresh_ms: u64,
    #[arg(long, default_value_t = DEFAULT_MAX_EVENTS)]
    max_events: usize,
    #[arg(long, default_value_t = DEFAULT_MAX_DETAIL_BYTES)]
    max_detail_bytes: usize,
    #[arg(long)]
    no_clipboard: bool,
    #[arg(long)]
    verbose: bool,
    #[arg(long)]
    setup: bool,
    #[arg(long)]
    write_config: bool,
    #[arg(long)]
    config_path: Option<PathBuf>,
    #[arg(long)]
    print: bool,
    #[arg(long)]
    agent_label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PersistedAgentsFile {
    preselected_agent: Option<String>,
    agents: Vec<PersistedAgentFile>,
}

#[derive(Debug, Deserialize)]
struct PersistedAgentFile {
    kind: String,
    display_name: String,
    detected: bool,
    exe_path: Option<String>,
    config_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TabKind {
    Setup,
    Audit,
    Approvals,
    Policy,
    Help,
}

#[derive(Debug, Clone)]
struct AuditSummary {
    raw: Value,
    time_ms: Option<u64>,
    decision: String,
    tool: String,
    client: String,
    rule: String,
    code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeDisplay {
    Local,
    Epoch,
}

#[derive(Debug, Clone)]
struct ApprovalSummary {
    created_at: Option<u64>,
    status: String,
    tool: String,
    method: String,
    client: String,
    summary: String,
    id: String,
    digest: String,
}

#[derive(Debug, Clone)]
enum Modal {
    Info(String),
    Token {
        approval_id: String,
        details: Option<String>,
        token: String,
        revealed: bool,
        copy_status: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusMode {
    Normal,
    AuditFilter,
    ApprovalsFilter,
    PolicyRequest,
    PolicyMaxSteps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyAction {
    Explain,
    Trace,
}

struct SetupState {
    agents: Vec<DetectedAgent>,
    selected: usize,
    snippet: String,
    manual_cmd: String,
    config_override: Option<PathBuf>,
}

struct AuditState {
    path: PathBuf,
    events: Vec<AuditSummary>,
    invalid_lines: usize,
    filtered_indices: Vec<usize>,
    selected: usize,
    filter: String,
    detail_open: bool,
    last_len: u64,
    partial: String,
    time_display: TimeDisplay,
    last_seen_time: String,
    last_seen_tool: String,
}

struct ApprovalsState {
    path: PathBuf,
    entries: Vec<ApprovalSummary>,
    filtered_indices: Vec<usize>,
    selected: usize,
    filter: String,
    pending_only: bool,
    time_display: TimeDisplay,
}

struct PolicyState {
    path: PathBuf,
    request_input: String,
    max_steps_input: String,
    action: PolicyAction,
    output: String,
}

struct App {
    tabs: Vec<TabKind>,
    active_tab: usize,
    focus: FocusMode,
    status: String,
    show_help_overlay: bool,
    modal: Option<Modal>,
    refresh_ms: u64,
    max_events: usize,
    max_detail_bytes: usize,
    no_clipboard: bool,
    run_dir: String,
    agent_label: String,
    approval_store_repaired: bool,
    setup: SetupState,
    routing: RoutingPaths,
    audit: Option<AuditState>,
    approvals: Option<ApprovalsState>,
    policy: Option<PolicyState>,
}

fn main() -> std::process::ExitCode {
    let cli = match Cli::try_parse() {
        Ok(v) => v,
        Err(e) => {
            if matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                print!("{e}");
                return std::process::ExitCode::SUCCESS;
            }
            eprintln!("{e}");
            return std::process::ExitCode::from(2);
        }
    };

    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let mut app = build_app(&cli)?;
    if cli.write_config {
        write_selected_config(&mut app)?;
    }
    if cli.print {
        print_setup(&app);
        return Ok(());
    }

    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_event_loop(&mut terminal, &mut app);

    disable_raw_mode().ok();
    terminal.backend_mut().execute(LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

fn build_app(cli: &Cli) -> Result<App> {
    let toolfw_bin = resolve_toolfw_bin(cli.toolfw_bin.clone());
    let gateway_bin = resolve_gateway_bin();
    let run_dir = cli.run_dir.clone();
    let (audit_path, approval_store, policy_path, checkpoint, mounts, views) =
        if let Some(dir) = run_dir.as_ref() {
            (
                dir.join("audit").join("audit.jsonl"),
                dir.join("approvals.json"),
                dir.join("out").join("toolfw.policy.yaml"),
                dir.join("audit").join("audit.checkpoint.json"),
                dir.join("out").join("gateway.mounts.yaml"),
                dir.join("out").join("gateway.views.yaml"),
            )
        } else {
            let audit_path = cli
                .audit
                .clone()
                .unwrap_or_else(|| PathBuf::from("./tmp/audit.jsonl"));
            let approval_store = cli
                .approval_store
                .clone()
                .unwrap_or_else(|| PathBuf::from("./tmp/approvals.json"));
            let policy_path = cli
                .policy
                .clone()
                .unwrap_or_else(|| PathBuf::from("configs/examples/toolfw.policy.yaml"));
            let checkpoint = cli.checkpoint.clone().unwrap_or_else(|| {
                audit_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("audit.checkpoint.json")
            });
            let mounts = cli
                .mounts
                .clone()
                .unwrap_or_else(|| PathBuf::from("configs/examples/gateway.mounts.yaml"));
            let views = cli
                .views
                .clone()
                .unwrap_or_else(|| PathBuf::from("configs/examples/gateway.views.yaml"));
            (
                audit_path,
                approval_store,
                policy_path,
                checkpoint,
                mounts,
                views,
            )
        };

    let routing = RoutingPaths {
        policy_path: policy_path.clone(),
        approval_store_path: approval_store.clone(),
        audit_path: audit_path.clone(),
        checkpoint_path: checkpoint.clone(),
        mounts_path: mounts.clone(),
        views_path: views.clone(),
        toolfw_bin: toolfw_bin.to_string_lossy().to_string(),
        gateway_bin,
    };

    let mut agents = load_agents_from_run_dir(run_dir.as_deref()).unwrap_or_else(detect_agents);
    if agents.is_empty() {
        agents.push(DetectedAgent {
            kind: AgentKind::CodexCli,
            display_name: "Codex CLI".to_string(),
            detected: false,
            exe_path: None,
            config_path: None,
            notes: vec!["No clients detected".to_string()],
        });
    }
    let selected = agents.iter().position(|a| a.detected).unwrap_or(0);
    let snippet = generate_mcp_server_snippet(agents[selected].kind, &routing);
    let manual_cmd = generate_manual_command_line(&routing);

    let setup = SetupState {
        agents,
        selected,
        snippet,
        manual_cmd,
        config_override: cli.config_path.clone(),
    };
    let default_agent_label = setup
        .agents
        .get(selected)
        .map(|a| a.display_name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let audit_enabled = run_dir.is_some() || cli.audit.is_some();
    let approvals_enabled = run_dir.is_some() || cli.approval_store.is_some();
    let policy_enabled = run_dir.is_some() || cli.policy.is_some();

    let approval_store_repaired = if approvals_enabled {
        toolfw_core::normalize_approval_store(&approval_store)?
    } else {
        false
    };

    let mut tabs = vec![TabKind::Setup];
    let audit = audit_enabled.then(|| AuditState {
        path: audit_path.clone(),
        events: vec![],
        invalid_lines: 0,
        filtered_indices: vec![],
        selected: 0,
        filter: String::new(),
        detail_open: false,
        last_len: 0,
        partial: String::new(),
        time_display: TimeDisplay::Local,
        last_seen_time: "-".to_string(),
        last_seen_tool: "-".to_string(),
    });
    if audit.is_some() {
        tabs.push(TabKind::Audit);
    }
    let approvals = approvals_enabled.then(|| ApprovalsState {
        path: approval_store.clone(),
        entries: vec![],
        filtered_indices: vec![],
        selected: 0,
        filter: String::new(),
        pending_only: true,
        time_display: TimeDisplay::Local,
    });
    if approvals.is_some() {
        tabs.push(TabKind::Approvals);
    }
    let policy = policy_enabled.then(|| PolicyState {
        path: policy_path.clone(),
        request_input: default_policy_request(),
        max_steps_input: "200".to_string(),
        action: PolicyAction::Explain,
        output: "Press Enter to run explain/trace; t toggles action".to_string(),
    });
    if policy.is_some() {
        tabs.push(TabKind::Policy);
    }
    tabs.push(TabKind::Help);

    let mut app = App {
        tabs,
        active_tab: 0,
        focus: FocusMode::Normal,
        status: if approval_store_repaired {
            "Approval store repaired (schema initialized)".to_string()
        } else {
            "Ready".to_string()
        },
        show_help_overlay: false,
        modal: None,
        refresh_ms: cli.refresh_ms.max(50),
        max_events: cli.max_events.max(1),
        max_detail_bytes: cli.max_detail_bytes.max(1024),
        no_clipboard: cli.no_clipboard,
        run_dir: run_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| ".".to_string()),
        agent_label: cli.agent_label.clone().unwrap_or(default_agent_label),
        approval_store_repaired,
        setup,
        routing,
        audit,
        approvals,
        policy,
    };

    if cli.setup {
        app.active_tab = 0;
    }

    reload_all(&mut app)?;
    Ok(app)
}
fn print_setup(app: &App) {
    println!(
        "Selected agent: {}",
        app.setup.agents[app.setup.selected].display_name
    );
    println!("\nSnippet:\n{}", app.setup.snippet);
    println!("\nManual command:\n{}", app.setup.manual_cmd);
}

fn resolve_toolfw_bin(from_cli: Option<PathBuf>) -> PathBuf {
    if let Some(path) = from_cli {
        return path;
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_toolfw") {
        return PathBuf::from(path);
    }
    PathBuf::from(if cfg!(windows) {
        "toolfw.exe"
    } else {
        "toolfw"
    })
}

fn resolve_gateway_bin() -> String {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_mcp-gateway") {
        return path;
    }
    if cfg!(windows) {
        "mcp-gateway.exe".to_string()
    } else {
        "mcp-gateway".to_string()
    }
}

fn load_agents_from_run_dir(run_dir: Option<&Path>) -> Option<Vec<DetectedAgent>> {
    let dir = run_dir?;
    let path = dir.join("out").join("agents.detected.json");
    let txt = fs::read_to_string(path).ok()?;
    let parsed: PersistedAgentsFile = serde_json::from_str(&txt).ok()?;
    let mut out = parsed
        .agents
        .into_iter()
        .filter_map(|a| {
            Some(DetectedAgent {
                kind: parse_agent_kind(&a.kind)?,
                display_name: a.display_name,
                detected: a.detected,
                exe_path: a.exe_path.map(PathBuf::from),
                config_path: a.config_path.map(PathBuf::from),
                notes: Vec::new(),
            })
        })
        .collect::<Vec<_>>();
    if let Some(pre) = parsed.preselected_agent {
        if let Some(pos) = out.iter().position(|a| a.display_name == pre) {
            for a in &mut out {
                a.detected = false;
            }
            if let Some(sel) = out.get_mut(pos) {
                sel.detected = true;
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn parse_agent_kind(raw: &str) -> Option<AgentKind> {
    match raw {
        "codex" => Some(AgentKind::CodexCli),
        "claude" => Some(AgentKind::ClaudeCode),
        "openclaw" => Some(AgentKind::OpenClaw),
        "other" => Some(AgentKind::OtherMcp),
        _ => None,
    }
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let refresh = Duration::from_millis(app.refresh_ms);
    let mut last_reload = Instant::now();

    loop {
        terminal.draw(|f| draw_ui(f, app))?;

        if last_reload.elapsed() >= refresh {
            let _ = reload_data(app);
            last_reload = Instant::now();
        }

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if handle_key(app, key)? {
                    return Ok(());
                }
            }
        }
    }
}

fn handle_key(app: &mut App, key: KeyEvent) -> Result<bool> {
    if let Some(modal) = app.modal.as_mut() {
        if handle_modal_key(modal, key, app.no_clipboard)? {
            app.modal = None;
        }
        return Ok(false);
    }

    if app.show_help_overlay {
        if matches!(key.code, KeyCode::Char('?') | KeyCode::Esc | KeyCode::Enter) {
            app.show_help_overlay = false;
        }
        return Ok(false);
    }

    match app.focus {
        FocusMode::AuditFilter => {
            if let Some(a) = app.audit.as_mut() {
                handle_text_edit_key(key, &mut a.filter);
                apply_audit_filter(a);
            }
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                app.focus = FocusMode::Normal;
            }
            return Ok(false);
        }
        FocusMode::ApprovalsFilter => {
            if let Some(a) = app.approvals.as_mut() {
                handle_text_edit_key(key, &mut a.filter);
                apply_approvals_filter(a);
            }
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                app.focus = FocusMode::Normal;
            }
            return Ok(false);
        }
        FocusMode::PolicyRequest => {
            if let Some(p) = app.policy.as_mut() {
                handle_multiline_edit_key(key, &mut p.request_input);
            }
            if key.code == KeyCode::Esc {
                app.focus = FocusMode::Normal;
            }
            return Ok(false);
        }
        FocusMode::PolicyMaxSteps => {
            if let Some(p) = app.policy.as_mut() {
                handle_text_edit_key(key, &mut p.max_steps_input);
            }
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                app.focus = FocusMode::Normal;
            }
            return Ok(false);
        }
        FocusMode::Normal => {}
    }

    match key.code {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::Tab => {
            app.active_tab = (app.active_tab + 1) % app.tabs.len();
            app.modal = None;
        }
        KeyCode::BackTab => {
            app.active_tab = if app.active_tab == 0 {
                app.tabs.len() - 1
            } else {
                app.active_tab - 1
            };
            app.modal = None;
        }
        KeyCode::Char('?') => app.show_help_overlay = true,
        KeyCode::Char('r') => {
            reload_all(app)?;
            app.status = "Reloaded".to_string();
        }
        _ => match current_tab(app) {
            TabKind::Setup => handle_setup_key(app, key)?,
            TabKind::Audit => handle_audit_key(app, key)?,
            TabKind::Approvals => handle_approvals_key(app, key)?,
            TabKind::Policy => handle_policy_key(app, key)?,
            TabKind::Help => {}
        },
    }

    Ok(false)
}

fn handle_setup_key(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => {
            if app.setup.selected + 1 < app.setup.agents.len() {
                app.setup.selected += 1;
                refresh_setup(app);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if app.setup.selected > 0 {
                app.setup.selected -= 1;
                refresh_setup(app);
            }
        }
        KeyCode::Char('c') => {
            app.modal = Some(Modal::Info(format!(
                "Manual copy snippet:\n\n{}",
                app.setup.snippet
            )));
        }
        KeyCode::Char('s') => {
            let config_target = selected_config_target(app)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<unknown>".to_string());
            app.modal = Some(Modal::Info(format!(
                "Run stack:\n{}\n\nConfig target:\n{}\n\nThen:\ntrust-console --run-dir {}",
                app.setup.manual_cmd, config_target, app.run_dir,
            )));
        }
        KeyCode::Enter => refresh_setup(app),
        KeyCode::Char('w') => write_selected_config(app)?,
        _ => {}
    }
    Ok(())
}

fn refresh_setup(app: &mut App) {
    if let Some(agent) = app.setup.agents.get(app.setup.selected) {
        app.setup.snippet = generate_mcp_server_snippet(agent.kind, &app.routing);
        app.setup.manual_cmd = generate_manual_command_line(&app.routing);
    }
}

fn write_selected_config(app: &mut App) -> Result<()> {
    let agent = app
        .setup
        .agents
        .get(app.setup.selected)
        .ok_or_else(|| anyhow!("no selected agent"))?
        .clone();
    let target = selected_config_target(app)
        .ok_or_else(|| anyhow!("no config path discovered; use --config-path"))?;
    let project_root = std::env::current_dir().context("resolve project directory")?;
    let result = write_config(agent.kind, &target, &app.routing, &project_root)?;
    app.status = format!("Wrote {}", result.path.display());
    let mut msg = format!("Wrote config: {}", result.path.display());
    if let Some(bak) = result.backup_path {
        msg.push_str(&format!("\nBackup: {}", bak.display()));
    }
    app.modal = Some(Modal::Info(msg));
    Ok(())
}

fn selected_config_target(app: &App) -> Option<PathBuf> {
    let agent = app.setup.agents.get(app.setup.selected)?;
    if let Some(path) = app.setup.config_override.clone() {
        return Some(path);
    }
    if let Some(path) = agent.config_path.clone() {
        return Some(path);
    }
    std::env::current_dir()
        .ok()
        .and_then(|root| default_config_path(agent.kind, &root))
}

fn handle_modal_key(modal: &mut Modal, key: KeyEvent, no_clipboard: bool) -> Result<bool> {
    match modal {
        Modal::Info(_) => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                return Ok(true);
            }
        }
        Modal::Token {
            token,
            revealed,
            copy_status,
            ..
        } => match key.code {
            KeyCode::Esc | KeyCode::Enter => return Ok(true),
            KeyCode::Char('c') => {
                *revealed = true;
                *copy_status = copy_to_clipboard(token, no_clipboard)
                    .unwrap_or_else(|e| format!("copy unavailable: {e}; manual copy"));
            }
            _ => {}
        },
    }
    Ok(false)
}

fn handle_text_edit_key(key: KeyEvent, target: &mut String) {
    match key.code {
        KeyCode::Backspace => {
            target.pop();
        }
        KeyCode::Char(ch) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL) {
                target.push(ch);
            }
        }
        _ => {}
    }
}

fn handle_multiline_edit_key(key: KeyEvent, target: &mut String) {
    match key.code {
        KeyCode::Enter => target.push('\n'),
        KeyCode::Backspace => {
            target.pop();
        }
        KeyCode::Char(ch) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL) {
                target.push(ch);
            }
        }
        _ => {}
    }
}
fn handle_audit_key(app: &mut App, key: KeyEvent) -> Result<()> {
    let Some(a) = app.audit.as_mut() else {
        return Ok(());
    };
    match key.code {
        KeyCode::Char('/') => app.focus = FocusMode::AuditFilter,
        KeyCode::Char('j') | KeyCode::Down => {
            if !a.filtered_indices.is_empty() {
                a.selected = (a.selected + 1).min(a.filtered_indices.len() - 1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if a.selected > 0 {
                a.selected -= 1;
            }
        }
        KeyCode::Char('t') | KeyCode::Char('T') => {
            a.time_display = if a.time_display == TimeDisplay::Local {
                TimeDisplay::Epoch
            } else {
                TimeDisplay::Local
            };
            refresh_audit_last_seen(a);
        }
        KeyCode::Enter => a.detail_open = !a.detail_open,
        _ => {}
    }
    Ok(())
}

fn handle_approvals_key(app: &mut App, key: KeyEvent) -> Result<()> {
    let Some(a) = app.approvals.as_mut() else {
        return Ok(());
    };
    let selected_index = a.filtered_indices.get(a.selected).copied();
    match key.code {
        KeyCode::Char('/') => app.focus = FocusMode::ApprovalsFilter,
        KeyCode::Char('j') | KeyCode::Down => {
            if !a.filtered_indices.is_empty() {
                a.selected = (a.selected + 1).min(a.filtered_indices.len() - 1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if a.selected > 0 {
                a.selected -= 1;
            }
        }
        KeyCode::Char('p') => {
            a.pending_only = !a.pending_only;
            apply_approvals_filter(a);
        }
        KeyCode::Char('t') | KeyCode::Char('T') => {
            a.time_display = if a.time_display == TimeDisplay::Local {
                TimeDisplay::Epoch
            } else {
                TimeDisplay::Local
            };
        }
        KeyCode::Char('a') => {
            if let Some(sel) = selected_index.and_then(|idx| a.entries.get(idx)) {
                let token = approve_request(&a.path, &sel.id)?;
                app.modal = Some(Modal::Token {
                    approval_id: sel.id.clone(),
                    details: None,
                    token,
                    revealed: false,
                    copy_status: "Press c to reveal/copy token".to_string(),
                });
                reload_approvals(a)?;
            }
        }
        KeyCode::Char('d') => {
            if let Some(sel) = selected_index.and_then(|idx| a.entries.get(idx)) {
                let removed = toolfw_core::deny_approval_request(&a.path, &sel.id)?;
                if removed {
                    app.status = format!("Denied {}", sel.id);
                } else {
                    app.status = format!("Approval request not found: {}", sel.id);
                }
                reload_approvals(a)?;
            }
        }
        KeyCode::Enter => {
            if let Some(sel) = selected_index.and_then(|idx| a.entries.get(idx)) {
                let detail = toolfw_core::approval_request_detail(&a.path, &sel.id)?
                    .unwrap_or_else(|| json!({"approval_request_id": sel.id, "status":"missing"}));
                let token = detail
                    .get("token")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                let msg =
                    format_approval_detail_text(&detail, a.time_display, app.max_detail_bytes);
                if let Some(token) = token {
                    app.modal = Some(Modal::Token {
                        approval_id: sel.id.clone(),
                        details: Some(msg),
                        token,
                        revealed: false,
                        copy_status: "Press c to reveal/copy token".to_string(),
                    });
                } else {
                    app.modal = Some(Modal::Info(msg));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn handle_policy_key(app: &mut App, key: KeyEvent) -> Result<()> {
    let Some(p) = app.policy.as_mut() else {
        return Ok(());
    };
    match key.code {
        KeyCode::Char('e') => app.focus = FocusMode::PolicyRequest,
        KeyCode::Char('m') => app.focus = FocusMode::PolicyMaxSteps,
        KeyCode::Char('t') => {
            p.action = if p.action == PolicyAction::Explain {
                PolicyAction::Trace
            } else {
                PolicyAction::Explain
            }
        }
        KeyCode::Enter => {
            let max_steps = p
                .max_steps_input
                .trim()
                .parse::<usize>()
                .unwrap_or(200)
                .max(1);
            let out = if p.action == PolicyAction::Explain {
                toolfw_core::policy_explain(&p.path, &p.request_input)
            } else {
                toolfw_core::policy_trace(&p.path, &p.request_input, max_steps)
            };
            match out {
                Ok(v) => {
                    p.output = truncate_text(
                        &serde_json::to_string_pretty(&redact_value(&v))
                            .unwrap_or_else(|_| v.to_string()),
                        app.max_detail_bytes,
                    );
                }
                Err(e) => p.output = truncate_text(&format!("error: {e}"), app.max_detail_bytes),
            }
        }
        _ => {}
    }
    Ok(())
}

fn approve_request(store: &Path, id: &str) -> Result<String> {
    let token = toolfw_core::issue_approval_token(store, id)?;
    if token.is_empty() {
        bail!("approve returned empty token");
    }
    Ok(token)
}

fn copy_to_clipboard(_token: &str, no_clipboard: bool) -> Result<String> {
    if no_clipboard {
        bail!("disabled by --no-clipboard");
    }
    bail!("clipboard unavailable in this build")
}

fn reload_all(app: &mut App) -> Result<()> {
    reload_data(app)
}

fn reload_data(app: &mut App) -> Result<()> {
    if let Some(a) = app.audit.as_mut() {
        reload_audit(a, app.max_events)?;
    }
    if let Some(a) = app.approvals.as_mut() {
        reload_approvals(a)?;
    }
    Ok(())
}

fn reload_audit(state: &mut AuditState, max_events: usize) -> Result<()> {
    if !state.path.exists() {
        return Ok(());
    }
    let len = fs::metadata(&state.path)?.len();

    if state.last_len == 0 {
        let lines = read_last_lines(&state.path, max_events)?;
        state.events.clear();
        state.invalid_lines = 0;
        for line in lines {
            push_audit_line(state, &line);
        }
        state.last_len = len;
        apply_audit_filter(state);
        refresh_audit_last_seen(state);
        return Ok(());
    }

    if len < state.last_len {
        state.events.clear();
        state.last_len = 0;
        state.partial.clear();
        return reload_audit(state, max_events);
    }
    if len == state.last_len {
        return Ok(());
    }

    let mut file = fs::File::open(&state.path)?;
    file.seek(SeekFrom::Start(state.last_len))?;
    use std::io::Read;
    let mut chunk = String::new();
    file.read_to_string(&mut chunk)?;
    let mut buf = String::new();
    buf.push_str(&state.partial);
    buf.push_str(&chunk);

    let mut complete = buf.split('\n').map(ToString::to_string).collect::<Vec<_>>();
    if buf.ends_with('\n') {
        state.partial.clear();
    } else {
        state.partial = complete.pop().unwrap_or_default();
    }

    for line in complete {
        push_audit_line(state, &line);
    }

    if state.events.len() > max_events {
        let drop_n = state.events.len() - max_events;
        state.events.drain(0..drop_n);
    }

    state.last_len = len;
    apply_audit_filter(state);
    refresh_audit_last_seen(state);
    Ok(())
}

fn read_last_lines(path: &Path, n: usize) -> Result<Vec<String>> {
    let f = fs::File::open(path)?;
    let reader = io::BufReader::new(f);
    use std::io::BufRead;
    let mut queue = VecDeque::new();
    for line in reader.lines() {
        let line = line?;
        if queue.len() == n {
            queue.pop_front();
        }
        queue.push_back(line);
    }
    Ok(queue.into_iter().collect())
}

fn push_audit_line(state: &mut AuditState, line: &str) {
    if line.trim().is_empty() {
        return;
    }
    match serde_json::from_str::<Value>(line) {
        Ok(v) => {
            let summary = summarize_audit_event(v);
            state.events.push(summary);
        }
        Err(_) => state.invalid_lines = state.invalid_lines.saturating_add(1),
    }
}

fn summarize_audit_event(raw: Value) -> AuditSummary {
    let time_ms = extract_timestamp_ms(&raw);
    let mcp_method = extract_first_string(
        &raw,
        &[
            &["mcp_method"],
            &["method"],
            &["request", "mcp_method"],
            &["request", "method"],
            &["meta", "mcp_method"],
        ],
    );
    let decision = raw
        .get("decision")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            raw.get("error_code")
                .and_then(Value::as_i64)
                .map(|c| match c {
                    -32040 => "deny".to_string(),
                    -32041 => "approval_required".to_string(),
                    -32042 => "rate_limited".to_string(),
                    -32602 => "invalid_params".to_string(),
                    _ => format!("error:{c}"),
                })
        })
        .unwrap_or_else(|| "-".to_string());
    let tool = extract_first_string(
        &raw,
        &[
            &["tool"],
            &["request", "tool"],
            &["meta", "tool"],
            &["params", "name"],
            &["request", "params", "name"],
            &["error", "data", "tool"],
        ],
    )
    .unwrap_or_else(|| {
        if mcp_method.as_deref() == Some("tools/call") {
            String::new()
        } else {
            "(meta)".to_string()
        }
    });
    let client = extract_first_string(
        &raw,
        &[
            &["client_id"],
            &["meta", "client_id"],
            &["request", "client_id"],
            &["auth", "client_id"],
            &["client", "id"],
            &["attribution", "client_id"],
        ],
    )
    .unwrap_or_else(|| "anon".to_string());
    let rule = extract_first_string(
        &raw,
        &[
            &["rule_id"],
            &["meta", "rule_id"],
            &["policy", "rule_id"],
            &["decision", "rule_id"],
            &["error", "data", "rule_id"],
        ],
    )
    .unwrap_or_else(|| "-".to_string());
    let code = extract_first_i64(
        &raw,
        &[
            &["error_code"],
            &["meta", "error_code"],
            &["decision", "error_code"],
            &["error", "code"],
        ],
    )
    .map(|v| v.to_string())
    .unwrap_or_else(|| "-".to_string());

    AuditSummary {
        time_ms,
        decision,
        tool,
        client,
        rule,
        code,
        raw,
    }
}

fn refresh_audit_last_seen(state: &mut AuditState) {
    if let Some(last) = state.events.last() {
        state.last_seen_time = format_event_time(last.time_ms, state.time_display);
        state.last_seen_tool = if last.tool.is_empty() {
            "(meta)".to_string()
        } else {
            last.tool.clone()
        };
    } else {
        state.last_seen_time = "-".to_string();
        state.last_seen_tool = "-".to_string();
    }
}

fn extract_timestamp_ms(raw: &Value) -> Option<u64> {
    let ms = extract_first_u64(
        raw,
        &[
            &["ts_unix_ms"],
            &["timestamp_ms"],
            &["ts_ms"],
            &["meta", "ts_unix_ms"],
            &["meta", "timestamp_ms"],
            &["ts"],
            &["timestamp"],
        ],
    );
    if let Some(v) = ms {
        return Some(normalize_epoch_ms(v));
    }
    let secs = extract_first_u64(
        raw,
        &[
            &["ts_unix_s"],
            &["ts_unix"],
            &["timestamp_s"],
            &["meta", "ts_unix_s"],
            &["meta", "ts_unix"],
        ],
    )?;
    Some(secs.saturating_mul(1000))
}

fn normalize_epoch_ms(raw: u64) -> u64 {
    if raw < 10_000_000_000 {
        raw.saturating_mul(1000)
    } else {
        raw
    }
}

fn extract_first_string(raw: &Value, paths: &[&[&str]]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value_at_path(raw, path).and_then(Value::as_str))
        .map(ToString::to_string)
}

fn extract_first_u64(raw: &Value, paths: &[&[&str]]) -> Option<u64> {
    paths
        .iter()
        .find_map(|path| value_at_path(raw, path).and_then(value_to_u64))
}

fn extract_first_i64(raw: &Value, paths: &[&[&str]]) -> Option<i64> {
    paths.iter().find_map(|path| {
        value_at_path(raw, path).and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
        })
    })
}

fn value_at_path<'a>(raw: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = raw;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn value_to_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
}

fn apply_audit_filter(state: &mut AuditState) {
    let needle = state.filter.to_ascii_lowercase();
    state.filtered_indices.clear();
    for (i, ev) in state.events.iter().enumerate() {
        if needle.is_empty()
            || ev.tool.to_ascii_lowercase().contains(&needle)
            || ev.client.to_ascii_lowercase().contains(&needle)
            || ev.rule.to_ascii_lowercase().contains(&needle)
            || ev.decision.to_ascii_lowercase().contains(&needle)
            || ev.code.to_ascii_lowercase().contains(&needle)
        {
            state.filtered_indices.push(i);
        }
    }
    if state.filtered_indices.is_empty() {
        state.selected = 0;
    } else if state.selected >= state.filtered_indices.len() {
        state.selected = state.filtered_indices.len() - 1;
    }
}

fn reload_approvals(state: &mut ApprovalsState) -> Result<()> {
    state.entries.clear();
    let _ = toolfw_core::normalize_approval_store(&state.path)?;
    let requests = toolfw_core::list_approval_requests(&state.path)?;
    for rec in requests {
        let tool = rec.tool.unwrap_or_else(|| "-".to_string());
        let client = rec.client_id.unwrap_or_else(|| "anon".to_string());
        let method = rec.mcp_method.unwrap_or_else(|| "-".to_string());
        let summary = rec
            .summary
            .as_ref()
            .map(summary_to_line)
            .unwrap_or_else(|| "-".to_string());
        state.entries.push(ApprovalSummary {
            id: rec.approval_request_id,
            digest: rec.request_digest,
            created_at: rec.created_at,
            status: rec.status,
            tool,
            method,
            client,
            summary,
        });
    }
    state
        .entries
        .sort_by(|a, b| b.created_at.cmp(&a.created_at));
    apply_approvals_filter(state);
    Ok(())
}

fn apply_approvals_filter(state: &mut ApprovalsState) {
    let needle = state.filter.to_ascii_lowercase();
    state.filtered_indices.clear();
    for (i, ev) in state.entries.iter().enumerate() {
        if state.pending_only && ev.status != "pending" {
            continue;
        }
        let haystack = format!(
            "{} {} {} {} {} {}",
            ev.tool, ev.client, ev.id, ev.summary, ev.method, ev.digest
        )
        .to_ascii_lowercase();
        if needle.is_empty() || haystack.contains(&needle) {
            state.filtered_indices.push(i);
        }
    }
    if state.filtered_indices.is_empty() {
        state.selected = 0;
    } else if state.selected >= state.filtered_indices.len() {
        state.selected = state.filtered_indices.len() - 1;
    }
}

fn summary_to_line(summary: &Value) -> String {
    if let Some(obj) = summary.as_object() {
        if let (Some(mount), Some(path)) = (
            obj.get("mount").and_then(Value::as_str),
            obj.get("path").and_then(Value::as_str),
        ) {
            if let Some(bytes) = obj.get("bytes").and_then(Value::as_u64) {
                return truncate_text(&format!("{mount}/{path} ({bytes}B)"), 48);
            }
            return truncate_text(&format!("{mount}/{path}"), 48);
        }
        if let Some(view) = obj.get("view").and_then(Value::as_str) {
            return truncate_text(&format!("view={view}"), 48);
        }
        if let Some(keys) = obj.get("keys").and_then(Value::as_array) {
            let joined = keys
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",");
            return truncate_text(&format!("keys:{joined}"), 48);
        }
    }
    truncate_text(&summary.to_string(), 48)
}
fn draw_ui(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let header_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(45),
            Constraint::Percentage(20),
            Constraint::Percentage(35),
        ])
        .split(chunks[0]);
    let left = Paragraph::new(format!(
        "trust-console v{} | run {}",
        APP_VERSION, app.run_dir
    ))
    .alignment(Alignment::Left);
    frame.render_widget(left, header_cols[0]);
    let center = Paragraph::new(tab_name(current_tab(app)))
        .alignment(Alignment::Center)
        .style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(center, header_cols[1]);
    let right = Paragraph::new(connection_label(app))
        .alignment(Alignment::Right)
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(right, header_cols[2]);

    let titles = app
        .tabs
        .iter()
        .map(|t| Line::from(tab_name(*t)))
        .collect::<Vec<_>>();
    let tabs = Tabs::new(titles).select(app.active_tab).highlight_style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(tabs, chunks[1]);

    match current_tab(app) {
        TabKind::Setup => draw_setup_tab(frame, chunks[2], app),
        TabKind::Audit => draw_audit_tab(frame, chunks[2], app),
        TabKind::Approvals => draw_approvals_tab(frame, chunks[2], app),
        TabKind::Policy => draw_policy_tab(frame, chunks[2], app),
        TabKind::Help => draw_help_tab(frame, chunks[2]),
    }

    let mut status_text = format!(
        "status: {} | q quit | Tab tabs | j/k move | Enter action | a approve | d deny | p pending/all | T time | r reload | ? help",
        app.status
    );
    if app.approval_store_repaired {
        status_text.push_str(" | Approval store repaired (schema initialized)");
    }
    let status = Paragraph::new(status_text).block(Block::default().borders(Borders::ALL));
    frame.render_widget(status, chunks[3]);

    if app.show_help_overlay {
        draw_help_overlay(frame);
    }
    if let Some(modal) = &app.modal {
        draw_modal(frame, modal);
    }
}

fn connection_label(app: &App) -> String {
    if let Some(audit) = &app.audit {
        return format!(
            "agent:{} | last:{} {}",
            app.agent_label, audit.last_seen_time, audit.last_seen_tool
        );
    }
    format!("agent:{} | audit:disabled", app.agent_label)
}

fn draw_setup_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Min(8),
        ])
        .split(area);

    let rows = app
        .setup
        .agents
        .iter()
        .map(|a| {
            Row::new(vec![
                if a.detected { "✅" } else { "❌" }.to_string(),
                a.display_name.clone(),
                a.exe_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "-".to_string()),
                a.config_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ])
        })
        .collect::<Vec<_>>();

    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(16),
            Constraint::Percentage(40),
            Constraint::Percentage(40),
        ],
    )
    .header(
        Row::new(vec!["ok", "agent", "exe", "config"]).style(Style::default().fg(Color::Yellow)),
    )
    .block(
        Block::default()
            .title("Setup (j/k select, c copy, w write, s show commands)")
            .borders(Borders::ALL),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("> ");

    let mut state = ratatui::widgets::TableState::default();
    if !app.setup.agents.is_empty() {
        state.select(Some(app.setup.selected));
    }
    frame.render_stateful_widget(table, chunks[0], &mut state);

    frame.render_widget(
        Paragraph::new(app.setup.manual_cmd.clone())
            .block(
                Block::default()
                    .title("Manual Command")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new(app.setup.snippet.clone())
            .block(Block::default().title("MCP Snippet").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
}

fn draw_audit_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let Some(a) = app.audit.as_ref() else {
        frame.render_widget(
            Paragraph::new("Audit disabled; pass --audit <path>")
                .block(Block::default().title("Audit").borders(Borders::ALL)),
            area,
        );
        return;
    };

    let layout = if a.detail_open {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(100), Constraint::Length(0)])
            .split(area)
    };

    let rows = a
        .filtered_indices
        .iter()
        .map(|idx| &a.events[*idx])
        .map(|ev| {
            Row::new(vec![
                Cell::from(format_event_time(ev.time_ms, a.time_display)),
                Cell::from(ev.decision.clone()),
                Cell::from(ev.tool.clone()),
                Cell::from(ev.client.clone()),
                Cell::from(ev.rule.clone()),
                Cell::from(ev.code.clone()),
            ])
        })
        .collect::<Vec<_>>();

    let table = Table::new(
        rows,
        [
            Constraint::Length(19),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Length(12),
            Constraint::Length(14),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["time", "decision", "tool", "client", "rule", "code"])
            .style(Style::default().fg(Color::Yellow)),
    )
    .block(
        Block::default()
            .title(format!(
                "Audit {} filtered {}/{} invalid={} time={}",
                a.path.display(),
                a.filtered_indices.len(),
                a.events.len(),
                a.invalid_lines,
                if a.time_display == TimeDisplay::Local {
                    "local"
                } else {
                    "epoch"
                }
            ))
            .borders(Borders::ALL),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("> ");

    let mut state = ratatui::widgets::TableState::default();
    if !a.filtered_indices.is_empty() {
        state.select(Some(a.selected));
    }
    frame.render_stateful_widget(table, layout[0], &mut state);

    if a.detail_open {
        let detail = selected_audit_detail(a, app.max_detail_bytes);
        frame.render_widget(
            Paragraph::new(detail)
                .block(
                    Block::default()
                        .title("Detail (redacted)")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false }),
            layout[1],
        );
    }
}

fn draw_approvals_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let Some(a) = app.approvals.as_ref() else {
        frame.render_widget(
            Paragraph::new("Approvals disabled; pass --approval-store <path>")
                .block(Block::default().title("Approvals").borders(Borders::ALL)),
            area,
        );
        return;
    };

    let rows = a
        .filtered_indices
        .iter()
        .map(|idx| &a.entries[*idx])
        .map(|e| {
            Row::new(vec![
                format_event_time(e.created_at.map(|s| s.saturating_mul(1000)), a.time_display),
                e.status.clone(),
                e.tool.clone(),
                e.client.clone(),
                e.summary.clone(),
                truncate_text(&e.id, 18),
                truncate_text(&e.digest, 14),
            ])
        })
        .collect::<Vec<_>>();

    let table = Table::new(
        rows,
        [
            Constraint::Length(19),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Percentage(36),
            Constraint::Length(20),
            Constraint::Length(16),
        ],
    )
    .header(
        Row::new(vec!["created", "status", "tool", "client", "summary", "id", "digest"])
            .style(Style::default().fg(Color::Yellow)),
    )
    .block(
        Block::default()
            .title(format!(
                "Approvals {} [{}] filtered {}/{} time={} (a approve, d deny, p pending/all, / filter, Enter details)",
                a.path.display(),
                if a.pending_only { "pending-only" } else { "all" },
                a.filtered_indices.len(),
                a.entries.len(),
                if a.time_display == TimeDisplay::Local {
                    "local"
                } else {
                    "epoch"
                }
            ))
            .borders(Borders::ALL),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("> ");

    let mut state = ratatui::widgets::TableState::default();
    if !a.filtered_indices.is_empty() {
        state.select(Some(a.selected));
    }
    frame.render_stateful_widget(table, area, &mut state);
}

fn draw_policy_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let Some(p) = app.policy.as_ref() else {
        frame.render_widget(
            Paragraph::new("Policy disabled; pass --policy <path>")
                .block(Block::default().title("Policy").borders(Borders::ALL)),
            area,
        );
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Min(8),
        ])
        .split(area);

    let action = if p.action == PolicyAction::Explain {
        "Explain"
    } else {
        "Trace"
    };
    frame.render_widget(
        Paragraph::new(format!(
            "Policy {} | action={} (t toggle) | e edit req | m edit steps ({}) | Enter run",
            p.path.display(),
            action,
            p.max_steps_input
        ))
        .block(Block::default().borders(Borders::ALL)),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(sanitize_request_text(&p.request_input))
            .block(Block::default().title("Request JSON").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new(p.output.clone())
            .block(Block::default().title("Result").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[2],
    );
}

fn draw_help_tab(frame: &mut Frame, area: ratatui::layout::Rect) {
    let p = Paragraph::new(Text::from(help_lines()))
        .block(Block::default().title("Help").borders(Borders::ALL));
    frame.render_widget(p, area);
}

fn draw_help_overlay(frame: &mut Frame) {
    let area = centered_rect(80, 60, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(Text::from(help_lines()))
            .block(Block::default().title("Help Overlay").borders(Borders::ALL)),
        area,
    );
}

fn help_lines() -> Vec<Line<'static>> {
    vec![
        Line::from("q quit | Tab/Shift+Tab switch tabs | ? help overlay"),
        Line::from("j/k or arrows move selection"),
        Line::from("Setup: Enter select, c copy snippet, w write config, s show run cmds"),
        Line::from("Audit: / filter, Enter toggle detail, T toggle local/epoch time"),
        Line::from("Approvals: / filter, a approve, d deny, p pending/all, T time, Enter detail"),
        Line::from("Policy: t toggle explain/trace, e/m edit, Enter run"),
        Line::from("r reload files"),
    ]
}

fn draw_modal(frame: &mut Frame, modal: &Modal) {
    let area = centered_rect(70, 55, frame.area());
    frame.render_widget(Clear, area);
    let (title, body) = match modal {
        Modal::Info(msg) => ("Info", msg.clone()),
        Modal::Token {
            approval_id,
            details,
            token,
            revealed,
            copy_status,
        } => {
            let shown = if *revealed {
                token.clone()
            } else {
                "[hidden]".to_string()
            };
            let mut body = String::new();
            if let Some(details) = details {
                body.push_str(details);
                body.push_str("\n\n");
            }
            body.push_str(&format!(
                "Approved: {}\n\nToken: {}\n\nPress c to reveal/copy token. Esc closes.\n{}",
                approval_id, shown, copy_status
            ));
            ("Approval Token", body)
        }
    };
    frame.render_widget(
        Paragraph::new(truncate_text(&body, MAX_MODAL_TEXT))
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn current_tab(app: &App) -> TabKind {
    app.tabs[app.active_tab]
}

fn tab_name(tab: TabKind) -> &'static str {
    match tab {
        TabKind::Setup => "Setup",
        TabKind::Audit => "Audit",
        TabKind::Approvals => "Approvals",
        TabKind::Policy => "Policy",
        TabKind::Help => "Help",
    }
}
fn selected_audit_detail(a: &AuditState, max_detail: usize) -> String {
    let Some(ev) = a
        .filtered_indices
        .get(a.selected)
        .and_then(|idx| a.events.get(*idx))
    else {
        return "No selection".to_string();
    };
    let redacted = redact_value(&ev.raw);
    let pretty = serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| redacted.to_string());
    truncate_text(&pretty, max_detail)
}

fn format_approval_detail_text(detail: &Value, display: TimeDisplay, max_detail: usize) -> String {
    let created = detail
        .get("created_at")
        .and_then(Value::as_u64)
        .map(|v| {
            (
                format_event_time(Some(v.saturating_mul(1000)), display),
                v.to_string(),
            )
        })
        .unwrap_or_else(|| ("-".to_string(), "-".to_string()));
    let decision = detail
        .get("decision_at")
        .and_then(Value::as_u64)
        .map(|v| {
            (
                format_event_time(Some(v.saturating_mul(1000)), display),
                v.to_string(),
            )
        })
        .unwrap_or_else(|| ("-".to_string(), "-".to_string()));
    let summary_obj = detail.get("summary").cloned().unwrap_or(Value::Null);
    let summary_pretty =
        serde_json::to_string_pretty(&summary_obj).unwrap_or_else(|_| "-".to_string());
    let text = format!(
        "id: {}\ndigest: {}\nstatus: {}\nmethod: {}\ntool: {}\nclient: {}\ncreated: {} (epoch {})\ndecision_at: {} (epoch {})\n\nsummary:\n{}",
        detail.get("approval_request_id").and_then(Value::as_str).unwrap_or("-"),
        detail.get("request_digest").and_then(Value::as_str).unwrap_or("-"),
        detail.get("status").and_then(Value::as_str).unwrap_or("-"),
        detail.get("mcp_method").and_then(Value::as_str).unwrap_or("-"),
        detail.get("tool").and_then(Value::as_str).unwrap_or("-"),
        detail.get("client_id").and_then(Value::as_str).unwrap_or("-"),
        created.0,
        created.1,
        decision.0,
        decision.1,
        summary_pretty
    );
    truncate_text(&text, max_detail)
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn format_event_time(ts_ms: Option<u64>, display: TimeDisplay) -> String {
    let Some(ms) = ts_ms else {
        return "?".to_string();
    };
    match display {
        TimeDisplay::Epoch => (ms / 1000).to_string(),
        TimeDisplay::Local => match i64::try_from(ms) {
            Ok(ms_i64) => Local
                .timestamp_millis_opt(ms_i64)
                .single()
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "?".to_string()),
            Err(_) => "?".to_string(),
        },
    }
}

fn default_policy_request() -> String {
    json!({
        "client_id": "alice",
        "auth_verified": true,
        "mcp_method": "tools/call",
        "tool": "views.query",
        "args": {"view": "notes_recent"}
    })
    .to_string()
}

fn truncate_text(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

fn sanitize_request_text(raw: &str) -> String {
    match serde_json::from_str::<Value>(raw) {
        Ok(v) => {
            let redacted = redact_value(&v);
            serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| redacted.to_string())
        }
        Err(_) => mask_sensitive_text(raw),
    }
}

fn redact_value(value: &Value) -> Value {
    fn walk(v: &Value, key_hint: Option<&str>) -> Value {
        match v {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, vv) in map {
                    out.insert(k.clone(), walk(vv, Some(k)));
                }
                Value::Object(out)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(|x| walk(x, key_hint)).collect()),
            Value::String(s) => {
                let sensitive =
                    key_hint.map(is_sensitive_key).unwrap_or(false) || looks_like_token_value(s);
                if sensitive {
                    Value::String("[REDACTED]".to_string())
                } else {
                    Value::String(s.clone())
                }
            }
            _ => v.clone(),
        }
    }
    walk(value, None)
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("token") || lower.contains("authorization") || lower.contains("bearer")
}

fn looks_like_token_value(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    lower.starts_with("bearer ") || lower.starts_with("v1:apr_")
}

fn mask_sensitive_text(raw: &str) -> String {
    let mut out = raw.to_string();
    for key in ["token", "authorization", "bearer"] {
        let needle = format!("\"{}\"", key);
        out = mask_after_key(&out, &needle);
        let upper = format!("\"{}\"", key.to_ascii_uppercase());
        out = mask_after_key(&out, &upper);
    }
    out
}

fn mask_after_key(input: &str, key_quoted: &str) -> String {
    let mut out = String::new();
    let mut rest = input;
    while let Some(pos) = rest.find(key_quoted) {
        let split = pos + key_quoted.len();
        let (head, tail) = rest.split_at(split);
        out.push_str(head);
        let mut t = tail;
        if let Some(colon_pos) = t.find(':') {
            let (before_colon, after_colon) = t.split_at(colon_pos + 1);
            out.push_str(before_colon);
            t = after_colon;
            let trimmed = t.trim_start();
            let ws_len = t.len() - trimmed.len();
            out.push_str(&t[..ws_len]);
            if let Some(stripped) = trimmed.strip_prefix('"') {
                if let Some(end_pos) = stripped.find('"') {
                    out.push_str("\"[REDACTED]\"");
                    rest = &trimmed[(end_pos + 2)..];
                    continue;
                }
            }
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_invalid_lines_are_skipped() {
        let mut s = AuditState {
            path: PathBuf::from("dummy"),
            events: vec![],
            invalid_lines: 0,
            filtered_indices: vec![],
            selected: 0,
            filter: String::new(),
            detail_open: false,
            last_len: 0,
            partial: String::new(),
            time_display: TimeDisplay::Local,
            last_seen_time: "-".to_string(),
            last_seen_tool: "-".to_string(),
        };
        push_audit_line(&mut s, "{not-json");
        push_audit_line(&mut s, "{\"ts_unix_ms\":1,\"tool\":\"views.query\"}");
        assert_eq!(s.invalid_lines, 1);
        assert_eq!(s.events.len(), 1);
        assert_eq!(s.events[0].tool, "views.query");
    }

    #[test]
    fn redacts_token_keys() {
        let v = json!({"approvalToken":"abc","nested":{"authorization":"Bearer x"}});
        let r = redact_value(&v);
        assert_eq!(r["approvalToken"], "[REDACTED]");
        assert_eq!(r["nested"]["authorization"], "[REDACTED]");
    }

    #[test]
    fn time_formatter_handles_seconds_and_milliseconds() {
        let sec_event = summarize_audit_event(json!({
            "ts_unix_ms": 1_700_000_000u64,
            "tool": "views.query"
        }));
        let ms_event = summarize_audit_event(json!({
            "ts_unix_ms": 1_700_000_000_000u64,
            "tool": "views.query"
        }));
        assert_eq!(
            format_event_time(sec_event.time_ms, TimeDisplay::Epoch),
            "1700000000"
        );
        assert_eq!(
            format_event_time(ms_event.time_ms, TimeDisplay::Epoch),
            "1700000000"
        );
    }

    #[test]
    fn summarize_reads_nested_fallback_fields() {
        let summary = summarize_audit_event(json!({
            "ts_unix_s": 10,
            "meta": {"client_id": "nested-client", "rule_id": "r-1"},
            "request": {"method": "tools/call", "params": {"name": "views.query"}},
            "error": {"code": -32040, "data": {"rule_id": "r-2"}}
        }));
        assert_eq!(summary.tool, "views.query");
        assert_eq!(summary.client, "nested-client");
        assert_eq!(summary.rule, "r-1");
        assert_eq!(summary.code, "-32040");
    }

    #[test]
    fn approvals_default_pending_only_and_p_toggle_behavior() {
        let mut state = ApprovalsState {
            path: PathBuf::from("dummy"),
            entries: vec![
                ApprovalSummary {
                    created_at: Some(10),
                    status: "pending".to_string(),
                    tool: "files.write".to_string(),
                    method: "tools/call".to_string(),
                    client: "Codex CLI".to_string(),
                    summary: "notes/x.txt (5B)".to_string(),
                    id: "apr_1".to_string(),
                    digest: "abc".to_string(),
                },
                ApprovalSummary {
                    created_at: Some(11),
                    status: "approved".to_string(),
                    tool: "files.write".to_string(),
                    method: "tools/call".to_string(),
                    client: "Codex CLI".to_string(),
                    summary: "notes/x.txt (5B)".to_string(),
                    id: "apr_2".to_string(),
                    digest: "def".to_string(),
                },
            ],
            filtered_indices: vec![],
            selected: 0,
            filter: String::new(),
            pending_only: true,
            time_display: TimeDisplay::Local,
        };
        apply_approvals_filter(&mut state);
        assert_eq!(state.filtered_indices, vec![0]);

        state.pending_only = false;
        apply_approvals_filter(&mut state);
        assert_eq!(state.filtered_indices, vec![0, 1]);
    }
}
