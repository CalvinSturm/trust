use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_profiles::{
    default_config_path, detect_agents, generate_manual_command_line, generate_mcp_server_snippet,
    write_config, AgentKind, DetectedAgent, RoutingPaths,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::Value;

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_RUN_DIR: &str = ".trust/run";
const SENTINEL: &str = "UP_SHOULD_NOT_LEAK";

#[derive(Debug, Parser)]
#[command(name = "trust-up")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Up(UpArgs),
    Plan(PlanArgs),
    Policy(PolicyArgs),
}

#[derive(Debug, Clone, Args)]
struct CommonArgs {
    #[arg(long, default_value = DEFAULT_RUN_DIR)]
    dir: PathBuf,
    #[arg(long)]
    force: bool,
    #[arg(long, conflicts_with = "no_console")]
    console: bool,
    #[arg(long, conflicts_with = "console")]
    no_console: bool,
    #[arg(long)]
    no_stack: bool,
    #[arg(long)]
    gateway: Option<PathBuf>,
    #[arg(long)]
    toolfw: Option<PathBuf>,
    #[arg(long)]
    console_bin: Option<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
    timeout_ms: u64,
    #[arg(long)]
    verbose: bool,
    #[arg(long, value_enum, default_value_t = AgentChoice::Auto)]
    agent: AgentChoice,
    #[arg(long, default_value_t = true)]
    write_agent_config: bool,
    #[arg(long, default_value_t = true)]
    print_agent_snippet: bool,
    #[arg(long, value_enum, default_value_t = PolicyModeArg::Auto)]
    mode: PolicyModeArg,
}

#[derive(Debug, Clone, Args)]
struct UpArgs {
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Debug, Clone, Args)]
struct PlanArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Clone, Subcommand)]
enum PolicyCommand {
    Set(PolicySetArgs),
}

#[derive(Debug, Clone, Args)]
struct PolicySetArgs {
    #[arg(long, default_value = DEFAULT_RUN_DIR)]
    dir: PathBuf,
    #[arg(value_enum)]
    mode: PolicyPreset,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AgentChoice {
    Auto,
    Codex,
    Claude,
    Openclaw,
    Other,
    None,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PolicyModeArg {
    Auto,
    Observe,
    Guarded,
    Strict,
}

#[derive(Debug, Clone, Copy)]
enum PolicyMode {
    Observe,
    Guarded,
    Strict,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PolicyPreset {
    Observe,
    Guarded,
    Strict,
}

impl PolicyMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Guarded => "guarded",
            Self::Strict => "strict",
        }
    }
}

impl From<PolicyPreset> for PolicyMode {
    fn from(value: PolicyPreset) -> Self {
        match value {
            PolicyPreset::Observe => Self::Observe,
            PolicyPreset::Guarded => Self::Guarded,
            PolicyPreset::Strict => Self::Strict,
        }
    }
}

#[derive(Debug, Clone)]
struct RunPaths {
    data_dir: PathBuf,
    out_dir: PathBuf,
    audit_dir: PathBuf,
    mounts_path: PathBuf,
    views_path: PathBuf,
    policy_path: PathBuf,
    audit_path: PathBuf,
    checkpoint_path: PathBuf,
    approvals_path: PathBuf,
}

#[derive(Debug, Clone)]
struct AgentSelection {
    selected: Option<DetectedAgent>,
    detected: Vec<DetectedAgent>,
}

#[derive(Debug, Clone)]
struct AgentWriteResult {
    path: PathBuf,
    wrote: bool,
    backup: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct PersistedAgents {
    run_dir: String,
    preselected_agent: Option<String>,
    agents: Vec<PersistedAgent>,
}

#[derive(Debug, Serialize)]
struct PersistedAgent {
    kind: String,
    display_name: String,
    detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exe_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct PlanReport {
    mode: String,
    security_mode: String,
    run_dir: String,
    stack_enabled: bool,
    console_enabled: bool,
    approvals_schema_version: String,
    binaries: BinaryPlan,
    paths: PathPlan,
    commands: CommandPlan,
    agent: AgentPlan,
}

#[derive(Debug, Serialize)]
struct BinaryPlan {
    toolfw: String,
    gateway: String,
    console: String,
}

#[derive(Debug, Serialize)]
struct PathPlan {
    data_dir: String,
    mounts_path: String,
    views_path: String,
    policy_path: String,
    audit_path: String,
    checkpoint_path: String,
    approvals_path: String,
}

#[derive(Debug, Serialize)]
struct CommandPlan {
    stack_argv: Vec<String>,
    console_argv: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AgentPlan {
    requested: String,
    selected: Option<String>,
    selected_config_path: Option<String>,
    config_write_status: String,
    detected: Vec<String>,
}

fn main() -> std::process::ExitCode {
    let mut argv = std::env::args().collect::<Vec<_>>();
    if argv.len() == 1 || argv.get(1).is_some_and(|x| x.starts_with('-')) {
        argv.insert(1, "up".to_string());
    }

    let cli = match Cli::try_parse_from(argv) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::from(2);
        }
    };

    let result = match cli.command {
        Commands::Up(args) => run_up(args.common),
        Commands::Plan(args) => run_plan(args),
        Commands::Policy(args) => run_policy(args),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            let msg = error_chain(&e);
            if let Some(rest) = msg.strip_prefix("USAGE: ") {
                eprintln!("{rest}");
                std::process::ExitCode::from(2)
            } else {
                eprintln!("trust-up failed: {msg}");
                std::process::ExitCode::from(1)
            }
        }
    }
}

fn run_plan(args: PlanArgs) -> Result<()> {
    let plan = build_plan(&args.common)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("trust-up plan");
        println!("run_dir: {}", plan.run_dir);
        println!("security_mode: {}", plan.security_mode);
        println!("stack_enabled: {}", plan.stack_enabled);
        println!("console_enabled: {}", plan.console_enabled);
        println!(
            "approvals_schema_version: {}",
            plan.approvals_schema_version
        );
        println!("toolfw: {}", plan.binaries.toolfw);
        println!("gateway: {}", plan.binaries.gateway);
        println!("console: {}", plan.binaries.console);
        println!(
            "selected_agent: {}",
            plan.agent.selected.unwrap_or_else(|| "none".to_string())
        );
    }
    Ok(())
}

fn run_policy(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::Set(set) => {
            let mode: PolicyMode = set.mode.into();
            let paths = run_paths(&set.dir);
            let out_dir = paths
                .policy_path
                .parent()
                .ok_or_else(|| anyhow!("invalid run directory: missing out path"))?;
            fs::create_dir_all(out_dir)?;
            fs::write(&paths.policy_path, policy_for_mode(mode))?;
            println!(
                "policy updated: {} ({})",
                paths.policy_path.display(),
                mode.as_str()
            );
            Ok(())
        }
    }
}

fn run_up(args: CommonArgs) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop_flag = Arc::clone(&stop);
        ctrlc::set_handler(move || {
            stop_flag.store(true, Ordering::SeqCst);
        })
        .context("install ctrl+c handler")?;
    }

    let resolved_mode = resolve_policy_mode_for_up(&args)?;
    let run_dir = choose_run_dir(&args.dir, args.force)?;
    if !args.no_stack {
        create_run_layout(&run_dir, resolved_mode)?;
    }
    let paths = run_paths(&run_dir);
    let _ = toolfw_core::normalize_approval_store(&paths.approvals_path)?;

    let toolfw_bin = resolve_bin_arg(args.toolfw.as_deref(), "toolfw")?;
    let gateway_bin = resolve_bin_arg(args.gateway.as_deref(), "mcp-gateway")?;
    let console_bin = resolve_bin_arg(args.console_bin.as_deref(), "trust-console")?;

    let routing = RoutingPaths {
        policy_path: paths.policy_path.clone(),
        approval_store_path: paths.approvals_path.clone(),
        audit_path: paths.audit_path.clone(),
        checkpoint_path: paths.checkpoint_path.clone(),
        mounts_path: paths.mounts_path.clone(),
        views_path: paths.views_path.clone(),
        toolfw_bin: display_path(&toolfw_bin),
        gateway_bin: display_path(&gateway_bin),
    };

    let selection = select_agent_for_up(&args)?;
    write_agents_detected_file(&run_dir, &selection)?;
    print_agent_block(
        &selection.detected,
        selection.selected.as_ref(),
        &routing,
        args.print_agent_snippet,
    );

    let write_result = write_agent_config_if_requested(
        selection.selected.as_ref(),
        &routing,
        args.write_agent_config,
    )?;

    let timeout = Duration::from_millis(args.timeout_ms);
    let mut stack: Option<Child> = None;

    let selected_agent_label = selection
        .selected
        .as_ref()
        .map(|a| a.display_name.clone())
        .unwrap_or_else(|| "none".to_string());

    if !args.no_stack {
        let mut child = spawn_stack(
            &toolfw_bin,
            &gateway_bin,
            &paths,
            selected_agent_label.as_str(),
        )?;
        wait_stack_ready(&mut child, &paths, timeout)?;
        println!("stack started: {}", run_dir.display());
        print_next_steps(
            &run_dir,
            &toolfw_bin,
            &gateway_bin,
            &console_bin,
            &routing,
            selection.selected.as_ref(),
            args.print_agent_snippet,
        );
        stack = Some(child);
    } else {
        ensure_existing_layout(&paths)?;
    }

    if let Some(sel) = selection.selected.as_ref() {
        println!("selected agent: {}", sel.display_name);
    } else {
        println!("selected agent: none");
    }
    println!("security mode: {}", resolved_mode.as_str());
    if let Some(write_result) = write_result {
        if write_result.wrote {
            println!("agent config written: {}", write_result.path.display());
            if let Some(backup) = write_result.backup {
                println!("agent config backup: {}", backup.display());
            }
        } else {
            println!("agent config unchanged: {}", write_result.path.display());
        }
    }

    let should_launch_console = if args.no_console {
        false
    } else if args.console {
        true
    } else {
        io::stdin().is_terminal() && io::stdout().is_terminal()
    };

    if should_launch_console {
        let mut console = spawn_console(&console_bin, &run_dir, &selected_agent_label)?;
        loop {
            if stop.load(Ordering::SeqCst) {
                let _ = console.kill();
                let _ = console.wait();
                break;
            }
            if let Some(_status) = console.try_wait()? {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    } else if stack.is_some() {
        if args.no_console {
            println!("console disabled; press Ctrl+C to stop stack");
        } else {
            println!("console not launched (non-interactive session); press Ctrl+C to stop stack");
        }
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    if let Some(mut child) = stack {
        terminate_child(&mut child);
    }

    println!("run directory: {}", run_dir.display());
    Ok(())
}

fn choose_run_dir(base: &Path, force: bool) -> Result<PathBuf> {
    if !base.exists() {
        return Ok(base.to_path_buf());
    }
    if force {
        fs::remove_dir_all(base).with_context(|| format!("remove {}", base.display()))?;
        return Ok(base.to_path_buf());
    }

    let parent = base.parent().unwrap_or_else(|| Path::new("."));
    let name = base
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("run")
        .to_string();
    let bak_root = parent.join(format!("{name}.bak"));
    let rotated = bak_root.join(now_unix_secs().to_string());
    fs::create_dir_all(&bak_root)?;
    fs::rename(base, &rotated).with_context(|| {
        format!(
            "rotate existing run dir {} -> {}",
            base.display(),
            rotated.display()
        )
    })?;
    Ok(base.to_path_buf())
}

fn create_run_layout(root: &Path, mode: PolicyMode) -> Result<()> {
    let paths = run_paths(root);
    fs::create_dir_all(&paths.data_dir)?;
    fs::create_dir_all(&paths.out_dir)?;
    fs::create_dir_all(&paths.audit_dir)?;

    fs::write(paths.data_dir.join("hello.txt"), "hello world\n")?;
    fs::write(paths.data_dir.join(".env"), format!("SECRET={SENTINEL}\n"))?;
    fs::write(&paths.audit_path, "")?;
    fs::write(&paths.checkpoint_path, "")?;

    toolfw_core::normalize_approval_store(&paths.approvals_path)?;

    fs::write(
        &paths.mounts_path,
        format!(
            "mounts:\n  - name: data\n    root: \"{}\"\n    read_only: false\n",
            yaml_path(&paths.data_dir)
        ),
    )?;
    fs::write(
        &paths.views_path,
        "views:\n  - name: data_recent\n    tool: files.search\n    args:\n      mount: data\n      query: \"hello\"\n      max_results: 10\n      max_bytes: 20000\n",
    )?;
    fs::write(&paths.policy_path, policy_for_mode(mode))?;

    Ok(())
}

fn resolve_policy_mode_for_up(args: &CommonArgs) -> Result<PolicyMode> {
    match args.mode {
        PolicyModeArg::Observe => Ok(PolicyMode::Observe),
        PolicyModeArg::Guarded => Ok(PolicyMode::Guarded),
        PolicyModeArg::Strict => Ok(PolicyMode::Strict),
        PolicyModeArg::Auto => {
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                return Ok(PolicyMode::Guarded);
            }
            choose_mode_interactive()
        }
    }
}

fn resolve_policy_mode_for_plan(args: &CommonArgs) -> PolicyMode {
    match args.mode {
        PolicyModeArg::Observe => PolicyMode::Observe,
        PolicyModeArg::Guarded => PolicyMode::Guarded,
        PolicyModeArg::Strict => PolicyMode::Strict,
        PolicyModeArg::Auto => PolicyMode::Guarded,
    }
}

fn choose_mode_interactive() -> Result<PolicyMode> {
    println!("Select security mode:");
    println!("  1) Safe (Recommended) - deny secret reads, require approval for writes");
    println!("  2) Balanced - audit all calls, allow by default");
    println!("  3) Strict - approvals for reads and writes");
    print!("Choice [1/2/3] (default 1): ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim();
    let mode = match choice {
        "2" | "balanced" | "observe" => PolicyMode::Observe,
        "3" | "strict" => PolicyMode::Strict,
        _ => PolicyMode::Guarded,
    };
    Ok(mode)
}

fn policy_for_mode(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Observe => {
            "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - id: allow_all_tools_observe\n    match:\n      mcp_method: \"tools/call\"\n    decision: allow\n"
        }
        PolicyMode::Guarded => {
            "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - id: deny_secret_env_reads\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n      args:\n        path_glob: \"**/.env*\"\n    decision: deny\n\n  - id: deny_key_material_reads\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n      args:\n        path_glob: \"**/*.{pem,key,p12,pfx,der}\"\n    decision: deny\n\n  - id: deny_ssh_reads\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n      args:\n        path_glob: \"**/.ssh/**\"\n    decision: deny\n\n  - id: require_approval_for_writes\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"files.write\"\n    decision: require_approval\n\n  - id: allow_regular_reads\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n    decision: allow\n\n  - id: allow_search\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"files.search\"\n    decision: allow\n\n  - id: allow_views\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"views.query\"\n    decision: allow\n\n  - id: allow_sqlite_query\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"sqlite.query\"\n    decision: allow\n\n  - id: allow_git_observe\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"git.*\"\n    decision: allow\n"
        }
        PolicyMode::Strict => {
            "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - id: allow_views\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"views.query\"\n      args:\n        view: \"data_recent\"\n    decision: allow\n\n  - id: require_approval_reads\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n    decision: require_approval\n\n  - id: require_approval_writes\n    match:\n      mcp_method: \"tools/call\"\n      tool: \"files.write\"\n    decision: require_approval\n"
        }
    }
}

fn ensure_existing_layout(paths: &RunPaths) -> Result<()> {
    for path in [
        &paths.audit_path,
        &paths.checkpoint_path,
        &paths.approvals_path,
        &paths.policy_path,
    ] {
        if !path.exists() {
            bail!(
                "--no-stack requires existing artifacts; missing {}",
                path.display()
            );
        }
    }
    let _ = toolfw_core::normalize_approval_store(&paths.approvals_path)?;
    Ok(())
}

fn run_paths(root: &Path) -> RunPaths {
    let data_dir = root
        .parent()
        .map(|p| p.join("data"))
        .unwrap_or_else(|| root.join("data"));
    let out_dir = root.join("out");
    let audit_dir = root.join("audit");
    RunPaths {
        data_dir,
        out_dir: out_dir.clone(),
        audit_dir: audit_dir.clone(),
        mounts_path: out_dir.join("gateway.mounts.yaml"),
        views_path: out_dir.join("gateway.views.yaml"),
        policy_path: out_dir.join("toolfw.policy.yaml"),
        audit_path: audit_dir.join("audit.jsonl"),
        checkpoint_path: audit_dir.join("audit.checkpoint.json"),
        approvals_path: root.join("approvals.json"),
    }
}

fn spawn_stack(
    toolfw_bin: &Path,
    gateway_bin: &Path,
    paths: &RunPaths,
    client_label: &str,
) -> Result<Child> {
    let mut cmd = Command::new(toolfw_bin);
    cmd.arg("proxy")
        .arg("stdio")
        .arg("--policy")
        .arg(&paths.policy_path)
        .arg("--approval-store")
        .arg(&paths.approvals_path)
        .arg("--audit")
        .arg(&paths.audit_path)
        .arg("--audit-checkpoint")
        .arg(&paths.checkpoint_path)
        .arg("--client-label")
        .arg(client_label)
        .arg("--")
        .arg(gateway_bin)
        .arg("--mounts")
        .arg(&paths.mounts_path)
        .arg("--views")
        .arg(&paths.views_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    cmd.spawn().context("spawn toolfw proxy stack")
}

fn wait_stack_ready(child: &mut Child, paths: &RunPaths, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("stack exited during startup with status {}", status);
        }

        if paths.audit_path.exists() && paths.checkpoint_path.exists() {
            return Ok(());
        }

        if started.elapsed() >= timeout {
            bail!("stack startup timed out after {} ms", timeout.as_millis());
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_console(console_bin: &Path, run_dir: &Path, agent_label: &str) -> Result<Child> {
    Command::new(console_bin)
        .arg("--run-dir")
        .arg(run_dir)
        .arg("--setup")
        .arg("--agent-label")
        .arg(agent_label)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn trust-console")
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn resolve_bin_arg(override_path: Option<&Path>, name: &str) -> Result<PathBuf> {
    if let Some(path) = override_path {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        bail!("binary override does not exist: {}", path.display());
    }
    resolve_bin(name)
}

fn resolve_bin(name: &str) -> Result<PathBuf> {
    let env_key = format!("CARGO_BIN_EXE_{name}");
    if let Ok(path) = std::env::var(&env_key) {
        let p = PathBuf::from(path);
        if p.is_file() {
            return Ok(p);
        }
    }

    let exe = std::env::current_exe().context("resolve current executable path")?;
    let mut candidates = Vec::new();
    if let Some(parent) = exe.parent() {
        candidates.push(parent.join(bin_file_name(name)));
        if let Some(grand) = parent.parent() {
            candidates.push(grand.join(bin_file_name(name)));
        }
    }
    for c in candidates {
        if c.is_file() {
            return Ok(c);
        }
    }

    Ok(PathBuf::from(bin_file_name(name)))
}

fn bin_file_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn detect_agents_for_runtime() -> Vec<DetectedAgent> {
    if let Ok(raw) = std::env::var("TRUST_AGENT_DETECT") {
        let lower = raw.to_ascii_lowercase();
        if lower.trim() == "none" {
            return detect_agents()
                .into_iter()
                .map(|mut a| {
                    a.detected = false;
                    a.exe_path = None;
                    a
                })
                .collect();
        }
        let wants = lower
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let mut agents = detect_agents();
        for agent in &mut agents {
            let key = match agent.kind {
                AgentKind::CodexCli => "codex",
                AgentKind::ClaudeCode => "claude",
                AgentKind::OpenClaw => "openclaw",
                AgentKind::OtherMcp => "other",
            };
            if wants.contains(&key) {
                agent.detected = true;
                if agent.exe_path.is_none() && !matches!(agent.kind, AgentKind::OtherMcp) {
                    agent.exe_path = Some(PathBuf::from(bin_file_name(key)));
                }
            } else {
                agent.detected = false;
                agent.exe_path = None;
            }
        }
        return agents;
    }
    detect_agents()
}

fn select_agent_for_up(args: &CommonArgs) -> Result<AgentSelection> {
    let agents = detect_agents_for_runtime();
    let mut selected = select_agent(&agents, args.agent);
    if matches!(args.agent, AgentChoice::Auto)
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && agents.iter().filter(|a| a.detected).count() > 1
    {
        selected = prompt_agent_choice(&agents)?;
    }
    Ok(AgentSelection {
        selected: selected.cloned(),
        detected: agents,
    })
}

fn prompt_agent_choice(agents: &[DetectedAgent]) -> Result<Option<&DetectedAgent>> {
    let detected = agents
        .iter()
        .enumerate()
        .filter(|(_, a)| a.detected)
        .collect::<Vec<_>>();
    if detected.is_empty() {
        return Ok(None);
    }
    if detected.len() == 1 {
        return Ok(Some(detected[0].1));
    }
    println!("Multiple MCP client targets detected. Select one:");
    for (i, (_, a)) in detected.iter().enumerate() {
        println!("  {}. {}", i + 1, a.display_name);
    }
    print!("> ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let idx = line.trim().parse::<usize>().unwrap_or(1);
    let pick = idx.saturating_sub(1).min(detected.len() - 1);
    Ok(Some(detected[pick].1))
}

fn select_agent(agents: &[DetectedAgent], choice: AgentChoice) -> Option<&DetectedAgent> {
    match choice {
        AgentChoice::None => None,
        AgentChoice::Codex => agents.iter().find(|a| a.kind == AgentKind::CodexCli),
        AgentChoice::Claude => agents.iter().find(|a| a.kind == AgentKind::ClaudeCode),
        AgentChoice::Openclaw => agents.iter().find(|a| a.kind == AgentKind::OpenClaw),
        AgentChoice::Other => agents.iter().find(|a| a.kind == AgentKind::OtherMcp),
        AgentChoice::Auto => {
            let detected = agents.iter().filter(|a| a.detected).collect::<Vec<_>>();
            if detected.len() == 1 {
                Some(detected[0])
            } else {
                None
            }
        }
    }
}

fn print_agent_block(
    agents: &[DetectedAgent],
    selected: Option<&DetectedAgent>,
    routing: &RoutingPaths,
    print_snippet: bool,
) {
    println!("agent wiring:");
    if let Some(agent) = selected {
        println!("selected: {}", agent.display_name);
        let others = agents
            .iter()
            .filter(|a| a.detected && a.kind != agent.kind)
            .map(|a| a.display_name.clone())
            .collect::<Vec<_>>();
        if !others.is_empty() {
            println!("also detected: {}", others.join(", "));
        }
        if print_snippet {
            let snippet = generate_mcp_server_snippet(agent.kind, routing);
            println!("snippet:\n{}", snippet);
        }
        if let Some(path) = &agent.config_path {
            println!("config path: {}", path.display());
        } else {
            println!("config path: not auto-detected");
        }
        println!(
            "manual stack cmd:\n{}",
            generate_manual_command_line(routing)
        );
    } else {
        println!("selected: none");
        let detected = agents
            .iter()
            .filter(|a| a.detected)
            .map(|a| a.display_name.as_str())
            .collect::<Vec<_>>();
        if detected.is_empty() {
            println!("no supported agent CLI detected on PATH");
        } else {
            println!("detected agents: {}", detected.join(", "));
        }
    }
}

fn write_agent_config_if_requested(
    selected: Option<&DetectedAgent>,
    routing: &RoutingPaths,
    required: bool,
) -> Result<Option<AgentWriteResult>> {
    if !required {
        return Ok(None);
    }

    let Some(agent) = selected else {
        bail!(
            "USAGE: --write-agent-config requires a resolved agent. Open trust-console --run-dir <dir> Setup tab to select and write config."
        );
    };

    let project_root = std::env::current_dir().context("resolve current project directory")?;
    let target = agent
        .config_path
        .clone()
        .or_else(|| default_config_path(agent.kind, &project_root))
        .ok_or_else(|| {
            anyhow!(
                "USAGE: selected agent has no discovered config path. Open trust-console --run-dir <dir> Setup tab to write config."
            )
        })?;

    let wrote = write_config(agent.kind, &target, routing, &project_root)?;

    Ok(Some(AgentWriteResult {
        path: wrote.path,
        wrote: true,
        backup: wrote.backup_path,
    }))
}

fn write_json_atomic(path: &Path, value: &Value) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.tmp", now_unix_secs()));
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn build_plan(args: &CommonArgs) -> Result<PlanReport> {
    let run_dir = args.dir.clone();
    let policy_mode = resolve_policy_mode_for_plan(args);
    let paths = run_paths(&run_dir);
    let toolfw = resolve_bin_arg(args.toolfw.as_deref(), "toolfw")?;
    let gateway = resolve_bin_arg(args.gateway.as_deref(), "mcp-gateway")?;
    let console = resolve_bin_arg(args.console_bin.as_deref(), "trust-console")?;

    let selection = select_agent_for_plan(args);
    let agent_label = selection
        .selected
        .as_ref()
        .map(|a| a.display_name.clone())
        .unwrap_or_else(|| "none".to_string());

    let console_argv = vec![
        display_path(&console),
        "--run-dir".to_string(),
        display_path(&run_dir),
        "--setup".to_string(),
        "--agent-label".to_string(),
        agent_label,
    ];
    let stack_client_label = selection
        .selected
        .as_ref()
        .map(|a| a.display_name.clone())
        .unwrap_or_else(|| "none".to_string());

    let stack_argv = vec![
        display_path(&toolfw),
        "proxy".to_string(),
        "stdio".to_string(),
        "--policy".to_string(),
        display_path(&paths.policy_path),
        "--approval-store".to_string(),
        display_path(&paths.approvals_path),
        "--audit".to_string(),
        display_path(&paths.audit_path),
        "--audit-checkpoint".to_string(),
        display_path(&paths.checkpoint_path),
        "--client-label".to_string(),
        stack_client_label,
        "--".to_string(),
        display_path(&gateway),
        "--mounts".to_string(),
        display_path(&paths.mounts_path),
        "--views".to_string(),
        display_path(&paths.views_path),
    ];

    Ok(PlanReport {
        mode: "plan".to_string(),
        security_mode: policy_mode.as_str().to_string(),
        run_dir: display_path(&run_dir),
        stack_enabled: !args.no_stack,
        console_enabled: !args.no_console,
        approvals_schema_version: toolfw_core::approval_store_schema_version().to_string(),
        binaries: BinaryPlan {
            toolfw: display_path(&toolfw),
            gateway: display_path(&gateway),
            console: display_path(&console),
        },
        paths: PathPlan {
            data_dir: display_path(&paths.data_dir),
            mounts_path: display_path(&paths.mounts_path),
            views_path: display_path(&paths.views_path),
            policy_path: display_path(&paths.policy_path),
            audit_path: display_path(&paths.audit_path),
            checkpoint_path: display_path(&paths.checkpoint_path),
            approvals_path: display_path(&paths.approvals_path),
        },
        commands: CommandPlan {
            stack_argv,
            console_argv,
        },
        agent: AgentPlan {
            requested: format!("{:?}", args.agent).to_ascii_lowercase(),
            selected: selection.selected.as_ref().map(|a| a.display_name.clone()),
            selected_config_path: planned_config_target(selection.selected.as_ref())
                .map(|p| p.display().to_string()),
            config_write_status: if args.write_agent_config {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            },
            detected: selection
                .detected
                .iter()
                .filter(|a| a.detected)
                .map(|a| a.display_name.clone())
                .collect(),
        },
    })
}

fn planned_config_target(selected: Option<&DetectedAgent>) -> Option<PathBuf> {
    let agent = selected?;
    if let Some(path) = agent.config_path.clone() {
        return Some(path);
    }
    let root = std::env::current_dir().ok()?;
    default_config_path(agent.kind, &root)
}

fn select_agent_for_plan(args: &CommonArgs) -> AgentSelection {
    let agents = detect_agents_for_runtime();
    AgentSelection {
        selected: select_agent(&agents, args.agent).cloned(),
        detected: agents,
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_agents_detected_file(run_dir: &Path, selection: &AgentSelection) -> Result<()> {
    let out = run_dir.join("out");
    fs::create_dir_all(&out)?;
    let path = out.join("agents.detected.json");
    let value = PersistedAgents {
        run_dir: run_dir.display().to_string(),
        preselected_agent: selection.selected.as_ref().map(|a| a.display_name.clone()),
        agents: selection
            .detected
            .iter()
            .map(|a| PersistedAgent {
                kind: agent_kind_name(a.kind).to_string(),
                display_name: a.display_name.clone(),
                detected: a.detected,
                exe_path: a.exe_path.as_ref().map(|p| p.display().to_string()),
                config_path: a.config_path.as_ref().map(|p| p.display().to_string()),
            })
            .collect(),
    };
    write_json_atomic(&path, &serde_json::to_value(value)?)?;
    Ok(())
}

fn print_next_steps(
    run_dir: &Path,
    toolfw_bin: &Path,
    gateway_bin: &Path,
    console_bin: &Path,
    routing: &RoutingPaths,
    selected: Option<&DetectedAgent>,
    print_snippet: bool,
) {
    println!("Stack is running");
    println!("Run dir: {}", run_dir.display());
    println!(
        "Open console: {} --run-dir {}",
        toolfw_quote(console_bin),
        toolfw_quote(run_dir)
    );
    if print_snippet {
        if let Some(agent) = selected {
            println!(
                "Agent wiring snippet ({}):\n{}",
                agent.display_name,
                generate_mcp_server_snippet(agent.kind, routing)
            );
        } else {
            println!("Agent wiring snippet: select in trust-console Setup tab");
        }
    }
    let client_label = selected
        .map(|agent| agent.display_name.as_str())
        .unwrap_or("none");
    println!(
        "Manual stack command:\n{} proxy stdio --policy {} --approval-store {} --audit {} --audit-checkpoint {} --client-label {} -- {} --mounts {} --views {}",
        toolfw_quote(toolfw_bin),
        toolfw_quote(&routing.policy_path),
        toolfw_quote(&routing.approval_store_path),
        toolfw_quote(&routing.audit_path),
        toolfw_quote(&routing.checkpoint_path),
        shell_quote(client_label),
        toolfw_quote(gateway_bin),
        toolfw_quote(&routing.mounts_path),
        toolfw_quote(&routing.views_path),
    );
}

fn toolfw_quote(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.contains(' ') {
        format!("\"{s}\"")
    } else {
        s.to_string()
    }
}

fn shell_quote(value: &str) -> String {
    if value.contains(' ') {
        format!("\"{value}\"")
    } else {
        value.to_string()
    }
}

fn agent_kind_name(kind: AgentKind) -> &'static str {
    match kind {
        AgentKind::ClaudeCode => "claude",
        AgentKind::CodexCli => "codex",
        AgentKind::OpenClaw => "openclaw",
        AgentKind::OtherMcp => "other",
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn yaml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "\\\\")
}

fn error_chain(err: &anyhow::Error) -> String {
    let mut out = String::new();
    for (idx, cause) in err.chain().enumerate() {
        if idx > 0 {
            out.push_str(": ");
        }
        out.push_str(&cause.to_string());
    }
    out
}
