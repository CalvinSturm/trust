use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::{json, Value};

const DEFAULT_TIMEOUT_MS: u64 = 15_000;
const MAX_JSON_LINE_BYTES: usize = 1_048_576;
const MAX_STEP_DETAILS: usize = 400;
const PRIVACY_SENTINEL: &str = "SMOKE_SHOULD_NOT_LEAK";
const TOOLFW_DENIED: i64 = -32040;
const TOOLFW_APPROVAL_REQUIRED: i64 = -32041;

#[derive(Debug, Parser)]
#[command(name = "trust-smoke")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
enum Commands {
    Stdio(StdioArgs),
}

#[derive(Debug, Clone, Args)]
struct StdioArgs {
    #[arg(long)]
    keep_temp: bool,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
    timeout_ms: u64,
    #[arg(long)]
    use_signed_audit: bool,
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Serialize)]
struct SmokeReport {
    ok: bool,
    steps: Vec<StepReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temp_dir: Option<String>,
}

#[derive(Debug, Serialize)]
struct StepReport {
    name: String,
    ok: bool,
    duration_ms: u64,
    details: String,
}

#[derive(Debug)]
struct SmokePaths {
    root: PathBuf,
    sandbox_dir: PathBuf,
    approvals_path: PathBuf,
    mounts_path: PathBuf,
    views_path: PathBuf,
    policy_path: PathBuf,
    audit_path: PathBuf,
    checkpoint_path: PathBuf,
    signing_key_path: Option<PathBuf>,
}

struct RunningStack {
    child: Child,
    rpc: RpcClient,
}

impl RunningStack {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct RpcClient {
    stdin: ChildStdin,
    rx: Receiver<Result<Value>>,
    pending: HashMap<String, Value>,
    verbose: bool,
}

impl RpcClient {
    fn new(stdin: ChildStdin, stdout: impl std::io::Read + Send + 'static, verbose: bool) -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if line.len() > MAX_JSON_LINE_BYTES {
                            let _ = tx.send(Err(anyhow!(
                                "response line exceeded {} bytes",
                                MAX_JSON_LINE_BYTES
                            )));
                            break;
                        }
                        if line.ends_with(b"\n") {
                            line.pop();
                        }
                        if line.ends_with(b"\r") {
                            line.pop();
                        }
                        if line.is_empty() {
                            continue;
                        }
                        let text = match String::from_utf8(line) {
                            Ok(s) => s,
                            Err(e) => {
                                let _ = tx.send(Err(anyhow!("response was not utf-8: {e}")));
                                break;
                            }
                        };
                        let parsed = serde_json::from_str::<Value>(&text)
                            .with_context(|| "parse JSON-RPC response line");
                        if tx.send(parsed).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(anyhow!("read response: {e}")));
                        break;
                    }
                }
            }
        });
        Self {
            stdin,
            rx,
            pending: HashMap::new(),
            verbose,
        }
    }

    fn send(&mut self, req: &Value) -> Result<()> {
        let raw = serde_json::to_string(req).context("serialize JSON-RPC request")?;
        if raw.contains('\n') {
            bail!("JSON-RPC request contained literal newline");
        }
        if self.verbose {
            eprintln!(">> {raw}");
        }
        self.stdin
            .write_all(raw.as_bytes())
            .context("write request line")?;
        self.stdin
            .write_all(b"\n")
            .context("write request newline")?;
        self.stdin.flush().context("flush request")?;
        Ok(())
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        let req = json!({"jsonrpc":"2.0","method":method,"params":params});
        self.send(&req)
    }

    fn request(
        &mut self,
        id: i64,
        method: &str,
        params: Value,
        deadline: Instant,
    ) -> Result<Value> {
        let req = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        self.send(&req)?;
        self.wait_for_id(&Value::from(id), deadline)
    }

    fn wait_for_id(&mut self, id: &Value, deadline: Instant) -> Result<Value> {
        let key = id.to_string();
        if let Some(v) = self.pending.remove(&key) {
            return Ok(v);
        }
        loop {
            let now = Instant::now();
            if now >= deadline {
                bail!("timed out waiting for response id {key}");
            }
            let timeout = deadline.saturating_duration_since(now);
            match self.rx.recv_timeout(timeout) {
                Ok(Ok(v)) => {
                    if self.verbose {
                        let line =
                            serde_json::to_string(&v).unwrap_or_else(|_| "<json>".to_string());
                        eprintln!("<< {line}");
                    }
                    if let Some(resp_id) = v.get("id") {
                        let resp_key = resp_id.to_string();
                        if resp_key == key {
                            return Ok(v);
                        }
                        self.pending.insert(resp_key, v);
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    bail!("timed out waiting for response id {key}");
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("response stream closed while waiting for id {key}");
                }
            }
        }
    }

    fn expect_no_response(&mut self, wait_for: Duration) -> Result<()> {
        match self.rx.recv_timeout(wait_for) {
            Ok(Ok(v)) => {
                if v.get("id").is_some() {
                    bail!(
                        "unexpected response after notification: {}",
                        truncate(&v.to_string())
                    );
                }
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(()),
        }
    }
}

fn main() -> std::process::ExitCode {
    let mut argv = std::env::args().collect::<Vec<_>>();
    if argv.len() == 1 || argv.get(1).is_some_and(|x| x.starts_with('-')) {
        argv.insert(1, "stdio".to_string());
    }
    let cli = match Cli::try_parse_from(argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return std::process::ExitCode::from(2);
        }
    };

    let emit_json = uses_json(&cli.command);
    let mut report = SmokeReport {
        ok: true,
        steps: Vec::new(),
        temp_dir: None,
    };

    let result = match &cli.command {
        Commands::Stdio(args) => run_stdio(args, &mut report),
    };

    if let Err(e) = result {
        report.ok = false;
        report.steps.push(StepReport {
            name: "fatal".to_string(),
            ok: false,
            duration_ms: 0,
            details: truncate(&error_chain(&e)),
        });
    }

    if emit_json {
        println!(
            "{}",
            serde_json::to_string(&report).unwrap_or_else(|_| "{\"ok\":false}".to_string())
        );
    } else {
        print_human_report(&report);
    }

    if report.ok {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(1)
    }
}

fn run_stdio(args: &StdioArgs, report: &mut SmokeReport) -> Result<()> {
    let timeout = Duration::from_millis(args.timeout_ms);
    let started = Instant::now();
    let mut stack: Option<RunningStack> = None;

    let temp = tempfile::tempdir().context("create temp dir")?;
    let paths = create_sandbox_layout(temp.path(), args.use_signed_audit)
        .context("create smoke test sandbox and configs")?;

    push_step(
        report,
        "prepare_sandbox",
        Instant::now(),
        Ok(format!("root={}", paths.root.display())),
    );

    let mut ok = true;
    ok &= run_step(report, "start_proxy_stack", || {
        let started_step = Instant::now();
        let running =
            start_proxy_stack(&paths, args.verbose).context("start toolfw+mcp-gateway stack")?;
        let elapsed = ms(started_step.elapsed());
        stack = Some(running);
        Ok(format!("spawned stack in {elapsed}ms"))
    });

    if ok {
        ok &= run_step(report, "initialize_lifecycle", || {
            let rpc = &mut stack
                .as_mut()
                .ok_or_else(|| anyhow!("stack unavailable"))?
                .rpc;
            let resp = rpc.request(1, "initialize", json!({}), deadline(started, timeout)?)?;
            if resp.get("result").is_none() {
                bail!("initialize missing result");
            }
            rpc.notify("notifications/initialized", json!({}))?;
            rpc.expect_no_response(Duration::from_millis(150))?;
            Ok("initialize + notifications/initialized completed".to_string())
        });
    }

    if ok {
        ok &= run_step(report, "policy_allow_views_query", || {
            let rpc = &mut stack
                .as_mut()
                .ok_or_else(|| anyhow!("stack unavailable"))?
                .rpc;
            let resp = rpc.request(
                2,
                "tools/call",
                json!({"name":"views.query","arguments":{"view":"sandbox_recent"}}),
                deadline(started, timeout)?,
            )?;
            if resp.get("result").is_none() {
                bail!("views.query did not return result");
            }
            let text = resp.to_string();
            if !text.to_ascii_lowercase().contains("hello") {
                bail!("views.query result did not contain expected hello evidence");
            }
            Ok("views.query allowed and returned hello evidence".to_string())
        });
    }

    if ok {
        ok &= run_step(report, "policy_deny_env_read", || {
            let rpc = &mut stack
                .as_mut()
                .ok_or_else(|| anyhow!("stack unavailable"))?
                .rpc;
            let resp = rpc.request(
                3,
                "tools/call",
                json!({"name":"files.read","arguments":{"mount":"sandbox","path":".env"}}),
                deadline(started, timeout)?,
            )?;
            let code = resp["error"]["code"]
                .as_i64()
                .ok_or_else(|| anyhow!("deny response missing error.code"))?;
            if code != TOOLFW_DENIED {
                bail!("expected deny code {TOOLFW_DENIED}, got {code}");
            }
            Ok(format!("files.read denied with code {code}"))
        });
    }

    let mut approval_token = String::new();
    if ok {
        ok &= run_step(report, "approval_request_and_replay", || {
            let rpc = &mut stack
                .as_mut()
                .ok_or_else(|| anyhow!("stack unavailable"))?
                .rpc;
            let resp = rpc.request(
                4,
                "tools/call",
                json!({"name":"files.write","arguments":{"mount":"sandbox","path":"write_test.txt","content":"hello"}}),
                deadline(started, timeout)?,
            )?;
            let code = resp["error"]["code"]
                .as_i64()
                .ok_or_else(|| anyhow!("approval-required response missing error.code"))?;
            if code != TOOLFW_APPROVAL_REQUIRED {
                bail!("expected approval code {TOOLFW_APPROVAL_REQUIRED}, got {code}");
            }
            let approval_request_id = resp["error"]["data"]["approval_request_id"]
                .as_str()
                .ok_or_else(|| anyhow!("missing approval_request_id"))?;

            let token = approve_request(&paths.approvals_path, approval_request_id)?;
            if token.is_empty() {
                bail!("approval token was empty");
            }

            let replay = rpc.request(
                5,
                "tools/call",
                json!({
                    "name":"files.write",
                    "arguments":{
                        "__toolfw":{"approvalToken":token},
                        "mount":"sandbox",
                        "path":"write_test.txt",
                        "content":"hello"
                    }
                }),
                deadline(started, timeout)?,
            )?;
            if replay["result"]["ok"] != Value::Bool(true) {
                bail!("approved replay did not succeed");
            }

            let wrote = fs::read_to_string(paths.sandbox_dir.join("write_test.txt"))
                .context("read write_test.txt")?;
            if wrote != "hello" {
                bail!("write_test.txt content mismatch after approval replay");
            }

            approval_token = token;
            Ok("approval issued and bound replay succeeded".to_string())
        });
    }

    if ok {
        ok &= run_step(report, "approval_token_binding", || {
            let rpc = &mut stack
                .as_mut()
                .ok_or_else(|| anyhow!("stack unavailable"))?
                .rpc;
            let resp = rpc.request(
                6,
                "tools/call",
                json!({
                    "name":"files.write",
                    "arguments":{
                        "__toolfw":{"approvalToken":approval_token},
                        "mount":"sandbox",
                        "path":"write_test.txt",
                        "content":"hello2"
                    }
                }),
                deadline(started, timeout)?,
            )?;
            let code = resp["error"]["code"]
                .as_i64()
                .ok_or_else(|| anyhow!("mutated replay missing error.code"))?;
            if code != TOOLFW_APPROVAL_REQUIRED && code != TOOLFW_DENIED {
                bail!("expected approval required/denied, got {code}");
            }
            let wrote = fs::read_to_string(paths.sandbox_dir.join("write_test.txt"))
                .context("read write_test.txt")?;
            if wrote != "hello" {
                bail!("write_test.txt was unexpectedly overwritten");
            }
            Ok(format!("mutated replay rejected with code {code}"))
        });
    }

    if let Some(s) = stack.as_mut() {
        s.stop();
    }

    if ok {
        ok &= run_step(report, "verify_audit_integrity", || {
            if args.use_signed_audit {
                let key = paths
                    .signing_key_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing signing key path"))?;
                verify_signed_audit_via_cli(&paths.audit_path, &paths.checkpoint_path, key)
                    .context("verify signed audit via CLI")?;
                Ok("signed audit checkpoint verification passed".to_string())
            } else {
                audit_log::verify_with_checkpoint(&paths.audit_path, &paths.checkpoint_path)
                    .context("verify audit checkpoint")?;
                Ok("audit checkpoint verification passed".to_string())
            }
        });
    }

    if ok {
        ok &= run_step(report, "verify_privacy_no_secret_leak", || {
            let audit_text = fs::read_to_string(&paths.audit_path)
                .with_context(|| format!("read {}", paths.audit_path.display()))?;
            if audit_text.contains(PRIVACY_SENTINEL) {
                bail!("audit log contained sentinel secret");
            }
            Ok("audit log does not contain sentinel secret".to_string())
        });
    }

    report.ok = ok;

    if args.keep_temp {
        report.temp_dir = Some(paths.root.display().to_string());
        std::mem::forget(temp);
    }

    Ok(())
}

fn create_sandbox_layout(root: &Path, signed: bool) -> Result<SmokePaths> {
    let sandbox_dir = root.join("sandbox");
    let out_dir = root.join("out");
    let audit_dir = root.join("audit");
    fs::create_dir_all(&sandbox_dir)?;
    fs::create_dir_all(&out_dir)?;
    fs::create_dir_all(&audit_dir)?;

    fs::write(sandbox_dir.join("hello.txt"), "hello world\n")?;
    fs::write(
        sandbox_dir.join(".env"),
        format!("SECRET={PRIVACY_SENTINEL}\n"),
    )?;

    let approvals_path = root.join("approvals.json");
    let mounts_path = out_dir.join("gateway.mounts.yaml");
    let views_path = out_dir.join("gateway.views.yaml");
    let policy_path = out_dir.join("toolfw.policy.yaml");
    let audit_path = audit_dir.join("audit.jsonl");
    let checkpoint_path = audit_dir.join("audit.checkpoint.json");
    let signing_key_path = signed.then(|| audit_dir.join("audit-signing-key.json"));

    fs::write(
        &mounts_path,
        format!(
            "mounts:\n  - name: sandbox\n    root: \"{}\"\n    read_only: false\n",
            yaml_path(&sandbox_dir)
        ),
    )?;

    fs::write(
        &views_path,
        "views:\n  - name: sandbox_recent\n    tool: files.search\n    args:\n      mount: sandbox\n      query: \"hello\"\n      max_results: 10\n      max_bytes: 20000\n",
    )?;

    fs::write(
        &policy_path,
        "protocol_version: \"2025-06-18\"\ndefaults:\n  decision: deny\nrules:\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"views.query\"\n      args:\n        view: \"sandbox_recent\"\n    decision: allow\n\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.read\"\n      args:\n        path_glob: \"**/.env\"\n    decision: deny\n\n  - match:\n      mcp_method: \"tools/call\"\n      tool: \"files.write\"\n    decision: require_approval\n",
    )?;

    Ok(SmokePaths {
        root: root.to_path_buf(),
        sandbox_dir,
        approvals_path,
        mounts_path,
        views_path,
        policy_path,
        audit_path,
        checkpoint_path,
        signing_key_path,
    })
}

fn start_proxy_stack(paths: &SmokePaths, verbose: bool) -> Result<RunningStack> {
    let toolfw_bin = resolve_bin("toolfw")?;
    let gateway_bin = resolve_bin("mcp-gateway")?;

    if let Some(signing_key) = &paths.signing_key_path {
        let out = Command::new(&toolfw_bin)
            .arg("audit")
            .arg("keygen")
            .arg("--out")
            .arg(signing_key)
            .output()
            .context("run toolfw audit keygen")?;
        if !out.status.success() {
            bail!(
                "toolfw audit keygen failed: {}",
                truncate(&String::from_utf8_lossy(&out.stderr))
            );
        }
    }

    let mut cmd = Command::new(&toolfw_bin);
    cmd.arg("proxy")
        .arg("stdio")
        .arg("--policy")
        .arg(&paths.policy_path)
        .arg("--approval-store")
        .arg(&paths.approvals_path)
        .arg("--audit")
        .arg(&paths.audit_path)
        .arg("--audit-checkpoint")
        .arg(&paths.checkpoint_path);

    if let Some(signing_key) = &paths.signing_key_path {
        cmd.arg("--audit-signing-key").arg(signing_key);
    }

    cmd.arg("--")
        .arg(gateway_bin)
        .arg("--mounts")
        .arg(&paths.mounts_path)
        .arg("--views")
        .arg(&paths.views_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    if verbose {
        eprintln!(
            "starting proxy with mounts={} views={} policy={}",
            paths.mounts_path.display(),
            paths.views_path.display(),
            paths.policy_path.display()
        );
    }

    let mut child = cmd.spawn().context("spawn proxy stack")?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open proxy stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to open proxy stdout"))?;
    let rpc = RpcClient::new(stdin, stdout, verbose);
    Ok(RunningStack { child, rpc })
}

fn approve_request(approval_store: &Path, approval_request_id: &str) -> Result<String> {
    let toolfw_bin = resolve_bin("toolfw")?;
    let out = Command::new(toolfw_bin)
        .arg("approve")
        .arg("--approval-store")
        .arg(approval_store)
        .arg(approval_request_id)
        .output()
        .context("run toolfw approve")?;
    if !out.status.success() {
        bail!(
            "toolfw approve failed: {}",
            truncate(&String::from_utf8_lossy(&out.stderr))
        );
    }
    Ok(String::from_utf8(out.stdout)
        .context("decode approval token")?
        .trim()
        .to_string())
}

fn verify_signed_audit_via_cli(audit: &Path, checkpoint: &Path, pubkey: &Path) -> Result<()> {
    let toolfw_bin = resolve_bin("toolfw")?;
    let out = Command::new(toolfw_bin)
        .arg("audit")
        .arg("verify")
        .arg("--audit")
        .arg(audit)
        .arg("--checkpoint")
        .arg(checkpoint)
        .arg("--pubkey")
        .arg(pubkey)
        .output()
        .context("run toolfw audit verify")?;
    if !out.status.success() {
        bail!(
            "toolfw audit verify failed: {}",
            truncate(&String::from_utf8_lossy(&out.stderr))
        );
    }
    Ok(())
}

fn resolve_bin(name: &str) -> Result<PathBuf> {
    let env_key = format!("CARGO_BIN_EXE_{name}");
    if let Ok(p) = std::env::var(&env_key) {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
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

    for path in candidates {
        if path.is_file() {
            return Ok(path);
        }
    }

    bail!(
        "could not locate binary '{name}'. Build workspace binaries first (e.g. cargo build --workspace --bins)."
    )
}

fn bin_file_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn yaml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "\\\\")
}

fn run_step<F>(report: &mut SmokeReport, name: &str, f: F) -> bool
where
    F: FnOnce() -> Result<String>,
{
    let started = Instant::now();
    match f() {
        Ok(details) => {
            push_step(report, name, started, Ok(details));
            true
        }
        Err(e) => {
            push_step(report, name, started, Err(e));
            false
        }
    }
}

fn push_step(report: &mut SmokeReport, name: &str, started: Instant, result: Result<String>) {
    let duration_ms = ms(started.elapsed());
    match result {
        Ok(details) => report.steps.push(StepReport {
            name: name.to_string(),
            ok: true,
            duration_ms,
            details: truncate(&details),
        }),
        Err(e) => report.steps.push(StepReport {
            name: name.to_string(),
            ok: false,
            duration_ms,
            details: truncate(&error_chain(&e)),
        }),
    }
}

fn deadline(started: Instant, timeout: Duration) -> Result<Instant> {
    started
        .checked_add(timeout)
        .ok_or_else(|| anyhow!("timeout overflow"))
}

fn ms(d: Duration) -> u64 {
    let ms = d.as_millis();
    ms.min(u128::from(u64::MAX)) as u64
}

fn truncate(input: &str) -> String {
    let clean = input.replace(['\r', '\n'], " ");
    if clean.len() <= MAX_STEP_DETAILS {
        clean
    } else {
        format!("{}...", &clean[..MAX_STEP_DETAILS])
    }
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

fn print_human_report(report: &SmokeReport) {
    println!(
        "trust-smoke stdio: {}",
        if report.ok { "PASS" } else { "FAIL" }
    );
    for step in &report.steps {
        println!(
            "- {} [{}] ({} ms) {}",
            step.name,
            if step.ok { "ok" } else { "fail" },
            step.duration_ms,
            step.details
        );
    }
    if let Some(temp_dir) = &report.temp_dir {
        println!("temp_dir: {temp_dir}");
    }
}

fn uses_json(command: &Commands) -> bool {
    match command {
        Commands::Stdio(args) => args.json,
    }
}
