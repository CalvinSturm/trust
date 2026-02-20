# First Run

This is the shortest path to a successful first experience.

## 1) Run trust-up

Windows (PowerShell):

```powershell
cargo build --workspace
.\target\debug\trust-up.exe up --agent codex --console
```

macOS/Linux:

```bash
cargo build --workspace
./target/debug/trust-up up --agent codex --console
```

`trust-up` will:
- create `.trust/run` artifacts (`out/`, `audit/`, `approvals.json`) and persistent `.trust/data/`
- start `toolfw -> mcp-gateway`
- open `trust-console` with live audit/approvals/policy paths
- prompt once for agent selection when multiple are detected
- write agent wiring automatically when a config target is known

Note: the agent selection is for MCP wiring target/config only. It does not imply full auditing of native shell/file actions outside MCP tool calls.
If your client is not Codex/Claude/OpenClaw, use `--agent other` for manual MCP wiring output.

Security mode presets:
- `--mode auto` (default): interactive chooser for terminal users, `guarded` fallback for non-interactive
- `--mode guarded`: safe default (deny secret reads, require approval for writes)
- `--mode observe`: audit everything, allow by default
- `--mode strict`: approvals for reads and writes

Switch modes later without recreating the run directory:

```bash
./target/debug/trust-up policy set --dir ./.trust/run guarded
```

## 2) Agent wiring options

- Setup tab (already open from `trust-up`) is the only interactive selector and writer.
- Optional print-only planning:

```bash
./target/debug/trust-up plan --json
```

If config path auto-detection fails, `trust-up` prints a snippet for manual paste.

## 3) Generate first events with smoke

```bash
cargo run -p trust-smoke -- stdio --json
```

Confirm JSON output includes `"ok": true`.

## 4) Open trust-console directly (optional)

```bash
./target/debug/trust-console --run-dir ./.trust/run
```

## 5) Optional extension demo

Try the C2PA extension + native host walkthrough in `docs/EXTENSION.md`.

## 6) Trigger an approval (optional)

From your agent, call `files.write` through the proxy. In `trust-console` Approvals:
- a new `pending` row should appear with real `created/tool/client/summary`
- press `a` to approve (status becomes `approved`)
- press `d` to deny (status becomes `denied`)

The summary stores metadata only (path/mount/byte counts), not file contents.

## 7) Troubleshooting

- Smoke issues: `docs/SMOKE_TESTS.md`
- Console workflow: `docs/CONSOLE.md`
- Agent wiring details: `docs/AGENTS.md`
- Release/install notes: `docs/RELEASING.md`
- Agent config permissions: rerun with an account that can write the detected config path.
- Do not run `cargo run -p trust-console` while console is open; this can fail on Windows because Cargo tries to rebuild/replace a running executable.
