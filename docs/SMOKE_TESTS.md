# Smoke Tests

## Prerequisites

- Rust toolchain installed
- Workspace binaries built (`cargo build --workspace --bins`)
- No network required

## Run The Stack Smoke Test

Windows (PowerShell):

```powershell
cargo run -p trust-smoke -- stdio
```

macOS/Linux:

```bash
cargo run -p trust-smoke -- stdio
```

The runner creates a temp sandbox, starts `toolfw proxy stdio -- mcp-gateway`, drives JSON-RPC, validates allow/deny/approval replay behavior, verifies audit checkpoint integrity, and checks that the sentinel secret does not leak into the audit log.

## JSON Output

Use `--json` for machine-readable output:

```bash
cargo run -p trust-smoke -- stdio --json
```

JSON shape:

- `ok`: overall pass/fail
- `steps[]`: `{ name, ok, duration_ms, details }`
- `temp_dir`: included only when `--keep-temp` is set

## Keep Temp Directory For Debugging

```bash
cargo run -p trust-smoke -- stdio --keep-temp --verbose
```

When enabled, the temp path is printed as `temp_dir` and not deleted.

## Failure Interpretation

- `policy_deny_env_read` fail: policy no longer denies `.env` reads as expected.
- `approval_request_and_replay` fail: approval flow, token issuance, or replay binding changed.
- `verify_audit_integrity` fail: audit chain/checkpoint mismatch or signed verify failure.
- `verify_privacy_no_secret_leak` fail: sentinel string appeared in audit output.

## Extension Manual Smoke

For browser extension manual smoke steps, see `docs/EXTENSION.md`.
