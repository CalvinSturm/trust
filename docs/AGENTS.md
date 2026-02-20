# Agents Wiring

This document explains automatic and manual agent wiring for trust-stack.

Operational note:
- Use `trust-up up --agent <agent> --mode <observe|guarded|strict> --console` to bootstrap wiring + stack + console in one step.
- Use `trust-up policy set --dir ./.trust/run <observe|guarded|strict>` to switch policy posture later without recreating the run directory.

## Codex CLI

Preferred project-scoped config:
- `<project-root>/.codex/config.toml`

`trust-up` writes/updates:
- `[mcp_servers.trust-stack]`
- `command = "<path-to-toolfw>"`
- `args = ["proxy","stdio",...]`
- `cwd = "<project-root>"`

If project-scoped config is unavailable, `trust-up` prints a manual snippet and command.

## Claude Code

Preferred project-scoped config:
- `<project-root>/.mcp.json`

`trust-up` writes/updates:
- `mcpServers.trust-stack`
- `command` + `args` with toolfw proxy routing

## OpenClaw

Current behavior:
- binary detection is supported
- automatic config writing is not implemented

Use manual snippet shown by Setup tab (`c`) or trust-up output.

## Other MCP Clients

Use this when your MCP-capable client is not a named built-in target.

Current behavior:
- select with `--agent other`
- manual snippet/command generation is supported
- automatic config writing is not implemented

## Safety

All config writes are:
- backup-first (`.bak.<timestamp>`)
- atomic replace
- merge-preserving other existing MCP server entries
