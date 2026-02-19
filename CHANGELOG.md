# Changelog

All notable changes to this project are documented in this file.

## v0.1.0 - 2026-02-19

- Added stdio MCP proxy/server MVP (`toolfw`, `mcp-gateway`) with policy, approvals, and bounded mount-scoped file/view tools.
- Added policy engine v2 controls: rich matchers, lint/compile, explain/trace, local rate limiting.
- Added auth and capability tokens, keyring rotation/revocation, and gateway auth enforcement.
- Added privacy-preserving audit log, signed checkpoints, verification CLI, and checkpoint integrity checks.
- Added `sqlite.query`, `c2pa.inspect`, and read-only bounded git tools in gateway.
- Added C2PA browser extension MVP with native host, page media detection, and settings.
- Added CI (`fmt`, `clippy`, `test`, `cargo-deny`) and operational docs.
- Added release automation with multi-OS packaged binaries, extension zip, checksums, and native-host install helpers.
