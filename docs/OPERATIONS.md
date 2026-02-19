# Operations

## Preflight

Before running the proxy in production-like environments, run:

```bash
toolfw doctor proxy-stdio \
  --policy configs/examples/toolfw.policy.yaml \
  --approval-store ./approval-store.json \
  --audit ./audit.jsonl \
  --audit-checkpoint ./audit.checkpoint.json \
  --audit-signing-key ./audit-signing-key.json \
  --auth-keys ./auth-keys.json \
  --gateway-mounts configs/examples/gateway.mounts.yaml \
  --gateway-views configs/examples/gateway.views.yaml
```

The doctor command validates:
- config parseability (policy/redaction/mounts/views)
- auth key file or keyring validity
- required flag dependencies and exclusivity
- best-effort writable path checks for audit/checkpoint/store targets

It prints a JSON report and exits non-zero if issues are found.

## CI Expectations

The CI workflow enforces:
- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check` (supply-chain policy)

## Key Rotation and Revocation

Initialize keyring:

```bash
toolfw auth keyring init --out ./auth-keys.json
```

Add key:

```bash
toolfw auth keyring add --keys ./auth-keys.json --pubkey ./signing-key.json --note "service key v1"
```

Rotate key:

```bash
toolfw auth rotate --keys ./auth-keys.json --out-signing-key ./signing-key-v2.json --note "service key v2"
```

Revoke key:

```bash
toolfw auth keyring revoke --keys ./auth-keys.json --key-id <key_id> --note "compromised"
```

## Audit Verification

Generate signing key:

```bash
toolfw audit keygen --out ./audit-signing-key.json
```

Run proxy with signed checkpoints:

```bash
toolfw proxy stdio --policy configs/examples/toolfw.policy.yaml --approval-store ./approval-store.json --audit ./audit.jsonl --audit-checkpoint ./audit.checkpoint.json --audit-signing-key ./audit-signing-key.json -- <upstream>
```

Verify:

```bash
toolfw audit verify --audit ./audit.jsonl --checkpoint ./audit.checkpoint.json --pubkey ./audit-signing-key.json
```
