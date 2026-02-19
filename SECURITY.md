# Security

## Threat model summary

This MVP is intended to mitigate:
- overbroad tool access by deny-by-default policy and mount-based gateway isolation
- unsafe writes by enforcing approval gates for selected tool calls
- accidental secret leaks via policy deny rules for obvious paths/patterns
- missing auditability (partial): minimal structured approval state exists now; richer audit logging is planned
- audit tampering and truncation with hash-chained logs and cryptographically signed checkpoints (when configured)
- unauthorized tool use when capability-token enforcement is enabled at the gateway
- stronger request attribution via token-derived client identity in toolfw audit metadata
- reduced blast radius from key compromise via keyring-based key rotation and revocation
- abusive request bursts via per-client tool rate limits in toolfw policy (when configured)

This MVP does not mitigate:
- a compromised host operating system
- malicious or compromised upstream server descriptions
- prompt injection intent understanding
- full data loss prevention (DLP)
- token exfiltration from compromised clients or hosts
- immediate invalidation of already-issued stolen tokens signed by still-active keys
- durable/global rate limiting (current limiter is in-memory per proxy process)

## Privacy defaults

- Gateway uses explicit mounts and denies access outside them.
- View output is bounded by configured limits.
- Full file contents are not logged by default.
