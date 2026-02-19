# Security

## Threat model summary

This MVP is intended to mitigate:
- overbroad tool access by deny-by-default policy and mount-based gateway isolation
- unsafe writes by enforcing approval gates for selected tool calls
- accidental secret leaks via policy deny rules for obvious paths/patterns
- missing auditability (partial): minimal structured approval state exists now; richer audit logging is planned

This MVP does not mitigate:
- a compromised host operating system
- malicious or compromised upstream server descriptions
- prompt injection intent understanding
- full data loss prevention (DLP)

## Privacy defaults

- Gateway uses explicit mounts and denies access outside them.
- View output is bounded by configured limits.
- Full file contents are not logged by default.
