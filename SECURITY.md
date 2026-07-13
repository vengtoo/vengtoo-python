# Security Policy

## Reporting a Vulnerability

Please **do not** open a public issue for security vulnerabilities.

Report them privately to **security@vengtoo.com**. Include:

- A description of the issue and its impact
- A minimal reproduction (code snippet using the SDK is ideal)
- The SDK version

We will acknowledge your report within 3 business days and keep you updated as
we work on a fix. We ask that you give us a reasonable window to release a
patch before public disclosure, and we will credit you in the release notes
unless you prefer otherwise.

## Scope

The SDK is the client half of an authorization decision, so we treat these as
high severity:

- **Fail-open behavior** — any code path where an infrastructure failure
  (timeout, 5xx, malformed response) yields an "allowed" result instead of an
  exception or deny. This includes the FastAPI `require()` dependency, which
  must never let a request through on a failed check.
- **Credential handling** — API keys, OAuth client secrets, or cached access
  tokens reaching logs, exception messages, or unintended endpoints.
- **Delegation lifecycle** — a delegation created by `with_delegation`
  remaining active past the task boundary without the caller being informed.

## Hardening Recommendations

- Pass credentials via environment/secret managers, not source code.
- Prefer OAuth client credentials over long-lived API keys — tokens are
  short-lived and cached in memory only.
- The `require()` subject extractor defines who you trust: only read identity
  from sources your authentication layer controls (e.g. `request.state.user`
  set by authn middleware), never from client-suppliable data.
- Treat SDK exceptions as denies in your application logic; the SDK never
  reports "allowed" on failure.

## Supported Versions

Security fixes are applied to the latest minor release. Older releases
receive fixes on a best-effort basis.
