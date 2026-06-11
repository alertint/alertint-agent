# Security Policy

## Supported versions

AlertINT is pre-1.0. Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| latest release (v0.x) | ✅ |
| anything older | ❌ |

## Reporting a vulnerability

Please report vulnerabilities **privately** — do not open a public issue.

- Use GitHub private vulnerability reporting: **Security → Report a
  vulnerability** on this repository, or
- email **ernests.knavins@gmail.com** with subject `[alertint security]`.

You can expect an acknowledgement within **72 hours** and a status update
within **14 days**. Please include reproduction steps and the affected
version; coordinated disclosure is appreciated and credited.

## Security posture (what the agent does and does not do)

- Read-only by design: the agent never mutates your infrastructure,
  Alertmanager, or Kubernetes state.
- Secrets (webhook token, MCP token, Slack bot token, LLM API key) are
  supplied via environment variables only — never stored in config files,
  logs, or the database.
- The Alertmanager webhook requires a bearer token; the agent refuses to
  start without one when the receiver is enabled.
- The MCP server is disabled by default; when enabled it binds to
  localhost only unless explicitly configured otherwise, and requires a
  bearer token.
- Outbound TLS verification is never disabled.
