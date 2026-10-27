# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private
vulnerability reporting ("Report a vulnerability" under the Security tab of the
repository) and include:

- a description of the issue and its impact
- steps or a proof of concept to reproduce it
- the version or commit you tested

You can expect an acknowledgement within a few days. Please allow reasonable
time for a fix before any public disclosure.

## Scope and deployment notes

- The dashboard has no built-in authentication. It is published on
  `127.0.0.1:8501` only. Do not expose it directly; use an SSH tunnel or a
  reverse proxy that enforces authentication and TLS.
- The ingest service has no authentication and its port is never published. It
  must only be reachable from the collector over the internal Docker network.
- Log lines are untrusted input. They are parsed with bounded regular
  expressions and are only ever rendered as plain text in the dashboard.
- Analyst decisions change detection behaviour. They are rate limited, checked
  for conflicts, and recorded in an append-only audit log
  (`personal_rules_audit.jsonl`).
