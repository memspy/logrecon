# Changelog

## 1.0.0

- Layered detection: signature rules, personal allow/deny rules, Isolation Forest.
- Signature normalisation for URL-encoding (up to three rounds) and SQL inline comments.
- Fluent Bit ingest over an isolated Docker network; dashboard bound to localhost.
- Streamlit dashboard with one-click classification and a manual classification panel.
- Anti-poisoning guards and an append-only audit log for analyst decisions.
- Personal rules are reloaded by the ingest service when the dashboard changes them.
- Parsers for nginx/Apache combined, Apache error, syslog (classic and ISO 8601) and OpenStack logs.
- Configurable log path through `.env` (`LOG_DIR`, `LOG_FILE`).
