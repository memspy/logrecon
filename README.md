# LogRecon

A lightweight log anomaly auditor for SOC analysts, DevOps, and DevSecOps.
Three independent detection layers, checked in priority order, feeding one
dashboard where an analyst triages alerts and teaches the system what's
normal for their own environment - plus a manual classification panel so
there's something to interact with from minute one, not just after the
first automatic alert.

A fourth layer - sequence-anomaly detection with a small transformer
trained on your own logs - is available as a drop-in add-on, see
[Pro add-on](#pro-add-on-sequence-detection) below.

## Quick start

Requires Docker and Docker Compose.

```bash
git clone https://github.com/memspy/logrecon.git
cd logrecon
./install.sh
```

This builds the images, generates a small synthetic baseline if no trained
model exists yet, and starts the `ingest` and `dashboard` services. Open
`http://localhost:8501`.

The dashboard is bound to `127.0.0.1` only - for remote access, use an SSH
tunnel (`ssh -L 8501:127.0.0.1:8501 user@host`) or put a reverse proxy with
authentication in front of it. LogRecon's own UI has no login.

To start ingesting real logs instead of synthetic ones:
1. Edit `fluent-bit.docker.conf` - set `Path` to the file you want to watch.
2. Edit `docker-compose.yml` - point the `fluent-bit` volume at the real log
   directory (defaults to `/var/log`).
3. `docker compose --profile fluentbit up -d fluent-bit`

## How it works


Logs arrive through Fluent Bit (tails a file, posts batches over HTTP) at
the single ingestion endpoint, `/fluentbit`. Each line is parsed and run
through three checks, in this order, with the first match ending the chain:

1. **Attack signatures** (`signature_rules.py`) - deterministic regex
   matching against a curated list of known indicators (path traversal,
   SQLi, XSS, command injection, Log4Shell, web shells, scanners,
   sensitive-path probing). Needs no trained model, works from the first
   second of deployment. Normalizes input (percent-decoding up to 3
   rounds, inline SQL comment stripping) against a couple of known
   evasion techniques. A match goes straight to "confirmed" - no
   classification needed.
2. **Allow/deny list** (`personal_rules.py`) - cosine similarity against
   log lines an analyst has already triaged on this specific deployment.
   A deny-list hit escalates immediately; an allow-list hit silences a
   known-benign repeat. Protected against poisoning (see below).
3. **Isolation Forest** (`anomaly_detector.py`) - per-line anomaly
   detection over a `service + status + message` vector
   (`HashingVectorizer`, no GPU needed). Catches content-level anomalies:
   an unusual status code, a suspicious command, a path never seen in the
   baseline traffic.

Anything that matches at least one layer lands in `alerts.db` (SQLite),
tagged with which layer fired. The dashboard shows these in priority
order; decisions made on layer-3 alerts (or through the manual panel) are
written back into `personal_rules.json`, closing the loop.

## Project structure

```
logrecon/
├── install.sh                   one-command bootstrap
├── docker-compose.yml           ingest + dashboard + fluent-bit, network isolation
├── Dockerfile
├── requirements.txt
├── .dockerignore / .gitignore
├── fluent-bit.conf              Fluent Bit config for running on bare metal
├── fluent-bit.docker.conf       Fluent Bit config for the container
│
├── log_parser.py                parses logs into one common format
├── signature_rules.py           layer 1 - attack signatures
├── personal_rules.py            layer 2 - allow/deny list + anti-poisoning
├── anomaly_detector.py          layer 3 - Isolation Forest
├── train_baseline.py            trains layer 3
│
├── storage.py                   SQLite alert store
├── ingest_service.py            FastAPI endpoint, runs all installed layers
├── app.py                       Streamlit dashboard + manual classification panel
│
├── generate_sample_logs.py      synthetic log generator for trying it without a real source
├── evaluate.py                  precision/recall on labeled synthetic data
└── testing-checklist.md         test cases and pass conditions (Russian; translation welcome)
```

| File | Purpose | In | Out |
|---|---|---|---|
| `log_parser.py` | Parses nginx/apache combined, Apache error log, syslog (classic and ISO 8601), OpenStack logs | raw line | dict: `ip`, `service`, `status`, `message`, `raw`, `source_key`, `format` |
| `signature_rules.py` | Deterministic match against known attack signatures | line | `(category, description)` or `None` |
| `personal_rules.py` | Allow/deny list on cosine similarity, anti-poisoning checks | vector + line | bool; writes `personal_rules.json` and `personal_rules_audit.jsonl` |
| `anomaly_detector.py` | Isolation Forest + HashingVectorizer | records | anomaly score, vector |
| `train_baseline.py` | Trains Isolation Forest on a batch of logs | log file path | `model.joblib` |
| `storage.py` | SQLite `alerts` table with a priority queue | alert | - |
| `ingest_service.py` | FastAPI `/fluentbit` endpoint, runs every installed layer in order; degrades gracefully if a model isn't trained or the Pro add-on isn't installed | JSON batch from Fluent Bit | batch stats |
| `app.py` | Streamlit dashboard, sections by priority, plus a manual classification panel | - | updates `personal_rules.json` via analyst actions |
| `generate_sample_logs.py` | Synthetic logs (normal + injected anomalies) | - | `logs/server.log` |
| `evaluate.py` | Precision/recall of Isolation Forest on honestly-labeled synthetic data | - | metrics to stdout |

## Generated state - what lives where

None of this is committed to the repo (see `.gitignore`):

| File | Written by | Contains |
|---|---|---|
| `model.joblib` | `train_baseline.py` | trained Isolation Forest + vectorizer |
| `alerts.db` | `storage.py` (via `ingest_service.py`) | every alert, read and unread |
| `personal_rules.json` | `personal_rules.py` (via `app.py`) | allow/deny list vectors |
| `personal_rules_audit.jsonl` | `personal_rules.py` | append-only log of every analyst decision |
| `fluent-bit-state/tail.db` | Fluent Bit | read offset, survives container restarts |

(The Pro add-on writes two more: `logbert.pt` and `logbert_vocab.json` -
see its own README.)

## Training on your own logs

```bash
docker compose run --rm ingest python train_baseline.py /path/to/your.log
```

## Using the dashboard

| Section | What it means | What to do |
|---|---|---|
| Known attack signatures | Deterministic match against a known pattern (layer 1) | Review, **Mark handled** - treat as a confirmed attack |
| Confirmed threats | Looks like (>=0.95 similarity) something already confirmed as a threat (layer 2) | **Mark handled** |
| Needs classification | Isolation Forest flagged it, neither signatures nor the deny list matched (layer 3) | The only automatic place real classification happens: **Mark normal** (goes to the allow list) or **Mark threat** (goes to the deny list) |

There's also a **Manual classification** panel, always visible, independent
of whatever's in the alert queue: paste any log line, see whether it hits
a signature and (once a baseline is trained) its Isolation Forest score,
then mark it normal or a threat directly. This works even before any
model is trained - the vectorizer itself needs no training - so an
administrator can start seeding the allow/deny list from day one instead
of waiting for the first real incident to pass through the automatic
queue.

Only "needs classification" and the manual panel change the system's
future behavior - that's the "teaching" part.

If the Pro add-on is installed, a fourth section ("Sequence anomalies")
appears automatically - see its README for what it means and how to work
with it.

## Ongoing maintenance

- **Review `personal_rules_audit.jsonl`** - an append-only log of every
  analyst decision with name and timestamp. Useful for after-the-fact
  incident review, and for catching anyone who edited
  `personal_rules.json` outside the dashboard.
- **Add signatures** to `SIGNATURES` in `signature_rules.py` as new known
  indicators show up. Restart `ingest` after editing (the module isn't
  hot-reloaded).

## Known limitations

Validated against public LogHub datasets (Apache, Linux, OpenStack):

- **Isolation Forest** correctly stays quiet on content that's normal
  line by line - expected, but it means purely sequential anomalies (a
  repeating event cycle with no single "bad" line) are structurally
  invisible to every layer in the open-source core. That's what the
  sequence-detection Pro add-on is for.
- **The signature layer** normalizes input against two specifically
  tested evasions (percent-encoding, including double encoding; SQL
  comments between or inside keywords). This is a starting normalization,
  not a full WAF parser - combined evasions (e.g. percent-encoding inside
  the SQL comment itself) haven't been tested and will likely slip
  through.
- **Networking**: `dashboard` sits on a separate network from
  `ingest`/`fluent-bit`, with internet egress - otherwise Docker
  Desktop/WSL2 refuses to publish its port at all (`internal: true`
  blocks publishing entirely, not just outbound traffic - confirmed in
  practice). `ingest` and `fluent-bit`, which handle untrusted content,
  stay fully egress-isolated.

## Anti-poisoning protections

`personal_rules.py` rejects (`RuleRejected`) an addition when:
- the line is too short/generic (`MIN_MESSAGE_TOKENS = 3`) - such a
  vector could accidentally match a pile of unrelated log lines;
- a proposed false positive is >=0.90 similar to an already-confirmed
  threat;
- the hourly cap (`MAX_ADDITIONS_PER_HOUR = 20`) per list is exceeded.

Every decision, accepted or rejected, is written to
`personal_rules_audit.jsonl`, kept separate from the active rule file.

## Pro add-on: sequence detection

A fourth layer is available separately: a small transformer
(`TinyLogBERT`), trained from scratch on your own logs, that scores a
sliding window of the last 10 events from the same source instead of one
line at a time. It catches incidents that are invisible to every layer
above - validated on OpenStack's public ground-truth anomaly dataset,
4 of 4 known incidents caught, each one a case where every individual
line looked completely normal and only the pattern as a whole was wrong.

It's a true drop-in: `ingest_service.py` tries to import it on startup,
and if the files aren't there, the core runs exactly as described above,
with no missing-dependency errors. See the add-on's own README for
installation and its own known limitations (notably: the alert threshold
drifts across different collection periods and needs periodic
recalibration - this is the one part of the system that isn't "train
once and forget").

## Testing

`testing-checklist.md` has concrete test strings and pass conditions for
every layer: signature true/false positives, known evasions, queue
priority, graceful degradation when models or the Pro add-on are missing,
extending the signature list, an end-to-end run through a real Fluent
Bit instance, and Docker network isolation. Currently in Russian - a
translated version is a welcome contribution.

## License

MIT - see `LICENSE`.
