"""
Lightweight HTTP ingestion endpoint for Fluent Bit's `http` output plugin.
Runs up to four independent checks per incoming line, in priority order:
  1. signature match — deterministic, curated known-attack patterns
     (signature_rules.py); no classification needed, straight to confirmed
  2. known-threat match (personal_rules black list) -> immediate escalation
  3. single-line Isolation Forest anomaly, minus whitelisted false positives
  4. LogBERT-style sequence anomaly across the recent window for that source
     (grouped by instance/session id when the log format provides one, by
     IP otherwise), for incidents that only become visible as a pattern

Either ML model can be missing at startup (first deploy, before running
train_baseline.py / train_logbert.py) — the service still starts and
serves whichever checks it has a trained model for, rather than crashing
outright. The signature layer needs no training and is always active.

Run with:
    uvicorn ingest_service:app --host 0.0.0.0 --port 8080
"""

import json
from typing import Any, List, Optional

from fastapi import FastAPI, Request

from anomaly_detector import AnomalyDetector
from log_parser import LogParser
from personal_rules import PersonalRules
from signature_rules import match as match_signature
from storage import AlertStore

try:
    from logbert_detector import LogBertDetector
except ImportError:
    LogBertDetector = None

try:
    from license_check import is_licensed
except ImportError:
    def is_licensed(path='license.key'):
        return False

app = FastAPI()

parser = LogParser()
detector = AnomalyDetector()
rules = PersonalRules()
store = AlertStore()
logbert: Optional['LogBertDetector'] = None
baseline_ready = False

@app.on_event('startup')
def load_models():
    global logbert, baseline_ready

    try:
        detector.load()
        baseline_ready = True
        print('Isolation Forest baseline loaded.')
    except FileNotFoundError as e:
        baseline_ready = False
        print(f'WARNING: {e}')
        print('Starting without a baseline model — single-line and known-threat '
              'checks are disabled until train_baseline.py is run and this '
              'service is restarted.')

    if LogBertDetector is None:
        logbert = None
        print('LogBERT module not installed (Pro add-on) — sequence-level '
              'detection disabled.')
    elif not is_licensed():
        logbert = None
        print('LogBERT module present but no valid license.key found — '
              'sequence-level detection disabled. Run print_fingerprint.py '
              'and contact your vendor for a license.')
    else:
        try:
            logbert = LogBertDetector()
            print('LogBERT sequence detector loaded.')
        except FileNotFoundError:
            logbert = None
            print('LogBERT model not found — run train_logbert.py to enable '
                  'sequence-level detection, then restart this service.')

def _extract_raw_lines(payload: Any) -> List[str]:
    if isinstance(payload, list):
        lines = []
        for item in payload:
            if isinstance(item, dict):
                lines.append(item.get('log') or item.get('message') or str(item))
            else:
                lines.append(str(item))
        return lines
    return [str(payload)]

@app.post('/fluentbit')
async def ingest(request: Request):
    body = await request.body()
    text = body.decode('utf-8', errors='ignore').strip()

    raw_lines: List[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
            raw_lines.extend(_extract_raw_lines(parsed))
        except ValueError:
            raw_lines.append(line)

    records = [r for r in (parser.parse_line(line) for line in raw_lines) if r]
    if not records:
        return {
            'received': 0, 'signature_matches': 0, 'confirmed_threats': 0,
            'suspicious': 0, 'sequence_incidents': 0,
        }

    if baseline_ready:
        vectors = detector.vectorize(records)
        raw_scores, predictions = detector.predict_vectors(vectors)

    signature_count = 0
    confirmed_count = 0
    suspicious_count = 0
    incident_count = 0

    for i, record in enumerate(records):
        source = record['source_key']
        vector_for_storage: list = []
        if baseline_ready:
            vector_for_storage = vectors[i].toarray().ravel().tolist()

        signature = match_signature(record['raw'])
        if signature:
            category, description = signature
            store.add_alert(record, vector_for_storage, match_type='signature_match',
                             context=[category, description])
            signature_count += 1
            if logbert is not None:
                logbert.check(source, record)
            continue

        if baseline_ready:
            vector = vectors[i]
            record['anomaly_score'] = float(raw_scores[i])

            if rules.check_true_positive(vector):
                store.add_alert(record, vector_for_storage, match_type='known_threat')
                confirmed_count += 1
            elif bool(predictions[i] == -1) and not rules.check_false_positive(vector):
                store.add_alert(record, vector_for_storage, match_type='model_anomaly')
                suspicious_count += 1

        if logbert is not None:
            is_incident, score, context_lines = logbert.check(source, record)
            if is_incident:
                record['anomaly_score'] = score
                store.add_alert(
                    record,
                    vector_for_storage,
                    match_type='sequence_anomaly',
                    context=context_lines,
                )
                incident_count += 1

    return {
        'received': len(records),
        'signature_matches': signature_count,
        'confirmed_threats': confirmed_count,
        'suspicious': suspicious_count,
        'sequence_incidents': incident_count,
        'baseline_ready': baseline_ready,
    }

@app.get('/health')
async def health():
    return {
        'status': 'ok',
        'baseline_model_loaded': baseline_ready,
        'logbert_model_loaded': logbert is not None,
    }
