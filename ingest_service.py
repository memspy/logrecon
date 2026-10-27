import json
from contextlib import asynccontextmanager
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

parser = LogParser()
detector = AnomalyDetector()
rules = PersonalRules()
store = AlertStore()
logbert: Optional['LogBertDetector'] = None
baseline_ready = False

def load_models() -> None:
    global logbert, baseline_ready

    try:
        detector.load()
        baseline_ready = True
        print('Isolation Forest baseline loaded.')
    except FileNotFoundError as e:
        baseline_ready = False
        print(f'WARNING: {e}')
        print('Starting without a baseline model. Anomaly scoring and known-threat '
              'matching are disabled until train_baseline.py is run and this '
              'service is restarted. Signature matching remains active.')

    if LogBertDetector is None:
        logbert = None
        print('Sequence detector module not installed. Sequence-level detection disabled.')
    elif not is_licensed():
        logbert = None
        print('Sequence detector module present but no valid license found. '
              'Sequence-level detection disabled.')
    else:
        try:
            logbert = LogBertDetector()
            print('Sequence detector loaded.')
        except FileNotFoundError:
            logbert = None
            print('Sequence detector model not found. Train it and restart this service.')

@asynccontextmanager
async def lifespan(_: FastAPI):
    load_models()
    yield

app = FastAPI(title='LogRecon ingest', lifespan=lifespan)

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

    rules.reload_if_changed()

    records = [r for r in (parser.parse_line(line) for line in raw_lines) if r]
    if not records:
        return {
            'received': 0,
            'signature_matches': 0,
            'confirmed_threats': 0,
            'suspicious': 0,
            'sequence_incidents': 0,
            'baseline_ready': baseline_ready,
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
