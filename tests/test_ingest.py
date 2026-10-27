import json

from fastapi.testclient import TestClient

from conftest import load_ingest

ATTACK = '10.0.0.5 - - [26/Oct/2026:10:00:01 +0000] "GET /../../../../etc/passwd HTTP/1.1" 403 256'
NORMAL = '10.0.0.7 - - [26/Oct/2026:10:00:02 +0000] "GET /api/orders HTTP/1.1" 200 512'
ODD = 'Oct 26 10:00:00 host custom-daemon[1]: unexpected handshake failure from 192.0.2.9 token xyz'

def post(client, *lines):
    payload = [{'log': line} for line in lines]
    return client.post('/fluentbit', content=json.dumps(payload))

def test_signature_layer_works_without_any_trained_model(workdir):
    module = load_ingest()
    with TestClient(module.app) as client:
        health = client.get('/health').json()
        assert health['baseline_model_loaded'] is False

        body = post(client, ATTACK).json()
        assert body['signature_matches'] == 1
        assert body['baseline_ready'] is False

    pending = module.store.get_pending()
    assert len(pending) == 1
    assert pending[0]['match_type'] == 'signature_match'

def test_signature_hit_is_not_duplicated_as_model_alert(trained_workdir):
    module = load_ingest()
    with TestClient(module.app) as client:
        body = post(client, ATTACK).json()
    assert body['signature_matches'] == 1
    assert body['suspicious'] == 0
    assert [a['match_type'] for a in module.store.get_pending()] == ['signature_match']

def test_health_reports_loaded_baseline(trained_workdir):
    module = load_ingest()
    with TestClient(module.app) as client:
        assert client.get('/health').json()['baseline_model_loaded'] is True

def test_newline_delimited_and_plain_payloads(workdir):
    module = load_ingest()
    with TestClient(module.app) as client:
        body = client.post('/fluentbit', content=ATTACK + '\n' + NORMAL + '\n').json()
    assert body['received'] == 2
    assert body['signature_matches'] == 1

def test_empty_payload(workdir):
    module = load_ingest()
    with TestClient(module.app) as client:
        body = client.post('/fluentbit', content='').json()
    assert body['received'] == 0

def test_dashboard_verdict_reaches_running_ingest_without_restart(trained_workdir):
    from personal_rules import PersonalRules

    module = load_ingest()
    with TestClient(module.app) as client:
        before = post(client, ODD).json()
        assert before['confirmed_threats'] == 0

        vector = module.detector.vectorize([module.parser.parse_line(ODD)])[0]
        PersonalRules().add_true_positive_threat(vector, ODD, reviewer='alice')

        after = post(client, ODD).json()
        assert after['confirmed_threats'] == 1

def test_alert_store_recovers_when_database_file_is_removed(workdir):
    from storage import AlertStore

    store = AlertStore()
    record = {'raw': 'x y z', 'service': 'http', 'status': '200', 'timestamp': None, 'anomaly_score': None}
    store.add_alert(record, [])
    (workdir / 'alerts.db').unlink()
    assert store.get_pending() == []
    store.add_alert(record, [])
    assert len(store.get_pending()) == 1
