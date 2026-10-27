import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from conftest import ROOT
from storage import AlertStore

@pytest.fixture(autouse=True)
def clear_streamlit_cache():
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()

def test_dashboard_renders_english_ui_with_pending_alerts(workdir):
    store = AlertStore()
    record = {'raw': 'GET /../../etc/passwd', 'service': 'http', 'status': '403', 'timestamp': None, 'anomaly_score': None}
    store.add_alert(record, [], match_type='signature_match', context=['path_traversal', 'directory traversal sequence'])

    at = AppTest.from_file(str(ROOT / 'app.py'), default_timeout=30).run()

    assert not at.exception
    assert at.title[0].value == 'LogRecon'
    assert any('Known attack signatures' in s.value for s in at.subheader)
    assert any('directory traversal sequence' in e.value for e in at.error)
    assert any(b.label == 'Acknowledge' for b in at.button)

def test_dashboard_empty_state(workdir):
    at = AppTest.from_file(str(ROOT / 'app.py'), default_timeout=30).run()
    assert not at.exception
    assert any('No suspicious entries' in i.value for i in at.info)

def test_acknowledge_removes_alert_from_queue(workdir):
    store = AlertStore()
    record = {'raw': 'GET /.env', 'service': 'http', 'status': '404', 'timestamp': None, 'anomaly_score': None}
    store.add_alert(record, [], match_type='signature_match', context=['sensitive_path', 'probing'])

    at = AppTest.from_file(str(ROOT / 'app.py'), default_timeout=30).run()
    next(b for b in at.button if b.label == 'Acknowledge').click().run()

    assert store.get_pending() == []
