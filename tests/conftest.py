import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path

@pytest.fixture
def trained_workdir(workdir):
    from datetime import datetime, timezone

    from anomaly_detector import AnomalyDetector
    from generate_sample_logs import generate_normal_line
    from log_parser import LogParser

    parser = LogParser()
    now = datetime.now(timezone.utc)
    records = [parser.parse_line(generate_normal_line(now)) for _ in range(400)]
    AnomalyDetector().train(records)
    return workdir

def load_ingest():
    sys.modules.pop('ingest_service', None)
    return importlib.import_module('ingest_service')
