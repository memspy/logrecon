import json

import numpy as np
import pytest

import personal_rules
from personal_rules import PersonalRules, RuleRejected

LINE = 'GET /api/orders/12345 HTTP/1.1 slow upstream response'

def vec(*values):
    arr = np.zeros(16)
    for i, v in enumerate(values):
        arr[i] = v
    return arr

def test_false_positive_suppresses_similar_vectors(workdir):
    rules = PersonalRules()
    rules.add_false_positive(vec(1, 0, 0), LINE, reviewer='alice')
    assert rules.check_false_positive(vec(1, 0.01, 0))
    assert not rules.check_false_positive(vec(0, 1, 0))

def test_threat_is_matched(workdir):
    rules = PersonalRules()
    rules.add_true_positive_threat(vec(0, 1, 0), LINE, reviewer='alice')
    assert rules.check_true_positive(vec(0, 1, 0))
    assert not rules.check_true_positive(vec(1, 0, 0))

def test_too_generic_line_is_rejected(workdir):
    rules = PersonalRules()
    with pytest.raises(RuleRejected):
        rules.add_false_positive(vec(1), 'ok', reviewer='alice')
    assert rules.false_positives == []

def test_conflicting_whitelist_is_rejected_and_audited(workdir):
    rules = PersonalRules()
    rules.add_true_positive_threat(vec(1, 0, 0), LINE, reviewer='alice')
    with pytest.raises(RuleRejected):
        rules.add_false_positive(vec(1, 0.05, 0), LINE + ' variant', reviewer='bob')
    actions = [json.loads(l)['action'] for l in open('personal_rules_audit.jsonl')]
    assert 'rejected_conflict_false_positive' in actions

def test_rate_limit(workdir, monkeypatch):
    monkeypatch.setattr(personal_rules, 'MAX_ADDITIONS_PER_HOUR', 3)
    rules = PersonalRules()
    for i in range(3):
        rules.add_false_positive(vec(i + 1), f'{LINE} {i}', reviewer='alice')
    with pytest.raises(RuleRejected):
        rules.add_false_positive(vec(9), f'{LINE} overflow', reviewer='alice')

def test_audit_trail_records_reviewer(workdir):
    rules = PersonalRules()
    rules.add_false_positive(vec(1), LINE, reviewer='alice')
    entries = [json.loads(l) for l in open('personal_rules_audit.jsonl')]
    assert entries[-1]['reviewer'] == 'alice'
    assert entries[-1]['action'] == 'add_false_positive'

def test_reload_picks_up_changes_from_another_process(workdir):
    reader = PersonalRules()
    assert reader.true_positive_threats == []
    writer = PersonalRules()
    writer.add_true_positive_threat(vec(0, 0, 1), LINE, reviewer='alice')
    assert reader.reload_if_changed() is True
    assert reader.check_true_positive(vec(0, 0, 1))
    assert reader.reload_if_changed() is False
