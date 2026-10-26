"""
Stores analyst feedback (false positives and confirmed threats) as
vectors and uses cosine similarity to adapt future alerts without
retraining the underlying model.

Every accepted addition is timestamped, attributed to a reviewer, and
logged to an append-only audit trail. Additions are rejected outright
when they look like an attempt (deliberate or accidental) to poison the
lists: whitelisting something that closely matches an already-confirmed
threat, submitting an overly generic log line that would suppress a wide
swath of unrelated traffic, or adding entries faster than a human review
process plausibly could.
"""

import json
import time
from pathlib import Path
from typing import List, Optional

import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

SIMILARITY_THRESHOLD = 0.95
CONFLICT_SIMILARITY_THRESHOLD = 0.90
MAX_ADDITIONS_PER_HOUR = 20
MIN_MESSAGE_TOKENS = 3

class RuleRejected(Exception):
    """Raised when an attempted rule addition looks unsafe to apply automatically."""

class PersonalRules:
    def __init__(self, rules_path: str = 'personal_rules.json',
                 audit_path: str = 'personal_rules_audit.jsonl'):
        self.rules_path = Path(rules_path)
        self.audit_path = Path(audit_path)
        self.false_positives: List[dict] = []
        self.true_positive_threats: List[dict] = []
        self._load()

    def _load(self) -> None:
        if not self.rules_path.exists():
            return
        with open(self.rules_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.false_positives = data.get('false_positives', [])
        self.true_positive_threats = data.get('true_positive_threats', [])

    def _save(self) -> None:
        data = {
            'false_positives': self.false_positives,
            'true_positive_threats': self.true_positive_threats,
        }
        with open(self.rules_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _audit(self, action: str, raw_log: str, reviewer: str, note: Optional[str] = None) -> None:
        record = {
            'timestamp': time.time(),
            'action': action,
            'reviewer': reviewer,
            'raw': raw_log,
            'note': note,
        }
        with open(self.audit_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')

    def _check_rate_limit(self, entries: List[dict], list_name: str) -> None:
        cutoff = time.time() - 3600
        recent = sum(1 for e in entries if e.get('added_at', 0) > cutoff)
        if recent >= MAX_ADDITIONS_PER_HOUR:
            raise RuleRejected(
                f'{list_name}: {recent} additions in the last hour, at the '
                f'{MAX_ADDITIONS_PER_HOUR}/hour limit. This usually means either a real '
                'incident flood (handle it, do not bulk-whitelist around it) or a '
                'compromised/scripted session — investigate before raising the limit.'
            )

    def _check_specificity(self, raw_log: str) -> None:
        token_count = len(raw_log.split())
        if token_count < MIN_MESSAGE_TOKENS:
            raise RuleRejected(
                f'Log line has only {token_count} token(s) — too generic to safely '
                'whitelist automatically, since its vector would likely match a wide '
                'range of unrelated log lines. Add a more specific rule by hand if this '
                'really is noise.'
            )

    def add_false_positive(self, vector, raw_log: str, reviewer: str = 'unknown') -> None:
        self._check_specificity(raw_log)
        self._check_rate_limit(self.false_positives, 'false_positives')

        conflict = self._max_similarity(vector, self.true_positive_threats)
        if conflict > CONFLICT_SIMILARITY_THRESHOLD:
            self._audit('rejected_conflict_false_positive', raw_log, reviewer,
                        note=f'similarity to a confirmed threat: {conflict:.3f}')
            raise RuleRejected(
                f'This log is {conflict:.2f} similar to an already-confirmed threat. '
                'Refusing to whitelist it automatically — if this really is a false '
                'positive, it needs manual review, not a one-click suppress.'
            )

        entry = {
            'vector': _to_dense_list(vector),
            'raw': raw_log,
            'added_at': time.time(),
            'reviewer': reviewer,
        }
        self.false_positives.append(entry)
        self._save()
        self._audit('add_false_positive', raw_log, reviewer)

    def add_true_positive_threat(self, vector, raw_log: str, reviewer: str = 'unknown') -> None:
        self._check_rate_limit(self.true_positive_threats, 'true_positive_threats')

        conflict = self._max_similarity(vector, self.false_positives)
        note = (f'similarity to a whitelisted entry: {conflict:.3f}'
                if conflict > CONFLICT_SIMILARITY_THRESHOLD else None)
        if note:
            self._audit('conflict_true_positive_vs_whitelist', raw_log, reviewer, note=note)

        entry = {
            'vector': _to_dense_list(vector),
            'raw': raw_log,
            'added_at': time.time(),
            'reviewer': reviewer,
        }
        self.true_positive_threats.append(entry)
        self._save()
        self._audit('add_true_positive_threat', raw_log, reviewer, note=note)

    def check_false_positive(self, vector) -> bool:
        return self._max_similarity(vector, self.false_positives) > SIMILARITY_THRESHOLD

    def check_true_positive(self, vector) -> bool:
        return self._max_similarity(vector, self.true_positive_threats) > SIMILARITY_THRESHOLD

    def _max_similarity(self, vector, stored: List[dict]) -> float:
        if not stored:
            return 0.0
        query = _to_dense_array(vector).reshape(1, -1)
        stored_matrix = np.array([entry['vector'] for entry in stored])
        similarities = cosine_similarity(query, stored_matrix)
        return float(similarities.max())

def _to_dense_list(vector) -> list:
    if hasattr(vector, 'toarray'):
        return vector.toarray().ravel().tolist()
    return list(vector)

def _to_dense_array(vector) -> np.ndarray:
    if hasattr(vector, 'toarray'):
        return vector.toarray().ravel()
    return np.asarray(vector)
