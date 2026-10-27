from pathlib import Path
from typing import Any, Dict, List

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import HashingVectorizer

VECTOR_DIM = 4096

def _log_to_text(record: Dict[str, Any]) -> str:
    parts = [
        str(record.get('service', '')),
        str(record.get('status', '')),
        str(record.get('message', '')),
    ]
    return ' '.join(p for p in parts if p)

class AnomalyDetector:
    def __init__(self, model_path: str = 'model.joblib', contamination: float = 0.02):
        self.model_path = Path(model_path)
        self.vectorizer = HashingVectorizer(
            n_features=VECTOR_DIM,
            alternate_sign=False,
            norm='l2',
        )
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
        )
        self._is_trained = False

    def vectorize(self, records: List[Dict[str, Any]]):
        texts = [_log_to_text(r) for r in records]
        return self.vectorizer.transform(texts)

    def train(self, records: List[Dict[str, Any]]) -> None:
        if not records:
            raise ValueError('Cannot train on an empty log batch')

        vectors = self.vectorize(records)
        self.model.fit(vectors)
        self._is_trained = True
        self.save()

    def predict_vectors(self, vectors):
        if not self._is_trained:
            self.load()

        raw_scores = self.model.decision_function(vectors)
        predictions = self.model.predict(vectors)
        return raw_scores, predictions

    def score(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        vectors = self.vectorize(records)
        raw_scores, predictions = self.predict_vectors(vectors)

        results = []
        for record, raw_score, prediction, vector in zip(records, raw_scores, predictions, vectors):
            annotated = dict(record)
            annotated['anomaly_score'] = float(raw_score)
            annotated['is_anomaly'] = bool(prediction == -1)
            annotated['_vector'] = vector
            results.append(annotated)

        return results

    def save(self) -> None:
        joblib.dump({'model': self.model, 'vectorizer': self.vectorizer}, self.model_path)

    def load(self) -> None:
        if not self.model_path.exists():
            raise FileNotFoundError(
                f'No trained model found at {self.model_path}. Run train_baseline.py first.'
            )
        bundle = joblib.load(self.model_path)
        self.model = bundle['model']
        self.vectorizer = bundle['vectorizer']
        self._is_trained = True

    @property
    def is_trained(self) -> bool:
        return self._is_trained
