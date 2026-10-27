import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

class AlertStore:
    def __init__(self, db_path: str = 'alerts.db'):
        self.db_path = Path(db_path)
        self._init_schema()

    def _connect(self):
        if not self.db_path.exists():
            self._init_schema()
        return sqlite3.connect(self.db_path)

    def _init_schema(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    raw TEXT NOT NULL,
                    service TEXT,
                    status TEXT,
                    timestamp TEXT,
                    anomaly_score REAL,
                    vector_json TEXT NOT NULL,
                    match_type TEXT NOT NULL DEFAULT 'model_anomaly',
                    context_json TEXT,
                    reviewed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            for column, definition in [
                ('match_type', "TEXT NOT NULL DEFAULT 'model_anomaly'"),
                ('context_json', 'TEXT'),
            ]:
                try:
                    conn.execute(f'ALTER TABLE alerts ADD COLUMN {column} {definition}')
                except sqlite3.OperationalError:
                    pass

    def add_alert(self, record: Dict[str, Any], vector: list, match_type: str = 'model_anomaly',
                  context: Optional[List[str]] = None) -> None:
        with self._connect() as conn:
            conn.execute(
                '''INSERT INTO alerts (raw, service, status, timestamp, anomaly_score, vector_json, match_type, context_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (
                    record.get('raw'),
                    record.get('service'),
                    str(record.get('status')),
                    record.get('timestamp'),
                    record.get('anomaly_score'),
                    json.dumps(vector),
                    match_type,
                    json.dumps(context) if context else None,
                ),
            )

    def get_pending(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute('''
                SELECT * FROM alerts
                WHERE reviewed = 0
                ORDER BY
                    CASE match_type
                        WHEN 'signature_match' THEN 0
                        WHEN 'known_threat' THEN 1
                        WHEN 'sequence_anomaly' THEN 2
                        ELSE 3
                    END,
                    created_at ASC
            ''').fetchall()
        return [dict(row) for row in rows]

    def mark_reviewed(self, alert_id: int) -> None:
        with self._connect() as conn:
            conn.execute('UPDATE alerts SET reviewed = 1 WHERE id = ?', (alert_id,))
