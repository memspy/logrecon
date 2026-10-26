"""
Evaluates the trained IsolationForest model against a labeled synthetic
log set, to sanity-check the contamination threshold before pointing
the pipeline at anything real.

Usage:
    python evaluate.py [count]
"""

import random
import sys
from datetime import datetime, timedelta

from anomaly_detector import AnomalyDetector
from generate_sample_logs import generate_anomalous_line, generate_normal_line
from log_parser import LogParser

def build_labeled_set(count: int, anomaly_ratio: float = 0.15):
    now = datetime.utcnow()
    lines = []
    labels = []

    for i in range(count):
        dt = now + timedelta(seconds=i)
        is_anomalous = random.random() < anomaly_ratio
        line = generate_anomalous_line(dt) if is_anomalous else generate_normal_line(dt)
        lines.append(line)
        labels.append(1 if is_anomalous else 0)

    return lines, labels

def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 500

    parser = LogParser()
    detector = AnomalyDetector()
    detector.load()

    lines, labels = build_labeled_set(count)
    records = [parser.parse_line(line) for line in lines]
    scored = detector.score(records)

    tp = fp = tn = fn = 0
    for record, label in zip(scored, labels):
        predicted = 1 if record['is_anomaly'] else 0
        if predicted == 1 and label == 1:
            tp += 1
        elif predicted == 1 and label == 0:
            fp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print(f'Test set: {count} lines ({sum(labels)} anomalous, {count - sum(labels)} normal)')
    print(f'TP={tp} FP={fp} TN={tn} FN={fn}')
    print(f'Precision: {precision:.3f}')
    print(f'Recall:    {recall:.3f}')
    print(f'F1:        {f1:.3f}')

if __name__ == '__main__':
    main()
