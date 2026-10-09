"""
Builds the initial 'normal behavior' model from a batch of historical
log lines. Run once before starting the dashboard, re-run periodically
to refresh the baseline.

Usage:
    python train_baseline.py logs/server.log
"""

import sys

from anomaly_detector import AnomalyDetector
from log_parser import LogParser

def main():
    if len(sys.argv) < 2:
        print('Usage: python train_baseline.py <path_to_log_file>')
        sys.exit(1)

    log_path = sys.argv[1]

    parser = LogParser()
    records = parser.parse_file(log_path)

    if not records:
        print(f'No parseable log lines found in {log_path}')
        sys.exit(1)

    detector = AnomalyDetector()
    detector.train(records)

    print(f'Baseline trained on {len(records)} log lines, saved to {detector.model_path}')

if __name__ == '__main__':
    main()
