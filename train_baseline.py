import argparse
import sys

from anomaly_detector import AnomalyDetector
from log_parser import LogParser

def main():
    cli = argparse.ArgumentParser(description='Train the Isolation Forest baseline on a log file of normal traffic.')
    cli.add_argument('log_path')
    cli.add_argument('--contamination', type=float, default=0.02)
    args = cli.parse_args()

    records = LogParser().parse_file(args.log_path)
    if not records:
        print(f'No parseable log lines found in {args.log_path}')
        sys.exit(1)

    detector = AnomalyDetector(contamination=args.contamination)
    detector.train(records)

    print(f'Baseline trained on {len(records)} log lines, saved to {detector.model_path}')

if __name__ == '__main__':
    main()
