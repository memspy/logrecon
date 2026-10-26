#!/usr/bin/env bash
set -e

docker compose build

if [ ! -f model.joblib ]; then
  echo "No trained model found - generating a synthetic baseline to get started."
  docker compose run --rm ingest python generate_sample_logs.py baseline
  docker compose run --rm ingest python train_baseline.py logs/server.log
fi

if [ -f train_logbert.py ] && [ ! -f logbert.pt ]; then
  docker compose run --rm ingest python train_logbert.py logs/server.log
fi

docker compose up -d ingest dashboard

echo ""
echo "LogRecon is running."
echo "Dashboard: http://localhost:8501 (bound to localhost - use an SSH tunnel for remote access)"
echo ""
echo "To start real log ingestion:"
echo "  1. Edit fluent-bit.docker.conf - set Path to the log file you want to watch"
echo "  2. Edit docker-compose.yml - point the fluent-bit volume at the real log directory"
echo "  3. docker compose --profile fluentbit up -d fluent-bit"
