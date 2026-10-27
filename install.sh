#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Error: the Docker Compose plugin is not available." >&2
  exit 1
fi

mkdir -p logs fluent-bit-state

if [ ! -f .env ]; then
  cp .env.example .env
fi

docker compose build

if [ ! -f model.joblib ]; then
  echo "No trained model found. Generating a synthetic baseline to get started."
  docker compose run --rm ingest python generate_sample_logs.py baseline
  docker compose run --rm ingest python train_baseline.py logs/server.log
fi

if [ -f train_logbert.py ] && [ ! -f logbert.pt ]; then
  docker compose run --rm ingest python train_logbert.py logs/server.log
fi

docker compose up -d ingest dashboard

echo "Waiting for the ingest service to become healthy..."
for _ in $(seq 1 30); do
  if docker compose exec -T ingest python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" >/dev/null 2>&1; then
    echo ""
    echo "LogRecon is running."
    echo "Dashboard: http://localhost:8501 (bound to localhost; use an SSH tunnel for remote access)"
    echo ""
    echo "To ingest real logs:"
    echo "  1. Set LOG_DIR and LOG_FILE in .env"
    echo "  2. docker compose --profile fluentbit up -d fluent-bit"
    exit 0
  fi
  sleep 2
done

echo "Error: the ingest service did not become healthy. Check: docker compose logs ingest" >&2
exit 1
