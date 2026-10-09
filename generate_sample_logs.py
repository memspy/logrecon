"""
Generates synthetic log lines for testing the anomaly detector end to end,
without needing access to a real server or Fluentbit/Logstash yet.

Usage:
    python generate_sample_logs.py baseline   # writes ~2000 normal lines
    python generate_sample_logs.py append     # appends a mix of normal + anomalous lines
"""

import os
import random
import sys
from datetime import datetime, timedelta

LOG_PATH = 'logs/server.log'

NORMAL_PATHS = ['/', '/api/users', '/api/orders', '/static/style.css', '/favicon.ico', '/api/health']
NORMAL_STATUSES = [200, 200, 200, 200, 304, 204]
NORMAL_IPS = [f'10.0.0.{i}' for i in range(2, 30)]

ANOMALOUS_TEMPLATES = [
    '{ip} - - [{ts}] "GET /wp-admin/setup-config.php HTTP/1.1" 404 512',
    '{ip} - - [{ts}] "POST /api/login HTTP/1.1" 401 128',
    '{ts_syslog} myserver sshd[9911]: Failed password for invalid user admin from {ip} port 51422 ssh2',
    '{ip} - - [{ts}] "GET /../../../../etc/passwd HTTP/1.1" 403 256',
    '{ts_syslog} myserver sudo: pam_unix(sudo:auth): authentication failure; user=root',
]

ANOMALOUS_IPS = ['203.0.113.5', '198.51.100.9', '185.220.101.7']

def _apache_ts(dt):
    return dt.strftime('%d/%b/%Y:%H:%M:%S +0000')

def _syslog_ts(dt):
    return dt.strftime('%b %e %H:%M:%S')

def generate_normal_line(dt):
    ip = random.choice(NORMAL_IPS)
    path = random.choice(NORMAL_PATHS)
    status = random.choice(NORMAL_STATUSES)
    return f'{ip} - - [{_apache_ts(dt)}] "GET {path} HTTP/1.1" {status} {random.randint(100, 5000)}'

def generate_anomalous_line(dt):
    template = random.choice(ANOMALOUS_TEMPLATES)
    return template.format(ip=random.choice(ANOMALOUS_IPS), ts=_apache_ts(dt), ts_syslog=_syslog_ts(dt))

def write_baseline(count: int = 2000) -> None:
    now = datetime.utcnow()
    with open(LOG_PATH, 'w', encoding='utf-8') as f:
        for i in range(count):
            dt = now - timedelta(seconds=(count - i))
            f.write(generate_normal_line(dt) + '\n')
    print(f'Wrote {count} baseline (normal) log lines to {LOG_PATH}')

def append_mixed(count: int = 30, anomaly_ratio: float = 0.2) -> None:
    now = datetime.utcnow()
    with open(LOG_PATH, 'a', encoding='utf-8') as f:
        for i in range(count):
            dt = now + timedelta(seconds=i)
            line = generate_anomalous_line(dt) if random.random() < anomaly_ratio else generate_normal_line(dt)
            f.write(line + '\n')
    print(f'Appended {count} log lines (~{int(count * anomaly_ratio)} anomalous) to {LOG_PATH}')

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'baseline'
    os.makedirs('logs', exist_ok=True)

    if mode == 'baseline':
        write_baseline()
    elif mode == 'append':
        append_mixed()
    else:
        print('Unknown mode. Use "baseline" or "append".')
        sys.exit(1)
