import argparse
import os
import random
from datetime import datetime, timedelta, timezone

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

def _now():
    return datetime.now(timezone.utc)

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

def write_baseline(path: str, count: int) -> None:
    now = _now()
    with open(path, 'w', encoding='utf-8') as f:
        for i in range(count):
            dt = now - timedelta(seconds=(count - i))
            f.write(generate_normal_line(dt) + '\n')
    print(f'Wrote {count} baseline (normal) log lines to {path}')

def append_mixed(path: str, count: int, anomaly_ratio: float = 0.2) -> None:
    now = _now()
    with open(path, 'a', encoding='utf-8') as f:
        for i in range(count):
            dt = now + timedelta(seconds=i)
            line = generate_anomalous_line(dt) if random.random() < anomaly_ratio else generate_normal_line(dt)
            f.write(line + '\n')
    print(f'Appended {count} log lines (about {int(count * anomaly_ratio)} anomalous) to {path}')

def main():
    cli = argparse.ArgumentParser(description='Generate synthetic log lines for demos and tests.')
    cli.add_argument('mode', nargs='?', default='baseline', choices=['baseline', 'append'])
    cli.add_argument('--path', default=LOG_PATH)
    cli.add_argument('--count', type=int, default=None)
    args = cli.parse_args()

    directory = os.path.dirname(args.path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    if args.mode == 'baseline':
        write_baseline(args.path, args.count or 2000)
    else:
        append_mixed(args.path, args.count or 30)

if __name__ == '__main__':
    main()
