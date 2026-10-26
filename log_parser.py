"""
Converts raw, unstructured log lines into normalized JSON records
suitable for ML-based anomaly detection. Supports nginx/apache combined
access logs, Apache error logs, syslog-style logs, and OpenStack's
structured service logs.
"""

import re
from typing import Any, Dict, List

NGINX_COMBINED_RE = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)

OPENSTACK_RE = re.compile(
    r'(?P<source>\S+)\s+'
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'(?P<pid>\d+)\s+'
    r'(?P<level>\w+)\s+'
    r'(?P<logger>\S+)\s+'
    r'\[(?P<context>[^\]]*)\]\s*'
    r'(?P<rest>.*)'
)

APACHE_ERROR_RE = re.compile(
    r'\[(?P<timestamp>\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4})\]\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<message>.*)'
)

SYSLOG_RE = re.compile(
    r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    r'|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<service>[\w\-/.()]+?)(?:\s[\w.]+)?(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.*)'
)

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
INSTANCE_RE = re.compile(r'instance:\s*([0-9a-f-]{36})', re.IGNORECASE)
STATUS_RE = re.compile(r'status:\s*(\d{3})')
REQ_ID_RE = re.compile(r'(req-[0-9a-f-]{36})')

class LogParser:
    """Parses raw log lines into a flat, normalized structure."""

    def __init__(self):
        self._patterns = [
            ('nginx_combined', NGINX_COMBINED_RE),
            ('openstack', OPENSTACK_RE),
            ('apache_error', APACHE_ERROR_RE),
            ('syslog', SYSLOG_RE),
        ]

    def parse_line(self, raw_line: str) -> Dict[str, Any]:
        raw_line = raw_line.strip()
        if not raw_line:
            return {}

        for fmt_name, pattern in self._patterns:
            match = pattern.match(raw_line)
            if match:
                record = self._normalize(fmt_name, match.groupdict(), raw_line)
                record['source_key'] = record.get('instance_id') or record.get('ip') or 'unknown'
                return record

        record = self._fallback(raw_line)
        record['source_key'] = record.get('ip') or 'unknown'
        return record

    def _normalize(self, fmt_name: str, fields: Dict[str, str], raw_line: str) -> Dict[str, Any]:
        if fmt_name == 'nginx_combined':
            return {
                'ip': fields.get('ip'),
                'timestamp': fields.get('timestamp'),
                'service': 'http',
                'status': fields.get('status'),
                'message': fields.get('request'),
                'raw': raw_line,
                'format': fmt_name,
            }

        if fmt_name == 'openstack':
            rest = fields.get('rest', '')
            context = fields.get('context', '')
            ip_match = IP_RE.search(rest)
            status_match = STATUS_RE.search(rest)
            instance_match = INSTANCE_RE.search(rest) or INSTANCE_RE.search(context)
            req_match = REQ_ID_RE.search(context)
            return {
                'ip': ip_match.group(0) if ip_match else None,
                'timestamp': fields.get('timestamp'),
                'service': fields.get('logger'),
                'status': status_match.group(1) if status_match else None,
                'message': rest,
                'raw': raw_line,
                'format': fmt_name,
                'instance_id': instance_match.group(1) if instance_match else None,
                'request_id': req_match.group(1) if req_match else None,
            }

        if fmt_name == 'apache_error':
            return {
                'ip': None,
                'timestamp': fields.get('timestamp'),
                'service': f"apache_{fields.get('level')}",
                'status': None,
                'message': fields.get('message'),
                'raw': raw_line,
                'format': fmt_name,
            }

        if fmt_name == 'syslog':
            ip_match = IP_RE.search(fields.get('message', ''))
            return {
                'ip': ip_match.group(0) if ip_match else None,
                'timestamp': fields.get('timestamp'),
                'service': fields.get('service'),
                'status': None,
                'message': fields.get('message'),
                'raw': raw_line,
                'format': fmt_name,
            }

        return self._fallback(raw_line)

    def _fallback(self, raw_line: str) -> Dict[str, Any]:
        ip_match = IP_RE.search(raw_line)
        return {
            'ip': ip_match.group(0) if ip_match else None,
            'timestamp': None,
            'service': 'unknown',
            'status': None,
            'message': raw_line,
            'raw': raw_line,
            'format': 'unrecognized',
        }

    def parse_file(self, path: str) -> List[Dict[str, Any]]:
        records = []
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                record = self.parse_line(line)
                if record:
                    records.append(record)
        return records
