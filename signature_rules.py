"""
Curated set of well-known attack indicator patterns — the kind of thing
any WAF or IDS ships with by default (path traversal, SQLi, XSS, command
injection, webshell names, known scanner tools, common exploit-prone
endpoints). A match here is deterministic and doesn't need classification:
it goes straight to the confirmed queue instead of sitting in the
model_anomaly review pile alongside genuinely ambiguous traffic.

This is a starter set, not exhaustive — extend SIGNATURES as needed.
"""

import re
import urllib.parse
from typing import List, Optional, Tuple

SIGNATURES: List[Tuple[str, re.Pattern, str]] = [
    ('path_traversal', re.compile(r'\.\.[/\\]\.\.[/\\]'), 'directory traversal sequence'),
    ('path_traversal', re.compile(r'/etc/(passwd|shadow)', re.IGNORECASE), 'sensitive unix file path'),
    ('path_traversal', re.compile(r'\b(boot\.ini|win\.ini)\b', re.IGNORECASE), 'sensitive windows file path'),

    ('sql_injection', re.compile(r'union\s+select', re.IGNORECASE), 'SQL UNION SELECT'),
    ('sql_injection', re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE), 'classic SQLi boolean bypass'),
    ('sql_injection', re.compile(r';\s*drop\s+table', re.IGNORECASE), 'SQL DROP TABLE'),
    ('sql_injection', re.compile(r'benchmark\s*\(|sleep\s*\(\s*\d+\s*\)', re.IGNORECASE), 'time-based SQLi probe'),
    ('sql_injection', re.compile(r'information_schema|xp_cmdshell', re.IGNORECASE), 'SQLi enumeration/RCE primitive'),

    ('xss', re.compile(r'<script[\s>]', re.IGNORECASE), 'inline script tag'),
    ('xss', re.compile(r'javascript:', re.IGNORECASE), 'javascript: URI scheme'),
    ('xss', re.compile(r'on(error|load)\s*=', re.IGNORECASE), 'event-handler XSS payload'),

    ('command_injection', re.compile(r';\s*cat\s+/etc', re.IGNORECASE), 'chained cat of sensitive file'),
    ('command_injection', re.compile(r'\|\s*nc\s+', re.IGNORECASE), 'piped netcat'),
    ('command_injection', re.compile(r'\$\([^)]+\)'), 'command substitution'),
    ('command_injection', re.compile(r'wget\s+https?://|curl\s+https?://\S+\s*\|\s*sh', re.IGNORECASE),
     'download-and-execute pattern'),

    ('log4shell', re.compile(r'\$\{jndi:', re.IGNORECASE), 'Log4Shell JNDI lookup'),

    ('webshell', re.compile(r'\b(c99|r57|wso|b374k)\.php\b', re.IGNORECASE), 'known webshell filename'),

    ('scanner_tool', re.compile(r'sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster', re.IGNORECASE),
     'known scanner/pentest tool signature'),

    ('sensitive_path', re.compile(r'\.env\b|\.git/config|wp-config\.php|id_rsa\b', re.IGNORECASE),
     'probing for sensitive config/credentials'),
    ('sensitive_path', re.compile(r'/actuator/env|/solr/admin|/phpmyadmin/', re.IGNORECASE),
     'known exploit-prone admin/debug endpoint'),
]

_COMMENT_RE = re.compile(r'/\*.*?\*/')
_MAX_DECODE_ROUNDS = 3

def _url_decode_fully(text: str) -> str:
    """Repeatedly percent-decodes text to catch single and double encoding
    (%2e%2e%2f, %252e%252e%252f), stopping once decoding stops changing
    anything or after a bounded number of rounds, so a crafted string
    can't force unbounded work."""
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            break
        text = decoded
    return text

def _strip_sql_comments(text: str, replacement: str) -> str:
    """Removes inline /* ... */ comments, a classic way to either split a
    keyword (UNI/**/ON) or fake a separator between keywords
    (UNION/**/SELECT) to dodge a literal match. Tried with two different
    replacements since real payloads use both styles."""
    return _COMMENT_RE.sub(replacement, text)

def _normalized_variants(text: str) -> List[str]:
    """Builds the text forms to check signatures against: the raw text,
    the fully percent-decoded text, and SQL-comment-stripped versions of
    both. Not exhaustive against every possible combined obfuscation —
    this is a starter defense against the two concrete evasions found
    during testing, not a general-purpose WAF normalizer."""
    decoded = _url_decode_fully(text)

    variants = {text, decoded}
    for variant in list(variants):
        variants.add(_strip_sql_comments(variant, ''))
        variants.add(_strip_sql_comments(variant, ' '))

    return list(variants)

def match(text: str) -> Optional[Tuple[str, str]]:
    """Returns (category, description) of the first matching signature,
    checked against the raw text and normalized variants (percent-decoded,
    SQL-comment-stripped) to catch common literal-match evasions."""
    for variant in _normalized_variants(text):
        for category, pattern, description in SIGNATURES:
            if pattern.search(variant):
                return category, description
    return None
