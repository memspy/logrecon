import pytest

from log_parser import LogParser

parser = LogParser()

def test_nginx_combined():
    line = '172.17.0.1 - - [26/Oct/2026:10:45:07 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.20.0" "-"'
    record = parser.parse_line(line)
    assert record['format'] == 'nginx_combined'
    assert record['ip'] == '172.17.0.1'
    assert record['status'] == '404'
    assert record['source_key'] == '172.17.0.1'

def test_syslog_classic_timestamp():
    record = parser.parse_line('Sep 27 05:52:41 myhost sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2')
    assert record['format'] == 'syslog'
    assert record['service'] == 'sshd'
    assert record['ip'] == '203.0.113.5'

def test_syslog_iso_timestamp_and_hyphenated_service():
    line = '2026-09-27T05:52:41.218692+00:00 myhost sshd-session[4321]: Accepted publickey for admin from 198.51.100.7 port 50022 ssh2'
    record = parser.parse_line(line)
    assert record['format'] == 'syslog'
    assert record['service'] == 'sshd-session'
    assert record['ip'] == '198.51.100.7'

def test_apache_error():
    record = parser.parse_line('[Thu Jun 09 06:07:04 2005] [notice] LDAP: Built with OpenLDAP LDAP SDK')
    assert record['format'] == 'apache_error'
    assert record['service'] == 'apache_notice'

def test_unrecognized_lines_fall_back_instead_of_being_dropped():
    record = parser.parse_line('completely free-form text from 192.0.2.44 without structure')
    assert record['format'] == 'unrecognized'
    assert record['ip'] == '192.0.2.44'

@pytest.mark.parametrize('blank', ['', '   ', '\n'])
def test_blank_lines_are_skipped(blank):
    assert parser.parse_line(blank) == {}
