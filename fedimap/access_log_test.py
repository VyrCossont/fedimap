from datetime import datetime, timezone
import socket
import unittest

from fedimap.access_log import parse_log_line, LogRecord


class TestAccessLog(unittest.TestCase):
    def test_simple(self):
        expected = LogRecord(
            ip=socket.inet_pton(socket.AF_INET, '12.34.56.78'),
            timestamp=datetime(
                2018, 12, 27, 18, 20, 28,
                tzinfo=timezone.utc
            ),
            method='GET',
            path='/example',
            protocol='HTTP/2.0',
            status=200,
            size=728,
            user_agent='curl/7.52.1'
        )
        log_record = parse_log_line(br'12.34.56.78 - - [27/Dec/2018:18:20:28 +0000] "GET /example '
                                    br'HTTP/2.0" 200 728 "-" "curl/7.52.1"')
        self.assertEqual(log_record, expected)

    def test_quotes_in_user_agent(self):
        log_record = parse_log_line(br'12.34.56.78 - - [27/Dec/2018:18:05:38 +0000] "GET /example '
                                    br'HTTP/2.0" 200 728 "-" "\x22hi\x22"')
        self.assertEqual(log_record.user_agent, '"hi"')

    def test_space_in_user_agent(self):
        log_record = parse_log_line(br'12.34.56.78 - - [27/Dec/2018:18:22:04 +0000] "GET /example '
                                    br'HTTP/2.0" 200 728 "-" "hel lo"')
        self.assertEqual(log_record.user_agent, 'hel lo')

    def test_unicode_in_user_agent(self):
        log_record = parse_log_line(br'12.34.56.78 - - [27/Dec/2018:18:05:38 +0000] "GET /example '
                                    br'HTTP/2.0" 200 728 "-" "\xE2\x88\x91"')
        self.assertEqual(log_record.user_agent, '∑')

    def test_space_in_path(self):
        log_record = parse_log_line(br'12.34.56.78 - - [27/Dec/2018:18:22:04 +0000] "GET '
                                    br'/ example HTTP/2.0" 200 728 "-" "hello"')
        self.assertEqual(log_record.path, '/ example')

    def test_unicode_in_path(self):
        log_record = parse_log_line(br'12.34.56.78 - - [27/Dec/2018:18:21:01 +0000] "GET '
                                    br'/example\xC3\xA7\xE2\x88\x9A HTTP/2.0" 502 173 "-" "-"')
        self.assertEqual(log_record.path, '/exampleç√')

    def test_bracket_and_space_in_username(self):
        log_record = parse_log_line(br'12.34.56.78 - [Jen] Problem [27/Dec/2018:18:58:28 +0000] '
                                    br'"GET /basic/ HTTP/2.0" 404 169 "-" "curl/7.54.0"')
        self.assertEqual(log_record.username, '[Jen] Problem')

    def test_unicode_and_space_in_username(self):
        log_record = parse_log_line(br'12.34.56.78 - J\xC3\xB8hn Problem [27/Dec/2018:18:32:30 '
                                    br'+0000] "GET /basic/ HTTP/2.0" 404 169 "-" "curl/7.54.0"')
        self.assertEqual(log_record.username, 'Jøhn Problem')

    def test_ipv6(self):
        log_record = parse_log_line(br'::1 - - [27/Dec/2018:19:00:36 +0000] "GET /ipv6 HTTP/1.1" '
                                    br'404 169 "-" "-"')
        self.assertEqual(log_record.ip, socket.inet_pton(socket.AF_INET6, '::1'))
