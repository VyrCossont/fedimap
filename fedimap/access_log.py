"""
Combined-format access log parser.

Should work with at least nginx.
The test data was generated with nginx 1.14.1 running on Debian 9.6 in an en-US UTF-8 locale.

May also work with Apache 2.0.46 and higher: Apache started escaping control characters in most
fields in that release, but it may still allow quotes to be written as `\"` instead of a hex escape,
which would break this. It's also unclear how Apache handles non-ASCII characters.

See https://httpd.apache.org/docs/current/mod/mod_log_config.html
See https://nginx.org/en/docs/http/ngx_http_log_module.html
"""

__all__ = ['LogRecord', 'parse_log_line', 'parse_log_file']

import codecs
import re
import socket
from datetime import datetime
from typing import NamedTuple, Optional


class LogRecord(NamedTuple):
    ip: bytes
    username: Optional[str]
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referrer: Optional[str]
    user_agent: Optional[str]


_common_datetime = '%d/%b/%Y:%H:%M:%S %z'

_combined_re = re.compile(
    br'''
        ^
        (?P<ip>[0-9a-fA-F.:]+)
        \ # The identd remote logname field is assumed to be empty because it's long obsolete.
        -
        \ # Optional. Note that usernames are not quoted but may have whitespace in them anyway.
        (?P<username>.+?)
        \ # See _common_datetime.
        \[(?P<datetime>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\ [+-]\d{4})\]
        \ # Technically this is just the first line of the request.
        "(?P<method>\w+)\ (?P<path>[^"]+)\ (?P<protocol>\w+/[\d.]+)"
        \ # HTTP status code.
        (?P<status>\d{3})
        \ # Response size in bytes.
        (?P<size>\d+)
        \ # Referrer header (optional).
        "(?P<referrer>[^"]+)"
        \ # User agent header (optional).
        "(?P<user_agent>[^"]+)"
        $
    ''',
    re.VERBOSE
)


def _unescape_decode(b: bytes) -> str:
    """
    Process backslash escapes in fields that can contain non-alphanumeric/non-ASCII characters,
    then decode as UTF-8.

    This version relies on an undocumented CPython function.
    See https://stackoverflow.com/a/23151714
    """
    return codecs.escape_decode(b)[0].decode('utf-8')


def _dash_empty(s: str) -> Optional[str]:
    """
    Several fields use a dash to indicate the field has no value.
    """
    return None if s == '-' else s


def parse_log_line(line: bytes) -> Optional[LogRecord]:
    """
    Parse one log line and return a `LogRecord` if possible, `None` otherwise.
    """
    match = _combined_re.match(line)
    if not match:
        return None
    groups = match.groupdict()

    try:
        ip_str = groups['ip'].decode('ascii')
        if ':' in ip_str:
            ip = socket.inet_pton(socket.AF_INET6, ip_str)
        else:
            ip = socket.inet_pton(socket.AF_INET, ip_str)

        username = _dash_empty(_unescape_decode(groups['username']))
        timestamp = datetime.strptime(groups['datetime'].decode('ascii'), _common_datetime)
        method = groups['method'].decode('ascii')
        path = _unescape_decode(groups['path'])
        protocol = groups['protocol'].decode('ascii')
        status = int(groups['status'].decode('ascii'))
        size = int(groups['size'].decode('ascii'))
        referrer = _dash_empty(_unescape_decode(groups['referrer']))
        user_agent = _dash_empty(_unescape_decode(groups['user_agent']))

        return LogRecord(
            ip=ip,
            username=username,
            timestamp=timestamp,
            method=method,
            path=path,
            protocol=protocol,
            status=status,
            size=size,
            referrer=referrer,
            user_agent=user_agent
        )

    except (UnicodeError, OSError, ValueError):
        return None


def parse_log_file(path):
    with open(path, 'rb') as f:
        for line in f:
            log_record = parse_log_line(line)
            if log_record is not None:
                yield log_record
