import socket
from typing import Optional, Tuple
from urllib.parse import urlsplit

import publicsuffix2
import validators

__all__ = ['af_for_ip', 'fmt_ip', 'extract_hostname_and_port', 'get_domain']


def af_for_ip(ip: bytes) -> socket.AddressFamily:
    return socket.AF_INET if len(ip) == 4 else socket.AF_INET6


def fmt_ip(ip: bytes) -> str:
    return socket.inet_ntop(af_for_ip(ip), ip)


def extract_hostname_and_port(instance_url: str) -> Optional[Tuple[str, int]]:
    """
    Get the hostname and port from a Mastodon instance URL.
    Assumes HTTPS and will return None if any unexpected URL parts are present.
    TODO: are there any servers that would use HTTP during normal operation?
    TODO: how many places could we just pass an HTTP or HTTPS URL straight through?
    """
    url = urlsplit(instance_url)
    if url.scheme != 'https':
        return None
    if url.path != '' and url.path != '/':
        return None
    if url.query != '':
        return None
    if url.query != '':
        return None
    if url.username is not None:
        return None
    if url.password is not None:
        return None
    if url.hostname is None:
        return None
    if not validators.domain(url.hostname):
        return None
    if url.port is None:
        return url.hostname, 443
    else:
        return url.hostname, url.port


# Domains where it's known that subdomains will be different instances.
_multi_user_domains = frozenset([
    'masto.host',
])


def get_domain(hostname: str) -> str:
    """
    Get the first private part of a hostname after the public suffix,
    but with exceptions where it's known that different hosts have different owners.

    There's one current exception to the PSL: masto.host.
    """
    # Note: `publicsuffix2.get_public_suffix` really should have been called `get_private_suffix`.
    # `get_public_suffix('example.com') sounds like it'd return `com`,
    # but actually returns `example.com`.
    private_suffix = publicsuffix2.get_public_suffix(hostname)
    if private_suffix in _multi_user_domains:
        return hostname
    return private_suffix
