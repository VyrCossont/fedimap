import socket
from typing import Optional, Tuple
from urllib.parse import urlsplit

__all__ = ['af_for_ip', 'fmt_ip', 'extract_hostname_and_port']


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
    if url.port is None:
        return url.hostname, 443
    else:
        return url.hostname, url.port
