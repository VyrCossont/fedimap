import json
import logging
import re
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import requests

from fedimap.user_agent import InstanceUserAgent
# TODO: overloading this for now

__all__ = ['UNKNOWN_SERVER_TYPE', 'get_instance_info']

_logger = logging.getLogger(__name__)

_mastodon_compatible_version_re = re.compile(
    r'^.*\(compatible; (?P<server>.+) (?P<version>[^)]+)\)$')

# For stuff we just can't identify.
UNKNOWN_SERVER_TYPE = 'UNKNOWN_SERVER_TYPE'


def get_instance_info(hostname: str, port: int) -> Optional[InstanceUserAgent]:
    """
    Calls various instance info APIs.
    Does not check to see if the reported hostname and port match the input hostname and port.
    TODO: could be faster if we had a hint as to what the server was before talking to it?
    """
    api_scheme = 'https'
    api_netloc = hostname if port == 443 else '{hostname}:{port}'.format(hostname=hostname, port=port)
    api_query = None
    api_fragment = None

    server: Optional[str] = None
    version: Optional[str] = None
    url: Optional[str] = None
    email: Optional[str] = None

    timeout = 5.0  # seconds

    # noinspection PyBroadException
    try:
        # Not sure where the nodeinfo API came from originally.
        # Works for Pleroma, might work for GNU social.
        # Note that you're supposed to look this path up from /.well-known/nodeinfo.
        try:
            api_url = urlunsplit((api_scheme, api_netloc, '/nodeinfo/2.0.json', api_query, api_fragment))
            resp = requests.get(api_url, timeout=timeout)
            if resp.status_code == 200:
                doc = resp.json()
                software = doc.get('software', {})
                server = software.get('name')
                version = software.get('version')
        except json.decoder.JSONDecodeError:
            _logger.warning("Couldn't decode JSON response for %(api_url)s!", {'api_url': api_url}, exc_info=True)

        # Mastodon instance API. Should work for Mastodon and Pleroma.
        try:
            api_url = urlunsplit((api_scheme, api_netloc, '/api/v1/instance', api_query, api_fragment))
            resp = requests.get(api_url, timeout=timeout)
            if resp.status_code == 200:
                doc = resp.json()
                url = doc.get('uri')
                if url is not None:
                    (scheme, netloc, path, _, _) = urlsplit(url)
                    # Pleroma servers include the scheme, Mastodon servers don't. Reconstruct it.
                    if not scheme and not netloc and path:
                        url = urlunsplit((api_scheme, path, '', '', ''))
                email = doc.get('email') or None  # Sometimes admins leave this field empty.
                if (server is None or version is None) and 'version' in doc:
                    match = _mastodon_compatible_version_re.match(doc['version'])
                    if match is None:
                        server = 'Mastodon'
                        version = doc['version']
                    else:
                        groups = match.groupdict()
                        server = groups.get('server')
                        version = groups.get('version')

        except json.decoder.JSONDecodeError:
            _logger.warning("Couldn't decode JSON response for %(api_url)s!", {'api_url': api_url}, exc_info=True)

        # TODO: neither of these endpoints work for Misskey or Friendica.

    except requests.exceptions.SSLError:
        _logger.warning("Couldn't verify TLS cert for %(api_netloc)s!", {'api_netloc': api_netloc}, exc_info=True)
        return None

    except Exception:
        _logger.warning("Something else went wrong while calling %(api_netloc)s instance info APIs!",
                        {'api_netloc': api_netloc}, exc_info=True)
        return None

    # A return from this function indicates that the TLS cert is valid even if we can't get any instance info.
    server = server or UNKNOWN_SERVER_TYPE

    return InstanceUserAgent(
        pattern_name='get_instance_info',
        server=server,
        version=version,
        url=url,
        email=email,
    )
