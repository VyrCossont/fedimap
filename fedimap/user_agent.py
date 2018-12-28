import re
from typing import NamedTuple, Optional

__all__ = ['InstanceUserAgent', 'classify_user_agent']


class InstanceUserAgent(NamedTuple):
    pattern_name: str
    server: str
    version: Optional[str] = None
    codename: Optional[str] = None
    url: Optional[str] = None
    email: Optional[str] = None
    http_client: Optional[str] = None
    http_client_version: Optional[str] = None


# Casual regex for an HTTP or HTTPS URL without a query part.
_url = r'(?P<url>https?://[a-z0-9./-]+)'

_servers = {
    'frendica': r"(?P<server>Friendica) '(?P<codename>[^']+)' (?P<version>[^;]+); {url}",
    # I've never seen a GNU social server with a URL in what looks like the URL field.
    # So far they all end with (Not decided yet).
    'gnu_social': r'(?P<server>GNU social)/(?P<version>\S+) \((?:{url}|[^)]+)\)',
    'mastodon': r'(?P<http_client>\S+)/(?P<http_client_version>\S+) '
                r'\((?P<server>Mastodon)/(?P<version>[^;]+); \+{url}\)',
    # The Ruby HTTP client used by Mastodon. Might be a Mastodon instance.
    'mastodon_probably': r'(?P<http_client>http\.rb)/(?P<http_client_version>.+)',
    'microblog_pub': r'(?P<http_client>\S+)/(?P<http_client_version>\S+) '
                     r'\((?P<server>microblog\.pub)/(?P<version>[^;]+); \+{url}\)',
    'misskey': r'(?P<server>Misskey)/(?P<version>\S+) \({url}\)',
    # Some Pleroma admins leave the email field blank.
    'pleroma_mediaproxy': r'(?P<server>Pleroma)/(?P<version>MediaProxy); {url} <(?P<email>[^>]*)>',
    # Hackney is just an Elixir HTTP client, but Elixir is likely to be Pleroma in this context.
    'pleroma_probably': r'(?P<http_client>hackney)/(?P<http_client_version>.+)',
    'postactiv': r'(?P<server>postActiv)/(?P<version>\S+) \((?P<codename>[^)]+)\)',
}

_server_res = {
    name: re.compile('^{pattern_with_url}$'.format(pattern_with_url=pattern.format(url=_url)))
    for name, pattern in _servers.items()
}

# Map from HTTP client to server behind it, assuming the traffic is from an instance.
_server_guesses = {
    'http.rb': 'Mastodon',
    'hackney': 'Pleroma',
}


def classify_user_agent(user_agent: str) -> Optional[InstanceUserAgent]:
    pattern_name = None
    match = None
    for name, server_re in _server_res.items():
        match = server_re.match(user_agent)
        if match is not None:
            pattern_name = name
            break
    if match is None:
        return None

    # Treat empty groups as None.
    attrs = {
        k: None if v == '' else v
        for k, v
        in dict(pattern_name=pattern_name, **match.groupdict()).items()
    }
    # Guess at unlabeled instances by HTTP client.
    if 'server' not in attrs and 'http_client' in attrs:
        attrs['server'] = _server_guesses[attrs['http_client']]

    return InstanceUserAgent(**attrs)
