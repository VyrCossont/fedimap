from datetime import datetime
from typing import NamedTuple, Optional

from fedimap.user_agent import InstanceUserAgent

__all__ = ['TimeWindow', 'UserAgentEvidence', 'ForwardDNSEvidence', 'ReverseDNSEvidence', 'TLSCertCheckEvidence',
           'InstanceAPIEvidence']


class TimeWindow:
    """
    Accumulator that tracks the min and max times seen (inclusive).
    """
    min: Optional[datetime] = None
    max: Optional[datetime] = None

    # noinspection PyShadowingBuiltins
    def __init__(self, min=None, max=None):
        self.min = min
        self.max = max

    def __repr__(self):
        args = []
        if self.min is not None:
            args.append('min={min!r}'.format(min=self.min))
        if self.max is not None:
            args.append('max={min!r}'.format(min=self.min))
        return '{module}.{qualname}({args})'.format(
            module=self.__class__.__module__, qualname=self.__class__.__qualname__, args=', '.join(args))

    def add(self, dt):
        if self.min is None:
            self.min = dt
            self.max = dt
        else:
            if dt < self.min:
                self.min = dt
            elif dt > self.max:
                self.max = dt


class UserAgentEvidence(NamedTuple):
    """
    Evidence from server access logs that a given instance was trying to access this server.
    User agents can be spoofed trivially so this is weak.
    """
    ip: bytes
    hostname: str
    port: int
    instance_user_agent: InstanceUserAgent
    time_window: TimeWindow


class ForwardDNSEvidence(NamedTuple):
    """
    Evidence that a given hostname resolved to a given IP at some time.
    (If the hostname resolved to multiple IPs, we create multiple copies of this evidence.)
    """
    ip: bytes
    hostname: str
    time: datetime


class ReverseDNSEvidence(NamedTuple):
    """
    Evidence that a given IP resolved to a given hostname at some time.
    Many Fediverse instances won't have reverse DNS entries matching their instance names.
    """
    ip: bytes
    hostname: str
    time: datetime


class TLSCertCheckEvidence(NamedTuple):
    """
    Evidence that a given hostname and port was serving with a valid TLS cert for it at some time.
    """
    hostname: str
    port: int
    time: datetime


class InstanceAPIEvidence(NamedTuple):
    """
    Evidence that a working Fediverse server exists at a given hostname and port,
    and identified itself with the matching hostname and port.
    """
    hostname: str
    port: int
    instance_user_agent: InstanceUserAgent
    time: datetime
