from datetime import datetime
# OrderedDict doesn't show in IntelliJ for some reason.
# noinspection PyUnresolvedReferences
from typing import NamedTuple, Optional, OrderedDict, Union

from fedimap.user_agent import InstanceUserAgent

__all__ = [
    'TimeWindowFrozen', 'TimeWindowAcc', 'UserAgentEvidence', 'ForwardDNSEvidence',
    'ReverseDNSEvidence', 'TLSCertCheckEvidence', 'InstanceAPIEvidence', 'IPEvidence',
    'InstanceEvidence', 'Evidence'
]


TimeWindowFrozen = OrderedDict[str, str]


class TimeWindowAcc:
    """
    Accumulator that tracks the min and max times seen (inclusive).
    """
    min: Optional[datetime] = None
    max: Optional[datetime] = None

    # noinspection PyShadowingBuiltins
    def __init__(self, min: Optional[datetime] = None, max: Optional[datetime] = None):
        if (min is None) != (max is None):
            raise ValueError()
        self.min = min
        self.max = max

    def __repr__(self) -> str:
        args = []
        if self.min is not None:
            args.append('min={min!r}'.format(min=self.min))
        if self.max is not None:
            args.append('max={min!r}'.format(min=self.min))
        return '{module}.{qualname}({args})'.format(
            module=self.__class__.__module__,
            qualname=self.__class__.__qualname__,
            args=', '.join(args)
        )

    def is_empty(self) -> bool:
        return self.min is None

    def add(self, x: Union[datetime, 'TimeWindowAcc']) -> None:
        if isinstance(x, TimeWindowAcc):
            if not x.is_empty():
                self.add(x.min)
                self.add(x.max)
        else:
            if self.is_empty():
                self.min = x
                self.max = x
            else:
                if x < self.min:
                    self.min = x
                elif x > self.max:
                    self.max = x

    def freeze(self) -> TimeWindowFrozen:
        if self.is_empty():
            raise ValueError()
        od = OrderedDict()
        od['first_seen'] = self.min.strftime('%Y-%m-%d')
        od['last_seen'] = self.max.strftime('%Y-%m-%d')
        return od


class UserAgentEvidence(NamedTuple):
    """
    Evidence from server access logs that a given instance was trying to access this server.
    User agents can be spoofed trivially so this is weak.
    """
    ip: bytes
    hostname: str
    domain: str
    port: int
    instance_user_agent: InstanceUserAgent
    time_window: TimeWindowAcc


class ForwardDNSEvidence(NamedTuple):
    """
    Evidence that a given hostname resolved to a given IP at some time.
    (If the hostname resolved to multiple IPs, we create multiple copies of this evidence.)
    """
    ip: bytes
    hostname: str
    domain: str
    time: datetime


class ReverseDNSEvidence(NamedTuple):
    """
    Evidence that a given IP resolved to a given hostname at some time.
    Many Fediverse instances won't have reverse DNS entries matching their instance names.
    """
    ip: bytes
    hostname: str
    domain: str
    time: datetime


class TLSCertCheckEvidence(NamedTuple):
    """
    Evidence that a given hostname and port was serving with a valid TLS cert for it
    at some time.
    """
    hostname: str
    domain: str
    port: int
    time: datetime


class InstanceAPIEvidence(NamedTuple):
    """
    Evidence that a working Fediverse server exists at a given hostname and port,
    and identified itself with the matching hostname and port.
    """
    hostname: str
    domain: str
    port: int
    instance_user_agent: InstanceUserAgent
    time: datetime


IPEvidence = Union[UserAgentEvidence, ForwardDNSEvidence, ReverseDNSEvidence]
InstanceEvidence = Union[TLSCertCheckEvidence, InstanceAPIEvidence]
Evidence = Union[IPEvidence, InstanceEvidence]
