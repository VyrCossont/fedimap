import itertools
import logging
import socket
import sys
from datetime import datetime, timezone
# OrderedDict doesn't show in IntelliJ for some reason.
# noinspection PyUnresolvedReferences
from typing import DefaultDict, Iterable, List, OrderedDict, Set, Tuple, Union

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap  # Hack: prevents !!omap annotation in YAML output

from fedimap.access_log import parse_log_file, LogRecord
from fedimap.evidence import TimeWindowAcc, UserAgentEvidence, ReverseDNSEvidence,\
    ForwardDNSEvidence, TLSCertCheckEvidence, InstanceAPIEvidence, IPEvidence,\
    InstanceEvidence
from fedimap.instance_api import UNKNOWN_SERVER_TYPE, get_instance_info
from fedimap.net import fmt_ip, extract_hostname_and_port, get_domain
from fedimap.user_agent import classify_user_agent, InstanceUserAgent


IPInfoFrozen = OrderedDict[str, Union[bool, str]]


class IPInfoAcc:
    """
    Accumulator for all evidence about an IP.
    """
    inbound: bool = False
    forward: bool = False
    reverse: bool = False
    time_window: TimeWindowAcc

    def __init__(self):
        self.time_window = TimeWindowAcc()

    def add(self, evidence: IPEvidence) -> TimeWindowAcc:
        """
        :return: Time window from this evidence, as a convenience for InstanceInfoAcc.
        """
        if isinstance(evidence, UserAgentEvidence):
            self.inbound = True
            self.time_window.add(evidence.time_window)
            return evidence.time_window
        elif isinstance(evidence, ForwardDNSEvidence):
            self.forward = True
            self.time_window.add(evidence.time)
            return TimeWindowAcc(min=evidence.time, max=evidence.time)
        elif isinstance(evidence, ReverseDNSEvidence):
            self.reverse = True
            self.time_window.add(evidence.time)
            return TimeWindowAcc(min=evidence.time, max=evidence.time)
        else:
            raise NotImplementedError()

    def freeze(self) -> IPInfoFrozen:
        od = OrderedDict()
        od['inbound'] = self.inbound
        od['forward'] = self.forward
        od['reverse'] = self.reverse
        od.update(self.time_window.freeze())
        return CommentedMap(od)  # Hack: prevents !!omap annotation in YAML output


InstanceInfoFrozen = OrderedDict[
    str,
    Union[
        bool,
        str,
        OrderedDict[str, IPInfoFrozen],
        List[str]
    ]
]


class InstanceInfoAcc:
    """
    Accumulator for all evidence about a hostname.
    """
    # Map of IP to IP info accumulator.
    tls_cert_ok: bool = False
    instance_api_called: bool = False
    urls: Set[str]
    ips: DefaultDict[bytes, IPInfoAcc]
    user_agents: DefaultDict[InstanceUserAgent, TimeWindowAcc]
    time_window: TimeWindowAcc

    # noinspection PyTypeHints
    def __init__(self):
        self.urls = set()
        self.ips = DefaultDict(IPInfoAcc)
        self.user_agents = DefaultDict(TimeWindowAcc)
        self.time_window = TimeWindowAcc()

    def add(self, evidence: Union[InstanceEvidence, IPEvidence]) -> None:
        if isinstance(evidence, TLSCertCheckEvidence):
            self.tls_cert_ok = True
            self.time_window.add(evidence.time)
        elif isinstance(evidence, InstanceAPIEvidence):
            self.instance_api_called = True
            self.time_window.add(evidence.time)
            if evidence.instance_user_agent.url is not None:
                self.urls.add(evidence.instance_user_agent.url)
        else:
            time_window = self.ips[evidence.ip].add(evidence)
            self.time_window.add(time_window)
            if isinstance(evidence, UserAgentEvidence):
                self.user_agents[evidence.instance_user_agent].add(time_window)

    def freeze(self) -> InstanceInfoFrozen:
        od = OrderedDict()
        od['urls'] = sorted(self.urls)
        od['tls_cert_ok'] = self.tls_cert_ok
        od['instance_api_called'] = self.instance_api_called
        od.update(self.time_window.freeze())

        # TODO: ignore time windows for now
        od['versions'] = sorted(set(
            '{server} {version}'.format(server=ua.server, version=ua.version)
            if ua.version is not None
            else ua.server
            for ua in self.user_agents.keys()
        ))

        frozen_ips = OrderedDict()
        for ip in sorted(self.ips.keys()):
            frozen_ips[fmt_ip(ip)] = self.ips[ip].freeze()
        od['ips'] = CommentedMap(frozen_ips)  # Hack: prevents !!omap annotation in YAML output

        return CommentedMap(od)  # Hack: prevents !!omap annotation in YAML output


def main(args: List[str]) -> None:
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    all_evidence = []

    log_records_all_files: Iterable[LogRecord] = \
        itertools.chain.from_iterable(parse_log_file(path) for path in args[1:])
    # noinspection PyTypeHints
    incoming_ips: DefaultDict[bytes, DefaultDict[InstanceUserAgent, TimeWindowAcc]] = \
        DefaultDict(lambda: DefaultDict(TimeWindowAcc))

    for log_record in log_records_all_files:
        if log_record.user_agent is None:
            continue
        instance_user_agent = classify_user_agent(log_record.user_agent)
        if instance_user_agent is None:
            continue
        incoming_ips[log_record.ip][instance_user_agent].add(log_record.timestamp)

    possible_instance_ips: Set[bytes] = set(incoming_ips.keys())
    possible_instance_hostnames: Set[str] = set()
    possible_instance_hostnames_and_ports: Set[Tuple[str, int]] = set()

    for ip in incoming_ips.keys():
        for instance_user_agent in incoming_ips[ip].keys():
            time_window = incoming_ips[ip][instance_user_agent]

            if instance_user_agent.url is not None:
                hostname_and_port = extract_hostname_and_port(instance_user_agent.url)
                if hostname_and_port is not None:
                    hostname, port = hostname_and_port

                    possible_instance_hostnames.add(hostname)
                    possible_instance_hostnames_and_ports.add(hostname_and_port)

                    all_evidence.append(UserAgentEvidence(
                        ip=ip,
                        hostname=hostname,
                        domain=get_domain(hostname),
                        port=port,
                        instance_user_agent=instance_user_agent,
                        time_window=time_window,
                    ))

    for ip in possible_instance_ips:
        ip_str = fmt_ip(ip)
        try:
            time = datetime.now(timezone.utc)
            hostname, aliases, addresses = socket.gethostbyaddr(ip_str)
            aliases = [alias for alias in aliases
                       if not alias.endswith('.in-addr.arpa')
                       and not alias.endswith('.ip6.arpa')]
            if addresses != [ip_str]:
                # TODO: when would this happen?
                logger.warning('%(ip_str)s resolved to multiple IPs: %(addresses)r',
                               {'ip_str': ip_str, 'addresses': addresses})

            for alias in [hostname] + aliases:
                all_evidence.append(ReverseDNSEvidence(
                    ip=ip,
                    hostname=alias,
                    domain=get_domain(alias),
                    time=time,
                ))
        except OSError:
            logger.warning(
                "Exception on reverse DNS lookup for %(ip_str)s!",
                {'ip_str': ip_str},
                exc_info=True
            )

    for hostname in possible_instance_hostnames:
        try:
            time = datetime.now(timezone.utc)
            # noinspection PyArgumentList
            for af, _, _, _, sockaddr in socket.getaddrinfo(hostname, None,
                                                            family=socket.AF_INET,
                                                            type=socket.SOCK_STREAM,
                                                            proto=socket.IPPROTO_IP):
                ip_str = sockaddr[0]
                ip = socket.inet_pton(af, ip_str)
                all_evidence.append(ForwardDNSEvidence(
                    ip=ip,
                    hostname=hostname,
                    domain=get_domain(hostname),
                    time=time,
                ))
        except OSError:
            logger.warning(
                "Exception on forward DNS lookup for %(hostname)s!",
                {'hostname': hostname},
                exc_info=True
            )

    for hostname, port in possible_instance_hostnames_and_ports:
        logger.info("%s:%d", hostname, port)  # DEBUG
        time = datetime.now(timezone.utc)
        instance_user_agent = get_instance_info(hostname, port)

        if instance_user_agent is not None:
            all_evidence.append(TLSCertCheckEvidence(
                hostname=hostname,
                domain=get_domain(hostname),
                port=port,
                time=time,
            ))

            if instance_user_agent.server != UNKNOWN_SERVER_TYPE \
                    and instance_user_agent.url is not None:
                reported_hostname_and_port = extract_hostname_and_port(instance_user_agent.url)
                if reported_hostname_and_port is not None:
                    reported_hostname, reported_port = reported_hostname_and_port
                    if hostname == reported_hostname and port == reported_port:
                        all_evidence.append(InstanceAPIEvidence(
                            hostname=hostname,
                            domain=get_domain(hostname),
                            port=port,
                            instance_user_agent=instance_user_agent,
                            time=time,
                        ))

    # TODO: Ignores ports: I've not seen a non-443 instance yet.

    # Map of hostname to instance info accumulator.
    # noinspection PyTypeHints
    instances: DefaultDict[str, InstanceInfoAcc] = DefaultDict(InstanceInfoAcc)
    for evidence in all_evidence:
        instances[evidence.domain].add(evidence)

    frozen: OrderedDict[str, InstanceInfoFrozen] = OrderedDict()
    for instance in sorted(instances.keys()):
        frozen[instance] = instances[instance].freeze()

    # Dump output as YAML.
    yaml = YAML()
    yaml.indent(mapping=2, sequence=2, offset=1)
    yaml.dump(CommentedMap(frozen), sys.stdout)  # Hack: prevents !!omap annotation in YAML output


if __name__ == '__main__':
    main(sys.argv)
