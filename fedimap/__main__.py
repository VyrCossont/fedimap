import itertools
import logging
import socket
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pprint import pprint
from typing import DefaultDict, Dict, Iterable, Set, Tuple

from fedimap.access_log import parse_log_file, LogRecord
from fedimap.evidence import TimeWindow, UserAgentEvidence, ReverseDNSEvidence, ForwardDNSEvidence,\
    TLSCertCheckEvidence, InstanceAPIEvidence
from fedimap.instance_api import UNKNOWN_SERVER_TYPE, get_instance_info
from fedimap.net import fmt_ip, extract_hostname_and_port
from fedimap.user_agent import classify_user_agent, InstanceUserAgent


def main(args):
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    evidence = []

    log_records_all_files: Iterable[LogRecord] = \
        itertools.chain.from_iterable(parse_log_file(path) for path in args[1:])
    incoming_ips: DefaultDict[bytes, Dict[InstanceUserAgent, TimeWindow]] = \
        defaultdict(lambda: defaultdict(TimeWindow))

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

                    evidence.append(UserAgentEvidence(
                        ip=ip,
                        hostname=hostname,
                        port=port,
                        instance_user_agent=instance_user_agent,
                        time_window=time_window,
                    ))

    for ip in possible_instance_ips:
        continue  # DEBUG
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
                evidence.append(ReverseDNSEvidence(
                    ip=ip,
                    hostname=alias,
                    time=time,
                ))
        except OSError:
            logger.warning("Exception on reverse DNS lookup for %(ip_str)s!", {'ip_str': ip_str}, exc_info=True)

    for hostname in possible_instance_hostnames:
        continue  # DEBUG
        try:
            time = datetime.now(timezone.utc)
            for af, _, _, _, sockaddr in socket.getaddrinfo(hostname, None,
                                                            family=socket.AF_INET,
                                                            type=socket.SOCK_STREAM,
                                                            proto=socket.IPPROTO_IP):
                ip_str = sockaddr[0]
                ip = socket.inet_pton(af, ip_str)
                evidence.append(ForwardDNSEvidence(
                    ip=ip,
                    hostname=hostname,
                    time=time,
                ))
        except OSError:
            logger.warning("Exception on forward DNS lookup for %(hostname)s!", {'hostname': hostname}, exc_info=True)

    for hostname, port in possible_instance_hostnames_and_ports:
        logger.info("%s:%d", hostname, port)  # DEBUG
        time = datetime.now(timezone.utc)
        instance_user_agent = get_instance_info(hostname, port)

        if instance_user_agent is not None:
            evidence.append(TLSCertCheckEvidence(
                hostname=hostname,
                port=port,
                time=time,
            ))

            if instance_user_agent.server != UNKNOWN_SERVER_TYPE and instance_user_agent.url is not None:
                reported_hostname_and_port = extract_hostname_and_port(instance_user_agent.url)
                if reported_hostname_and_port is not None:
                    reported_hostname, reported_port = reported_hostname_and_port
                    if hostname == reported_hostname and port == reported_port:
                        evidence.append(InstanceAPIEvidence(
                            hostname=hostname,
                            port=port,
                            instance_user_agent=instance_user_agent,
                            time=time,
                        ))

    pprint(evidence)


if __name__ == '__main__':
    main(sys.argv)
