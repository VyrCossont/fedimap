import itertools
import sys

from fedimap.access_log import parse_log_file


def main(args):
    distinct_uas = {
        log_record.user_agent for log_record
        in itertools.chain.from_iterable(parse_log_file(path) for path in args[1:])
        if log_record.user_agent is not None
    }
    for ua in sorted(distinct_uas):
        print(ua)


if __name__ == '__main__':
    main(sys.argv)
