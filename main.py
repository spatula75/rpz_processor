#!/usr/bin/env python3.8
import sys
import os

from converter import PassThruRpzConverter, converters
from processor import RpzProcessor

try:
    import pwd
except ModuleNotFoundError:
    pass
from argparse import ArgumentParser
from urllib import parse

"""
Retrieve a DNS blackhole list from a given URL, optionally apply an allow-list, and write the list out in
RPZ format.  Does not use temporary files nor are remote files read into memory, for maximum performance with
minimum footprint.
"""

DEFAULT_URL = 'https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/rpz.txt'
DEFAULT_OUTPUT_FILE = '/usr/local/etc/namedb/rpz.localhost'
DEFAULT_ALLOW_LIST_FILE = '/usr/local/etc/namedb/rpz-allowlist'
MAX_DOMAIN_LENGTH = 240


def converter_choice(choice: str):
    try:
        return converters[choice]
    except KeyError:
        raise AttributeError(f'Bad converter value {choice}, valid choices are {converters.keys()}')


# Give the user meaningful feedback if the script is being run as root without -U, or if the script has been
# run with -U, but setuid support is not available on this platform.
def check_suid(username: str):
    try:
        uid = os.getuid()
        if uid == 0:
            if username:
                try:
                    user = pwd.getpwnam(username)
                    os.setuid(user.pw_uid)
                except KeyError:
                    print(f'User named {username} not found!')
                    exit(1)
                except NameError:
                    print(f'-U specified, but no getpwnam support available on this system.')
                    exit(1)
            else:
                print('Please do not run this script as root!  (See also the -U argument.)')
                exit(1)
    except AttributeError:
        if username:
            print('-U specified, but setuid support is not available on this system.')
            exit(1)


if __name__ == '__main__':
    parser = ArgumentParser(prog=sys.argv[0], description='Read an RPZ file from a URL and apply an allow list')
    parser.add_argument('-a', metavar='file',
                        default=DEFAULT_ALLOW_LIST_FILE,
                        nargs='?',
                        type=str,
                        help='Path to the allow-list file. Use `-` for no allow-list.')
    parser.add_argument('-u', metavar='URL',
                        default=DEFAULT_URL,
                        nargs='?',
                        type=parse.urlparse,
                        help='URL pointing to an RPZ file to import.')
    parser.add_argument('-o', metavar='file',
                        default=DEFAULT_OUTPUT_FILE,
                        nargs='?',
                        type=str,
                        help='Path to the output file containing the filtered RPZ file.')
    parser.add_argument('-c', metavar='converter',
                        default=PassThruRpzConverter.get_name(),
                        nargs='?',
                        type=str,
                        choices=list(converters.keys()),
                        help='Conversion method to use when importing list.')
    parser.add_argument('-U', metavar='User',
                        nargs='?',
                        type=str,
                        help='Username whose identity should be assumed before running (requires running as root).')

    args = parser.parse_args()

    check_suid(args.U)

    processor = RpzProcessor(converter_choice(args.c))

    if args.a != '-':
        if not processor.read_allow_list(args.a):
            exit(1)

    url = args.u.geturl()
    print(f'Fetching {url}, applying {len(processor.allow_domains_exact)} allow-list entries,\n'
          f'and writing to {args.o} using converter `{args.c}`')
    exit(0 if processor.import_rpz_list(url, args.o) else 1)
