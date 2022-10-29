#!/usr/bin/env python3.8
import requests
import sys
from argparse import ArgumentParser
from urllib import parse

from requests import HTTPError

DEFAULT_URL = 'https://block.energized.pro/blu/formats/rpz.txt'
DEFAULT_OUTPUT_FILE = '/usr/local/etc/namedb/rpz.localhost'
DEFAULT_ALLOW_LIST_FILE = '/usr/local/etc/namedb/rpz-allowlist'
MAX_DOMAIN_LENGTH = 240


class RpzProcessor:
    """
    Class for importing a Response Policy Zone (RPZ) file from a URL, optionally applying an Allow List to ignore
    matching lines in that file, then writing the output to a local file.
    """

    allow_domains_exact = set()
    allow_domains_right = set()

    def read_allow_list(self, allow_list_file: str):
        """
        Read an allow-list file.  The format of this file is as follows:

        # Comments start at the beginning of a line with a hash symbol
        #
        # Exact match domains begin with any valid character other than a dot (.)
        example.com
        #
        # Lines which begin with a dot (.) are "right-hand" matches and also exact matches:
        .example.net
        # The above will match foo.example.net, foo.bar.baz.example.net and example.net.
        .badness.example.edu
        # The above will match some.badness.example.edu and badness.example.edu, but not example.edu.

        :param allow_list_file: the path to the file containing the Allow List.
        :return: True if reading the file was successful; false otherwise.
        """
        try:
            with open(allow_list_file, 'r') as allow_list:
                while line := allow_list.readline():
                    line = line.strip()
                    if len(line) < 2 or line.startswith('#'):
                        continue
                    if line.startswith('.'):
                        line = line[1:]
                        self.allow_domains_right.add(line)
                        self.allow_domains_exact.add(line)
                    else:
                        self.allow_domains_exact.add(line)
            return True
        except OSError as e:
            print(f'Failed to read allow-list file {allow_list_file}: {e}')
        return False

    def import_rpz_list(self, rpz_url: str, output_file: str):
        try:
            self._do_import(rpz_url, output_file)
            return True
        except HTTPError as e:
            print(f'Failed to retrieve {rpz_url}: {e}')
        except OSError as e:
            print(f'Unable to open or write {output_file}: {e}')

        return False

    def _do_import(self, rpz_url: str, output_file: str):
        session = requests.Session()

        with session.get(rpz_url, stream=True) as request:
            request.raise_for_status()  # in case the response is not a 200

            with open(output_file, 'w') as output:
                for line in request.iter_lines(chunk_size=256, decode_unicode=True):
                    if not line:  # skip blank lines
                        continue

                    # cheap & easy skip DNS directives and comments
                    firstch: str = line[0]
                    if firstch in (';', '$', '@', ' '):
                        output.write(line)
                        output.write('\n')
                        continue

                    domain = line.split()[0]  # get the domain part only

                    # sometimes there's garbage in an RPZ file and the resulting domain name is > 255 characters long
                    # including the base domain name (e.g., 'localhost').  This is a cheap attempt to ignore very long
                    # domain names.
                    if len(domain) > MAX_DOMAIN_LENGTH:
                        continue

                    if domain in self.allow_domains_exact:
                        continue

                    # check for a right-hand match by decomosing the domain into successive subdomains and checking each
                    # against the right-mand match set
                    segments = domain.split('.')
                    if len(segments) < 2:  # what nonsense is this?
                        continue

                    # decompose 'zot.foo.bar.baz' into [ 'zot.foo.bar.baz', 'foo.bar.baz', 'bar.baz' ]
                    checklist = ['.'.join(segments[i:]) for i in range(len(segments) - 1)]

                    # check set membership.  This can be cheaper than any() if we get a match partway through the list
                    found = False
                    for item in checklist:
                        if item in self.allow_domains_right:
                            found = True
                            break
                    if found:
                        continue

                    # if we got here, there was no match, exact or right-hand.
                    output.write(line)
                    output.write('\n')


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

    args = parser.parse_args()

    processor = RpzProcessor()

    if args.a != '-':
        if not processor.read_allow_list(args.a):
            exit(1)

    url = args.u.geturl()
    print(f'Fetching {url}, applying {len(processor.allow_domains_exact)} allow-list entries, and writing to {args.o}')
    exit(0 if processor.import_rpz_list(url, args.o) else 1)
