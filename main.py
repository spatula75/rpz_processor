#!/usr/bin/env python3.8
from abc import ABC, abstractmethod
from typing import TextIO

import requests
import sys
from argparse import ArgumentParser
from urllib import parse

from requests import HTTPError

DEFAULT_URL = 'https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/rpz.txt'
DEFAULT_OUTPUT_FILE = '/usr/local/etc/namedb/rpz.localhost'
DEFAULT_ALLOW_LIST_FILE = '/usr/local/etc/namedb/rpz-allowlist'
MAX_DOMAIN_LENGTH = 240


class RpzConverter(ABC):
    """
    Abstract Base Class for RPZ writers so that different strategies may be employed based on the type of data
    being read from the blocklist.
    """

    @abstractmethod
    def before_writing(self, output: TextIO):
        """
        Called after the RPZ file has been opened for writing, but before any data has been written to the file.
        """
        pass

    @abstractmethod
    def write_line(self, output: TextIO, line: str):
        """
        Called for every line that needs to be written to the RPZ file.
        """
        pass

    @abstractmethod
    def after_writing(self, output: TextIO):
        """
        Called once all the lines have been written, but the file is still open.  (Do not close the file here;
        the RpzProcessor will handle that.)
        """
        pass

    @abstractmethod
    def should_passthru(self, line: str):
        """
        Called once per line; return true if the line should be passed through, or false if it probably contains
        a domain which should be evaluated
        """

    def extract_domain(self, line: str):
        """
        Given a line from the source file, extract just the domain from the line.
        """
        return line.split()[0]

    @staticmethod
    @abstractmethod
    def get_name():
        """
        Name for this converter, suitable for consumption as a command-line argument.
        """
        pass


class PassThruRpzConverter(RpzConverter):
    """
    Pass-through writer for files which are already in RPZ format.  Does nothing special.
    """
    def before_writing(self, output: TextIO):
        pass

    def after_writing(self, output: TextIO):
        pass

    def should_passthru(self, line: str):
        # cheap & easy skip DNS directives and comments
        return line[0] in (';', '$', '@', ' ')

    def write_line(self, output: TextIO, line: str):
        output.write(line)
        output.write('\n')

    @staticmethod
    def get_name():
        return 'rpz'


class DomainConverter(RpzConverter):
    """
    Convert from a hash-commented, domain-per-line text file to an RPZ file.
    """

    PREAMBLE = '''$TTL 2h
@ IN SOA localhost. root.localhost. (1 6h 1h 1w 2h)
  IN NS  localhost.
'''

    def before_writing(self, output: TextIO):
        output.write(DomainConverter.PREAMBLE)
        output.write('\n')

    def after_writing(self, output: TextIO):
        pass

    def should_passthru(self, line: str):
        return line[0] in (';', '#')

    def write_line(self, output: TextIO, line: str):
        # convert hashes to semicolons for RPZ
        if line[0] == '#':  # Faster than line.startswith('#')
            line = line.replace('#', ';', 1)  # Faster than ';' + line[1:]
            output.write(line)
            output.write('\n')
        else:
            output.write(line)
            output.write(' CNAME .\n')

    @staticmethod
    def get_name():
        return 'domains'


class RpzProcessor:
    """
    Class for importing a Response Policy Zone (RPZ) file from a URL, optionally applying an Allow List to ignore
    matching lines in that file, then writing the output to a local file.
    """

    allow_domains_exact = set()
    allow_domains_right = set()
    converter = None

    def __init__(self, converter: RpzConverter):
        self.converter = converter

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

                self.converter.before_writing(output)

                for line in request.iter_lines(chunk_size=256, decode_unicode=True):
                    if not line:  # skip blank lines
                        continue

                    if self.converter.should_passthru(line):
                        self.converter.write_line(output, line)
                        continue

                    domain = self.converter.extract_domain(line)

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
                    self.converter.write_line(output, line)
                self.converter.after_writing(output)


converters = {clazz.get_name(): clazz() for clazz in RpzConverter.__subclasses__()}


def converter_choice(choice: str):
    try:
        return converters[choice]
    except KeyError:
        raise AttributeError(f'Bad converter value {choice}, valid choices are {converters.keys()}')


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

    args = parser.parse_args()

    processor = RpzProcessor(converter_choice(args.c))

    if args.a != '-':
        if not processor.read_allow_list(args.a):
            exit(1)

    url = args.u.geturl()
    print(f'Fetching {url}, applying {len(processor.allow_domains_exact)} allow-list entries,\n'
          f'and writing to {args.o} using converter `{args.c}`')
    exit(0 if processor.import_rpz_list(url, args.o) else 1)
