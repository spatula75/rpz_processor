import requests
from requests import HTTPError

from main import MAX_DOMAIN_LENGTH
from converter import RpzConverter


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

                    # check for a right-hand match by decomposing the domain into successive subdomains and checking each
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