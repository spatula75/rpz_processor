from abc import ABC, abstractmethod
from time import time
from typing import TextIO


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
    Convert from a hash-commented, domain-per-line text file to an RPZ file.  Generates a barebones zone file
    header using the current epoch time as the serial number.
    """

    PREAMBLE = f'''$TTL 2h
@ IN SOA localhost. root.localhost. ({int(time())} 6h 1h 1w 2h)
  IN NS  localhost.
'''

    def extract_domain(self, line: str):
        return line

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


class WildcardDomainConverter(DomainConverter):
    """
    Convert from a hash-commented, wildcard-domain-per-line text file to an RPZ file.
    Specifically, this should be used for wildcard domain files that include the wildcard
    domain, but not the domain itself.   For example, *.example.com, but not example.com.

    Because BIND RPZ does not match `example.com` on `*.example.com`, it is necessary to
    output both the wildcard line, and the bare domain line as well; ie, for `*.example.com`,
    RRs for both `*.example.com` and `example.com` will be written.
    """
    def extract_domain(self, line: str):
        return line[2:] if line[0:2] == '*.' else line

    def write_line(self, output: TextIO, line: str):
        # convert hashes to semicolons for RPZ
        if line[0] == '#':  # Faster than line.startswith('#')
            line = line.replace('#', ';', 1)  # Faster than ';' + line[1:]
            output.write(line)
            output.write('\n')
        else:
            output.write(line)
            output.write(' CNAME .\n')
            # For wildcard domains, also write out the bare domain for BIND.
            if line[0:2] == '*.':
                output.write(line[2:])
                output.write(' CNAME .\n')

    @staticmethod
    def get_name():
        return 'wildcards'


# Thanks for this really elegant solution, https://stackoverflow.com/a/33607093
def all_subclasses(cls):
    for subclass in cls.__subclasses__():
        yield from all_subclasses(subclass)
        yield subclass


converters = {clazz.get_name(): clazz() for clazz in all_subclasses(RpzConverter)}
