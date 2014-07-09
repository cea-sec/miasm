import struct

upck8 = lambda x: struct.unpack('B', x)[0]
upck16 = lambda x: struct.unpack('H', x)[0]
upck32 = lambda x: struct.unpack('I', x)[0]
upck64 = lambda x: struct.unpack('Q', x)[0]
pck8 = lambda x: struct.pack('B', x)
pck16 = lambda x: struct.pack('H', x)
pck32 = lambda x: struct.pack('I', x)
pck64 = lambda x: struct.pack('Q', x)


pck = {8:pck8,
       16:pck16,
       32:pck32,
       64:pck64}


class Disasm_Exception(Exception):
    pass


def hexdump(src, length=16):
    FILTER = ''.join(
        [(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(
            ["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
    print ''.join(lines)

# stackoverflow.com/questions/2912231

import collections


class keydefaultdict(collections.defaultdict):

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        value = self[key] = self.default_factory(key)
        return value
