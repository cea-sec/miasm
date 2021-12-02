from __future__ import print_function
import re
import sys
from builtins import range
import struct
import inspect

try:
    from collections.abc import MutableMapping as DictMixin
except ImportError:
    from collections import MutableMapping as DictMixin

from operator import itemgetter
import codecs

from future.utils import viewitems

import collections

COLOR_INT = "azure4"
COLOR_ID = "forestgreen"#"chartreuse3"
COLOR_MEM = "deeppink4"
COLOR_OP_FUNC = "blue1"
COLOR_LOC = "darkslateblue"
COLOR_OP = "black"

COLOR_MNEMO = "blue1"

ESCAPE_CHARS = re.compile('[' + re.escape('{}') + '&|<>' + ']')

def set_html_text_color(text, color):
    return '<font color="%s">%s</font>' % (color, text)


def _fix_chars(token):
    return "&#%04d;" % ord(token.group())


def fix_html_chars(text):
    return ESCAPE_CHARS.sub(_fix_chars, str(text))

upck8 = lambda x: struct.unpack('B', x)[0]
upck16 = lambda x: struct.unpack('H', x)[0]
upck32 = lambda x: struct.unpack('I', x)[0]
upck64 = lambda x: struct.unpack('Q', x)[0]
pck8 = lambda x: struct.pack('B', x)
pck16 = lambda x: struct.pack('H', x)
pck32 = lambda x: struct.pack('I', x)
pck64 = lambda x: struct.pack('Q', x)

# Little endian
upck8le = lambda x: struct.unpack('<B', x)[0]
upck16le = lambda x: struct.unpack('<H', x)[0]
upck32le = lambda x: struct.unpack('<I', x)[0]
upck64le = lambda x: struct.unpack('<Q', x)[0]
pck8le = lambda x: struct.pack('<B', x)
pck16le = lambda x: struct.pack('<H', x)
pck32le = lambda x: struct.pack('<I', x)
pck64le = lambda x: struct.pack('<Q', x)

# Big endian
upck8be = lambda x: struct.unpack('>B', x)[0]
upck16be = lambda x: struct.unpack('>H', x)[0]
upck32be = lambda x: struct.unpack('>I', x)[0]
upck64be = lambda x: struct.unpack('>Q', x)[0]
pck8be = lambda x: struct.pack('>B', x)
pck16be = lambda x: struct.pack('>H', x)
pck32be = lambda x: struct.pack('>I', x)
pck64be = lambda x: struct.pack('>Q', x)


LITTLE_ENDIAN = 1
BIG_ENDIAN = 2


pck = {8: pck8,
       16: pck16,
       32: pck32,
       64: pck64}


def get_caller_name(caller_num=0):
    """Get the nth caller's name
    @caller_num: 0 = the caller of get_caller_name, 1 = next parent, ..."""
    pystk = inspect.stack()
    if len(pystk) > 1 + caller_num:
        return pystk[1 + caller_num][3]
    else:
        return "Bad caller num"


def whoami():
    """Returns the caller's name"""
    return get_caller_name(1)


class Disasm_Exception(Exception):
    pass


def printable(string):
    if isinstance(string, bytes):
        return "".join(
            c.decode() if b" " <= c < b"~" else "."
            for c in (string[i:i+1] for i in range(len(string)))
        )
    return string


def force_bytes(value):
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        return value
    out = []
    for c in value:
        c = ord(c)
        assert c < 0x100
        out.append(c)
    return bytes(out)


def force_str(value):
    if isinstance(value, str):
        return value
    elif isinstance(value, bytes):
        out = ""
        for i in range(len(value)):
            # For Python2/Python3 compatibility
            c = ord(value[i:i+1])
            out += chr(c)
        value = out
    else:
        raise ValueError("Unsupported type")
    return value


def iterbytes(string):
    for i in range(len(string)):
        yield string[i:i+1]


def int_to_byte(value):
    return struct.pack('B', value)

def cmp_elts(elt1, elt2):
    return (elt1 > elt2) - (elt1 < elt2)


_DECODE_HEX = codecs.getdecoder("hex_codec")
_ENCODE_HEX = codecs.getencoder("hex_codec")

def decode_hex(value):
    return _DECODE_HEX(value)[0]

def encode_hex(value):
    return _ENCODE_HEX(value)[0]

def size2mask(size):
    """Return the bit mask of size @size"""
    return (1 << size) - 1

def hexdump(src, length=16):
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c + length]
        hexa = ' '.join("%02x" % ord(x) for x in iterbytes(chars))
        printable = ''.join(
            x.decode() if 32 <= ord(x) <= 126 else '.' for x in iterbytes(chars)
        )
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hexa, printable))
    print(''.join(lines))


# stackoverflow.com/questions/2912231
class keydefaultdict(collections.defaultdict):

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        value = self[key] = self.default_factory(key)
        return value


class BoundedDict(DictMixin):

    """Limited in size dictionary.

    To reduce combinatory cost, once an upper limit @max_size is reached,
    @max_size - @min_size elements are suppressed.
    The targeted elements are the less accessed.

    One can define a callback called when an element is removed
    """

    def __init__(self, max_size, min_size=None, initialdata=None,
                 delete_cb=None):
        """Create a BoundedDict
        @max_size: maximum size of the dictionary
        @min_size: (optional) number of most used element to keep when resizing
        @initialdata: (optional) dict instance with initial data
        @delete_cb: (optional) callback called when an element is removed
        """
        self._data = initialdata.copy() if initialdata else {}
        self._min_size = min_size if min_size else max_size // 3
        self._max_size = max_size
        self._size = len(self._data)
        # Do not use collections.Counter as it is quite slow
        self._counter = {k: 1 for k in self._data}
        self._delete_cb = delete_cb

    def __setitem__(self, asked_key, value):
        if asked_key not in self._data:
            # Update internal size and use's counter
            self._size += 1

            # Bound can only be reached on a new element
            if (self._size >= self._max_size):
                most_common = sorted(
                    viewitems(self._counter),
                    key=itemgetter(1),
                    reverse=True
                )

                # Handle callback
                if self._delete_cb is not None:
                    for key, _ in most_common[self._min_size - 1:]:
                        self._delete_cb(key)

                # Keep only the most @_min_size used
                self._data = {key: self._data[key]
                              for key, _ in most_common[:self._min_size - 1]}
                self._size = self._min_size

                # Reset use's counter
                self._counter = {k: 1 for k in self._data}

            # Avoid rechecking in dict: set to 1 here, add 1 otherwise
            self._counter[asked_key] = 1
        else:
            self._counter[asked_key] += 1

        self._data[asked_key] = value

    def __contains__(self, key):
        # Do not call has_key to avoid adding function call overhead
        return key in self._data

    def has_key(self, key):
        return key in self._data

    def keys(self):
        "Return the list of dict's keys"
        return list(self._data)

    @property
    def data(self):
        "Return the current instance as a dictionary"
        return self._data

    def __getitem__(self, key):
        # Retrieve data first to raise the proper exception on error
        data = self._data[key]
        # Should never raise, since the key is in self._data
        self._counter[key] += 1
        return data

    def __delitem__(self, key):
        if self._delete_cb is not None:
            self._delete_cb(key)
        del self._data[key]
        self._size -= 1
        del self._counter[key]

    def __del__(self):
        """Ensure the callback is called when last reference is lost"""
        if self._delete_cb:
            for key in self._data:
                self._delete_cb(key)


    def __len__(self):
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

