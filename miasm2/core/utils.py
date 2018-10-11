import struct
import inspect
import UserDict
from operator import itemgetter

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


def hexdump(src, length=16):
    FILTER = ''.join(
        [(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hexa = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(
            ["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hexa, printable))
    print ''.join(lines)

# stackoverflow.com/questions/2912231

import collections


class keydefaultdict(collections.defaultdict):

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        value = self[key] = self.default_factory(key)
        return value


class BoundedDict(UserDict.DictMixin):

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
        self._min_size = min_size if min_size else max_size / 3
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
                most_common = sorted(self._counter.iteritems(),
                                     key=itemgetter(1), reverse=True)

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
        return self._data.keys()

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
