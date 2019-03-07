from array import array
import struct
from sys import maxsize

from future.utils import PY3

if PY3:

    def array_frombytes(arr, value):
        return arr.frombytes(value)

    def array_tobytes(arr):
        return arr.tobytes()


else:

    def array_frombytes(arr, value):
        return arr.fromstring(value)

    def array_tobytes(arr):
        return arr.tostring()


class StrPatchwork(object):

    def __init__(self, s=b"", paddingbyte=b"\x00"):
        s_raw = bytes(s)
        val = array("B")
        array_frombytes(val, s_raw)
        self.s = val
        # cache s to avoid rebuilding str after each find
        self.s_cache = s_raw
        self.paddingbyte = paddingbyte

    def __bytes__(self):
        return array_tobytes(self.s)

    def __str__(self):
        if PY3:
            return repr(self)
        return self.__bytes__()

    def __getitem__(self, item):
        s = self.s
        if isinstance(item, slice):
            end = item.stop
            l = len(s)
            if (end is not None and l < end) and end != maxsize:
                # XXX hack [x:] give 2GB limit
                # This is inefficient but avoids complicated maths if step is
                # not 1
                s = s[:]

                tmp = array("B")
                array_frombytes(tmp, self.paddingbyte * (end - l))
                s.extend(tmp)
            r = s[item]
            return array_tobytes(r)

        else:
            if item > len(s):
                return self.paddingbyte
            else:
                return struct.pack("B", s[item])

    def __setitem__(self, item, val):
        if val is None:
            return
        val_array = array("B")
        array_frombytes(val_array, bytes(val))
        if type(item) is not slice:
            item = slice(item, item + len(val_array))
        end = item.stop
        l = len(self.s)
        if l < end:
            tmp = array("B")
            array_frombytes(tmp, self.paddingbyte * (end - l))
            self.s.extend(tmp)
        self.s[item] = val_array
        self.s_cache = None

    def __repr__(self):
        return "<Patchwork %r>" % array_tobytes(self.s)

    def __len__(self):
        return len(self.s)

    def __contains__(self, val):
        return val in bytes(self)

    def __iadd__(self, other):
        tmp = array("B")
        array_frombytes(tmp, bytes(other))
        self.s.extend(tmp)
        return self

    def find(self, pattern, start=0, end=None):
        if not self.s_cache:
            self.s_cache = array_tobytes(self.s)
        return self.s_cache.find(pattern, start, end)

    def rfind(self, pattern, start=0, end=None):
        if not self.s_cache:
            self.s_cache = array_tobytes(self.s)
        return self.s_cache.rfind(pattern, start, end)
