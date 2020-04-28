#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

from builtins import str
from future.utils import PY3

from miasm.core.utils import BIG_ENDIAN, LITTLE_ENDIAN
from miasm.core.utils import upck8le, upck16le, upck32le, upck64le
from miasm.core.utils import upck8be, upck16be, upck32be, upck64be


class bin_stream(object):

    # Cache must be initialized by entering atomic mode
    _cache = None
    CACHE_SIZE = 10000
    # By default, no atomic mode
    _atomic_mode = False

    def __init__(self, *args, **kargs):
        self.endianness = LITTLE_ENDIAN

    def __repr__(self):
        return "<%s !!>" % self.__class__.__name__

    def __str__(self):
        if PY3:
            return repr(self)
        return self.__bytes__()

    def hexdump(self, offset, l):
        return

    def enter_atomic_mode(self):
        """Enter atomic mode. In this mode, read may be cached"""
        assert not self._atomic_mode
        self._atomic_mode = True
        self._cache = {}

    def leave_atomic_mode(self):
        """Leave atomic mode"""
        assert self._atomic_mode
        self._atomic_mode = False
        self._cache = None

    def _getbytes(self, start, length):
        return self.bin[start:start + length]

    def getbytes(self, start, l=1):
        """Return the bytes from the bit stream
        @start: starting offset (in byte)
        @l: (optional) number of bytes to read

        Wrapper on _getbytes, with atomic mode handling.
        """
        if self._atomic_mode:
            val = self._cache.get((start,l), None)
            if val is None:
                val = self._getbytes(start, l)
                self._cache[(start,l)] = val
        else:
            val = self._getbytes(start, l)
        return val

    def getbits(self, start, n):
        """Return the bits from the bit stream
        @start: the offset in bits
        @n: number of bits to read
        """
        # Trivial case
        if n == 0:
            return 0

        # Get initial bytes
        if n > self.getlen() * 8:
            raise IOError('not enough bits %r %r' % (n, len(self.bin) * 8))
        byte_start = start // 8
        byte_stop = (start + n + 7) // 8
        temp = self.getbytes(byte_start, byte_stop - byte_start)
        if not temp:
            raise IOError('cannot get bytes')

        # Init
        start = start % 8
        out = 0
        while n:
            # Get needed bits, working on maximum 8 bits at a time
            cur_byte_idx = start // 8
            new_bits = ord(temp[cur_byte_idx:cur_byte_idx + 1])
            to_keep = 8 - start % 8
            new_bits &= (1 << to_keep) - 1
            cur_len = min(to_keep, n)
            new_bits >>= (to_keep - cur_len)

            # Update output
            out <<= cur_len
            out |= new_bits

            # Update counters
            n -= cur_len
            start += cur_len
        return out

    def get_u8(self, addr, endianness=None):
        """
        Return u8 from address @addr
        endianness: Optional: LITTLE_ENDIAN/BIG_ENDIAN
        """
        if endianness is None:
            endianness = self.endianness
        data = self.getbytes(addr, 1)
        return data

    def get_u16(self, addr, endianness=None):
        """
        Return u16 from address @addr
        endianness: Optional: LITTLE_ENDIAN/BIG_ENDIAN
        """
        if endianness is None:
            endianness = self.endianness
        data = self.getbytes(addr, 2)
        if endianness == LITTLE_ENDIAN:
            return upck16le(data)
        else:
            return upck16be(data)

    def get_u32(self, addr, endianness=None):
        """
        Return u32 from address @addr
        endianness: Optional: LITTLE_ENDIAN/BIG_ENDIAN
        """
        if endianness is None:
            endianness = self.endianness
        data = self.getbytes(addr, 4)
        if endianness == LITTLE_ENDIAN:
            return upck32le(data)
        else:
            return upck32be(data)

    def get_u64(self, addr, endianness=None):
        """
        Return u64 from address @addr
        endianness: Optional: LITTLE_ENDIAN/BIG_ENDIAN
        """
        if endianness is None:
            endianness = self.endianness
        data = self.getbytes(addr, 8)
        if endianness == LITTLE_ENDIAN:
            return upck64le(data)
        else:
            return upck64be(data)


class bin_stream_str(bin_stream):

    def __init__(self, input_str=b"", offset=0, base_address=0, shift=None):
        bin_stream.__init__(self)
        if shift is not None:
            raise DeprecationWarning("use base_address instead of shift")
        self.bin = input_str
        self.offset = offset
        self.base_address = base_address
        self.l = len(input_str)

    def _getbytes(self, start, l=1):
        if start + l - self.base_address > self.l:
            raise IOError("not enough bytes in str")
        if start - self.base_address < 0:
            raise IOError("Negative offset")

        return super(bin_stream_str, self)._getbytes(start - self.base_address, l)

    def readbs(self, l=1):
        if self.offset + l - self.base_address > self.l:
            raise IOError("not enough bytes in str")
        if self.offset - self.base_address < 0:
            raise IOError("Negative offset")
        self.offset += l
        return self.bin[self.offset - l - self.base_address:self.offset - self.base_address]

    def __bytes__(self):
        return self.bin[self.offset - self.base_address:]

    def setoffset(self, val):
        self.offset = val

    def getlen(self):
        return self.l - (self.offset - self.base_address)


class bin_stream_file(bin_stream):

    def __init__(self, binary, offset=0, base_address=0, shift=None):
        bin_stream.__init__(self)
        if shift is not None:
            raise DeprecationWarning("use base_address instead of shift")
        self.bin = binary
        self.bin.seek(0, 2)
        self.base_address = base_address
        self.l = self.bin.tell()
        self.offset = offset

    def getoffset(self):
        return self.bin.tell() + self.base_address

    def setoffset(self, val):
        self.bin.seek(val - self.base_address)
    offset = property(getoffset, setoffset)

    def readbs(self, l=1):
        if self.offset + l - self.base_address > self.l:
            raise IOError("not enough bytes in file")
        if self.offset - self.base_address < 0:
            raise IOError("Negative offset")
        return self.bin.read(l)

    def __bytes__(self):
        return self.bin.read()

    def getlen(self):
        return self.l - (self.offset - self.base_address)


class bin_stream_container(bin_stream):

    def __init__(self, binary, offset=0):
        bin_stream.__init__(self)
        self.bin = binary
        self.l = binary.virt.max_addr()
        self.offset = offset

    def is_addr_in(self, ad):
        return self.bin.virt.is_addr_in(ad)

    def getlen(self):
        return self.l

    def readbs(self, l=1):
        if self.offset + l > self.l:
            raise IOError("not enough bytes")
        if self.offset < 0:
            raise IOError("Negative offset")
        self.offset += l
        return self.bin.virt.get(self.offset - l, self.offset)

    def _getbytes(self, start, l=1):
        try:
            return self.bin.virt.get(start, start + l)
        except ValueError:
            raise IOError("cannot get bytes")

    def __bytes__(self):
        return self.bin.virt.get(self.offset, self.offset + self.l)

    def setoffset(self, val):
        self.offset = val


class bin_stream_pe(bin_stream_container):
    def __init__(self, binary, *args, **kwargs):
        super(bin_stream_pe, self).__init__(binary, *args, **kwargs)
        self.endianness = binary._sex


class bin_stream_elf(bin_stream_container):
    def __init__(self, binary, *args, **kwargs):
        super(bin_stream_elf, self).__init__(binary, *args, **kwargs)
        self.endianness = binary.sex


class bin_stream_vm(bin_stream):

    def __init__(self, vm, offset=0, base_offset=0):
        self.offset = offset
        self.base_offset = base_offset
        self.vm = vm
        if self.vm.is_little_endian():
            self.endianness = LITTLE_ENDIAN
        else:
            self.endianness = BIG_ENDIAN

    def getlen(self):
        return 0xFFFFFFFFFFFFFFFF

    def _getbytes(self, start, l=1):
        try:
            s = self.vm.get_mem(start + self.base_offset, l)
        except:
            raise IOError('cannot get mem ad', hex(start))
        return s

    def readbs(self, l=1):
        try:
            s = self.vm.get_mem(self.offset + self.base_offset, l)
        except:
            raise IOError('cannot get mem ad', hex(self.offset))
        self.offset += l
        return s

    def setoffset(self, val):
        self.offset = val
