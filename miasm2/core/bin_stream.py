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


class bin_stream(object):

    def __init__(self, *args, **kargs):
        pass

    def __repr__(self):
        return "<%s !!>" % self.__class__.__name__

    def hexdump(self, offset, l):
        return

    def getbytes(self, start, l=1):
        return self.bin[start:start + l]

    def getbits(self, start, n):
        """Return the bits from the bit stream
        @start: the offset in bits
        @n: number of bits to read
        """
        if not n:
            return 0
        o = 0
        if n > self.getlen() * 8:
            raise IOError('not enough bits %r %r' % (n, len(self.bin) * 8))
        while n:
            # print 'xxx', n, start
            i = start / 8
            c = self.getbytes(i)
            if not c:
                raise IOError('cannot get bytes')
            c = ord(c)
            # print 'o', hex(c)
            r = 8 - start % 8
            c &= (1 << r) - 1
            # print 'm', hex(c)
            l = min(r, n)
            # print 'd', r-l
            c >>= (r - l)
            o <<= l
            o |= c
            n -= l
            start += l
        return o


class bin_stream_str(bin_stream):

    def __init__(self, input_str="", offset=0L, shift=0):
        bin_stream.__init__(self)
        self.bin = input_str
        self.offset = offset
        self.shift = shift
        self.l = len(input_str)

    def getbytes(self, start, l=1):
        if start + l + self.shift > self.l:
            raise IOError("not enough bytes in str")

        return super(bin_stream_str, self).getbytes(start + self.shift, l)

    def readbs(self, l=1):
        if self.offset + l + self.shift > self.l:
            raise IOError("not enough bytes in str")
        self.offset += l
        return self.bin[self.offset - l + self.shift:self.offset + self.shift]

    def __str__(self):
        out = self.bin[self.offset + self.shift:]
        return out

    def setoffset(self, val):
        self.offset = val

    def getlen(self):
        return self.l - (self.offset + self.shift)


class bin_stream_file(bin_stream):

    def __init__(self, binary, offset=0L, shift=0):
        bin_stream.__init__(self)
        self.bin = binary
        self.bin.seek(0, 2)
        self.shift = shift
        self.l = self.bin.tell()
        self.offset = offset

    def getoffset(self):
        return self.bin.tell() - self.shift

    def setoffset(self, val):
        self.bin.seek(val +  self.shift)
    offset = property(getoffset, setoffset)

    def readbs(self, l=1):
        if self.offset + l + self.shift > self.l:
            raise IOError("not enough bytes in file")
        return self.bin.read(l)

    def __str__(self):
        return str(self.bin)

    def getlen(self):
        return self.l - (self.offset + self.shift)



class bin_stream_container(bin_stream):

    def __init__(self, virt_view, offset=0L):
        bin_stream.__init__(self)
        self.bin = virt_view
        self.l = virt_view.max_addr()
        self.offset = offset

    def is_addr_in(self, ad):
        return self.bin.is_addr_in(ad)

    def getlen(self):
        return self.l

    def readbs(self, l=1):
        if self.offset + l > self.l:
            raise IOError("not enough bytes")
        self.offset += l
        return self.bin(self.offset - l, self.offset)

    def getbytes(self, start, l=1):
        return self.bin(start, start + l)

    def __str__(self):
        out = self.bin(self.offset, self.l)
        return out

    def setoffset(self, val):
        self.offset = val


class bin_stream_pe(bin_stream_container):
    pass


class bin_stream_elf(bin_stream_container):
    pass


class bin_stream_vm(bin_stream):

    def __init__(self, vm, offset=0L, base_offset=0L):
        self.offset = offset
        self.base_offset = base_offset
        self.vm = vm

    def getlen(self):
        return 0xFFFFFFFFFFFFFFFF

    def getbytes(self, start, l=1):
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
