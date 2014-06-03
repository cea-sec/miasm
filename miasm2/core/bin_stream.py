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
        if not n:
            return 0
        o = 0
        if n > self.getlen() * 8:
            raise ValueError('not enought bits %r %r' % (n, len(self.bin) * 8))
        while n:
            # print 'xxx', n, start
            i = start / 8
            c = self.getbytes(i)
            if not c:
                raise IOError
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

    def __init__(self, bin="", offset=0L, shift=0):
        bin_stream.__init__(self)
        if offset > len(bin):
            raise IOError
        self.bin = bin
        self.offset = offset
        self.shift = shift
        self.l = len(bin)
        if "is_addr_in" in self.bin.__class__.__dict__:
            self.is_addr_in = lambda ad: self.bin.is_addr_in(ad)

    def getbytes(self, start, l=1):
        if start + l > self.l:
            raise IOError

        return super(bin_stream_str, self).getbytes(start + self.shift, l)

    def readbs(self, l=1):
        if self.offset + l > self.l:
            raise IOError
        self.offset += l
        print hex(self.offset + self.shift)
        return self.bin[self.offset - l + self.shift:self.offset + self.shift]

    def writebs(self, l=1):
        raise ValueError('writebs unsupported')

    def __str__(self):
        out = self.bin[self.offset + self.shift:]
        return out

    def setoffset(self, val):
        self.offset = val

    def __len__(self):
        return len(self.bin) - self.offset + self.shift

    def getlen(self):
        return len(self.bin) - self.offset + self.shift


class bin_stream_file(bin_stream):

    def __init__(self, bin, offset=0L):
        bin_stream.__init__(self)
        self.bin = bin
        self.bin.seek(0, 2)
        self.l = self.bin.tell()
        self.offset = offset

    def getoffset(self):
        return self.bin.tell()

    def setoffset(self, val):
        self.bin.seek(val)
    offset = property(getoffset, setoffset)

    def readbs(self, l=1):
        if self.offset + l > self.l:
            raise IOError
        return self.bin.read(l)

    def writebs(self, l=1):
        if self.offset + l > self.l:
            raise IOError
        return self.bin.write(l)

    def __str__(self):
        return str(self.bin)


class bin_stream_pe(bin_stream):

    def __init__(self, bin="", offset=0L):
        bin_stream.__init__(self)
        # print 'ELF/PE'
        self.mylen = len(bin)
        if offset > bin.__len__():
            raise IOError
        self.bin = bin
        self.offset = offset
        self.l = bin.__len__()
        if "is_addr_in" in self.bin.__class__.__dict__:
            self.is_addr_in = lambda ad: self.bin.is_addr_in(ad)

    def getlen(self):
        return self.mylen
        # s = self.bin.parent.SHList[-1]
        # l = self.bin.parent.rva2virt(s.addr+s.size)
        # return l

    def readbs(self, l=1):
        if self.offset + l > self.l:
            raise IOError
        self.offset += l
        return self.bin(self.offset - l, self.offset)

    def writebs(self, l=1):
        raise ValueError('writebs unsupported')

    def getbytes(self, start, l=1):
        return self.bin(start, start + l)

    def __str__(self):
        out = self.bin[self.offset:]
        return out

    def setoffset(self, val):
        self.offset = val


class bin_stream_elf(bin_stream_pe):
    pass
