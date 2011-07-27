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
class bin_stream_mother(type):
    def __call__(self, *arg):
        if arg and arg[0].__class__ in [str]:
            cls = bin_stream_str
        elif arg and type(arg[0]) is file:
            cls = bin_stream_file
        else:
            cls = bin_stream_str

        i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        i.__init__(*arg)
        return i


class bin_stream(object):
    __metaclass__ = bin_stream_mother
    def __init__(self, *args, **kargs):
        pass
    def __repr__(self):
        return "<%s !!>"%self.__class__.__name__

    def hexdump(self, offset, l):
        return

    
        
class bin_stream_str(bin_stream):
    def __init__(self, bin ="", offset = 0L):
        if offset>len(bin):
            raise IOError
        self.bin = bin
        self.offset = offset
        self.l = len(bin)
        if "is_addr_in" in self.bin.__class__.__dict__:
            self.is_addr_in = lambda ad:self.bin.is_addr_in(ad)
            

    def readbs(self, l=1):
        if self.offset+l>self.l:
            raise IOError
        self.offset+=l
        return self.bin[self.offset-l:self.offset]

    def writebs(self, l=1):
        raise ValueError('writebs unsupported')

    def __str__(self):
        out =  self.bin[self.offset:]
        return out
    def setoffset(self, val):
        val = val & 0xFFFFFFFF
        self.offset = val

class bin_stream_file(bin_stream):
    def __init__(self, bin, offset=0L):
        self.bin = bin
        self.bin.seek(0, 2)
        self.l = self.bin.tell()
        self.offset = offset

        
                
    def getoffset(self):
        return self.bin.tell()

    def setoffset(self, val):
        val = val & 0xFFFFFFFF
        self.bin.seek(val)
        
    offset = property(getoffset, setoffset)

    def readbs(self, l=1):
        if self.offset+l>self.l:
            raise IOError
        return self.bin.read(l)

    def writebs(self, l=1):
        if self.offset+l>self.l:
            raise IOError
        return self.bin.write(l)

    def __str__(self):
        return str(self.bin)

