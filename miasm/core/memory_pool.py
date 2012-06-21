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
import array
import struct
import cPickle
import StringIO
from miasm.tools.modint import uint1, uint8, uint16, uint32, uint64

from elfesteem import *


class mempool:
    def gen_pad(x):
        if x>0:
            return '\x00'*x
        else:
            return ''
    def __init__(self, start, stop, perm = "RW", data = {}, name = "", extern_func  = {}):
        self.start = start
        self.stop = stop
        self.extern_func = extern_func
        self.perm_R = "R" in perm
        self.perm_W = "W" in perm
        self.perm_X = "X" in perm
        self.name = name
        
        my_data = array.array('B')

        if type(data) is dict:
            pad = stop-start
            pass
            
        elif type(data) is file:
            pos = data.tell()
            data.seek(0, 2)
            end = data.tell()
            data.seek(pos)
            pad = stop-start - (end-pos)
            if pad>0:
                my_data = my_data.fromfile(data, end-pos)
            else:
                my_data = my_data.fromfile(f, stop-start)
        else:
            pad = stop-start - len(data)
            my_data.fromstring(str(data))

        
        my_data.extend([0 for x in xrange(pad)])
        self.data = my_data

    def __str__(self):
        return repr(self)+'<%.8X-%.8X>'%(int(self.start),int(self.stop))+"-R"[self.perm_R]+"-W"[self.perm_W]+"-X"[self.perm_X]+" "+self.name

    def has_extern(self, address):
        if address in self.extern_func:
            return self.extern_func[address]
        return False

    def get_b(self, x):
        return self.data[int(uint32(x))-self.start]
    def get_w(self, x):
        return struct.unpack('H', self.data[int(uint32(x))-self.start:int(uint32(x))-self.start+2].tostring())[0]
    def get_d(self, x):
        return struct.unpack('L', self.data[int(uint32(x))-self.start:int(uint32(x))-self.start+4].tostring())[0]
    def get_data(self, x, l):
        return self.data[int(uint32(x))-self.start:int(uint32(x))-self.start+l]
    
    def set_b(self, x, v):
        self.data[int(uint32(x))-self.start] = int(v)
    def set_w(self, x, v):
        i = map(ord, struct.pack('H', int(v)))
        i.reverse()
        for j in xrange(2):
            self.data[int(uint32(x))-self.start+j] = i.pop()
    def set_d(self, x, v):
        i = map(ord, struct.pack('L', int(v)))
        i.reverse()
        for j in xrange(4):
            self.data[int(uint32(x))-self.start+j] = i.pop()
    def set_data(self, x, v):
        for i, c in enumerate(v):
            self.data[int(uint32(x))-self.start+i] = ord(c)
            
    def to_file(self, f):
        if type(f) is str:
            f = open(f,"w")
        my_data = self.data
        self.data = self.data.tostring()
        cPickle.dump(self, f)
        self.data = my_data
    
    @staticmethod

    def from_file(f):
        if type(f) is str:
            f = open(f,"r")
        m = cPickle.load(f)
        my_data = array.array('B')
        my_data.fromstring(m.data)
        m.data = my_data
        return m

class mempool_manager:
    def __init__(self, mems = []):
        self._mems = mems

    def __str__(self):
        out = repr(self)+'\n'
        out += reduce(lambda x,y:x+str(y)+'\n', self._mems, "")
        return out[:-1]

    def get_mems(self):
        return self._mems
    
    def set_mems(self):
        tmp = [[m.start, m.stop] for m in self._mems]
        for m in tmp:
            if m[0]>m[1]:
                raise 'stop inf start: %s'%str(m)
        for i, m in enumerate(tmp[:-1]):
            if m[1] > tmp[i+1][0]:
                raise 'overlapping mems: %s %s'%(str(m), str(tmp[i+1])) 
        
        return self._mems
    
    mems = property(get_mems, set_mems)
    
    def get_mem_pool(self, x):
        x = int(uint32(x))
        for m in self._mems:
            if x >=m.start and x <m.stop:
                return m
        raise 'unknown mem', str(x)
        

    def get_b(self, x):
        m = self.get_mem_pool(x)
        return m.get_b(x)

    def get_w(self, x):
        m = self.get_mem_pool(x)
        try:
            return m.get_w(x)
        except:
            pass
        out = ""
        for i in xrange(2):
            m = self.get_mem_pool(x+i)
            out+=chr(m.get_b(x+i))
        return struct.unpack('H', out)[0]
        
    def get_d(self, x):
        m = self.get_mem_pool(x)
        try:
            return m.get_d(x)
        except:
            pass
        out = ""
        for i in xrange(4):
            m = self.get_mem_pool(x+i)
            out+=chr(m.get_b(x+i))
        return struct.unpack('L', out)[0]
        
    def get_data(self, x, l):
        m = self.get_mem_pool(x)
        try:
            return m.get_data(x,l)
        except:
            pass
        out = ""
        for i in xrange(l):
            m = self.get_mem_pool(x+i)
            out+=chr(m.get_b(x+i))
        return out
        
    def set_b(self, x, v):
        m = self.get_mem_pool(x)
        m.set_b(x,v)

    def set_w(self, x, v):
        m = self.get_mem_pool(x)
        try:
            m.set_w(x, v)
            return
        except:
            pass
        i = map(ord, struct.pack('H', int(v)))
        i.reverse()
        for j in xrange(2):
            m = self.get_mem_pool(x+j)
            m.set_b(x+j, i.pop())

    def set_d(self, x, v):
        m = self.get_mem_pool(x)
        try:
            m.set_d(x, v)
            return
        except:
            pass
        i = map(ord, struct.pack('L', int(v)))
        i.reverse()
        print hex(int(x)), i
        for j in xrange(4):
            m = self.get_mem_pool(x+j)
            print j, m
            m.set_b(x+j, i.pop())
            print 'iii'

    def set_data(self, x, v):
        m = self.get_mem_pool(x)
        try:
            m.set_data(x, v)
            return
        except:
            pass
        for i, c in enumerate(v):
            m = self.get_mem_pool(x+i)
            m.set_b(x+i, ord(c))
            

    def to_file(self, f):
        if type(f) is str:
            f = open(f,"w")
        for m in self._mems:
            m.to_file(f)
    
    @staticmethod

    def from_file(f):
        if type(f) is str:
            f = open(f,"r")
        mems = []
        while True:
            try:
                mems.append(mempool.from_file(f))
            except:
                break
        return mempool_manager(mems)


def load_pe(e, loadhdr=False):
    mems = []
    if loadhdr:
      hdr = open(fname, 'rb').read(0x1000)
      mems.append(mempool(e.NThdr.ImageBase,
                            e.NThdr.ImageBase+0x1000,
                            'RWX', hdr, "PE HDR"))
    for section in e.SHList:
        section_size = max(section.rawsize,section.size)
        section_size = (section_size+0xfff)&~0xfff
        mems.append(mempool(e.NThdr.ImageBase+section.addr,
                            e.NThdr.ImageBase+section.addr+section_size,
                            'RWX', section.data, section.name.replace('\x00', ' ')))

    return mems


def load_from_pe(pe):
    
    mems = []
    for section in pe.SHList:
        section_size = max(section.rawsize,section.size)
        section_size = (section_size+0xfff)&~0xfff
        mems.append(mempool(pe.NThdr.ImageBase+section.addr,
                            pe.NThdr.ImageBase+section.addr+section_size,
                            'RWX', section.data, section.name.replace('\x00', ' ')))

    return mems
