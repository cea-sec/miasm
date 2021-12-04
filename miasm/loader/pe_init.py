#! /usr/bin/env python

from __future__ import print_function

from builtins import range
import array
from functools import reduce
import logging
import struct

from future.builtins import int as int_types
from future.utils import PY3

from miasm.loader import pe
from miasm.loader.strpatchwork import StrPatchwork

log = logging.getLogger("peparse")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


class ContentManager(object):

    def __get__(self, owner, _):
        if hasattr(owner, '_content'):
            return owner._content

    def __set__(self, owner, new_content):
        owner.resize(len(owner._content), len(new_content))
        owner._content = new_content

    def __delete__(self, owner):
        self.__set__(owner, None)


class ContectRva(object):

    def __init__(self, parent):
        self.parent = parent

    def get(self, rva_start, rva_stop=None):
        """
        Get data in RVA view starting at @rva_start, stopping at @rva_stop
        @rva_start: rva start address
        @rva_stop: rva stop address
        """
        if rva_start is None:
            raise IOError("Out of range")
        if rva_start < 0:
            raise IOError("Out of range")
        if rva_stop is not None:
            if rva_stop > len(self.parent.img_rva):
                rva_stop = len(self.parent.img_rva)
            if rva_start > len(self.parent.img_rva):
                raise ValueError("Out of range")
            return self.parent.img_rva[rva_start:rva_stop]
        if rva_start > len(self.parent.img_rva):
            raise ValueError("Out of range")
        return self.parent.img_rva[rva_start]

    def set(self, rva, data):
        """
        Set @data in RVA view starting at @start
        @rva: rva start address
        @data: data to set
        """
        if not isinstance(rva, int_types):
            raise ValueError('addr must be int/long')

        if rva < 0:
            raise ValueError("Out of range")

        if rva + len(data) > len(self.parent.img_rva):
            raise ValueError("Out of range")
        self.parent.img_rva[rva] = data

    def __getitem__(self, item):
        if isinstance(item, slice):
            assert(item.step is None)
            return self.get(item.start, item.stop)
        return self.get(item)

    def __setitem__(self, item, data):
        if isinstance(item, slice):
            rva = item.start
        else:
            rva = item
        self.set(rva, data)


class ContentVirtual(object):

    def __init__(self, parent):
        self.parent = parent

    def __getitem__(self, item):
        raise DeprecationWarning("Replace code by virt.get(start, [stop])")

    def __setitem__(self, item, data):
        raise DeprecationWarning("Replace code by virt.set(start, data)")

    def __call__(self, ad_start, ad_stop=None, ad_step=None):
        raise DeprecationWarning("Replace code by virt.get(start, stop)")

    def get(self, virt_start, virt_stop=None):
        """
        Get data in VIRTUAL view starting at @virt_start, stopping at @virt_stop
        @virt_start: virt start address
        @virt_stop: virt stop address
        """
        rva_start = self.parent.virt2rva(virt_start)
        if virt_stop != None:
            rva_stop = self.parent.virt2rva(virt_stop)
        else:
            rva_stop = None
        return self.parent.rva.get(rva_start, rva_stop)

    def set(self, addr, data):
        """
        Set @data in VIRTUAL view starting at @start
        @addr: virtual start address
        @data: data to set
        """
        if not isinstance(addr, int_types):
            raise ValueError('addr must be int/long')
        self.parent.rva.set(self.parent.virt2rva(addr), data)

    def max_addr(self):
        section = self.parent.SHList[-1]
        length = section.addr + section.size + self.parent.NThdr.ImageBase
        return int(length)

    def find(self, pattern, start=0, end=None):
        if start != 0:
            start = self.parent.virt2rva(start)
        if end != None:
            end = self.parent.virt2rva(end)

        ret = self.parent.img_rva.find(pattern, start, end)
        if ret == -1:
            return -1
        return self.parent.rva2virt(ret)

    def rfind(self, pattern, start=0, end=None):
        if start != 0:
            start = self.parent.virt2rva(start)
        if end != None:
            end = self.parent.virt2rva(end)

        ret = self.parent.img_rva.rfind(pattern, start, end)
        if ret == -1:
            return -1
        return self.parent.rva2virt(ret)

    def is_addr_in(self, addr):
        return self.parent.is_in_virt_address(addr)



def compute_crc(raw, olds):
    out = 0
    data = raw[:]
    if len(raw) % 2:
        end = struct.unpack('B', data[-1:])[0]
        data = data[:-1]
    if (len(raw) & ~0x1) % 4:
        out += struct.unpack('H', data[:2])[0]
        data = data[2:]
    data = array.array('I', data)
    out = reduce(lambda x, y: x + y, data, out)
    out -= olds
    while out > 0xFFFFFFFF:
        out = (out >> 32) + (out & 0xFFFFFFFF)
    while out > 0xFFFF:
        out = (out & 0xFFFF) + ((out >> 16) & 0xFFFF)
    if len(raw) % 2:
        out += end
    out += len(data)
    return out



# PE object
class PE(object):
    content = ContentManager()

    def __init__(self, pestr=None,
                 loadfrommem=False,
                 parse_resources=True,
                 parse_delay=True,
                 parse_reloc=True,
                 wsize=32,
                 **kwargs):
        self._rva = ContectRva(self)
        self._virt = ContentVirtual(self)
        self.img_rva = StrPatchwork()
        if pestr is None:
            self._content = StrPatchwork()
            self._sex = 0
            self._wsize = wsize
            self.Doshdr = pe.Doshdr(self)
            self.NTsig = pe.NTsig(self)
            self.Coffhdr = pe.Coffhdr(self)

            if self._wsize == 32:
                Opthdr = pe.Opthdr32
            else:
                Opthdr = pe.Opthdr64

            self.Opthdr = Opthdr(self)
            self.NThdr = pe.NThdr(self)
            self.NThdr.optentries = [pe.Optehdr(self) for _ in range(0x10)]
            self.NThdr.CheckSum = 0
            self.SHList = pe.SHList(self)
            self.SHList.shlist = []

            self.NThdr.sizeofheaders = 0x1000

            self.DirImport = pe.DirImport(self)
            self.DirExport = pe.DirExport(self)
            self.DirDelay = pe.DirDelay(self)
            self.DirReloc = pe.DirReloc(self)
            self.DirRes = pe.DirRes(self)
            self.DirTls = pe.DirTls(self)

            self.Doshdr.magic = 0x5a4d
            self.Doshdr.lfanew = 0xe0

            self.NTsig.signature = 0x4550
            if wsize == 32:
                self.Opthdr.magic = 0x10b
            elif wsize == 64:
                self.Opthdr.magic = 0x20b
            else:
                raise ValueError('unknown pe size %r' % wsize)
            self.Opthdr.majorlinkerversion = 0x7
            self.Opthdr.minorlinkerversion = 0x0
            self.NThdr.filealignment = 0x1000
            self.NThdr.sectionalignment = 0x1000
            self.NThdr.majoroperatingsystemversion = 0x5
            self.NThdr.minoroperatingsystemversion = 0x1
            self.NThdr.MajorImageVersion = 0x5
            self.NThdr.MinorImageVersion = 0x1
            self.NThdr.majorsubsystemversion = 0x4
            self.NThdr.minorsubsystemversion = 0x0
            self.NThdr.subsystem = 0x3
            if wsize == 32:
                self.NThdr.dllcharacteristics = 0x8000
            else:
                self.NThdr.dllcharacteristics = 0x8000

            # for createthread
            self.NThdr.sizeofstackreserve = 0x200000
            self.NThdr.sizeofstackcommit = 0x1000
            self.NThdr.sizeofheapreserve = 0x100000
            self.NThdr.sizeofheapcommit = 0x1000

            self.NThdr.ImageBase = 0x400000
            self.NThdr.sizeofheaders = 0x1000
            self.NThdr.numberofrvaandsizes = 0x10

            self.NTsig.signature = 0x4550
            if wsize == 32:
                self.Coffhdr.machine = 0x14c
            elif wsize == 64:
                self.Coffhdr.machine = 0x8664
            else:
                raise ValueError('unknown pe size %r' % wsize)
            if wsize == 32:
                self.Coffhdr.characteristics = 0x10f
                self.Coffhdr.sizeofoptionalheader = 0xe0
            else:
                self.Coffhdr.characteristics = 0x22  # 0x2f
                self.Coffhdr.sizeofoptionalheader = 0xf0

        else:
            self._content = StrPatchwork(pestr)
            self.loadfrommem = loadfrommem
            self.parse_content(parse_resources=parse_resources,
                               parse_delay=parse_delay,
                               parse_reloc=parse_reloc)

    def isPE(self):
        if self.NTsig is None:
            return False
        return self.NTsig.signature == 0x4550

    def parse_content(self,
                      parse_resources=True,
                      parse_delay=True,
                      parse_reloc=True):
        off = 0
        self._sex = 0
        self._wsize = 32
        self.Doshdr = pe.Doshdr.unpack(self.content, off, self)
        off = self.Doshdr.lfanew
        if off > len(self.content):
            log.warn('ntsig after eof!')
            self.NTsig = None
            return
        self.NTsig = pe.NTsig.unpack(self.content,
                                     off, self)
        self.DirImport = None
        self.DirExport = None
        self.DirDelay = None
        self.DirReloc = None
        self.DirRes = None

        if self.NTsig.signature != 0x4550:
            log.warn('not a valid pe!')
            return
        off += len(self.NTsig)
        self.Coffhdr, length = pe.Coffhdr.unpack_l(self.content,
                                                   off,
                                                   self)

        off += length
        self._wsize = ord(self.content[off+1]) * 32

        if self._wsize == 32:
            Opthdr = pe.Opthdr32
        else:
            Opthdr = pe.Opthdr64

        if len(self.content) < 0x200:
            # Fix for very little PE
            self.content += (0x200 - len(self.content)) * b'\x00'

        self.Opthdr, length = Opthdr.unpack_l(self.content, off, self)
        self.NThdr = pe.NThdr.unpack(self.content, off + length, self)
        self.img_rva[0] = self.content[:self.NThdr.sizeofheaders]
        off += self.Coffhdr.sizeofoptionalheader
        self.SHList = pe.SHList.unpack(self.content, off, self)

        # load section data
        filealignment = self.NThdr.filealignment
        sectionalignment = self.NThdr.sectionalignment
        for section in self.SHList.shlist:
            virt_size = (section.size // sectionalignment + 1) * sectionalignment
            if self.loadfrommem:
                section.offset = section.addr
            if self.NThdr.sectionalignment > 0x1000:
                raw_off = 0x200 * (section.offset // 0x200)
            else:
                raw_off = section.offset
            if raw_off != section.offset:
                log.warn('unaligned raw section (%x %x)!', raw_off, section.offset)
            section.data = StrPatchwork()

            if section.rawsize == 0:
                rounded_size = 0
            else:
                if section.rawsize % filealignment:
                    rs = (section.rawsize // filealignment + 1) * filealignment
                else:
                    rs = section.rawsize
                rounded_size = rs
            if rounded_size > virt_size:
                rounded_size = min(rounded_size, section.size)
            data = self.content[raw_off:raw_off + rounded_size]
            section.data = data
            # Pad data to page size 0x1000
            length = len(data)
            data += b"\x00" * ((((length + 0xfff)) & 0xFFFFF000) - length)
            self.img_rva[section.addr] = data
        # Fix img_rva
        self.img_rva = self.img_rva

        try:
            self.DirImport = pe.DirImport.unpack(self.img_rva,
                                                 self.NThdr.optentries[
                                                     pe.DIRECTORY_ENTRY_IMPORT].rva,
                                                 self)
        except pe.InvalidOffset:
            log.warning('cannot parse DirImport, skipping')
            self.DirImport = pe.DirImport(self)

        try:
            self.DirExport = pe.DirExport.unpack(self.img_rva,
                                                 self.NThdr.optentries[
                                                     pe.DIRECTORY_ENTRY_EXPORT].rva,
                                                 self)
        except pe.InvalidOffset:
            log.warning('cannot parse DirExport, skipping')
            self.DirExport = pe.DirExport(self)

        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            self.DirDelay = pe.DirDelay(self)
            if parse_delay:
                try:
                    self.DirDelay = pe.DirDelay.unpack(self.img_rva,
                                                       self.NThdr.optentries[
                                                           pe.DIRECTORY_ENTRY_DELAY_IMPORT].rva,
                                                       self)
                except pe.InvalidOffset:
                    log.warning('cannot parse DirDelay, skipping')
        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_BASERELOC:
            self.DirReloc = pe.DirReloc(self)
            if parse_reloc:
                try:
                    self.DirReloc = pe.DirReloc.unpack(self.img_rva,
                                                       self.NThdr.optentries[
                                                           pe.DIRECTORY_ENTRY_BASERELOC].rva,
                                                       self)
                except pe.InvalidOffset:
                    log.warning('cannot parse DirReloc, skipping')
        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_RESOURCE:
            self.DirRes = pe.DirRes(self)
            if parse_resources:
                self.DirRes = pe.DirRes(self)
                try:
                    self.DirRes = pe.DirRes.unpack(self.img_rva,
                                                   self.NThdr.optentries[
                                                       pe.DIRECTORY_ENTRY_RESOURCE].rva,
                                                   self)
                except pe.InvalidOffset:
                    log.warning('cannot parse DirRes, skipping')

        if len(self.NThdr.optentries) > pe.DIRECTORY_ENTRY_TLS:
            self.DirTls = pe.DirTls(self)
            try:
                self.DirTls = pe.DirTls.unpack(
                    self.img_rva,
                    self.NThdr.optentries[pe.DIRECTORY_ENTRY_TLS].rva,
                    self
                )
            except pe.InvalidOffset:
                log.warning('cannot parse DirTls, skipping')

    def resize(self, old, new):
        pass

    def __getitem__(self, item):
        return self.content[item]

    def __setitem__(self, item, data):
        self.content.__setitem__(item, data)
        return

    def getsectionbyrva(self, rva):
        if self.SHList is None:
            return None
        for section in self.SHList.shlist:
            """
            TODO CHECK:
            some binaries have import rva outside section, but addresses
            seems to be rounded
            """
            mask = self.NThdr.sectionalignment - 1
            if section.addr <= rva < (section.addr + section.size + mask) & ~(mask):
                return section
        return None

    def getsectionbyvad(self, vad):
        return self.getsectionbyrva(self.virt2rva(vad))

    def getsectionbyoff(self, off):
        if self.SHList is None:
            return None
        for section in self.SHList.shlist:
            if section.offset <= off < section.offset + section.rawsize:
                return section
        return None

    def getsectionbyname(self, name):
        if self.SHList is None:
            return None
        for section in self.SHList:
            if section.name.strip(b'\x00').decode() == name:
                return section
        return None

    def is_rva_ok(self, rva):
        return self.getsectionbyrva(rva) is not None

    def rva2off(self, rva):
        # Special case rva in header
        if rva < self.NThdr.sizeofheaders:
            return rva
        section = self.getsectionbyrva(rva)
        if section is None:
            raise pe.InvalidOffset('cannot get offset for 0x%X' % rva)
        soff = (section.offset // self.NThdr.filealignment) * self.NThdr.filealignment
        return rva - section.addr + soff

    def off2rva(self, off):
        section = self.getsectionbyoff(off)
        if section is None:
            return
        return off - section.offset + section.addr

    def virt2rva(self, addr):
        """
        Return rva of virtual address @addr; None if addr is below ImageBase
        """
        if addr is None:
            return None
        rva = addr - self.NThdr.ImageBase
        if rva < 0:
            return None
        return rva

    def rva2virt(self, rva):
        if rva is None:
            return
        return rva + self.NThdr.ImageBase

    def virt2off(self, addr):
        """
        Return offset of virtual address @addr
        """
        rva = self.virt2rva(addr)
        if rva is None:
            return None
        return self.rva2off(rva)

    def off2virt(self, off):
        return self.rva2virt(self.off2rva(off))

    def is_in_virt_address(self, addr):
        if addr < self.NThdr.ImageBase:
            return False
        addr = self.virt2rva(addr)
        for section in self.SHList.shlist:
            if section.addr <= addr < section.addr + section.size:
                return True
        return False

    def get_drva(self):
        print('Deprecated: Use PE.rva instead of PE.drva')
        return self._rva

    def get_rva(self):
        return self._rva

    # TODO XXX remove drva api
    drva = property(get_drva)
    rva = property(get_rva)

    def get_virt(self):
        return self._virt

    virt = property(get_virt)

    def build_content(self):

        content = StrPatchwork()
        content[0] = bytes(self.Doshdr)

        for section in self.SHList.shlist:
            content[section.offset:section.offset + section.rawsize] = bytes(section.data)

        # fix image size
        section_last = self.SHList.shlist[-1]
        size = section_last.addr + section_last.size + (self.NThdr.sectionalignment - 1)
        size &= ~(self.NThdr.sectionalignment - 1)
        self.NThdr.sizeofimage = size

        off = self.Doshdr.lfanew
        content[off] = bytes(self.NTsig)
        off += len(self.NTsig)
        content[off] = bytes(self.Coffhdr)
        off += len(self.Coffhdr)
        off_shlist = off + self.Coffhdr.sizeofoptionalheader
        content[off] = bytes(self.Opthdr)
        off += len(self.Opthdr)
        content[off] = bytes(self.NThdr)
        off += len(self.NThdr)
        # content[off] = bytes(self.Optehdr)

        off = off_shlist
        content[off] = bytes(self.SHList)

        for section in self.SHList:
            if off + len(bytes(self.SHList)) > section.offset:
                log.warn("section offset overlap pe hdr 0x%x 0x%x" %
                         (off + len(bytes(self.SHList)), section.offset))
        self.DirImport.build_content(content)
        self.DirExport.build_content(content)
        self.DirDelay.build_content(content)
        self.DirReloc.build_content(content)
        self.DirRes.build_content(content)
        self.DirTls.build_content(content)

        if (self.Doshdr.lfanew + len(self.NTsig) + len(self.Coffhdr)) % 4:
            log.warn("non aligned coffhdr, bad crc calculation")
        crcs = compute_crc(bytes(content), self.NThdr.CheckSum)
        content[self.Doshdr.lfanew + len(self.NTsig) + len(self.Coffhdr) + 64] = struct.pack('I', crcs)
        return bytes(content)

    def __bytes__(self):
        return self.build_content()

    def __str__(self):
        if PY3:
            return repr(self)
        return self.__bytes__()

    def export_funcs(self):
        if self.DirExport is None:
            print('no export dir found')
            return None, None

        all_func = {}
        for i, export in enumerate(self.DirExport.f_names):
            all_func[export.name.name] = self.rva2virt(
                self.DirExport.f_address[self.DirExport.f_nameordinals[i].ordinal].rva)
            all_func[self.DirExport.f_nameordinals[i].ordinal + self.DirExport.expdesc.base] = self.rva2virt(
                self.DirExport.f_address[self.DirExport.f_nameordinals[i].ordinal].rva)
        # XXX todo: test if redirected export
        return all_func

    def reloc_to(self, imgbase):
        offset = imgbase - self.NThdr.ImageBase
        if self.DirReloc is None:
            log.warn('no relocation found!')
        for rel in self.DirReloc.reldesc:
            rva = rel.rva
            for reloc in rel.rels:
                reloc_type, off = reloc.rel
                if reloc_type == 0 and off == 0:
                    continue
                if reloc_type != 3:
                    raise NotImplementedError('Reloc type not supported')
                off += rva
                value = struct.unpack('I', self.rva.get(off, off + 4))[0]
                value += offset
                self.rva.set(off, struct.pack('I', value & 0xFFFFFFFF))
        self.NThdr.ImageBase = imgbase
