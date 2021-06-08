#! /usr/bin/env python

from __future__ import print_function
from builtins import range
import logging
import struct

from future.utils import PY3, with_metaclass

from miasm.core.utils import force_bytes, force_str
from miasm.loader import cstruct
from miasm.loader import elf
from miasm.loader.strpatchwork import StrPatchwork

log = logging.getLogger("elfparse")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


def printable(string):
    if isinstance(string, bytes):
        return "".join(
            c.decode() if b" " <= c < b"~" else "."
            for c in (string[i:i+1] for i in range(len(string)))
        )
    return string


class StructWrapper_metaclass(type):

    def __new__(cls, name, bases, dct):
        wrapped = dct["wrapped"]
        if wrapped is not None:  # XXX: make dct lookup look into base classes
            for fname, v in wrapped._fields:
                dct[fname] = property(dct.pop("get_" + fname,
                                              lambda self, fname=fname: getattr(
                                                  self.cstr, fname)),
                                      dct.pop("set_" + fname,
                                              lambda self, v, fname=fname: setattr(
                                                  self.cstr, fname, v)),
                                      dct.pop("del_" + fname, None))
        return type.__new__(cls, name, bases, dct)


class StructWrapper(with_metaclass(StructWrapper_metaclass, object)):

    wrapped = None

    def __init__(self, parent, sex, size, *args, **kargs):
        self.cstr = self.wrapped(sex, size, *args, **kargs)
        self.parent = parent

    def __getitem__(self, item):
        return getattr(self, item)

    def __repr__(self):
        return "<W-" + repr(self.cstr)[1:]

    def __str__(self):
        return str(self.cstr)

    def __bytes__(self):
        return bytes(self.cstr)


class WEhdr(StructWrapper):
    wrapped = elf.Ehdr

    def set_shstrndx(self, val):
        self.cstr.shstrndx = val


class WSym32(StructWrapper):
    wrapped = elf.Sym32

    def get_name(self):
        return self.parent.linksection.get_name(self.cstr.name)


class WSym64(StructWrapper):
    wrapped = elf.Sym64

    def get_name(self):
        return self.parent.linksection.get_name(self.cstr.name)


class WRel32(StructWrapper):
    wrapped = elf.Rel32
    wrapped._fields.append(("sym", "u32"))
    wrapped._fields.append(("type", "u08"))

    def get_sym(self):
        if isinstance(self.parent.linksection, NullSection):
            return None
        return self.parent.linksection.symtab[self.cstr.info >> 8].name

    def get_type(self):
        return self.cstr.info & 0xff


class WRel64(StructWrapper):
    wrapped = elf.Rel64
    wrapped._fields.append(("sym", "u32"))
    wrapped._fields.append(("type", "u32"))

    def get_sym(self):
        if not hasattr(self.parent.linksection, 'symtab'):
            return None
        return self.parent.linksection.symtab[self.cstr.info >> 32].name

    def get_type(self):
        return self.cstr.info & 0xffffffff


class WRela32(WRel32):
    wrapped = elf.Rela32
    wrapped._fields.append(("sym", "u32"))
    wrapped._fields.append(("type", "u08"))

    def get_sym(self):
        return self.parent.linksection.symtab[self.cstr.info >> 8].name

    def get_type(self):
        return self.cstr.info & 0xff


class WRela64(WRel64):
    wrapped = elf.Rela64
    wrapped._fields.append(("sym", "u32"))
    wrapped._fields.append(("type", "u32"))

    def get_sym(self):
        return self.parent.linksection.symtab[self.cstr.info >> 32].name

    def get_type(self):
        return self.cstr.info & 0xffffffff


class WShdr(StructWrapper):
    wrapped = elf.Shdr

    def get_name(self):
        return self.parent.parent._shstr.get_name(self.cstr.name)


class WDynamic(StructWrapper):
    wrapped = elf.Dynamic

    def get_name(self):
        if self.type == elf.DT_NEEDED:
            return self.parent.linksection.get_name(self.cstr.name)
        return self.cstr.name


class WPhdr(StructWrapper):
    wrapped = elf.Phdr


class WPhdr64(StructWrapper):
    wrapped = elf.Phdr64


class WNhdr(StructWrapper):
    wrapped = elf.Nhdr


class ContentManager(object):

    def __get__(self, owner, x):
        if hasattr(owner, '_content'):
            return owner._content

    def __set__(self, owner, new_content):
        owner.resize(len(owner._content), len(new_content))
        owner._content = StrPatchwork(new_content)
        owner.parse_content(owner.sex, owner.size)

    def __delete__(self, owner):
        self.__set__(owner, None)


# Sections

class Section_metaclass(type):

    def __new__(cls, name, bases, dct):
        o = type.__new__(cls, name, bases, dct)
        if name != "Section":
            Section.register(o)
        return o

    def register(cls, o):
        if o.sht is not None:
            cls.sectypes[o.sht] = o

    def __call__(cls, parent, sex, size, shstr=None):
        sh = None
        if shstr is not None:
            sh = WShdr(None, sex, size, shstr)
            if sh.type in Section.sectypes:
                cls = Section.sectypes[sh.type]
        i = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        if sh is not None:
            sh.parent = i
        i.__init__(parent, sh)
        return i


class Section(with_metaclass(Section_metaclass, object)):

    sectypes = {}
    content = ContentManager()

    def resize(self, old, new):
        self.sh.size += new - old
        self.parent.resize(self, new - old)
        if self.phparent:
            self.phparent.resize(self, new - old)

    def parse_content(self, sex, size):
        self.sex, self.size = sex, size
        pass

    def get_linksection(self):
        return self.parent[self.sh.link]

    def set_linksection(self, val):
        if isinstance(val, Section):
            val = self.parent.shlist.find(val)
        if type(val) is int:
            self.sh.link = val
    linksection = property(get_linksection, set_linksection)

    def get_infosection(self):
        # XXX info may not be in sh list ?!?
        if not self.sh.info in self.parent:
            return None
        return self.parent[self.sh.info]

    def set_infosection(self, val):
        if isinstance(val, Section):
            val = self.parent.shlist.find(val)
        if type(val) is int:
            self.sh.info = val
    infosection = property(get_infosection, set_infosection)

    def __init__(self, parent, sh=None):
        self.parent = parent
        self.phparent = None
        self.sh = sh
        self._content = b""

    def __repr__(self):
        r = "{%(name)s ofs=%(offset)#x sz=%(size)#x addr=%(addr)#010x}" % self.sh
        return r


class NullSection(Section):
    sht = elf.SHT_NULL

    def get_name(self, ofs):
        # XXX check this
        return b""


class ProgBits(Section):
    sht = elf.SHT_PROGBITS


class HashSection(Section):
    sht = elf.SHT_HASH


class NoBitsSection(Section):
    sht = elf.SHT_NOBITS


class ShLibSection(Section):
    sht = elf.SHT_SHLIB


class InitArray(Section):
    sht = elf.SHT_INIT_ARRAY


class FiniArray(Section):
    sht = elf.SHT_FINI_ARRAY


class GroupSection(Section):
    sht = elf.SHT_GROUP


class SymTabSHIndeces(Section):
    sht = elf.SHT_SYMTAB_SHNDX


class GNUVerSym(Section):
    sht = elf.SHT_GNU_versym


class GNUVerNeed(Section):
    sht = elf.SHT_GNU_verneed


class GNUVerDef(Section):
    sht = elf.SHT_GNU_verdef


class GNULibLIst(Section):
    sht = elf.SHT_GNU_LIBLIST


class CheckSumSection(Section):
    sht = elf.SHT_CHECKSUM


class NoteSection(Section):
    sht = elf.SHT_NOTE

    def parse_content(self, sex, size):
        self.sex, self.size = sex, size
        c = self.content
        hsz = 12
        self.notes = []
        # XXX: c may not be aligned?
        while len(c) > hsz:
            note = WNhdr(self, sex, size, c)
            namesz, descsz = note.namesz, note.descsz
            name = c[hsz:hsz + namesz]
            desc = c[hsz + namesz:hsz + namesz + descsz]
            c = c[hsz + namesz + descsz:]
            self.notes.append((note.type, name, desc))


class Dynamic(Section):
    sht = elf.SHT_DYNAMIC

    def parse_content(self, sex, size):
        self.sex, self.size = sex, size
        c = self.content
        self.dyntab = []
        self.dynamic = {}
        sz = self.sh.entsize
        idx = 0
        while len(c) > sz*idx:
            s = c[sz*idx:sz*(idx+1)]
            idx += 1
            dyn = WDynamic(self, sex, size, s)
            self.dyntab.append(dyn)
            if isinstance(dyn.name, str):
                self[dyn.name] = dyn

    def __setitem__(self, item, value):
        if isinstance(item, bytes):
            self.dynamic[item] = value
            return
        if isinstance(item, str):
            self.symbols[item.encode()] = value
            return
        self.dyntab[item] = value

    def __getitem__(self, item):
        if isinstance(item, bytes):
            return self.dynamic[item]
        if isinstance(item, str):
            return self.dynamic[item.encode()]
        return self.dyntab[item]


class StrTable(Section):
    sht = elf.SHT_STRTAB

    def parse_content(self, sex, size):
        self.sex, self.size = sex, size
        self.res = {}
        c = self.content
        q = 0
        index = 0
        l = len(c)
        while index < l:
            p = c.find(b"\x00", index)
            if p < 0:
                log.warning("Missing trailing 0 for string [%s]" % c)  # XXX
                p = len(c) - index
            self.res[index] = c[index:p]
            # print q, c[:p]
            index = p + 1
            # q += p+1
            # c = c[p+1:]

    def get_name(self, ofs):
        return self.content[ofs:self.content.find(b'\x00', start=ofs)]

    def add_name(self, name):
        name = force_bytes(name)
        name = name + b"\x00"
        if name in self.content:
            return self.content.find(name)
        n = len(self.content)
        self.content = bytes(self.content) + name
        return n

    def mod_name(self, name, new_name):
        s = bytes(self.content)
        name_b = b'\x00%s\x00' % name.encode()
        if not name_b in s:
            raise ValueError('Unknown name %r' % name)
        self.content = s.replace(
            name_b,
            b'\x00%s\x00' % new_name.encode()
        )
        return len(self.content)


class SymTable(Section):
    sht = elf.SHT_SYMTAB

    def parse_content(self, sex, size):
        self.sex, self.size = sex, size
        c = self.content
        self.symtab = []
        self.symbols = {}
        sz = self.sh.entsize
        index = 0
        l = len(c)
        if size == 32:
            WSym = WSym32
        elif size == 64:
            WSym = WSym64
        else:
            ValueError('unknown size')
        while index < l:
            s = c[index:index + sz]
            index += sz
            sym = WSym(self, sex, size, s)
            self.symtab.append(sym)
            self[sym.name] = sym

    def __getitem__(self, item):
        if isinstance(item, bytes):
            return self.symbols[item]
        if isinstance(item, str):
            return self.symbols[item.encode()]
        return self.symtab[item]

    def __setitem__(self, item, value):
        if isinstance(item, bytes):
            self.symbols[item] = value
            return
        if isinstance(item, str):
            self.symbols[item.encode()] = value
            return
        self.symtab[item] = value


class DynSymTable(SymTable):
    sht = elf.SHT_DYNSYM


class RelTable(Section):
    sht = elf.SHT_REL

    def parse_content(self, sex, size):
        self.sex, self.size = sex, size
        if size == 32:
            WRel = WRel32
        elif size == 64:
            WRel = WRel64
        else:
            ValueError('unknown size')
        c = self.content
        self.reltab = []
        self.rel = {}
        sz = self.sh.entsize

        idx = 0
        while len(c) > sz*idx:
            s = c[sz*idx:sz*(idx+1)]
            idx += 1
            rel = WRel(self, sex, size, s)
            self.reltab.append(rel)
            if rel.parent.linksection != self.parent.shlist[0]:
                self.rel[rel.sym] = rel


class RelATable(RelTable):
    sht = elf.SHT_RELA

# Section List


class SHList(object):

    def __init__(self, parent, sex, size):
        self.parent = parent
        self.shlist = []
        ehdr = self.parent.Ehdr
        of1 = ehdr.shoff
        if not of1:  # No SH table
            return
        for i in range(ehdr.shnum):
            of2 = of1 + ehdr.shentsize
            shstr = parent[of1:of2]
            self.shlist.append(Section(self, sex, size, shstr=shstr))
            of1 = of2
        self._shstr = self.shlist[ehdr.shstrndx]

        for s in self.shlist:
            if not isinstance(s, NoBitsSection):
                s._content = StrPatchwork(
                    parent[s.sh.offset: s.sh.offset + s.sh.size]
                )
        # Follow dependencies when initializing sections
        zero = self.shlist[0]
        todo = self.shlist[1:]
        done = []
        while todo:
            s = todo.pop(0)
            if ((s.linksection == zero or s.linksection in done) and
                    (s.infosection in [zero, None] or s.infosection in done)):
                done.append(s)
                s.parse_content(sex, size)
            else:
                todo.append(s)
        for s in self.shlist:
            self.do_add_section(s)

    def do_add_section(self, section):
        n = section.sh.name
        if n.startswith(b"."):
            n = n[1:]
        n = printable(n).replace(".", "_").replace("-", "_")
        setattr(self, n, section)  # xxx

    def append(self, item):
        self.do_add_section(item)
        self.shlist.append(item)

    def __getitem__(self, item):
        return self.shlist[item]

    def __repr__(self):
        rep = ["#  section         offset   size   addr     flags"]
        for i, s in enumerate(self.shlist):
            l = "%(name)-15s %(offset)08x %(size)06x %(addr)08x %(flags)x " % s.sh
            l = ("%2i " % i) + l + s.__class__.__name__
            rep.append(l)
        return "\n".join(rep)

    def __bytes__(self):
        return b"".join(
            bytes(s.sh) for s in self.shlist
        )

    def __str__(self):
        if PY3:
            return repr(self)
        return bytes(self)

    def resize(self, sec, diff):
        for s in self.shlist:
            if s.sh.offset > sec.sh.offset:
                s.sh.offset += diff
        if self.parent.Ehdr.shoff > sec.sh.offset:
            self.parent.Ehdr.shoff += diff
        if self.parent.Ehdr.phoff > sec.sh.offset:
            self.parent.Ehdr.phoff += diff

# Program Header List


class ProgramHeader(object):

    def __init__(self, parent, sex, size, phstr):
        self.parent = parent
        self.ph = WPhdr(self, sex, size, phstr)
        self.shlist = []
        for s in self.parent.parent.sh:
            if isinstance(s, NullSection):
                continue
            if ((isinstance(s, NoBitsSection) and s.sh.offset == self.ph.offset + self.ph.filesz)
               or self.ph.offset <= s.sh.offset < self.ph.offset + self.ph.filesz):
                s.phparent = self
                self.shlist.append(s)

    def resize(self, sec, diff):
        self.ph.filesz += diff
        self.ph.memsz += diff
        self.parent.resize(sec, diff)


class ProgramHeader64(object):

    def __init__(self, parent, sex, size, phstr):
        self.parent = parent
        self.ph = WPhdr64(self, sex, size, phstr)
        self.shlist = []
        for s in self.parent.parent.sh:
            if isinstance(s, NullSection):
                continue
            if ((isinstance(s, NoBitsSection) and s.sh.offset == self.ph.offset + self.ph.filesz)
               or self.ph.offset <= s.sh.offset < self.ph.offset + self.ph.filesz):
                s.phparent = self
                self.shlist.append(s)

    def resize(self, sec, diff):
        self.ph.filesz += diff
        self.ph.memsz += diff
        self.parent.resize(sec, diff)


class PHList(object):

    def __init__(self, parent, sex, size):
        self.parent = parent
        self.phlist = []
        ehdr = self.parent.Ehdr
        of1 = ehdr.phoff
        for i in range(ehdr.phnum):
            of2 = of1 + ehdr.phentsize
            phstr = parent[of1:of2]
            if size == 32:
                self.phlist.append(ProgramHeader(self, sex, size, phstr))
            else:
                self.phlist.append(ProgramHeader64(self, sex, size, phstr))
            of1 = of2

    def __getitem__(self, item):
        return self.phlist[item]

    def __repr__(self):
        r = ["   offset filesz vaddr    memsz"]
        for i, p in enumerate(self.phlist):
            l = "%(offset)07x %(filesz)06x %(vaddr)08x %(memsz)07x %(type)02x %(flags)01x" % p.ph
            l = ("%2i " % i) + l
            r.append(l)
            r.append("   " + " ".join(printable(s.sh.name) for s in p.shlist))
        return "\n".join(r)

    def __bytes__(self):
        return b"".join(
            bytes(p.ph) for p in self.phlist
        )

    def __str__(self):
        if PY3:
            return repr(self)
        return self.__bytes__(self)

    def resize(self, sec, diff):
        for p in self.phlist:
            if p.ph.offset > sec.sh.offset:
                p.ph.offset += diff
            if p.ph.vaddr > sec.phparent.ph.vaddr + sec.sh.offset:
                p.ph.vaddr += diff
            if p.ph.paddr > sec.phparent.ph.paddr + sec.sh.offset:
                p.ph.paddr += diff


class virt(object):

    def __init__(self, x):
        self.parent = x

    def get_rvaitem(self, start, stop=None):
        if stop == None:
            s = self.parent.getsectionbyvad(start)
            if s:
                start = start - s.sh.addr
            else:
                s = self.parent.getphbyvad(start)
                if s:
                    start = start - s.ph.vaddr
            if not s:
                return [(None, start)]
            return [(s, start)]
        total_len = stop - start

        virt_item = []
        while total_len:
            s = self.parent.getsectionbyvad(start)
            if not s:
                s = self.parent.getphbyvad(start)
            if not s:
                raise ValueError('unknown rva address! %x' % start)
            if isinstance(s, ProgramHeader) or isinstance(s, ProgramHeader64):
                s_max = s.ph.filesz
                s_start = start - s.ph.vaddr
                s_stop = stop - s.ph.vaddr
            else:
                s_max = s.sh.size
                s_start = start - s.sh.addr
                s_stop = stop - s.sh.addr
            if s_stop > s_max:
                s_stop = s_max

            s_len = s_stop - s_start
            if s_len == 0:
                raise ValueError('empty section! %x' % start)
            total_len -= s_len
            start += s_len
            n_item = slice(s_start, s_stop)
            virt_item.append((s, n_item))
        return virt_item

    def item2virtitem(self, item):
        if not type(item) is slice:  # integer
            return self.get_rvaitem(item)
        start = item.start
        stop = item.stop
        assert(item.step is None)
        return self.get_rvaitem(start, stop)

    def get(self, ad_start, ad_stop=None):
        rva_items = self.get_rvaitem(ad_start, ad_stop)
        data_out = b""
        for s, n_item in rva_items:
            if not (isinstance(s, ProgramHeader) or isinstance(s, ProgramHeader64)):
                data_out += s.content.__getitem__(n_item)
                continue
            if not type(n_item) is slice:
                n_item = slice(n_item, n_item + 1, 1)
            start = n_item.start + s.ph.offset
            stop = n_item.stop + s.ph.offset
            if n_item.step != None:
                step = n_item.step + s.ph.offset
            else:
                step = None
            n_item = slice(start, stop, step)
            # data_out += self.parent.content.__s.content.__getitem__(n_item)
            data_out += self.parent.content.__getitem__(n_item)

        return data_out

    def set(self, item, data):
        if not type(item) is slice:
            item = slice(item, item + len(data), None)
        virt_item = self.item2virtitem(item)
        if not virt_item:
            return
        off = 0
        for s, n_item in virt_item:
            if isinstance(s, ProgBits):
                i = slice(off, n_item.stop + off - n_item.start, n_item.step)

                data_slice = data.__getitem__(i)
                s.content.__setitem__(n_item, data_slice)
                off = i.stop
            else:
                raise ValueError('TODO XXX')

        return

    def __getitem__(self, item):
        if isinstance(item, slice):
            assert(item.step is None)
            return self.get(item.start, item.stop)
        else:
            return self.get(item)

    def __setitem__(self, item, data):
        if isinstance(item, slice):
            rva = item.start
        else:
            rva = item
        self.set(rva, data)

    def max_addr(self):
        # the maximum virtual address is found by retrieving the maximum
        # possible virtual address, either from the program entries, and
        # section entries. if there is no such object, raise an error.
        l = 0
        if self.parent.ph.phlist:
            for phdr in self.parent.ph.phlist:
                l = max(l, phdr.ph.vaddr + phdr.ph.memsz)
        if self.parent.sh.shlist:
            for shdr in self.parent.sh.shlist:
                l = max(l, shdr.sh.addr + shdr.sh.size)
        if not l:
            raise ValueError('maximum virtual address not found !')
        return l

    def is_addr_in(self, ad):
        return self.parent.is_in_virt_address(ad)

    def find(self, pattern, start=0):
        sections = []
        offset = start
        for s in self.parent.ph:
            s_max = s.ph.memsz  # max(s.ph.filesz, s.ph.memsz)
            if offset < s.ph.vaddr + s_max:
                sections.append(s)

        if not sections:
            return -1
        offset -= sections[0].ph.vaddr
        if offset < 0:
            offset = 0
        for s in sections:
            data = self.parent.content[s.ph.offset:s.ph.offset + s.ph.filesz]
            ret = data.find(pattern, offset)
            if ret != -1:
                return ret + s.ph.vaddr  # self.parent.rva2virt(s.addr + ret)
            offset = 0
        return -1

# ELF object


class ELF(object):

    def __init__(self, elfstr):
        self._content = elfstr
        self.parse_content()

        self._virt = virt(self)

    def get_virt(self):
        return self._virt
    virt = property(get_virt)

    content = ContentManager()

    def parse_content(self):
        h = self.content[:8]
        self.size = struct.unpack('B', h[4:5])[0] * 32
        self.sex = struct.unpack('B', h[5:6])[0]
        self.Ehdr = WEhdr(self, self.sex, self.size, self.content)
        self.sh = SHList(self, self.sex, self.size)
        self.ph = PHList(self, self.sex, self.size)

    def resize(self, old, new):
        pass

    def __getitem__(self, item):
        return self.content[item]

    def build_content(self):
        c = StrPatchwork()
        c[0] = bytes(self.Ehdr)
        c[self.Ehdr.phoff] = bytes(self.ph)
        for s in self.sh:
            c[s.sh.offset] = bytes(s.content)
        c[self.Ehdr.shoff] = bytes(self.sh)
        return bytes(c)

    def __bytes__(self):
        return self.build_content()

    def __str__(self):
        if PY3:
            return repr(self)
        return bytes(self)

    def getphbyvad(self, ad):
        for s in self.ph:
            if s.ph.vaddr <= ad < s.ph.vaddr + s.ph.memsz:
                return s

    def getsectionbyvad(self, ad):
        for s in self.sh:
            if s.sh.addr <= ad < s.sh.addr + s.sh.size:
                return s

    def getsectionbyname(self, name):
        name = force_bytes(name)
        for s in self.sh:
            try:
                if s.sh.name.strip(b'\x00') == name:
                    return s
            except UnicodeDecodeError:
                pass
        return None

    def is_in_virt_address(self, ad):
        for s in self.sh:
            if s.sh.addr <= ad < s.sh.addr + s.sh.size:
                return True
        return False
