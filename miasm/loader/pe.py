#! /usr/bin/env python

from __future__ import print_function
from builtins import range, str
from collections import defaultdict
import logging
import struct

from future.builtins import int as int_types
from future.utils import PY3

from miasm.core.utils import force_bytes
from miasm.loader.new_cstruct import CStruct
from miasm.loader.strpatchwork import StrPatchwork

log = logging.getLogger("pepy")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


class InvalidOffset(Exception):
    pass


class Doshdr(CStruct):
    _fields = [("magic", "u16"),
               ("cblp", "u16"),
               ("cp", "u16"),
               ("crlc", "u16"),
               ("cparhdr", "u16"),
               ("minalloc", "u16"),
               ("maxalloc", "u16"),
               ("ss", "u16"),
               ("sp", "u16"),
               ("csum", "u16"),
               ("ip", "u16"),
               ("cs", "u16"),
               ("lfarlc", "u16"),
               ("ovno", "u16"),
               ("res", "8s"),
               ("oemid", "u16"),
               ("oeminfo", "u16"),
               ("res2", "20s"),
               ("lfanew", "u32")]


class NTsig(CStruct):
    _fields = [("signature", "u32"),
               ]


class Coffhdr(CStruct):
    _fields = [("machine", "u16"),
               ("numberofsections", "u16"),
               ("timedatestamp", "u32"),
               ("pointertosymboltable", "u32"),
               ("numberofsymbols", "u32"),
               ("sizeofoptionalheader", "u16"),
               ("characteristics", "u16")]


class Optehdr(CStruct):
    _fields = [("rva", "u32"),
               ("size", "u32")]


def get_optehdr_num(nthdr):
    numberofrva = nthdr.numberofrvaandsizes
    parent = nthdr.parent_head
    entry_size = 8
    if parent.Coffhdr.sizeofoptionalheader < numberofrva * entry_size + len(parent.Opthdr):
        numberofrva = (parent.Coffhdr.sizeofoptionalheader - len(parent.Opthdr)) // entry_size
        log.warn('Bad number of rva.. using default %d' % numberofrva)
        numberofrva = 0x10
    return numberofrva


class Opthdr32(CStruct):
    _fields = [("magic", "u16"),
               ("majorlinkerversion", "u08"),
               ("minorlinkerversion", "u08"),
               ("SizeOfCode", "u32"),
               ("sizeofinitializeddata", "u32"),
               ("sizeofuninitializeddata", "u32"),
               ("AddressOfEntryPoint", "u32"),
               ("BaseOfCode", "u32"),
               ("BaseOfData", "u32"),
               ]


class Opthdr64(CStruct):
    _fields = [("magic", "u16"),
               ("majorlinkerversion", "u08"),
               ("minorlinkerversion", "u08"),
               ("SizeOfCode", "u32"),
               ("sizeofinitializeddata", "u32"),
               ("sizeofuninitializeddata", "u32"),
               ("AddressOfEntryPoint", "u32"),
               ("BaseOfCode", "u32"),
               ]


class NThdr(CStruct):
    _fields = [("ImageBase", "ptr"),
               ("sectionalignment", "u32"),
               ("filealignment", "u32"),
               ("majoroperatingsystemversion", "u16"),
               ("minoroperatingsystemversion", "u16"),
               ("MajorImageVersion", "u16"),
               ("MinorImageVersion", "u16"),
               ("majorsubsystemversion", "u16"),
               ("minorsubsystemversion", "u16"),
               ("Reserved1", "u32"),
               ("sizeofimage", "u32"),
               ("sizeofheaders", "u32"),
               ("CheckSum", "u32"),
               ("subsystem", "u16"),
               ("dllcharacteristics", "u16"),
               ("sizeofstackreserve", "ptr"),
               ("sizeofstackcommit", "ptr"),
               ("sizeofheapreserve", "ptr"),
               ("sizeofheapcommit", "ptr"),
               ("loaderflags", "u32"),
               ("numberofrvaandsizes", "u32"),
               ("optentries", "Optehdr", lambda c:get_optehdr_num(c))
               ]


class Shdr(CStruct):
    _fields = [("name", "8s"),
               ("size", "u32"),
               ("addr", "u32"),
               ("rawsize", "u32"),
               ("offset", "u32"),
               ("pointertorelocations", "u32"),
               ("pointertolinenumbers", "u32"),
               ("numberofrelocations", "u16"),
               ("numberoflinenumbers", "u16"),
               ("flags", "u32")]


    def get_data(self):
        parent = self.parent_head
        data = parent.img_rva[self.addr:self.addr + self.size]
        return data

    def set_data(self, data):
        parent = self.parent_head
        parent.img_rva[self.addr] = data


    data = property(get_data, set_data)

class SHList(CStruct):
    _fields = [
        ("shlist", "Shdr", lambda c:c.parent_head.Coffhdr.numberofsections)]

    def add_section(self, name="default", data=b"", **args):
        s_align = self.parent_head.NThdr.sectionalignment
        s_align = max(0x1000, s_align)

        f_align = self.parent_head.NThdr.filealignment
        f_align = max(0x200, f_align)
        size = len(data)
        rawsize = len(data)
        if len(self):
            addr = self[-1].addr + self[-1].size
            s_last = self[0]
            for section in self:
                if s_last.offset + s_last.rawsize < section.offset + section.rawsize:
                    s_last = section
            offset = s_last.offset + s_last.rawsize
        else:
            s_null = bytes(Shdr.unpack(b"\x00" * 0x100))
            offset = self.parent_head.Doshdr.lfanew + len(self.parent_head.NTsig) + len(
                self.parent_head.Coffhdr) + self.parent_head.Coffhdr.sizeofoptionalheader + len(bytes(self.parent_head.SHList) + s_null)
            addr = 0x2000
        # round addr
        addr = (addr + (s_align - 1)) & ~(s_align - 1)
        offset = (offset + (f_align - 1)) & ~(f_align - 1)

        attrs = {"name": name, "size": size,
                 "addr": addr, "rawsize": rawsize,
                 "offset": offset,
                 "pointertorelocations": 0,
                 "pointertolinenumbers": 0,
                 "numberofrelocations": 0,
                 "numberoflinenumbers": 0,
                 "flags": 0xE0000020,
                 "data": data
        }
        attrs.update(args)
        section = Shdr(self.parent_head, _sex=self.parent_head._sex,
                 _wsize=self.parent_head._wsize, **attrs)
        section.data = data

        if section.rawsize > len(data):
            section.data = section.data + b'\x00' * (section.rawsize - len(data))
            section.size = section.rawsize
        section.data = bytes(StrPatchwork(section.data))
        section.size = max(s_align, section.size)

        self.append(section)
        self.parent_head.Coffhdr.numberofsections = len(self)

        length = (section.addr + section.size + (s_align - 1)) & ~(s_align - 1)
        self.parent_head.NThdr.sizeofimage = length
        return section

    def align_sections(self, f_align=None, s_align=None):
        if f_align == None:
            f_align = self.parent_head.NThdr.filealignment
            f_align = max(0x200, f_align)
        if s_align == None:
            s_align = self.parent_head.NThdr.sectionalignment
            s_align = max(0x1000, s_align)

        if self is None:
            return

        addr = self[0].offset
        for section in self:
            raw_off = f_align * ((addr + f_align - 1) // f_align)
            section.offset = raw_off
            section.rawsize = len(section.data)
            addr = raw_off + section.rawsize

    def __repr__(self):
        rep = ["#  section         offset   size   addr     flags   rawsize  "]
        for i, section in enumerate(self):
            name = force_bytes(section.name)
            out = "%-15s" % name.strip(b'\x00').decode()
            out += "%(offset)08x %(size)06x %(addr)08x %(flags)08x %(rawsize)08x" % section
            out = ("%2i " % i) + out
            rep.append(out)
        return "\n".join(rep)

    def __getitem__(self, item):
        return self.shlist[item]

    def __len__(self):
        return len(self.shlist)

    def append(self, section):
        self.shlist.append(section)


class Rva(CStruct):
    _fields = [("rva", "ptr"),
               ]


class Rva32(CStruct):
    _fields = [("rva", "u32"),
               ]


class DescName(CStruct):
    _fields = [("name", (lambda c, raw, off: c.gets(raw, off),
                         lambda c, value: c.sets(value)))
               ]

    def gets(self, raw, off):
        name = raw[off:raw.find(b'\x00', off)]
        return name, off + len(name) + 1

    def sets(self, value):
        return force_bytes(value) + b"\x00"


class ImportByName(CStruct):
    _fields = [("hint", "u16"),
               ("name", "sz")
               ]


class ImpDesc_e(CStruct):
    _fields = [("originalfirstthunk", "u32"),
               ("timestamp", "u32"),
               ("forwarderchain", "u32"),
               ("name", "u32"),
               ("firstthunk", "u32")
               ]


class struct_array(object):

    def __init__(self, target_class, raw, off, cstr, num=None):
        self.l = []
        self.cls = target_class
        self.end = None
        i = 0
        if not raw:
            return

        while (num == None) or (num and i < num):
            entry, length = cstr.unpack_l(raw, off,
                                          target_class.parent_head,
                                          target_class.parent_head._sex,
                                          target_class.parent_head._wsize)
            if num == None:
                if raw[off:off + length] == b'\x00' * length:
                    self.end = b'\x00' * length
                    break
            self.l.append(entry)
            off += length
            i += 1

    def __bytes__(self):
        out = b"".join(bytes(x) for x in self.l)
        if self.end is not None:
            out += self.end
        return out

    def __str__(self):
        if PY3:
            return repr(self)
        return self.__bytes__()

    def __getitem__(self, item):
        return self.l.__getitem__(item)

    def __len__(self):
        return len(self.l)

    def append(self, entry):
        self.l.append(entry)

    def insert(self, index, entry):
        self.l.insert(index, entry)


class DirImport(CStruct):
    _fields = [("impdesc", (lambda c, raw, off:c.gete(raw, off),
                            lambda c, value:c.sete(value)))]

    def gete(self, raw, off):
        if not off:
            return None, off
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000

        ofend = off + \
                self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_IMPORT].size
        out = []
        while off < ofend:
            if not 0 <= off < len(self.parent_head.img_rva):
                break
            imp, length = ImpDesc_e.unpack_l(raw, off)
            if (raw[off:off+length] == b'\x00' * length or
                imp.name == 0):
                # Special case
                break
            if not (imp.originalfirstthunk or imp.firstthunk):
                log.warning("no thunk!!")
                break

            out.append(imp)
            off += length
            imp.dlldescname = DescName.unpack(raw, imp.name, self.parent_head)
            if imp.originalfirstthunk and imp.originalfirstthunk < len(self.parent_head.img_rva):
                imp.originalfirstthunks = struct_array(self, raw,
                                                       imp.originalfirstthunk,
                                                       Rva)
            else:
                imp.originalfirstthunks = None

            if imp.firstthunk and imp.firstthunk  < len(self.parent_head.img_rva):
                imp.firstthunks = struct_array(self, raw,
                                               imp.firstthunk,
                                               Rva)
            else:
                imp.firstthunks = None
            imp.impbynames = []
            if imp.originalfirstthunk and imp.originalfirstthunk < len(self.parent_head.img_rva):
                tmp_thunk = imp.originalfirstthunks
            elif imp.firstthunk:
                tmp_thunk = imp.firstthunks
            for i in range(len(tmp_thunk)):
                if tmp_thunk[i].rva & mask_ptr == 0:
                    try:
                        entry = ImportByName.unpack(raw,
                                                    tmp_thunk[i].rva,
                                                    self.parent_head)
                    except:
                        log.warning(
                            'cannot import from add %s' % tmp_thunk[i].rva
                        )
                        entry = 0
                    imp.impbynames.append(entry)
                else:
                    imp.impbynames.append(tmp_thunk[i].rva & (mask_ptr - 1))
        return out, off

    def sete(self, entries):
        return b"".join(bytes(entry) for entry in entries) + b"\x00" * (4 * 5)

    def __len__(self):
        length = (len(self.impdesc) + 1) * (5 * 4)  # ImpDesc_e size
        rva_size = self.parent_head._wsize // 8
        for entry in self.impdesc:
            length += len(entry.dlldescname)
            if entry.originalfirstthunk and self.parent_head.rva2off(entry.originalfirstthunk):
                length += (len(entry.originalfirstthunks) + 1) * rva_size
            if entry.firstthunk:
                length += (len(entry.firstthunks) + 1) * rva_size
            for imp in entry.impbynames:
                if isinstance(imp, ImportByName):
                    length += len(imp)
        return length

    def set_rva(self, rva, size=None):
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_IMPORT].rva = rva
        rva_size = self.parent_head._wsize // 8
        if not size:
            self.parent_head.NThdr.optentries[
                DIRECTORY_ENTRY_IMPORT].size = len(self)
        else:
            self.parent_head.NThdr.optentries[
                DIRECTORY_ENTRY_IMPORT].size = size
        rva += (len(self.impdesc) + 1) * 5 * 4  # ImpDesc size
        for entry in self.impdesc:
            entry.name = rva
            rva += len(entry.dlldescname)
            if entry.originalfirstthunk:  # and self.parent_head.rva2off(entry.originalfirstthunk):
                entry.originalfirstthunk = rva
                rva += (len(entry.originalfirstthunks) + 1) * rva_size
            # XXX rva fthunk not patched => keep original func addr
            # if entry.firstthunk:
            #    entry.firstthunk = rva
            # rva+=(len(entry.firstthunks)+1)*self.parent_head._wsize//8 # Rva size
            if entry.originalfirstthunk and entry.firstthunk:
                if isinstance(entry.originalfirstthunks, struct_array):
                    tmp_thunk = entry.originalfirstthunks
                elif isinstance(entry.firstthunks, struct_array):
                    tmp_thunk = entry.firstthunks
                else:
                    raise RuntimeError("No thunk!")
            elif entry.originalfirstthunk:  # and self.parent_head.rva2off(entry.originalfirstthunk):
                tmp_thunk = entry.originalfirstthunks
            elif entry.firstthunk:
                tmp_thunk = entry.firstthunks
            else:
                raise RuntimeError("No thunk!")

            if tmp_thunk == entry.originalfirstthunks:
                entry.firstthunks = tmp_thunk
            else:
                entry.originalfirstthunks = tmp_thunk
            for i, imp in enumerate(entry.impbynames):
                if isinstance(imp, ImportByName):
                    tmp_thunk[i].rva = rva
                    rva += len(imp)

    def build_content(self, raw):
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000

        dirimp = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_IMPORT]
        of1 = dirimp.rva
        if not of1:  # No Import
            return
        raw[self.parent_head.rva2off(of1)] = bytes(self)
        for entry in self.impdesc:
            raw[self.parent_head.rva2off(entry.name)] = bytes(entry.dlldescname)
            if (entry.originalfirstthunk and
                self.parent_head.rva2off(entry.originalfirstthunk)):
                # Add thunks list and terminating null entry
                off = self.parent_head.rva2off(entry.originalfirstthunk)
                raw[off] = bytes(entry.originalfirstthunks)
            if entry.firstthunk:
                # Add thunks list and terminating null entry
                off = self.parent_head.rva2off(entry.firstthunk)
                raw[off] = bytes(entry.firstthunks)
            if (entry.originalfirstthunk and
                self.parent_head.rva2off(entry.originalfirstthunk)):
                tmp_thunk = entry.originalfirstthunks
            elif entry.firstthunk:
                tmp_thunk = entry.firstthunks
            else:
                raise RuntimeError("No thunk!")
            for j, imp in enumerate(entry.impbynames):
                if isinstance(imp, ImportByName):
                    raw[self.parent_head.rva2off(tmp_thunk[j].rva)] = bytes(imp)

    def get_dlldesc(self):
        out = []
        for impdesc in self.impdesc:
            dllname = impdesc.dlldescname.name
            funcs = []
            for imp in impdesc.impbynames:
                if isinstance(imp, ImportByName):
                    funcs.append(imp.name)
                else:
                    funcs.append(imp)
            entry = ({"name": dllname, "firstthunk": impdesc.firstthunk}, funcs)
            out.append(entry)
        return out

    def __repr__(self):
        rep = ["<%s>" % self.__class__.__name__]
        for i, entry in enumerate(self.impdesc):
            out = "%2d %-25s %s" % (i, repr(entry.dlldescname), repr(entry))
            rep.append(out)
            for index, imp in enumerate(entry.impbynames):
                out = "    %2d %-16s" % (index, repr(imp))
                rep.append(out)
        return "\n".join(rep)

    def add_dlldesc(self, new_dll):
        rva_size = self.parent_head._wsize // 8
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000
        new_impdesc = []
        of1 = None
        for import_descriptor, new_functions in new_dll:
            if isinstance(import_descriptor.get("name"), str):
                import_descriptor["name"] = import_descriptor["name"].encode()
            new_functions = [
                funcname.encode() if isinstance(funcname, str) else funcname
                for funcname in new_functions
            ]
            for attr in ["timestamp", "forwarderchain", "originalfirstthunk"]:
                if attr not in import_descriptor:
                    import_descriptor[attr] = 0
            entry = ImpDesc_e(self.parent_head, **import_descriptor)
            if entry.firstthunk != None:
                of1 = entry.firstthunk
            elif of1 == None:
                raise RuntimeError("set fthunk")
            else:
                entry.firstthunk = of1
            entry.dlldescname = DescName(self.parent_head, name=entry.name)
            entry.originalfirstthunk = 0
            entry.originalfirstthunks = struct_array(self, None,
                                                     None,
                                                     Rva)
            entry.firstthunks = struct_array(self, None,
                                             None,
                                             Rva)

            impbynames = []
            for new_function in new_functions:
                rva_ofirstt = Rva(self.parent_head)
                if isinstance(new_function, int_types):
                    rva_ofirstt.rva = mask_ptr + new_function
                    ibn = new_function
                elif isinstance(new_function, bytes):
                    rva_ofirstt.rva = True
                    ibn = ImportByName(self.parent_head)
                    ibn.name = new_function
                    ibn.hint = 0
                else:
                    raise RuntimeError('unknown func type %s' % new_function)
                impbynames.append(ibn)
                entry.originalfirstthunks.append(rva_ofirstt)
                rva_func = Rva(self.parent_head)
                if isinstance(ibn, ImportByName):
                    rva_func.rva = 0xDEADBEEF  # default func addr
                else:
                    # ord ?XXX?
                    rva_func.rva = rva_ofirstt.rva
                entry.firstthunks.append(rva_func)
                of1 += rva_size
            # for null thunk
            of1 += rva_size
            entry.impbynames = impbynames
            new_impdesc.append(entry)
        if self.impdesc is None:
            self.impdesc = struct_array(self, None,
                                        None,
                                        ImpDesc_e)
            self.impdesc.l = new_impdesc
        else:
            for entry in new_impdesc:
                self.impdesc.append(entry)

    def get_funcrva(self, dllname, funcname):
        dllname = force_bytes(dllname)
        funcname = force_bytes(funcname)

        rva_size = self.parent_head._wsize // 8
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000 - 1
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000 - 1

        for entry in self.impdesc:
            if entry.dlldescname.name.lower() != dllname.lower():
                continue
            if entry.originalfirstthunk and self.parent_head.rva2off(entry.originalfirstthunk):
                tmp_thunk = entry.originalfirstthunks
            elif entry.firstthunk:
                tmp_thunk = entry.firstthunks
            else:
                raise RuntimeError("No thunk!")
            if isinstance(funcname, bytes):
                for j, imp in enumerate(entry.impbynames):
                    if isinstance(imp, ImportByName):
                        if funcname == imp.name:
                            return entry.firstthunk + j * rva_size
            elif isinstance(funcname, int_types):
                for j, imp in enumerate(entry.impbynames):
                    if not isinstance(imp, ImportByName):
                        if tmp_thunk[j].rva & mask_ptr == funcname:
                            return entry.firstthunk + j * rva_size
            else:
                raise ValueError('Unknown: %s %s' % (dllname, funcname))

    def get_funcvirt(self, dllname, funcname):
        rva = self.get_funcrva(dllname, funcname)
        if rva == None:
            return
        return self.parent_head.rva2virt(rva)


class ExpDesc_e(CStruct):
    _fields = [("characteristics", "u32"),
               ("timestamp", "u32"),
               ("majorv", "u16"),
               ("minorv", "u16"),
               ("name", "u32"),
               ("base", "u32"),
               ("numberoffunctions", "u32"),
               ("numberofnames", "u32"),
               ("addressoffunctions", "u32"),
               ("addressofnames", "u32"),
               ("addressofordinals", "u32"),
               ]


class DirExport(CStruct):
    _fields = [("expdesc", (lambda c, raw, off:c.gete(raw, off),
                            lambda c, value:c.sete(value)))]

    def gete(self, raw, off):
        off_o = off
        if not off:
            return None, off
        off_sav = off
        if off >= len(raw):
            log.warn("export dir malformed!")
            return None, off_o
        expdesc = ExpDesc_e.unpack(raw,
                                   off,
                                   self.parent_head)
        if self.parent_head.rva2off(expdesc.addressoffunctions) == None or \
                self.parent_head.rva2off(expdesc.addressofnames) == None or \
                self.parent_head.rva2off(expdesc.addressofordinals) == None:
            log.warn("export dir malformed!")
            return None, off_o
        self.dlldescname = DescName.unpack(raw, expdesc.name, self.parent_head)
        try:
            self.f_address = struct_array(self, raw,
                                          expdesc.addressoffunctions,
                                          Rva32, expdesc.numberoffunctions)
            self.f_names = struct_array(self, raw,
                                        expdesc.addressofnames,
                                        Rva32, expdesc.numberofnames)
            self.f_nameordinals = struct_array(self, raw,
                                               expdesc.addressofordinals,
                                               Ordinal, expdesc.numberofnames)
        except RuntimeError:
            log.warn("export dir malformed!")
            return None, off_o
        for func in self.f_names:
            func.name = DescName.unpack(raw, func.rva, self.parent_head)
        return expdesc, off_sav

    def sete(self, _):
        return bytes(self.expdesc)

    def build_content(self, raw):
        direxp = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT]
        of1 = direxp.rva
        if self.expdesc is None:  # No Export
            return
        raw[self.parent_head.rva2off(of1)] = bytes(self.expdesc)
        raw[self.parent_head.rva2off(self.expdesc.name)] = bytes(self.dlldescname)
        raw[self.parent_head.rva2off(self.expdesc.addressoffunctions)] = bytes(self.f_address)
        if self.expdesc.addressofnames != 0:
            raw[self.parent_head.rva2off(self.expdesc.addressofnames)] = bytes(self.f_names)
        if self.expdesc.addressofordinals != 0:
            raw[self.parent_head.rva2off(self.expdesc.addressofordinals)] = bytes(self.f_nameordinals)
        for func in self.f_names:
            raw[self.parent_head.rva2off(func.rva)] = bytes(func.name)

        # XXX BUG names must be alphanumeric ordered
        names = [func.name for func in self.f_names]
        names_ = names[:]
        if names != names_:
            log.warn("unsorted export names, may bug")

    def set_rva(self, rva, size=None):
        rva_size = self.parent_head._wsize // 8
        if self.expdesc is None:
            return
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_EXPORT].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[
                DIRECTORY_ENTRY_EXPORT].size = len(self)
        else:
            self.parent_head.NThdr.optentries[
                DIRECTORY_ENTRY_EXPORT].size = size
        rva += len(self.expdesc)
        self.expdesc.name = rva
        rva += len(self.dlldescname)
        self.expdesc.addressoffunctions = rva
        rva += len(self.f_address) * 4
        self.expdesc.addressofnames = rva
        rva += len(self.f_names) * 4
        self.expdesc.addressofordinals = rva
        rva += len(self.f_nameordinals) * 2  # Ordinal size
        for func in self.f_names:
            func.rva = rva
            rva += len(func.name)

    def __len__(self):
        rva_size = self.parent_head._wsize // 8
        length = 0
        if self.expdesc is None:
            return length
        length += len(self.expdesc)
        length += len(self.dlldescname)
        length += len(self.f_address) * 4
        length += len(self.f_names) * 4
        length += len(self.f_nameordinals) * 2  # Ordinal size
        for entry in self.f_names:
            length += len(entry.name)
        return length

    def __repr__(self):
        rep = ["<%s>" % self.__class__.__name__]
        if self.expdesc is None:
            return "\n".join(rep)

        rep = ["<%s %d (%s) %s>" % (self.__class__.__name__,
                                    self.expdesc.numberoffunctions, self.dlldescname, repr(self.expdesc))]
        tmp_names = [[] for _ in range(self.expdesc.numberoffunctions)]
        for i, entry in enumerate(self.f_names):
            tmp_names[self.f_nameordinals[i].ordinal].append(entry.name)
        for i, entry in enumerate(self.f_address):
            tmpn = []
            if not entry.rva:
                continue
            out = "%2d %.8X %s" % (i + self.expdesc.base, entry.rva, repr(tmp_names[i]))
            rep.append(out)
        return "\n".join(rep)

    def create(self, name='default.dll'):
        self.expdesc = ExpDesc_e(self.parent_head)
        for attr in ["characteristics",
                     "timestamp",
                     "majorv",
                     "minorv",
                     "name",
                     "base",
                     "numberoffunctions",
                     "numberofnames",
                     "addressoffunctions",
                     "addressofnames",
                     "addressofordinals",
                     ]:
            setattr(self.expdesc, attr, 0)

        self.dlldescname = DescName(self.parent_head)
        self.dlldescname.name = name
        self.f_address = struct_array(self, None,
                                      None,
                                      Rva32)
        self.f_names = struct_array(self, None,
                                    None,
                                    Rva32)
        self.f_nameordinals = struct_array(self, None,
                                           None,
                                           Ordinal)
        self.expdesc.base = 1

    def add_name(self, name, rva=0xdeadc0fe, ordinal=None):
        if self.expdesc is None:
            return
        names = [func.name.name for func in self.f_names]
        names_s = names[:]
        names_s.sort()
        if names_s != names:
            log.warn('tab names was not sorted may bug')
        names.append(name)
        names.sort()
        index = names.index(name)
        descname = DescName(self.parent_head)

        descname.name = name
        wname = Rva32(self.parent_head)

        wname.name = descname
        woffset = Rva32(self.parent_head)
        woffset.rva = rva
        wordinal = Ordinal(self.parent_head)
        # func is append to list
        if ordinal is None:
            wordinal.ordinal = len(self.f_address)
        else:
            wordinal.ordinal = ordinal

        self.f_address.append(woffset)
        # self.f_names.insert(index, wname)
        # self.f_nameordinals.insert(index, wordinal)
        self.f_names.insert(index, wname)
        self.f_nameordinals.insert(index, wordinal)
        self.expdesc.numberofnames += 1
        self.expdesc.numberoffunctions += 1

    def get_funcrva(self, f_str):
        if self.expdesc is None:
            return None
        for i, entry in enumerate(self.f_names):
            if f_str != entry.name.name:
                continue
            ordinal = self.f_nameordinals[i].ordinal
            rva = self.f_address[ordinal].rva
            return rva
        return None

    def get_funcvirt(self, addr):
        rva = self.get_funcrva(addr)
        if rva == None:
            return
        return self.parent_head.rva2virt(rva)


class Delaydesc_e(CStruct):
    _fields = [("attrs", "u32"),
               ("name", "u32"),
               ("hmod", "u32"),
               ("firstthunk", "u32"),
               ("originalfirstthunk", "u32"),
               ("boundiat", "u32"),
               ("unloadiat", "u32"),
               ("timestamp", "u32"),
               ]


class DirDelay(CStruct):
    _fields = [("delaydesc", (lambda c, raw, off:c.gete(raw, off),
                              lambda c, value:c.sete(value)))]

    def gete(self, raw, off):
        if not off:
            return None, off

        ofend = off + \
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].size
        out = []
        while off < ofend:
            if off >= len(raw):
                log.warn('warning bad reloc offset')
                break

            delaydesc, length = Delaydesc_e.unpack_l(raw,
                                                     off,
                                                     self.parent_head)
            if raw[off:off+length] == b'\x00' * length:
                # Special case
                break
            off += length
            out.append(delaydesc)

        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000

        parent = self.parent_head
        for entry in out:
            isfromva = (entry.attrs & 1) == 0
            if isfromva:
                isfromva = lambda x: parent.virt2rva(x)
            else:
                isfromva = lambda x: x
            entry.dlldescname = DescName.unpack(raw, isfromva(entry.name),
                                                self.parent_head)
            if entry.originalfirstthunk:
                addr = isfromva(entry.originalfirstthunk)
                if not 0 <= addr < len(raw):
                    log.warning("Bad delay")
                    break
                entry.originalfirstthunks = struct_array(self, raw,
                                                         addr,
                                                         Rva)
            else:
                entry.originalfirstthunks = None

            if entry.firstthunk:
                entry.firstthunks = struct_array(self, raw,
                                                 isfromva(entry.firstthunk),
                                                 Rva)
            else:
                entry.firstthunk = None

            entry.impbynames = []
            if entry.originalfirstthunk and self.parent_head.rva2off(isfromva(entry.originalfirstthunk)):
                tmp_thunk = entry.originalfirstthunks
            elif entry.firstthunk:
                tmp_thunk = entry.firstthunks
            else:
                print(ValueError("no thunk in delay dir!! "))
                return
            for i in range(len(tmp_thunk)):
                if tmp_thunk[i].rva & mask_ptr == 0:
                    imp = ImportByName.unpack(raw,
                                              isfromva(tmp_thunk[i].rva),
                                              self.parent_head)
                    entry.impbynames.append(imp)
                else:
                    entry.impbynames.append(
                        isfromva(tmp_thunk[i].rva & (mask_ptr - 1)))
                    # print(repr(entry[-1]))
                    # raise ValueError('XXX to check')
        return out, off

    def sete(self, entries):
        return b"".join(bytes(entry) for entry in entries) + b"\x00" * (4 * 8)  # DelayDesc_e

    def __len__(self):
        rva_size = self.parent_head._wsize // 8
        length = (len(self.delaydesc) + 1) * (4 * 8)  # DelayDesc_e
        for entry in self.delaydesc:
            length += len(entry.dlldescname)
            if entry.originalfirstthunk and self.parent_head.rva2off(entry.originalfirstthunk):
                length += (len(entry.originalfirstthunks) + 1) * rva_size
            if entry.firstthunk:
                length += (len(entry.firstthunks) + 1) * rva_size
            for imp in entry.impbynames:
                if isinstance(imp, ImportByName):
                    length += len(imp)
        return length

    def set_rva(self, rva, size=None):
        rva_size = self.parent_head._wsize // 8
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].size = len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_DELAY_IMPORT].size = size
        rva += (len(self.delaydesc) + 1) * (4 * 8)  # DelayDesc_e
        parent = self.parent_head
        for entry in self.delaydesc:
            isfromva = (entry.attrs & 1) == 0
            if isfromva:
                isfromva = lambda x: self.parent_head.rva2virt(x)
            else:
                isfromva = lambda x: x

            entry.name = isfromva(rva)
            rva += len(entry.dlldescname)
            if entry.originalfirstthunk:  # and self.parent_head.rva2off(entry.originalfirstthunk):
                entry.originalfirstthunk = isfromva(rva)
                rva += (len(entry.originalfirstthunks) + 1) * rva_size
            # XXX rva fthunk not patched => fun addr
            # if entry.firstthunk:
            #    entry.firstthunk = rva
            #    rva+=(len(entry.firstthunks)+1)*pe.Rva._size
            if entry.originalfirstthunk and self.parent_head.rva2off(entry.originalfirstthunk):
                tmp_thunk = entry.originalfirstthunks
            elif entry.firstthunk:
                tmp_thunk = entry.firstthunks
            else:
                raise RuntimeError("No thunk!")
            for i, imp in enumerate(entry.impbynames):
                if isinstance(imp, ImportByName):
                    tmp_thunk[i].rva = isfromva(rva)
                    rva += len(imp)

    def build_content(self, raw):
        if len(self.parent_head.NThdr.optentries) < DIRECTORY_ENTRY_DELAY_IMPORT:
            return
        dirdelay = self.parent_head.NThdr.optentries[
            DIRECTORY_ENTRY_DELAY_IMPORT]
        of1 = dirdelay.rva
        if not of1:  # No Delay Import
            return
        raw[self.parent_head.rva2off(of1)] = bytes(self)
        for entry in self.delaydesc:
            raw[self.parent_head.rva2off(entry.name)] = bytes(entry.dlldescname)
            if entry.originalfirstthunk and self.parent_head.rva2off(entry.originalfirstthunk):
                raw[self.parent_head.rva2off(entry.originalfirstthunk)] = bytes(entry.originalfirstthunks)
            if entry.firstthunk:
                raw[self.parent_head.rva2off(entry.firstthunk)] = bytes(entry.firstthunks)
            if entry.originalfirstthunk and self.parent_head.rva2off(entry.originalfirstthunk):
                tmp_thunk = entry.originalfirstthunks
            elif entry.firstthunk:
                tmp_thunk = entry.firstthunks
            else:
                raise RuntimeError("No thunk!")
            for j, imp in enumerate(entry.impbynames):
                if isinstance(imp, ImportByName):
                    raw[self.parent_head.rva2off(tmp_thunk[j].rva)] = bytes(imp)

    def __repr__(self):
        rep = ["<%s>" % self.__class__.__name__]
        for i, entry in enumerate(self.delaydesc):
            out = "%2d %-25s %s" % (i, repr(entry.dlldescname), repr(entry))
            rep.append(out)
            for index, func in enumerate(entry.impbynames):
                out = "    %2d %-16s" % (index, repr(func))
                rep.append(out)
        return "\n".join(rep)

    def add_dlldesc(self, new_dll):
        if self.parent_head._wsize == 32:
            mask_ptr = 0x80000000
        elif self.parent_head._wsize == 64:
            mask_ptr = 0x8000000000000000
        new_impdesc = []
        of1 = None
        new_delaydesc = []
        for import_descriptor, new_functions in new_dll:
            if isinstance(import_descriptor.get("name"), str):
                import_descriptor["name"] = import_descriptor["name"].encode()
            new_functions = [
                funcname.encode() if isinstance(funcname, str) else funcname
                for funcname in new_functions
            ]
            for attr in ["attrs", "name", "hmod", "firstthunk", "originalfirstthunk", "boundiat", "unloadiat", "timestamp"]:
                if not attr in import_descriptor:
                    import_descriptor[attr] = 0
            entry = Delaydesc_e(self.parent_head, **import_descriptor)
            # entry.cstr.__dict__.update(import_descriptor)
            if entry.firstthunk != None:
                of1 = entry.firstthunk
            elif of1 == None:
                raise RuntimeError("set fthunk")
            else:
                entry.firstthunk = of1
            entry.dlldescname = DescName(self.parent_head, name=entry.name)
            entry.originalfirstthunk = 0
            entry.originalfirstthunks = struct_array(self, None,
                                                     None,
                                                     Rva)
            entry.firstthunks = struct_array(self, None,
                                             None,
                                             Rva)

            impbynames = []
            for new_function in new_functions:
                rva_ofirstt = Rva(self.parent_head)
                if isinstance(new_function, int_types):
                    rva_ofirstt.rva = mask_ptr + new_function
                    ibn = None
                elif isinstance(new_function, bytes):
                    rva_ofirstt.rva = True
                    ibn = ImportByName(self.parent_head)
                    ibn.name = new_function
                    ibn.hint = 0
                else:
                    raise RuntimeError('unknown func type %s' % new_function)
                impbynames.append(ibn)
                entry.originalfirstthunks.append(rva_ofirstt)

                rva_func = Rva(self.parent_head)
                if ibn != None:
                    rva_func.rva = 0xDEADBEEF  # default func addr
                else:
                    # ord ?XXX?
                    rva_func.rva = rva_ofirstt.rva
                entry.firstthunks.append(rva_func)
                of1 += 4
            # for null thunk
            of1 += 4
            entry.impbynames = impbynames
            new_delaydesc.append(entry)
        if self.delaydesc is None:
            self.delaydesc = struct_array(self, None,
                                          None,
                                          Delaydesc_e)
            self.delaydesc.l = new_delaydesc
        else:
            for entry in new_delaydesc:
                self.delaydesc.append(entry)

    def get_funcrva(self, func):
        for entry in self.delaydesc:
            isfromva = (entry.attrs & 1) == 0
            if isfromva:
                isfromva = lambda x: self.parent_head.virt2rva(x)
            else:
                isfromva = lambda x: x
            if entry.originalfirstthunk and self.parent_head.rva2off(isfromva(entry.originalfirstthunk)):
                tmp_thunk = entry.originalfirstthunks
            elif entry.firstthunk:
                tmp_thunk = entry.firstthunks
            else:
                raise RuntimeError("No thunk!")
            if isinstance(func, bytes):
                for j, imp in enumerate(entry.impbynames):
                    if isinstance(imp, ImportByName):
                        if func == imp.name:
                            return isfromva(entry.firstthunk) + j * 4
            elif isinstance(func, int_types):
                for j, imp in enumerate(entry.impbynames):
                    if not isinstance(imp, ImportByName):
                        if isfromva(tmp_thunk[j].rva & 0x7FFFFFFF) == func:
                            return isfromva(entry.firstthunk) + j * 4
            else:
                raise ValueError('unknown func tpye %r' % func)

    def get_funcvirt(self, addr):
        rva = self.get_funcrva(addr)
        if rva == None:
            return
        return self.parent_head.rva2virt(rva)


class Rel(CStruct):
    _fields = [("rva", "u32"),
               ("size", "u32")
               ]


class Reloc(CStruct):
    _fields = [("rel", (lambda c, raw, off:c.gete(raw, off),
                        lambda c, value:c.sete(value)))]

    def gete(self, raw, off):
        rel = struct.unpack('H', raw[off:off + 2])[0]
        return (rel >> 12, rel & 0xfff), off + 2

    def sete(self, value):
        return struct.pack('H', (value[0] << 12) | value[1])

    def __repr__(self):
        return '<%d %d>' % (self.rel[0], self.rel[1])


class DirReloc(CStruct):
    _fields = [("reldesc", (lambda c, raw, off:c.gete(raw, off),
                            lambda c, value:c.sete(value)))]

    def gete(self, raw, off):
        if not off:
            return None, off

        ofend = off + \
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].size
        out = []
        while off < ofend:
            if off >= len(raw):
                log.warn('warning bad reloc offset')
                break
            reldesc, length = Rel.unpack_l(raw,
                                           off,
                                           self.parent_head)
            if reldesc.size == 0:
                log.warn('warning null reldesc')
                reldesc.size = length
                break
            of2 = off + length
            if of2 + reldesc.size > len(self.parent_head.img_rva):
                log.warn('relocation too big, skipping')
                break
            reldesc.rels = struct_array(self, raw,
                                        of2,
                                        Reloc,
                                        (reldesc.size - length) // 2)  # / Reloc size
            reldesc.patchrel = False
            out.append(reldesc)
            off += reldesc.size
        return out, off

    def sete(self, entries):
        return b"".join(
            bytes(entry) + bytes(entry.rels)
            for entry in entries
        )

    def set_rva(self, rva, size=None):
        if self.reldesc is None:
            return
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[
                DIRECTORY_ENTRY_BASERELOC].size = len(self)
        else:
            self.parent_head.NThdr.optentries[
                DIRECTORY_ENTRY_BASERELOC].size = size

    def build_content(self, raw):
        dirrel = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC]
        dirrel.size = len(self)
        of1 = dirrel.rva
        if self.reldesc is None:  # No Reloc
            return
        raw[self.parent_head.rva2off(of1)] = bytes(self)

    def __len__(self):
        if self.reldesc is None:
            return 0
        length = 0
        for entry in self.reldesc:
            length += entry.size
        return length

    def __bytes__(self):
        return b"".join(
            bytes(entry) + bytes(entry.rels)
            for entry in self.reldesc
        )

    def __str__(self):
        if PY3:
            return repr(self)
        return self.__bytes__()

    def __repr__(self):
        rep = ["<%s>" % self.__class__.__name__]
        if self.reldesc is None:
            return "\n".join(rep)
        for i, entry in enumerate(self.reldesc):
            out = "%2d %s" % (i, repr(entry))
            rep.append(out)
            """
            #display too many lines...
            for ii, m in enumerate(entry.rels):
                l = "\t%2d %s"%(ii, repr(m) )
                rep.append(l)
            """
            out = "\t%2d rels..." % (len(entry.rels))
            rep.append(out)
        return "\n".join(rep)

    def add_reloc(self, rels, rtype=3, patchrel=True):
        dirrel = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_BASERELOC]
        if not rels:
            return
        rels.sort()
        all_base_ad = set([x & 0xFFFFF000 for x in rels])
        all_base_ad = list(all_base_ad)
        all_base_ad.sort()
        rels_by_base = defaultdict(list)
        while rels:
            reloc = rels.pop()
            if reloc >= all_base_ad[-1]:
                rels_by_base[all_base_ad[-1]].append(reloc)
            else:
                all_base_ad.pop()
                rels_by_base[all_base_ad[-1]].append(reloc)
        rels_by_base = [x for x in list(rels_by_base.items())]
        rels_by_base.sort()
        for o_init, rels in rels_by_base:
            # o_init = rels[0]&0xFFFFF000
            offsets = struct_array(self, None, None, Reloc, 0)
            for reloc_value in rels:
                if (reloc_value & 0xFFFFF000) != o_init:
                    raise RuntimeError("relocs must be in same range")
                reloc = Reloc(self.parent_head)
                reloc.rel = (rtype, reloc_value - o_init)
                offsets.append(reloc)
            while len(offsets) & 3:
                reloc = Reloc(self.parent_head)
                reloc.rel = (0, 0)
                offsets.append(reloc)
            reldesc = Rel(self.parent_head)  # Reloc(self.parent_head)
            reldesc.rva = o_init
            reldesc.size = (len(offsets) * 2 + 8)
            reldesc.rels = offsets
            reldesc.patchrel = patchrel
            # if self.reldesc is None:
            #    self.reldesc = []
            self.reldesc.append(reldesc)
            dirrel.size += reldesc.size

    def del_reloc(self, taboffset):
        if self.reldesc is None:
            return
        for rel in self.reldesc:
            of1 = rel.rva
            i = 0
            while i < len(rel.rels):
                reloc = rel.rels[i]
                if reloc.rel[0] != 0 and reloc.rel[1] + of1 in taboffset:
                    print('del reloc', hex(reloc.rel[1] + of1))
                    del rel.rels[i]
                    rel.size -= Reloc._size
                else:
                    i += 1


class DirRes(CStruct):
    _fields = [("resdesc", (lambda c, raw, off:c.gete(raw, off),
                            lambda c, value:c.sete(value)))]

    def gete(self, raw, off):
        if not off:
            return None, off
        if off >= len(self.parent_head.img_rva):
            log.warning('cannot parse resources, %X' % off)
            return None, off

        off_orig = off
        ofend = off + self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].size

        resdesc, length = ResDesc_e.unpack_l(raw,
                                             off,
                                             self.parent_head)
        off += length
        nbr = resdesc.numberofnamedentries + resdesc.numberofidentries

        out = []
        tmp_off = off
        resdesc.resentries = struct_array(self, raw,
                                          off,
                                          ResEntry,
                                          nbr)
        dir_todo = {off_orig: resdesc}
        dir_done = {}
        while dir_todo:
            off, my_dir = dir_todo.popitem()
            dir_done[off] = my_dir
            for entry in my_dir.resentries:
                off = entry.offsettosubdir
                if not off:
                    # data dir
                    off = entry.offsettodata
                    if not 0 <= off < len(raw):
                        log.warn('bad resource entry')
                        continue
                    data = ResDataEntry.unpack(raw,
                                               off,
                                               self.parent_head)
                    off = data.offsettodata
                    data.s = StrPatchwork(raw[off:off + data.size])
                    entry.data = data
                    continue
                # subdir
                if off in dir_done:
                    log.warn('warning recusif subdir')
                    continue
                if not 0 <= off < len(self.parent_head.img_rva):
                    log.warn('bad resource entry')
                    continue
                subdir, length = ResDesc_e.unpack_l(raw,
                                                    off,
                                                    self.parent_head)
                nbr = subdir.numberofnamedentries + subdir.numberofidentries
                try:
                    subdir.resentries = struct_array(self, raw,
                                                     off + length,
                                                     ResEntry,
                                                     nbr)
                except RuntimeError:
                    log.warn('bad resource entry')
                    continue

                entry.subdir = subdir
                dir_todo[off] = entry.subdir
        return resdesc, off

    def build_content(self, raw):
        if self.resdesc is None:
            return
        of1 = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva
        raw[self.parent_head.rva2off(of1)] = bytes(self.resdesc)
        length = len(self.resdesc)
        dir_todo = {
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva: self.resdesc
        }
        of1 = of1 + length
        raw[self.parent_head.rva2off(of1)] = bytes(self.resdesc.resentries)
        dir_done = {}
        while dir_todo:
            of1, my_dir = dir_todo.popitem()
            dir_done[of1] = my_dir
            raw[self.parent_head.rva2off(of1)] = bytes(my_dir)
            of1 += len(my_dir)
            raw[self.parent_head.rva2off(of1)] = bytes(my_dir.resentries)
            of_base = of1
            for entry in my_dir.resentries:
                of_base += len(entry)
                if entry.name_s:
                    raw[self.parent_head.rva2off(entry.name)] = bytes(entry.name_s)
                of1 = entry.offsettosubdir
                if not of1:
                    raw[self.parent_head.rva2off(entry.offsettodata)] = bytes(entry.data)
                    raw[self.parent_head.rva2off(entry.data.offsettodata)] = bytes(entry.data.s)
                    continue
                dir_todo[of1] = entry.subdir

    def __len__(self):
        length = 0
        if self.resdesc is None:
            return length
        dir_todo = [self.resdesc]
        dir_done = []
        while dir_todo:
            my_dir = dir_todo.pop()
            if my_dir in dir_done:
                raise ValueError('Recursive directory')
            dir_done.append(my_dir)
            length += len(my_dir)
            length += len(my_dir.resentries) * 8  # ResEntry size
            for entry in my_dir.resentries:
                if not entry.offsettosubdir:
                    continue
                if not entry.subdir in dir_todo:
                    dir_todo.append(entry.subdir)
                else:
                    raise RuntimeError("recursive dir")

        dir_todo = dir_done
        while dir_todo:
            my_dir = dir_todo.pop()
            for entry in my_dir.resentries:
                if entry.name_s:
                    length += len(entry.name_s)
                of1 = entry.offsettosubdir
                if not of1:
                    length += 4 * 4  # WResDataEntry size
                    # XXX because rva may be even rounded
                    length += 1
                    length += entry.data.size
                    continue
        return length

    def set_rva(self, rva, size=None):
        if self.resdesc is None:
            return
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].size = len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].size = size
        dir_todo = [self.resdesc]
        dir_done = {}
        while dir_todo:
            my_dir = dir_todo.pop()
            dir_done[rva] = my_dir
            rva += len(my_dir)
            rva += len(my_dir.resentries) * 8  # ResEntry size
            for entry in my_dir.resentries:
                if not entry.offsettosubdir:
                    continue
                if not entry.subdir in dir_todo:
                    dir_todo.append(entry.subdir)
                else:
                    raise RuntimeError("recursive dir")
        dir_todo = dir_done
        dir_inv = dict([(x[1], x[0]) for x in list(dir_todo.items())])
        while dir_todo:
            rva_tmp, my_dir = dir_todo.popitem()
            for entry in my_dir.resentries:
                if entry.name_s:
                    entry.name = rva
                    rva += len(entry.name_s)
                of1 = entry.offsettosubdir
                if not of1:
                    entry.offsettodata = rva
                    rva += 4 * 4  # ResDataEntry size
                    # XXX menu rsrc must be even aligned?
                    if rva % 2:
                        rva += 1
                    entry.data.offsettodata = rva
                    rva += entry.data.size
                    continue
                entry.offsettosubdir = dir_inv[entry.subdir]

    def __repr__(self):
        rep = ["<%s>" % (self.__class__.__name__)]
        if self.resdesc is None:
            return "\n".join(rep)
        dir_todo = [self.resdesc]
        resources = []
        index = -1
        while dir_todo:
            entry = dir_todo.pop(0)
            if isinstance(entry, int):
                index += entry
            elif isinstance(entry, ResDesc_e):
                # resources.append((index, repr(entry)))
                dir_todo = [1] + entry.resentries.l + [-1] + dir_todo
            elif isinstance(entry, ResEntry):
                if entry.offsettosubdir:
                    resources.append((index, repr(entry)))
                    dir_todo = [entry.subdir] + dir_todo
                else:
                    resources.append((index, repr(entry)))
            else:
                raise RuntimeError("zarb")
        for i, resource in resources:
            rep.append(' ' * 4 * i + resource)
        return "\n".join(rep)


class Ordinal(CStruct):
    _fields = [("ordinal", "u16"),
               ]


class ResDesc_e(CStruct):
    _fields = [("characteristics", "u32"),
               ("timestamp", "u32"),
               ("majorv", "u16"),
               ("minorv", "u16"),
               ("numberofnamedentries", "u16"),
               ("numberofidentries", "u16")
               ]


class SUnicode(CStruct):
    _fields = [("length", "u16"),
               ("value", (lambda c, raw, off:c.gets(raw, off),
                          lambda c, value:c.sets(value)))
               ]

    def gets(self, raw, off):
        value = raw[off:off + self.length * 2]
        return value, off + self.length

    def sets(self, value):
        return self.value


class ResEntry(CStruct):
    _fields = [("name", (lambda c, raw, off:c._get_name(raw, off),
                         lambda c, value:c._set_name(value))),
               ("offsettodata", (lambda c, raw, off:c._get_offset(raw, off),
                                 lambda c, value:c._set_offset(value)))
               ]

    def _get_name(self, raw, off):
        self.data = None
        # off = self.parent_head.rva2off(off)
        name = struct.unpack('I', raw[off:off + 4])[0]
        self.name_s = None
        if name & 0x80000000:
            name = (name & 0x7FFFFFFF) + self.parent_head.NThdr.optentries[
                DIRECTORY_ENTRY_RESOURCE].rva  # XXX res rva??
            name &= 0x7FFFFFFF
            if name >= len(raw):
                raise RuntimeError("Bad resentry")
            self.name_s = SUnicode.unpack(raw,
                                          name,
                                          self.parent_head)
        return name, off + 4

    def _set_name(self, name):
        if self.name_s:
            rva = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva
            name = (self.name - rva) + 0x80000000
        return struct.pack('I', name)

    def _get_offset(self, raw, off):
        self.offsettosubdir = None
        rva = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva
        offsettodata_o = struct.unpack('I', raw[off:off + 4])[0]
        offsettodata = (offsettodata_o & 0x7FFFFFFF) + rva  # XXX res rva??
        if offsettodata_o & 0x80000000:
            self.offsettosubdir = offsettodata
        return offsettodata, off + 4

    def _set_offset(self, offset):
        rva = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_RESOURCE].rva
        offsettodata = offset - rva
        if self.offsettosubdir:
            offsettodata = (self.offsettosubdir - rva) + 0x80000000
        return struct.pack('I', offsettodata)

    def __repr__(self):
        if self.name_s:
            nameid = "%s" % repr(self.name_s)
        else:
            if self.name in RT:  # and not self.offsettosubdir:
                nameid = "ID %s" % RT[self.name]
            else:
                nameid = "ID %d" % self.name
        if self.offsettosubdir:
            offsettodata = "subdir: %x" % self.offsettosubdir
        else:
            offsettodata = "data: %x" % self.offsettodata
        return "<%s %s>" % (nameid, offsettodata)


class ResDataEntry(CStruct):
    _fields = [("offsettodata", "u32"),
               ("size", "u32"),
               ("codepage", "u32"),
               ("reserved", "u32"),
               ]


class Symb(CStruct):
    _fields = [("name", "8s"),
               ("res1", "u32"),
               ("res2", "u32"),
               ("res3", "u16")]


class DirTls(CStruct):
    _fields = [
        ("data_start", "ptr"),
        ("data_end", "ptr"),
        ("addr_index", "ptr"),
        ("callbacks", "ptr"),
        ("size_of_zero", "u32"),
        ("characteristics", "u32")
    ]

    def build_content(self, raw):
        dirtls = self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_TLS]
        of1 = dirtls.rva
        if of1 is None:  # No Tls
            return
        raw[self.parent_head.rva2off(of1)] = bytes(self)

    def set_rva(self, rva, size=None):
        self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_TLS].rva = rva
        if not size:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_TLS].size = len(self)
        else:
            self.parent_head.NThdr.optentries[DIRECTORY_ENTRY_TLS].size = size


DIRECTORY_ENTRY_EXPORT = 0
DIRECTORY_ENTRY_IMPORT = 1
DIRECTORY_ENTRY_RESOURCE = 2
DIRECTORY_ENTRY_EXCEPTION = 3
DIRECTORY_ENTRY_SECURITY = 4
DIRECTORY_ENTRY_BASERELOC = 5
DIRECTORY_ENTRY_DEBUG = 6
DIRECTORY_ENTRY_COPYRIGHT = 7
DIRECTORY_ENTRY_GLOBALPTR = 8
DIRECTORY_ENTRY_TLS = 9
DIRECTORY_ENTRY_LOAD_CONFIG = 10
DIRECTORY_ENTRY_BOUND_IMPORT = 11
DIRECTORY_ENTRY_IAT = 12
DIRECTORY_ENTRY_DELAY_IMPORT = 13
DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
DIRECTORY_ENTRY_RESERVED = 15


RT_CURSOR = 1
RT_BITMAP = 2
RT_ICON = 3
RT_MENU = 4
RT_DIALOG = 5
RT_STRING = 6
RT_FONTDIR = 7
RT_FONT = 8
RT_ACCELERATOR = 9
RT_RCDATA = 10
RT_MESSAGETABLE = 11
RT_GROUP_CURSOR = 12
RT_GROUP_ICON = 14
RT_VERSION = 16
RT_DLGINCLUDE = 17
RT_PLUGPLAY = 19
RT_VXD = 20
RT_ANICURSOR = 21
RT_ANIICON = 22
RT_HTML = 23
RT_MANIFEST = 24


RT = {
    RT_CURSOR: "RT_CURSOR",
    RT_BITMAP: "RT_BITMAP",
    RT_ICON: "RT_ICON",
    RT_MENU: "RT_MENU",
    RT_DIALOG: "RT_DIALOG",
    RT_STRING: "RT_STRING",
    RT_FONTDIR: "RT_FONTDIR",
    RT_FONT: "RT_FONT",
    RT_ACCELERATOR: "RT_ACCELERATOR",
    RT_RCDATA: "RT_RCDATA",
    RT_MESSAGETABLE: "RT_MESSAGETABLE",
    RT_GROUP_CURSOR: "RT_GROUP_CURSOR",
    RT_GROUP_ICON: "RT_GROUP_ICON",
    RT_VERSION: "RT_VERSION",
    RT_DLGINCLUDE: "RT_DLGINCLUDE",
    RT_PLUGPLAY: "RT_PLUGPLAY",
    RT_VXD: "RT_VXD",
    RT_ANICURSOR: "RT_ANICURSOR",
    RT_ANIICON: "RT_ANIICON",
    RT_HTML: "RT_HTML",
    RT_MANIFEST: "RT_MANIFEST",
}
