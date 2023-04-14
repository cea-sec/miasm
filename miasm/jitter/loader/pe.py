from builtins import map
import os
import re
import struct
import json
import logging
import warnings
from collections import defaultdict

from future.utils import viewitems, viewvalues

from miasm.loader import pe
from miasm.loader import cstruct
from miasm.loader import *

from miasm.jitter.csts import *
from miasm.jitter.loader.utils import canon_libname_libfunc, Loader
from miasm.core.utils import force_str

log = logging.getLogger('loader_pe')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.INFO)

match_hyphen_digit = re.compile(".*-[\d]+-[\d]+$")


def get_import_address_pe(e):
    """Compute the addresses of imported symbols.
    @e: pe object
    Returns a dict mapping from tuple (dll name string, symbol name string) to set of virtual addresses.

    Example:

        pe = miasm.analysis.binary.Container.from_string(buf)
        imports = miasm.jitter.loader.pe.get_import_address_pe(pe.executable)
        assert imports[('api-ms-win-core-rtlsupport-l1-1-0.dll', 'RtlCaptureStackBackTrace')] == {0x6b88a6d0}
    """
    import2addr = defaultdict(set)
    if e.DirImport.impdesc is None:
        return import2addr
    for s in e.DirImport.impdesc:
        # fthunk = e.rva2virt(s.firstthunk)
        # l = "%2d %-25s %s" % (i, repr(s.dlldescname), repr(s))
        libname = force_str(s.dlldescname.name.lower())

        for ii, imp in enumerate(s.impbynames):
            if isinstance(imp, pe.ImportByName):
                funcname = force_str(imp.name)
            else:
                funcname = imp
            # l = "    %2d %-16s" % (ii, repr(funcname))
            import2addr[(libname, funcname)].add(
                e.rva2virt(s.firstthunk + (e._wsize * ii) // 8)
            )
    return import2addr


def is_redirected_export(pe_obj, addr):
    """Test if the @addr is a forwarded export address. If so, return
    dllname/function name couple. If not, return False.

    An export address is a forwarded export if the rva is in the export
    directory of the pe.

    @pe_obj: PE instance
    @addr: virtual address of the function to test
    """

    export_dir = pe_obj.NThdr.optentries[pe.DIRECTORY_ENTRY_EXPORT]
    addr_rva = pe_obj.virt2rva(addr)
    if not (export_dir.rva <= addr_rva < export_dir.rva + export_dir.size):
        return False
    addr_end = pe_obj.virt.find(b'\x00', addr)
    data = pe_obj.virt.get(addr, addr_end)

    data = force_str(data)
    dllname, func_info = data.split('.', 1)
    dllname = dllname.lower()

    # Test if function is forwarded using ordinal
    if func_info.startswith('#'):
        func_info = int(func_info[1:])
    return dllname, func_info


def get_export_name_addr_list(e, parent=None):
    """Collect names/ordinals and addresses of symbols exported by the given PE.
    @e: PE instance
    Returns a list of tuples:
        (symbol name string, virtual address)
        (ordinal number, virtual address)

    Example:

        pe = miasm.analysis.binary.Container.from_string(buf)
        exports = miasm.jitter.loader.pe.get_export_name_addr_list(pe.executable)
        assert exports[0] == ('AcquireSRWLockExclusive', 0x6b89b22a)
    """
    out = []
    if e.DirExport.expdesc is None:
        return out

    # add func name
    for i, n in enumerate(e.DirExport.f_names):
        addr = e.DirExport.f_address[e.DirExport.f_nameordinals[i].ordinal]
        f_name = force_str(n.name.name)
        # log.debug('%s %s' % (f_name, hex(e.rva2virt(addr.rva))))
        out.append((f_name, e.rva2virt(addr.rva)))

    # add func ordinal
    for i, s in enumerate(e.DirExport.f_address):
        if not s.rva:
            continue
        out.append((i + e.DirExport.expdesc.base, e.rva2virt(s.rva)))

    return out


def vm_load_pe(vm, fdata, align_s=True, load_hdr=True, name="", winobjs=None, base_addr=None, **kargs):
    """Load a PE in memory (@vm) from a data buffer @fdata
    @vm: VmMngr instance
    @fdata: data buffer to parse
    @align_s: (optional) If False, keep gaps between section
    @load_hdr: (optional) If False, do not load the NThdr in memory
    Return the corresponding PE instance.

    Extra arguments are passed to PE instantiation.
    If all sections are aligned, they will be mapped on several different pages
    Otherwise, a big page is created, containing all sections
    """

    # Parse and build a PE instance
    pe = pe_init.PE(fdata, **kargs)

    # Optionally rebase PE
    if base_addr is not None:
        pe.reloc_to(base_addr)

    # Check if all section are aligned
    aligned = True
    for section in pe.SHList:
        if section.addr & 0xFFF:
            aligned = False
            break

    if aligned:
        # Loader NT header
        if load_hdr:
            # Header length
            hdr_len = max(0x200, pe.NThdr.sizeofheaders)
            # Page minimum size
            min_len = min(pe.SHList[0].addr, 0x1000)

            # Get and pad the pe_hdr
            pe_hdr = (
                pe.content[:hdr_len] +
                max(0, (min_len - hdr_len)) * b"\x00"
            )

            if winobjs:
                winobjs.allocated_pages[pe.NThdr.ImageBase] = (pe.NThdr.ImageBase, len(pe_hdr))
            vm.add_memory_page(
                pe.NThdr.ImageBase,
                PAGE_READ | PAGE_WRITE,
                pe_hdr,
                "%r: PE Header" % name
            )

        # Align sections size
        if align_s:
            # Use the next section address to compute the new size
            for i, section in enumerate(pe.SHList[:-1]):
                new_size = pe.SHList[i + 1].addr - section.addr
                section.size = new_size
                section.rawsize = new_size
                section.data = strpatchwork.StrPatchwork(
                    section.data[:new_size]
                )
                section.offset = section.addr

            # Last section alignment
            last_section = pe.SHList[-1]
            last_section.size = (last_section.size + 0xfff) & 0xfffff000

        # Pad sections with null bytes and map them
        for section in pe.SHList:
            data = bytes(section.data)
            data += b"\x00" * (section.size - len(data))
            attrib = PAGE_READ
            if section.flags & 0x80000000:
                attrib |= PAGE_WRITE

            section_addr = pe.rva2virt(section.addr)
            if winobjs:
                winobjs.allocated_pages[section_addr] = (section_addr, len(data))
            vm.add_memory_page(
                section_addr,
                attrib,
                data,
                "%r: %r" % (name, section.name)
            )

        return pe

    # At least one section is not aligned
    log.warning('PE is not aligned, creating big section')
    min_addr = 0 if load_hdr else None
    max_addr = None
    data = ""

    for i, section in enumerate(pe.SHList):
        if i < len(pe.SHList) - 1:
            # If it is not the last section, use next section address
            section.size = pe.SHList[i + 1].addr - section.addr
        section.rawsize = section.size
        section.offset = section.addr

        # Update min and max addresses
        if min_addr is None or section.addr < min_addr:
            min_addr = section.addr
        max_section_len = max(section.size, len(section.data))
        if max_addr is None or section.addr + max_section_len > max_addr:
            max_addr = section.addr + max_section_len

    min_addr = pe.rva2virt(min_addr)
    max_addr = pe.rva2virt(max_addr)
    log.debug('Min: 0x%x, Max: 0x%x, Size: 0x%x', min_addr, max_addr,
              (max_addr - min_addr))

    # Create only one big section containing the whole PE
    vm.add_memory_page(
        min_addr,
        PAGE_READ | PAGE_WRITE,
        (max_addr - min_addr) * b"\x00"
    )

    # Copy each sections content in memory
    for section in pe.SHList:
        log.debug('Map 0x%x bytes to 0x%x', len(section.data),
                  pe.rva2virt(section.addr))
        vm.set_mem(pe.rva2virt(section.addr), bytes(section.data))

    return pe


def vm2pe(myjit, fname, loader=None, e_orig=None,
          min_addr=None, max_addr=None,
          min_section_offset=0x1000, img_base=None,
          added_funcs=None, **kwargs):
    if e_orig:
        size = e_orig._wsize
    else:
        size = 32
    mye = pe_init.PE(wsize=size)

    if min_addr is None and e_orig is not None:
        min_addr = min([e_orig.rva2virt(s.addr) for s in e_orig.SHList])
    if max_addr is None and e_orig is not None:
        max_addr = max([e_orig.rva2virt(s.addr + s.size)
                       for s in e_orig.SHList])

    if img_base is None:
        img_base = e_orig.NThdr.ImageBase

    mye.NThdr.ImageBase = img_base
    all_mem = myjit.vm.get_all_memory()
    addrs = list(all_mem)
    addrs.sort()
    entry_point = mye.virt2rva(myjit.pc)
    if entry_point is None or not 0 < entry_point < 0xFFFFFFFF:
        raise ValueError(
            "Current pc (0x%x) used as entry point seems to be out of the binary" %
            myjit.pc
        )

    mye.Opthdr.AddressOfEntryPoint = entry_point
    first = True
    for ad in addrs:
        if not min_addr <= ad < max_addr:
            continue
        log.debug("0x%x", ad)
        if first:
            mye.SHList.add_section(
                "%.8X" % ad,
                addr=ad - mye.NThdr.ImageBase,
                data=all_mem[ad]['data'],
                offset=min_section_offset)
        else:
            mye.SHList.add_section(
                "%.8X" % ad,
                addr=ad - mye.NThdr.ImageBase,
                data=all_mem[ad]['data'])
        first = False
    if loader:
        filter_import = kwargs.get(
            'filter_import', lambda _, ad: mye.virt.is_addr_in(ad))
        new_dll = loader.gen_new_lib(mye, filter_import)
    else:
        new_dll = {}

    log.debug('%s', new_dll)

    mye.DirImport.add_dlldesc(new_dll)
    s_imp = mye.SHList.add_section("import", rawsize=len(mye.DirImport))
    mye.DirImport.set_rva(s_imp.addr)
    log.debug('%r', mye.SHList)
    if e_orig:
        # resource
        xx = bytes(mye)
        mye.content = xx
        ad = e_orig.NThdr.optentries[pe.DIRECTORY_ENTRY_RESOURCE].rva
        size = e_orig.NThdr.optentries[pe.DIRECTORY_ENTRY_RESOURCE].size
        log.debug('dirres 0x%x', ad)
        if ad != 0:
            mye.NThdr.optentries[pe.DIRECTORY_ENTRY_RESOURCE].rva = ad
            mye.NThdr.optentries[pe.DIRECTORY_ENTRY_RESOURCE].size = size
            mye.DirRes = pe.DirRes.unpack(mye.img_rva, ad, mye)
            log.debug('%r', mye.DirRes)
            s_res = mye.SHList.add_section(
                name="myres",
                rawsize=len(mye.DirRes)
            )
            mye.DirRes.set_rva(s_res.addr)
    # generation
    open(fname, 'wb').write(bytes(mye))
    return mye


class LoaderWindows(Loader):

    def __init__(self, vm, apiset=None, loader_start_address=None, fake_dll_load=False, *args, **kwargs):
        super(LoaderWindows, self).__init__(vm, *args, **kwargs)
        self.library_path = ["win_dll", "./"]
        # dependency -> redirector
        self.created_redirected_imports = {}
        self.module_name_to_module = {}
        self.apiset = apiset
        self.loader_start_address = loader_start_address
        self.fake_dll_load = fake_dll_load

    def lib_get_add_base(self, name):
        name = name.lower().strip(' ')
        if not "." in name:
            log.warning('warning adding .dll to modulename')
            name += '.dll'
            log.warning(name)

        if name in self.module_name_to_base_address:
            ad = self.module_name_to_base_address[name]
        else:
            ad = self.fake_library_entry(name)
        return ad


    def gen_new_lib(self, target_pe, filter_import=lambda peobj, ad: True, **kwargs):
        """Gen a new DirImport description
        @target_pe: PE instance
        @filter_import: (boolean f(pe, address)) restrict addresses to keep
        """

        new_lib = []
        module_to_dsts = {}
        for canonical_name, dsts in self.canonical_name_to_dst_addr.items():
            address  = self.function_canonical_name_to_address[canonical_name]
            module_name, imp_ord_or_name = self.function_address_to_info[address]
            if module_name not in module_to_dsts:
                module_to_dsts[module_name] = {}
            module_to_dsts[module_name].setdefault(imp_ord_or_name, set()).update(dsts)
        #for lib_name, ad in viewitems(self.module_name_to_base_address):
        for module_name, info_dsts in module_to_dsts.items():
            # Build an IMAGE_IMPORT_DESCRIPTOR

            # Get fixed addresses
            out_ads = dict()  # addr -> func_name
            """
            if ad not in self.lib_imp2dstad:
                continue
            """
            for func_name, dst_addresses in info_dsts.items():
                out_ads.update({addr: func_name for addr in dst_addresses})

            # Filter available addresses according to @filter_import
            all_ads = [
                addr for addr in list(out_ads) if filter_import(target_pe, addr)
            ]

            if not all_ads:
                continue

            # Keep non-NULL elements
            all_ads.sort(key=str)
            for i, x in enumerate(all_ads):
                if x not in [0,  None]:
                    break
            all_ads = all_ads[i:]
            log.debug('ads: %s', list(map(hex, all_ads)))

            while all_ads:
                # Find libname's Import Address Table
                othunk = all_ads[0]
                i = 0
                while (i + 1 < len(all_ads) and
                       all_ads[i] + target_pe._wsize // 8 == all_ads[i + 1]):
                    i += 1
                # 'i + 1' is IAT's length

                # Effectively build an IMAGE_IMPORT_DESCRIPTOR
                funcs = [out_ads[addr] for addr in all_ads[:i + 1]]
                try:
                    rva = target_pe.virt2rva(othunk)
                except pe.InvalidOffset:
                    pass
                else:
                    new_lib.append(({"name": module_name,
                                     "firstthunk": rva},
                                    funcs)
                                   )

                # Update elements to handle
                all_ads = all_ads[i + 1:]

        return new_lib

    def vm_load_pe(self, fdata, align_s=True, load_hdr=True, name="", winobjs=None, **kargs):
        pe = vm_load_pe(
            self.vm, fdata,
            align_s=align_s,
            load_hdr=load_hdr,
            name=name, winobjs=winobjs,
            base_addr=self.loader_start_address,
            **kargs
        )
        if self.loader_start_address:
            self.loader_start_address += pe.NThdr.sizeofimage + 0x1000
        return pe

    def find_module_path(self, module_name):
        """
        Find the real path of module_name
        """
        module_name = module_name.lower()
        if self.fake_dll_load:
            self.fake_library_entry(module_name)
            return None
        for path in self.library_path:
            fname = os.path.join(path, module_name)
            if os.access(fname, os.R_OK):
                return fname
        if module_name in self.unresolved_modules_names:
            return None
        self.fake_library_entry(module_name)
        return None


    def resolve_function(self, module_name, imp_ord_or_name, parent=None, dst_ad=None):
        """
        Resolve the function named @imp_ord_or_name of the module @module_name
        Optionally use @parent for ApiSet resolution
        Use @dst_ad to hint the destination address of the function
        """
        if self.apiset:
            # First, try to resolve ApiSet
            module_name = self.apiset.get_redirection(module_name, parent)

        if module_name in self.unresolved_modules_names:
            module_base_addr = self.module_name_to_base_address[module_name]
            addr = self.fake_resolve_function(module_base_addr, imp_ord_or_name, dst_ad=dst_ad)
            self.add_function(module_name, imp_ord_or_name, addr, dst_ad=dst_ad)
            return addr

        if module_name not in self.module_name_to_module:
            raise RuntimeError("Module %r not found" % module_name)
        pe = self.module_name_to_module[module_name]
        export = self.module_name_to_export[module_name]
        addr = export.get(imp_ord_or_name, None)
        if addr is None:
            raise RuntimeError("Function %r not found in %r" %( imp_ord_or_name, module_name))
        ret = is_redirected_export(pe, addr)
        if ret is False:
            self.add_function(module_name, imp_ord_or_name, addr, dst_ad=dst_ad)
            return addr

        module_target, func_info = ret
        log.debug(
            "Function %r %r redirected to %r %r",
            module_name, imp_ord_or_name,
            module_target, func_info
        )


        module_target += '.dll'

        # First, try to resolve ApiSet
        if self.apiset:
            module_target = self.apiset.get_redirection(module_target, module_name)

        self.load_module(module_target)
        addr = self.resolve_function(module_target, func_info, module_name, dst_ad=dst_ad)
        self.add_function(module_target, imp_ord_or_name, addr, dst_ad=dst_ad)
        return addr

    def load_module(self, name):
        """
        Resolve the path of @name and load module and it's dependencies

        Return image base address of the module

        """
        name = name.lower()
        fname = self.find_module_path(name)
        return self.load_resolved_module(name, fname)

    def load_resolved_module(self, name, fname):
        """
        Load module @name using its @fname path and it's dependencies
        Return image base address of the module
        """
        if name in self.unresolved_modules_names:
            return self.module_name_to_base_address[name]
        if fname is None:
            raise RuntimeError("Cannot find module %r" % fname)

        module_address = self.module_name_to_base_address.get(name, None)
        if module_address is not None:
            # Module is already loaded
            return module_address
        #log.info("load module %r %r", name, fname)
        try:
            with open(fname, "rb") as fstream:
                log.info('Loading module name %r', fname)
                pe = self.vm_load_pe(
                    fstream.read(), name=fname
                )
        except IOError:
            raise RuntimeError('Cannot open module %s' % fname)

        image_base = pe.NThdr.ImageBase
        self.module_name_to_module[name] = pe
        exports = get_export_name_addr_list(pe)
        self.module_name_to_export[name] = dict(exports)
        self.module_name_to_base_address[name] = pe.NThdr.ImageBase
        self.module_base_address_to_name[pe.NThdr.ImageBase] = name

        # Resolve imports
        if pe.DirImport.impdesc is None:
            # No imports
            return image_base
        out = set()
        for dependency in pe.DirImport.impdesc:
            libname = dependency.dlldescname.name.lower()
            libname = force_str(libname)
            if self.apiset:
                # Resolve ApiSet
                libname = self.apiset.get_redirection(libname, name)
            self.load_module(libname)

        # Fix imports
        import_information = get_import_address_pe(pe)
        dyn_funcs = {}
        # log.debug('imported funcs: %s' % import_information)
        for (libname, funcname), ads in import_information.items():
            addr_resolved = self.resolve_function(libname, funcname, name)
            addr_bytes = struct.pack(cstruct.size2type[pe._wsize], addr_resolved)
            for addr in ads:
                self.vm.set_mem(addr, addr_bytes)
        return image_base


class limbimp_pe(LoaderWindows):
    def __init__(self, *args, **kwargs):
        raise DeprecationWarning("DEPRECATION WARNING: Use LoaderWindows instead of limimb_pe")


# machine -> arch
PE_machine = {
    0x14c: "x86_32",
    0x8664: "x86_64",
}


def guess_arch(pe):
    """Return the architecture specified by the PE container @pe.
    If unknown, return None"""
    return PE_machine.get(pe.Coffhdr.machine, None)


class ApiSet(object):
    def __init__(self, fname):
        data = json.load(open(fname))
        self.version = data['version']
        self.hash_entries = data['hashes']

    def compute_hash(self, apiset_lib_name):
        """
        Hash func can be found in ntdll!ApiSetpSearchForApiSet
        """
        hashk = 0
        for c in apiset_lib_name:
            hashk = (hashk * self.hash_factor + ord(c)) & ((1 << 32) - 1)
        return hashk

    def get_redirected_host(self, libname, entries, parent):
        #log.info("\tlibname %r %r", parent, libname)
        if len(entries) == 1:
            assert "" in entries
            log.debug("ApiSet %s => %s" % (libname, entries[""]))
            libname = entries[""]
        else:
            if parent in entries:
                libname = entries[parent]
            else:
                libname = entries[""]
        return libname

    def get_redirection(self, libname, parent_name):
        has_dll = libname.endswith(".dll")
        if has_dll:
            name_nodll = libname[:-4]
        else:
            name_nodll = libname

        # Remove last hyphen part to compute crc
        if match_hyphen_digit.match(name_nodll):
            cname = name_nodll[:name_nodll.rfind('-')]
        else:
            cname = name_nodll
        #log.info("\t cname %r", cname)
        values = self.hash_entries.get(
            cname,
            self.hash_entries.get(
                cname+"-1", None
            )
        )
        if not values:
            # No entry found
            return libname
        libname = self.get_redirected_host(cname, values, parent_name)
        if has_dll and not libname.endswith('.dll'):
            libname += ".dll"
        elif not has_dll and libname.endswith('.dll'):
            libname = libname[:-4]
        return libname
