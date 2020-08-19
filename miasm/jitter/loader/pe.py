from builtins import map
import os
import struct
import logging
from collections import defaultdict

from future.utils import viewitems, viewvalues

from miasm.loader import pe
from miasm.loader import cstruct
from miasm.loader import *

from miasm.jitter.csts import *
from miasm.jitter.loader.utils import canon_libname_libfunc, libimp
from miasm.core.utils import force_str

log = logging.getLogger('loader_pe')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.INFO)


def get_pe_dependencies(pe_obj):
    """Collect the shared libraries upon which this PE depends.
    
    @pe_obj: pe object
    Returns a set of strings of DLL names.
    
    Example:
    
        pe = miasm.analysis.binary.Container.from_string(buf)
        deps = miasm.jitter.loader.pe.get_pe_dependencies(pe.executable)
        assert sorted(deps)[0] == 'api-ms-win-core-appcompat-l1-1-0.dll'
    """

    if pe_obj.DirImport.impdesc is None:
        return set()
    out = set()
    for dependency in pe_obj.DirImport.impdesc:
        libname = dependency.dlldescname.name.lower()
        # transform bytes to str
        libname = force_str(libname)
        out.add(libname)

    # If binary has redirected export, add dependencies
    if pe_obj.DirExport.expdesc != None:
        addrs = get_export_name_addr_list(pe_obj)
        for imp_ord_or_name, ad in addrs:
            # if export is a redirection, search redirected dll
            # and get function real addr
            ret = is_redirected_export(pe_obj, ad)
            if ret is False:
                continue
            dllname, func_info = ret
            dllname = dllname + '.dll'
            out.add(dllname)

    return out


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


def preload_pe(vm, e, runtime_lib, patch_vm_imp=True):
    fa = get_import_address_pe(e)
    dyn_funcs = {}
    # log.debug('imported funcs: %s' % fa)
    for (libname, libfunc), ads in viewitems(fa):
        for ad in ads:
            libname = force_str(libname)
            ad_base_lib = runtime_lib.lib_get_add_base(libname)
            ad_libfunc = runtime_lib.lib_get_add_func(ad_base_lib, libfunc, ad)

            libname_s = canon_libname_libfunc(libname, libfunc)
            dyn_funcs[libname_s] = ad_libfunc
            if patch_vm_imp:
                vm.set_mem(
                    ad, struct.pack(cstruct.size2type[e._wsize], ad_libfunc))
    return dyn_funcs


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


def get_export_name_addr_list(e):
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


def vm_load_pe(vm, fdata, align_s=True, load_hdr=True, name="", winobjs=None, **kargs):
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


def vm_load_pe_lib(vm, fname_in, libs, lib_path_base, **kargs):
    """Call vm_load_pe on @fname_in and update @libs accordingly
    @vm: VmMngr instance
    @fname_in: library name
    @libs: libimp_pe instance
    @lib_path_base: DLLs relative path
    Return the corresponding PE instance
    Extra arguments are passed to vm_load_pe
    """

    log.info('Loading module %r', fname_in)

    fname = os.path.join(lib_path_base, fname_in)
    with open(fname, "rb") as fstream:
        pe = vm_load_pe(vm, fstream.read(), name=fname_in, **kargs)
    libs.add_export_lib(pe, fname_in)
    return pe


def vm_load_pe_libs(vm, libs_name, libs, lib_path_base, **kargs):
    """Call vm_load_pe_lib on each @libs_name filename
    @vm: VmMngr instance
    @libs_name: list of str
    @libs: libimp_pe instance
    @lib_path_base: (optional) DLLs relative path
    Return a dictionary Filename -> PE instances
    Extra arguments are passed to vm_load_pe_lib
    """
    out = {}
    for fname in libs_name:
        assert isinstance(fname, str)
        out[fname] = vm_load_pe_lib(vm, fname, libs, lib_path_base, **kargs)
    return out


def vm_fix_imports_pe_libs(lib_imgs, libs, lib_path_base,
                           patch_vm_imp=True, **kargs):
    for e in viewvalues(lib_imgs):
        preload_pe(e, libs, patch_vm_imp)


def vm2pe(myjit, fname, libs=None, e_orig=None,
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
    if libs:
        if added_funcs is not None:
            for addr, funcaddr in added_funcs:
                libbase, dllname = libs.fad2info[funcaddr]
                libs.lib_get_add_func(libbase, dllname, addr)

        filter_import = kwargs.get(
            'filter_import', lambda _, ad: mye.virt.is_addr_in(ad))
        new_dll = libs.gen_new_lib(mye, filter_import)
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


class libimp_pe(libimp):

    def __init__(self, *args, **kwargs):
        super(libimp_pe, self).__init__(*args, **kwargs)
        # dependency -> redirector
        self.created_redirected_imports = {}


    def add_function(self, dllname, imp_ord_or_name, addr):
        assert isinstance(dllname, str)
        assert isinstance(imp_ord_or_name, (int, str))
        libad = self.name2off[dllname]
        c_name = canon_libname_libfunc(
            dllname, imp_ord_or_name
        )
        update_entry = True
        if addr in self.fad2info:
            known_libad, known_imp_ord_or_name = self.fad2info[addr]
            if isinstance(imp_ord_or_name, int):
                update_entry = False
        self.cname2addr[c_name] = addr
        log.debug("Add func %s %s", hex(addr), c_name)
        if update_entry:
            log.debug("Real Add func %s %s", hex(addr), c_name)
            self.fad2cname[addr] = c_name
            self.fad2info[addr] = libad, imp_ord_or_name


    def add_export_lib(self, e, name):
        if name in self.created_redirected_imports:
            log.error("%r has previously been created due to redirect\
            imports due to %r. Change the loading order.",
                      name, self.created_redirected_imports[name])
            raise RuntimeError('Bad import: loading previously created import')

        self.all_exported_lib.append(e)
        # will add real lib addresses to database
        if name in self.name2off:
            ad = self.name2off[name]
            if e is not None and name in self.fake_libs:
                log.error(
                    "You are trying to load %r but it has been faked previously. Try loading this module earlier.", name)
                raise RuntimeError("Bad import")
        else:
            log.debug('new lib %s', name)
            ad = e.NThdr.ImageBase
            libad = ad
            self.name2off[name] = ad
            self.libbase2lastad[ad] = ad + 0x1
            self.lib_imp2ad[ad] = {}
            self.lib_imp2dstad[ad] = {}
            self.libbase_ad += 0x1000

            ads = get_export_name_addr_list(e)
            todo = list(ads)
            # done = []
            while todo:
                # for imp_ord_or_name, ad in ads:
                imp_ord_or_name, ad = todo.pop()

                # if export is a redirection, search redirected dll
                # and get function real addr
                ret = is_redirected_export(e, ad)
                if ret:
                    exp_dname, exp_fname = ret
                    exp_dname = exp_dname + '.dll'
                    exp_dname = exp_dname.lower()
                    # if dll auto refes in redirection
                    if exp_dname == name:
                        libad_tmp = self.name2off[exp_dname]
                        if isinstance(exp_fname, str):
                            exp_fname = bytes(ord(c) for c in exp_fname)
                        found = None
                        for tmp_func, tmp_addr in ads:
                            if tmp_func == exp_fname:
                                found = tmp_addr
                        assert found is not None
                        ad = found
                    else:
                        # import redirected lib from non loaded dll
                        if not exp_dname in self.name2off:
                            self.created_redirected_imports.setdefault(
                                exp_dname, set()).add(name)

                        # Ensure import entry is created
                        new_lib_base = self.lib_get_add_base(exp_dname)
                        # Ensure function entry is created
                        _ = self.lib_get_add_func(new_lib_base, exp_fname)

                        libad_tmp = self.name2off[exp_dname]
                        ad = self.lib_imp2ad[libad_tmp][exp_fname]

                self.lib_imp2ad[libad][imp_ord_or_name] = ad
                name_inv = dict(
                    (value, key) for key, value in viewitems(self.name2off)
                )
                c_name = canon_libname_libfunc(
                    name_inv[libad], imp_ord_or_name)
                self.fad2cname[ad] = c_name
                self.cname2addr[c_name] = ad
                log.debug("Add func %s %s", hex(ad), c_name)
                self.fad2info[ad] = libad, imp_ord_or_name

    def gen_new_lib(self, target_pe, filter_import=lambda peobj, ad: True, **kwargs):
        """Gen a new DirImport description
        @target_pe: PE instance
        @filter_import: (boolean f(pe, address)) restrict addresses to keep
        """

        new_lib = []
        for lib_name, ad in viewitems(self.name2off):
            # Build an IMAGE_IMPORT_DESCRIPTOR

            # Get fixed addresses
            out_ads = dict()  # addr -> func_name
            for func_name, dst_addresses in viewitems(self.lib_imp2dstad[ad]):
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
                    new_lib.append(({"name": lib_name,
                                     "firstthunk": rva},
                                    funcs)
                                   )

                # Update elements to handle
                all_ads = all_ads[i + 1:]

        return new_lib


def vm_load_pe_and_dependencies(vm, fname, name2module, runtime_lib,
                                lib_path_base, **kwargs):
    """Load a binary and all its dependencies. Returns a dictionary containing
    the association between binaries names and it's pe object

    @vm: virtual memory manager instance
    @fname: full path of the binary
    @name2module: dict containing association between name and pe
    object. Updated.
    @runtime_lib: libimp instance
    @lib_path_base: directory of the libraries containing dependencies

    """

    todo = [(fname, fname, 0)]
    weight2name = {}
    done = set()

    # Walk dependencies recursively
    while todo:
        name, fname, weight = todo.pop()
        if name in done:
            continue
        done.add(name)
        weight2name.setdefault(weight, set()).add(name)
        if name in name2module:
            pe_obj = name2module[name]
        else:
            try:
                with open(fname, "rb") as fstream:
                    log.info('Loading module name %r', fname)
                    pe_obj = vm_load_pe(
                        vm, fstream.read(), name=fname, **kwargs)
            except IOError:
                log.error('Cannot open %s' % fname)
                name2module[name] = None
                continue
            name2module[name] = pe_obj

        new_dependencies = get_pe_dependencies(pe_obj)
        todo += [(name, os.path.join(lib_path_base, name), weight - 1)
                 for name in new_dependencies]

    known_export_addresses = {}
    to_resolve = {}
    for name, pe_obj in name2module.items():
        print(name)
        if pe_obj is None:
            continue
        if pe_obj.DirExport.expdesc == None:
            continue
        addrs = get_export_name_addr_list(pe_obj)
        for imp_ord_or_name, ad in addrs:
            # if export is a redirection, search redirected dll
            # and get function real addr
            ret = is_redirected_export(pe_obj, ad)
            if ret is False:
                known_export_addresses[(name, imp_ord_or_name)] = ad
            else:
                dllname, func_info = ret
                dllname = dllname + '.dll'
                to_resolve[(name, imp_ord_or_name)] = (dllname, func_info)

    modified = True
    while modified:
        modified = False
        out = {}
        for target, dependency in to_resolve.items():
            dllname, funcname = dependency
            if dependency in known_export_addresses:
                known_export_addresses[target] = known_export_addresses[dependency]
                modified = True
            else:
                log.error("Cannot resolve redirection %r %r", dllname, dependency)
                raise RuntimeError('Cannot resolve redirection')
        to_resolve = out

    for dllname, pe_obj in name2module.items():
        if pe_obj is None:
            continue
        ad = pe_obj.NThdr.ImageBase
        libad = ad
        runtime_lib.name2off[dllname] = ad
        runtime_lib.libbase2lastad[ad] = ad + 0x1
        runtime_lib.lib_imp2ad[ad] = {}
        runtime_lib.lib_imp2dstad[ad] = {}
        runtime_lib.libbase_ad += 0x1000

    for (dllname, imp_ord_or_name), addr in known_export_addresses.items():
        runtime_lib.add_function(dllname, imp_ord_or_name, addr)
        libad = runtime_lib.name2off[dllname]
        runtime_lib.lib_imp2ad[libad][imp_ord_or_name] = addr

    assert not to_resolve

    for dllname, pe_obj in name2module.items():
        if pe_obj is None:
            continue
        preload_pe(vm, pe_obj, runtime_lib, patch_vm_imp=True)

    return name2module

# machine -> arch
PE_machine = {
    0x14c: "x86_32",
    0x8664: "x86_64",
}


def guess_arch(pe):
    """Return the architecture specified by the PE container @pe.
    If unknown, return None"""
    return PE_machine.get(pe.Coffhdr.machine, None)
