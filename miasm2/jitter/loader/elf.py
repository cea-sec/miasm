import struct
from collections import defaultdict

from elfesteem import cstruct
from elfesteem import *
from miasm2.jitter.csts import *
from miasm2.jitter.loader.utils import canon_libname_libfunc, libimp
from miasm2.core.interval import interval

import logging

log = logging.getLogger('loader_elf')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

def get_import_address_elf(e):
    import2addr = defaultdict(set)
    for sh in e.sh:
        if not hasattr(sh, 'rel'):
            continue
        for k, v in sh.rel.items():
            import2addr[('xxx', k)].add(v.offset)
    return import2addr


def preload_elf(vm, e, runtime_lib, patch_vm_imp=True):
    # XXX quick hack
    fa = get_import_address_elf(e)
    dyn_funcs = {}
    # log.debug('imported funcs: %s' % fa)
    for (libname, libfunc), ads in fa.items():
        for ad in ads:
            ad_base_lib = runtime_lib.lib_get_add_base(libname)
            ad_libfunc = runtime_lib.lib_get_add_func(ad_base_lib, libfunc, ad)

            libname_s = canon_libname_libfunc(libname, libfunc)
            dyn_funcs[libname_s] = ad_libfunc
            if patch_vm_imp:
                log.debug('patch %s %s %s' %
                          (hex(ad), hex(ad_libfunc), libfunc))
                vm.set_mem(
                    ad, struct.pack(cstruct.size2type[e.size], ad_libfunc))
    return runtime_lib, dyn_funcs



def vm_load_elf(vm, fdata, **kargs):
    """
    Very dirty elf loader
    TODO XXX: implement real loader
    """
    #log.setLevel(logging.DEBUG)
    e = elf_init.ELF(fdata, **kargs)
    i = interval()
    all_data = {}
    for p in e.ph.phlist:
        if p.ph.type != 1:
            continue
        log.debug('%s %s %s %s' %
                  (hex(p.ph.vaddr), hex(p.ph.memsz), hex(p.ph.offset), hex(p.ph.filesz)))
        data_o = e._content[p.ph.offset:p.ph.offset + p.ph.filesz]
        addr_o = p.ph.vaddr
        a_addr = addr_o & ~0xFFF
        b_addr = addr_o + max(p.ph.memsz, p.ph.filesz)
        b_addr = (b_addr + 0xFFF) & ~0xFFF
        all_data[addr_o] = data_o
        # -2: Trick to avoid merging 2 consecutive pages
        i += [(a_addr, b_addr-2)]
    for a, b in i.intervals:
        #print hex(a), hex(b)
        vm.add_memory_page(a, PAGE_READ | PAGE_WRITE, "\x00"*(b+2-a))

    #vm.dump_memory_page_pool()

    for r_vaddr, data in all_data.items():
        vm.set_mem(r_vaddr, data)
    return e

class libimp_elf(libimp):
    pass
