import struct
from collections import defaultdict

from future.utils import viewitems

from miasm.loader import cstruct
from miasm.loader import *
import miasm.loader.elf as elf_csts

from miasm.jitter.csts import *
from miasm.jitter.loader.utils import canon_libname_libfunc, libimp
from miasm.core.utils import force_str
from miasm.core.interval import interval

import logging

log = logging.getLogger('loader_elf')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)


def get_import_address_elf(e):
    import2addr = defaultdict(set)
    for sh in e.sh:
        if not hasattr(sh, 'rel'):
            continue
        for k, v in viewitems(sh.rel):
            k = force_str(k)
            import2addr[('xxx', k)].add(v.offset)
    return import2addr


def preload_elf(vm, e, runtime_lib, patch_vm_imp=True, loc_db=None):
    # XXX quick hack
    fa = get_import_address_elf(e)
    dyn_funcs = {}
    for (libname, libfunc), ads in viewitems(fa):
        # Quick hack - if a symbol is already known, do not stub it
        if loc_db and loc_db.get_name_location(libfunc) is not None:
            continue
        for ad in ads:
            ad_base_lib = runtime_lib.lib_get_add_base(libname)
            ad_libfunc = runtime_lib.lib_get_add_func(ad_base_lib, libfunc, ad)

            libname_s = canon_libname_libfunc(libname, libfunc)
            dyn_funcs[libname_s] = ad_libfunc
            if patch_vm_imp:
                log.debug('patch 0x%x 0x%x %s', ad, ad_libfunc, libfunc)
                set_endianness = { elf_csts.ELFDATA2MSB: ">",
                                   elf_csts.ELFDATA2LSB: "<",
                                   elf_csts.ELFDATANONE: "" }[e.sex]
                vm.set_mem(ad,
                           struct.pack(set_endianness +
                                       cstruct.size2type[e.size],
                                       ad_libfunc))
    return runtime_lib, dyn_funcs

def fill_loc_db_with_symbols(elf, loc_db, base_addr=0):
    """Parse the miasm.loader's ELF @elf to extract symbols, and fill the LocationDB
    instance @loc_db with parsed symbols.

    The ELF is considered mapped at @base_addr
    @elf: miasm.loader's ELF instance
    @loc_db: LocationDB used to retrieve symbols'offset
    @base_addr: addr to reloc to (if any)
    """
    # Get symbol sections
    symbol_sections = []
    for section_header in elf.sh:
        if hasattr(section_header, 'symbols'):
            for name, sym in viewitems(section_header.symbols):
                if not name or sym.value == 0:
                    continue
                name = loc_db.find_free_name(force_str(name))
                loc_db.add_location(name, sym.value, strict=False)

        if hasattr(section_header, 'reltab'):
            for rel in section_header.reltab:
                if not rel.sym or rel.offset == 0:
                    continue
                name = loc_db.find_free_name(force_str(rel.sym))
                loc_db.add_location(name, rel.offset, strict=False)

        if hasattr(section_header, 'symtab'):
            log.debug("Find %d symbols in %r", len(section_header.symtab),
                      section_header)
            symbol_sections.append(section_header)
        elif isinstance(section_header, (
                elf_init.GNUVerDef, elf_init.GNUVerSym, elf_init.GNUVerNeed
        )):
            log.debug("Find GNU version related section, unsupported for now")

    for section in symbol_sections:
        for symbol_entry in section.symtab:
            # Here, the computation of vaddr assumes 'elf' is an executable or a
            # shared object file

            # For relocatable file, symbol_entry.value is an offset from the section
            # base -> not handled here
            st_bind = symbol_entry.info >> 4
            st_type = symbol_entry.info & 0xF

            if st_type not in [
                    elf_csts.STT_NOTYPE,
                    elf_csts.STT_OBJECT,
                    elf_csts.STT_FUNC,
                    elf_csts.STT_COMMON,
                    elf_csts.STT_GNU_IFUNC,
            ]:
                # Ignore symbols useless in linking
                continue

            if st_bind == elf_csts.STB_GLOBAL:
                # Global symbol
                weak = False
            elif st_bind == elf_csts.STB_WEAK:
                # Weak symbol
                weak = True
            else:
                # Ignore local & others symbols
                continue

            absolute = False
            if symbol_entry.shndx == 0:
                # SHN_UNDEF
                continue
            elif symbol_entry.shndx == 0xfff1:
                # SHN_ABS
                absolute = True
                log.debug("Absolute symbol %r - %x", symbol_entry.name,
                          symbol_entry.value)
            elif 0xff00 <= symbol_entry.shndx <= 0xffff:
                # Reserved index (between SHN_LORESERV and SHN_HIRESERVE)
                raise RuntimeError("Unsupported reserved index: %r" % symbol_entry)

            name = force_str(symbol_entry.name)
            if name == "":
                # Ignore empty symbol
                log.debug("Empty symbol %r", symbol_entry)
                continue

            if absolute:
                vaddr = symbol_entry.value
            else:
                vaddr = symbol_entry.value + base_addr

            # 'weak' information is only used to force global symbols for now
            already_existing_loc = loc_db.get_name_location(name)
            if already_existing_loc is not None:
                if weak:
                    # Weak symbol, this is ok to already exists, skip it
                    continue
                else:
                    # Global symbol, force it
                    loc_db.remove_location_name(already_existing_loc,
                                                name)
            already_existing_off = loc_db.get_offset_location(vaddr)
            if already_existing_off is not None:
                loc_db.add_location_name(already_existing_off, name)
            else:
                loc_db.add_location(name=name, offset=vaddr)


def apply_reloc_x86(elf, vm, section, base_addr, loc_db):
    """Apply relocation for x86 ELF contained in the section @section
    @elf: miasm.loader's ELF instance
    @vm: VmMngr instance
    @section: elf's section containing relocation to perform
    @base_addr: addr to reloc to
    @loc_db: LocationDB used to retrieve symbols'offset
    """
    if elf.size == 64:
        addr_writer = lambda vaddr, addr: vm.set_mem(vaddr,
                                                     struct.pack("<Q", addr))
    elif elf.size == 32:
        addr_writer = lambda vaddr, addr: vm.set_mem(vaddr,
                                                     struct.pack("<I", addr))
    else:
        raise ValueError("Unsupported elf size %d" % elf.size)

    symb_section = section.linksection
    for reloc in section.reltab:

        # Parse relocation info
        r_info = reloc.info
        if elf.size == 64:
            r_info_sym = (r_info >> 32) & 0xFFFFFFFF
            r_info_type = r_info & 0xFFFFFFFF
        elif elf.size == 32:
            r_info_sym = (r_info >> 8) & 0xFFFFFF
            r_info_type = r_info & 0xFF

        is_ifunc = False
        symbol_entry = None
        if r_info_sym > 0:
            symbol_entry = symb_section.symtab[r_info_sym]

        r_offset = reloc.offset
        r_addend = reloc.cstr.sym

        if (elf.size, reloc.type) in [
                (64, elf_csts.R_X86_64_RELATIVE),
                (64, elf_csts.R_X86_64_IRELATIVE),
                (32, elf_csts.R_386_RELATIVE),
                (32, elf_csts.R_386_IRELATIVE),
        ]:
            # B + A
            addr = base_addr + r_addend
            where = base_addr + r_offset
        elif reloc.type == elf_csts.R_X86_64_64:
            # S + A
            addr_symb = loc_db.get_name_offset(symbol_entry.name)
            if addr_symb is None:
                log.warning("Unable to find symbol %r" % symbol_entry.name)
                continue
            addr = addr_symb + r_addend
            where = base_addr + r_offset
        elif (elf.size, reloc.type) in [
                (64, elf_csts.R_X86_64_TPOFF64),
                (64, elf_csts.R_X86_64_DTPMOD64),
                (32, elf_csts.R_386_TLS_TPOFF),
        ]:
            # Thread dependent, ignore for now
            log.debug("Skip relocation TPOFF64 %r", reloc)
            continue
        elif (elf.size, reloc.type) in [
                (64, elf_csts.R_X86_64_GLOB_DAT),
                (64, elf_csts.R_X86_64_JUMP_SLOT),
                (32, elf_csts.R_386_JMP_SLOT),
                (32, elf_csts.R_386_GLOB_DAT),
        ]:
            # S
            addr = loc_db.get_name_offset(symbol_entry.name)
            if addr is None:
                log.warning("Unable to find symbol %r" % symbol_entry.name)
                continue
            is_ifunc = symbol_entry.info & 0xF == elf_csts.STT_GNU_IFUNC
            where = base_addr + r_offset
        else:
            raise ValueError(
                "Unknown relocation type: %d (%r)" % (reloc.type,
                                                      reloc)
            )
        if is_ifunc:
            # Resolve at runtime - not implemented for now
            log.warning("Relocation for %r (at %x, currently pointing on %x) "
                        "has to be resolved at runtime",
                        name, where, sym_addr)
            continue

        log.debug("Write %x at %x", addr, where)
        addr_writer(where, addr)


def vm_load_elf(vm, fdata, name="", base_addr=0, loc_db=None, apply_reloc=False,
                **kargs):
    """
    Very dirty elf loader
    TODO XXX: implement real loader
    """
    elf = elf_init.ELF(fdata, **kargs)
    i = interval()
    all_data = {}

    for p in elf.ph.phlist:
        if p.ph.type != elf_csts.PT_LOAD:
            continue
        log.debug(
            '0x%x 0x%x 0x%x 0x%x 0x%x', p.ph.vaddr, p.ph.memsz, p.ph.offset,
                  p.ph.filesz, p.ph.type)
        data_o = elf._content[p.ph.offset:p.ph.offset + p.ph.filesz]
        addr_o = p.ph.vaddr + base_addr
        a_addr = addr_o & ~0xFFF
        b_addr = addr_o + max(p.ph.memsz, p.ph.filesz)
        b_addr = (b_addr + 0xFFF) & ~0xFFF
        all_data[addr_o] = data_o
        # -2: Trick to avoid merging 2 consecutive pages
        i += [(a_addr, b_addr - 2)]
    for a, b in i.intervals:
        vm.add_memory_page(
            a,
            PAGE_READ | PAGE_WRITE,
            b"\x00" * (b + 2 - a),
            repr(name)
        )

    for r_vaddr, data in viewitems(all_data):
        vm.set_mem(r_vaddr, data)

    if loc_db is not None:
        fill_loc_db_with_symbols(elf, loc_db, base_addr)

    if apply_reloc:
        arch = guess_arch(elf)
        sections = []
        for section in elf.sh:
            if not hasattr(section, 'reltab'):
                continue
            if isinstance(section, elf_init.RelATable):
                pass
            elif isinstance(section, elf_init.RelTable):
                if arch == "x86_64":
                    log.warning("REL section should not happen in x86_64")
            else:
                raise RuntimeError("Unknown relocation section type: %r" % section)
            sections.append(section)
        for section in sections:
            if arch in ["x86_64", "x86_32"]:
                apply_reloc_x86(elf, vm, section, base_addr, loc_db)
            else:
                log.debug("Unsupported relocation for arch %r" % arch)

    return elf


class libimp_elf(libimp):
    pass


# machine, size, sex -> arch_name
ELF_machine = {(elf_csts.EM_ARM, 32, elf_csts.ELFDATA2LSB): "arml",
               (elf_csts.EM_ARM, 32, elf_csts.ELFDATA2MSB): "armb",
               (elf_csts.EM_AARCH64, 64, elf_csts.ELFDATA2LSB): "aarch64l",
               (elf_csts.EM_AARCH64, 64, elf_csts.ELFDATA2MSB): "aarch64b",
               (elf_csts.EM_MIPS, 32, elf_csts.ELFDATA2MSB): "mips32b",
               (elf_csts.EM_MIPS, 32, elf_csts.ELFDATA2LSB): "mips32l",
               (elf_csts.EM_386, 32, elf_csts.ELFDATA2LSB): "x86_32",
               (elf_csts.EM_X86_64, 64, elf_csts.ELFDATA2LSB): "x86_64",
               (elf_csts.EM_SH, 32, elf_csts.ELFDATA2LSB): "sh4",
               (elf_csts.EM_PPC, 32, elf_csts.ELFDATA2MSB): "ppc32b",
               }


def guess_arch(elf):
    """Return the architecture specified by the ELF container @elf.
    If unknown, return None"""
    return ELF_machine.get((elf.Ehdr.machine, elf.size, elf.sex), None)
