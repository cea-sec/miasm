import struct
from collections import defaultdict

from typing import Literal
from future.utils import viewitems

from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
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
    # TODO: rely on DT_NEEDED and/or .dynsym rather than relocs ?
    import2addr = defaultdict(set)
    for sh in e.sh:
        rel = []
        if hasattr(sh, 'rel'):
            rel += sh.rel.items()
        if hasattr(sh, 'rela'):
            rel += sh.rela.items()
        for k, v in rel:
            k = force_str(k)
            import2addr[('xxx', k)].add(v.offset)
    return import2addr

def preload_elf(vm, e, runtime_lib, patch_vm_imp=True, loc_db=None, elf_base_addr: int = 0):
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
                log.debug('patch 0x%x 0x%x %s', ad + elf_base_addr, ad_libfunc, libfunc)
                set_endianness = { elf_csts.ELFDATA2MSB: ">",
                                   elf_csts.ELFDATA2LSB: "<",
                                   elf_csts.ELFDATANONE: "" }[e.sex]
                vm.set_mem(ad + elf_base_addr,
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

class RelocOptions():
    def __init__(self, run_ifuncs: bool = False, ifunc_jitter_engine: Literal["python", "gcc", "llvm"] | None = None, ifunc_jitter = None) -> None:
        """@run_ifuncs: whether or not to run, resolve and apply ifuncs
        @ifunc_jitter_engine: set to "gcc" by default, unless @ifunc_jitter is used. The engine to use for the default ifunc jitter.
        @ifunc_jitter: a user-provided jitter to run/resolve ifuncs with. Needs to have an initialized stack. Overrides the default ifunc jitter.

        WARNING: @ifunc_jitter_engine and @ifunc_jitter are mutually exclusive.
        """
        if ifunc_jitter_engine is not None and ifunc_jitter is not None:
            raise ValueError("ifunc_jitter_engine and ifunc_jitter are mutually exclusive")
        self.run_ifuncs = run_ifuncs
        if ifunc_jitter_engine is None:
            if ifunc_jitter is None:
                self.ifunc_jitter_engine = "gcc"
        else:
            self.ifunc_jitter_engine = ifunc_jitter_engine

        if ifunc_jitter is not None:
            self.ifunc_jitter = ifunc_jitter

def apply_reloc_x86(elf, vm, section, base_addr, loc_db: LocationDB | None, reloc_options: RelocOptions | None = None):
    """Apply relocation for x86 ELF contained in the section @section
    @elf: miasm.loader's ELF instance
    @vm: VmMngr instance
    @section: elf's section containing relocation to perform
    @base_addr: addr to reloc to
    @loc_db: LocationDB used to retrieve symbols'offset
    @reloc_options: Options for which reloc to process and how to process them
    """
    if reloc_options is None:
        reloc_options = RelocOptions()

    if reloc_options.run_ifuncs and elf.Ehdr.type == elf_csts.ET_EXEC:
        log.warning("Running ifuncs as a part of the loading process is only accurate for dynamically-linked executables, as they are normally ran during glibc initialization for static and static-pie executables. See GNU C Library Reference Manual, version 2.44, chapter/section 37.4.2 When IFUNC Resolvers Run.")

    log.debug(f"Applying relocations for section {section}")

    symb_section = section.linksection
    if hasattr(section, "reltab"):
        table = section.reltab
    elif hasattr(section, "relatab"):
        table = section.relatab
    else:
        raise ValueError(f"Trying to apply reloc on section without RelTable or RelATable.")

    if reloc_options.run_ifuncs:
        if hasattr(reloc_options, "ifunc_jitter"):
            ifunc_jitter = reloc_options.ifunc_jitter
        else:
            ifunc_machine = Machine(guess_arch(elf))
            ifunc_jitter = ifunc_machine.jitter(loc_db, reloc_options.ifunc_jitter_engine)

            last_addr = 0x100
            stack_base_found = False
            ifunc_jitter.stack_size = 0x100
            for map_addr, map_mem in vm.get_all_memory().items():
                map_data = map_mem["data"]
                # find somewhere for our stack to go
                if map_addr - last_addr > ifunc_jitter.stack_size:
                    ifunc_jitter.stack_base = last_addr
                    last_addr = float("inf")
                    stack_base_found = True
                else:
                    last_addr = map_addr + len(map_data)

                # and copy the memory already mapped by the loader
                ifunc_jitter.vm.add_memory_page(map_addr, map_mem["access"], map_data)

            if not stack_base_found and last_addr + ifunc_jitter.stack_size < 1 << elf.size:
                ifunc_jitter.stack_base = last_addr
                stack_base_found = True

            if stack_base_found:
                ifunc_jitter.init_stack()
            else:
                raise ValueError("Couldn't find enough space to allocate our ifunc runner's stack")

    for reloc in table:
        # Parse relocation info
        r_info = reloc.info
        if elf.size == 64:
            r_info_sym = (r_info >> 32) & 0xFFFFFFFF
            r_info_type = r_info & 0xFFFFFFFF
        elif elf.size == 32:
            r_info_sym = (r_info >> 8) & 0xFFFFFF
            r_info_type = r_info & 0xFF
        else:
            raise ValueError(
                f"Cannot parse relocations on an ELF with {elf.size=}"
            )

        is_ifunc = False
        symbol_entry = None
        symbol_name = None
        if r_info_sym > 0:
            symbol_entry = symb_section.symtab[r_info_sym]
            symbol_name = symbol_entry.name.decode()

        r_offset = reloc.offset
        if hasattr(reloc, "addend"):
            addend = reloc.addend
        else:
            addend = int.from_bytes(elf.get_virt().get(r_offset, r_offset + elf.size // 8), byteorder="little")

        if (elf.size, reloc.type) in [
                (64, elf_csts.R_X86_64_RELATIVE),
                (32, elf_csts.R_386_RELATIVE),
        ]:
            # B + A
            where = base_addr + r_offset
            addr = base_addr + addend
        elif (elf.size, reloc.type) in [
                (64, elf_csts.R_X86_64_IRELATIVE),
                (32, elf_csts.R_386_IRELATIVE),
        ]:
            # indirect B + A (indirect as in ifunc)
            where = base_addr + r_offset
            addr = base_addr + addend
            is_ifunc = True
        elif reloc.type == elf_csts.R_X86_64_64:
            # S + A
            addr_symb = loc_db.get_name_offset(symbol_name)
            if addr_symb is None:
                log.warning(f"Unable to find symbol {symbol_name}")
                continue
            addr = addr_symb + addend
            where = base_addr + r_offset
        elif (elf.size, reloc.type) in [
                (64, elf_csts.R_X86_64_TPOFF64),
                (64, elf_csts.R_X86_64_DTPMOD64),
                (32, elf_csts.R_386_TLS_TPOFF),
        ]:
            # Thread dependent, ignore for now
            log.debug(f"Skip relocation TPOFF64 {reloc}")
            continue
        elif (elf.size, reloc.type) in [
                (64, elf_csts.R_X86_64_GLOB_DAT),
                (64, elf_csts.R_X86_64_JUMP_SLOT),
                (32, elf_csts.R_386_JMP_SLOT),
                (32, elf_csts.R_386_GLOB_DAT),
        ]:
            # S
            addr = loc_db.get_name_offset(symbol_name)
            if addr is None:
                log.warning(f"Unable to find symbol {symbol_name}")
                continue
            where = base_addr + r_offset
        else:
            raise ValueError(f"Unknown relocation type: {reloc.type} ({reloc})")
        if is_ifunc and reloc_options.run_ifuncs:
            addr = _resolve_ifunc_x86(addr, elf, ifunc_jitter)

        log.debug(f"Write {addr:x} at {where:x}")
        if elf.size == 64:
            return vm.set_u64(where, addr)
        elif elf.size == 32:
            return vm.set_u32(where, addr)
        else:
            raise ValueError(f"Unsupported elf size {elf.size}")


def vm_load_elf(vm, fdata, name="", base_addr=0, loc_db=None, apply_reloc=False,
                reloc_options=None, **kargs):
    """
    Very dirty elf loader
    TODO XXX: implement real loader
    """
    if reloc_options is None:
        reloc_options = RelocOptions()

    if reloc_options.run_ifuncs and not apply_reloc:
        log.warning("vm_load_elf was called with reloc_options.run_ifuncs=True but they won't be run nor applied since apply_reloc=False.")

    elf = elf_init.ELF(fdata, **kargs)
    i = interval()
    all_data = {}
    if elf.Ehdr.type == elf_csts.ET_EXEC and base_addr != 0:
        log.warning("This elf has Ehdr.type == ET_EXEC meaning it isn't relocatable. Reversing base_addr to 0.")
        base_addr = 0

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
            if not (hasattr(section, 'reltab') or hasattr(section, 'relatab')):
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
                apply_reloc_x86(elf, vm, section, base_addr, loc_db, reloc_options)
            else:
                log.debug("Unsupported relocation for arch %r" % arch)

    return elf

def get_ifuncs_x86(elf, base_addr, with_syms=False):
    """
    Returns all ifunc resolvers found in @elf along with their GOT entry and their associated symbols if they exist and @with_syms == True

    @elf: miasm.loader.elf_init.ELF
    @return: list[(to_reloc: int, resolver: int, list[miasm.loader.elf_init.WSym(32|64)] if with_syms)]
    """
    res = []
    explicit_addend = False
    for sh in elf.sh:
        if hasattr(sh, "reltab"):
            table = sh.reltab
        elif hasattr(sh, "relatab"):
            table = sh.relatab
            explicit_addend = True
        else:
            continue
        for reloc in table:
            if (elf.size, reloc.type) in [
                    (64, elf_csts.R_X86_64_IRELATIVE),
                    (32, elf_csts.R_386_IRELATIVE),
            ]:
                addend = reloc.addend if explicit_addend else int.from_bytes(elf.get_virt().get(reloc.offset, reloc.offset + elf.size // 8), byteorder="little")

                # indirect B + A (indirect as in ifunc)
                to_reloc = base_addr + reloc.offset
                resolver = base_addr + addend
                if with_syms:
                    ifunc_syms = [s for s in elf.sh.symtab.symtab if s.value == resolver and s.info & elf_csts.STT_GNU_IFUNC == elf_csts.STT_GNU_IFUNC]
                    res.append((to_reloc, resolver, ifunc_syms))
                else:
                    res.append((to_reloc, resolver))
    return res

def _resolve_ifunc_x86(resolver_addr, elf, run_jitter):
    """
    WARNING: this is only accurate for dynamically-linked binaries. Static and static-pie executables' ifuncs are loaded at runtime during glibc initialization.
    WARNING: this requires the jitter to have an initialized stack
    Runs provided ifunc resolver

    @reloc_addr: int - the address where we want to apply our reloc
    @resolver_addr: int - the address of the ifunc resolver
    @elf: miasm.loader.elf_init.ELF
    @run_jitter: Jitter to run the ifunc resolver on
    @return: None
    """
    end_addr = 0x1337beef
    def _code_sentinelle(j):
        j.running = False
        return False
    run_jitter.add_breakpoint(end_addr, _code_sentinelle)
    if elf.size == 32:
        run_jitter.push_uint32_t(end_addr)
    elif elf.size == 64:
        run_jitter.push_uint64_t(end_addr)
    else:
        raise ValueError(
            f"Cannot resolve ifunc on an ELF with unsupported size {elf.size}"
        )

    run_jitter.run(resolver_addr)
    resolved_funcaddr = getattr(run_jitter.cpu, "RAX" if elf.size == 64 else "EAX")
    return resolved_funcaddr

def apply_ifunc_x86(reloc_addr, resolver_addr, elf, jitter, run_jitter=None):
    """
    WARNING: this is only accurate for dynamically-linked binaries. Static and static-pie executables' ifuncs are loaded at runtime during glibc initialization.
    WARNING: this requires the jitter or run_jitter (if present) to have an initialized stack
    Runs and applies provided ifunc resolver

    @reloc_addr: int - the address where we want to apply our reloc
    @resolver_addr: int - the address of the ifunc resolver
    @elf: miasm.loader.elf_init.ELF
    @jitter: Jitter instance to apply the reloc to
    @run_jitter: (optional) Jitter to run the ifunc resolver on in place of @jitter
    @return: None
    """
    if run_jitter is None:
        run_jitter = jitter

    resolved_funcaddr = _resolve_ifunc_x86(resolver_addr, elf, run_jitter)

    log.debug(f"Write {resolved_funcaddr:x} at {reloc_addr:x}")
    if elf.size == 64:
        return jitter.vm.set_u64(reloc_addr, resolved_funcaddr)
    elif elf.size == 32:
        return jitter.vm.set_u32(reloc_addr, resolved_funcaddr)
    else:
        raise ValueError(f"Unsupported elf size {elf.size}")

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
