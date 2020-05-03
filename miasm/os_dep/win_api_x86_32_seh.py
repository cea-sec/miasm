#-*- coding:utf-8 -*-

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
import logging
import os
import struct

from future.utils import viewitems

from miasm.loader import pe_init

from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.utils import pck32
import miasm.arch.x86.regs as x86_regs

from miasm.os_dep.win_32_structs import LdrDataEntry, ListEntry, \
    TEB, NT_TIB, PEB, PEB_LDR_DATA, ContextException, \
    EXCEPTION_REGISTRATION_RECORD, EXCEPTION_RECORD

# Constants Windows
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ACCESS_VIOLATION = 0xc0000005
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xc0000094
EXCEPTION_PRIV_INSTRUCTION = 0xc0000096
EXCEPTION_ILLEGAL_INSTRUCTION = 0xc000001d


log = logging.getLogger("seh_helper")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

# fs:[0] Page (TIB)
tib_address = 0x7ff70000
PEB_AD = 0x7ffdf000
LDR_AD = 0x340000
DEFAULT_SEH = 0x7ffff000

MAX_MODULES = 0x40

peb_address = PEB_AD
peb_ldr_data_offset = 0x1ea0
peb_ldr_data_address = LDR_AD + peb_ldr_data_offset


modules_list_offset = 0x1f00

InInitializationOrderModuleList_offset = 0x1ee0
InInitializationOrderModuleList_address = LDR_AD + \
    InInitializationOrderModuleList_offset

InLoadOrderModuleList_offset = 0x1ee0 + \
    MAX_MODULES * 0x1000
InLoadOrderModuleList_address = LDR_AD + \
    InLoadOrderModuleList_offset


process_environment_address = 0x10000
process_parameters_address = 0x200000

return_from_exception = 0x6eadbeef


name2module = []
main_pe = None
main_pe_name = "c:\\xxx\\toto.exe"

MAX_SEH = 5


def build_teb(jitter, teb_address):
    """
    Build TEB information using following structure:

    @jitter: jitter instance
    @teb_address: the TEB address
    """

    # Only allocate space for ExceptionList/ProcessEnvironmentBlock/Self
    jitter.vm.add_memory_page(
        teb_address,
        PAGE_READ | PAGE_WRITE,
        b"\x00" * NT_TIB.get_offset("StackBase"),
        "TEB.NtTib.ExceptionList"
    )
    jitter.vm.add_memory_page(
        teb_address + NT_TIB.get_offset("Self"),
        PAGE_READ | PAGE_WRITE,
        b"\x00" * (NT_TIB.sizeof() - NT_TIB.get_offset("Self")),
        "TEB.NtTib.Self"
    )
    jitter.vm.add_memory_page(
        teb_address + TEB.get_offset("ProcessEnvironmentBlock"),
        PAGE_READ | PAGE_WRITE,
        b"\x00" * (
            TEB.get_offset("LastErrorValue") -
            TEB.get_offset("ProcessEnvironmentBlock")
        ),
        "TEB.ProcessEnvironmentBlock"
    )
    Teb = TEB(jitter.vm, teb_address)
    Teb.NtTib.ExceptionList = DEFAULT_SEH
    Teb.NtTib.Self = teb_address
    Teb.ProcessEnvironmentBlock = peb_address

def build_peb(jitter, peb_address):
    """
    Build PEB information using following structure:

    @jitter: jitter instance
    @peb_address: the PEB address
    """

    if main_pe:
        offset, length = 8, 4
    else:
        offset, length = 0xC, 0
    length += 4

    jitter.vm.add_memory_page(
        peb_address + offset,
        PAGE_READ | PAGE_WRITE,
        b"\x00" * length,
        "PEB + 0x%x" % offset
    )

    Peb = PEB(jitter.vm, peb_address)
    if main_pe:
        Peb.ImageBaseAddress = main_pe.NThdr.ImageBase
    Peb.Ldr = peb_ldr_data_address


def build_ldr_data(jitter, modules_info):
    """
    Build Loader information using following structure:

    +0x000 Length                          : Uint4B
    +0x004 Initialized                     : UChar
    +0x008 SsHandle                        : Ptr32 Void
    +0x00c InLoadOrderModuleList           : _LIST_ENTRY
    +0x014 InMemoryOrderModuleList         : _LIST_ENTRY
    +0x01C InInitializationOrderModuleList         : _LIST_ENTRY
    # dummy dll base
    +0x024 DllBase : Ptr32 Void

    @jitter: jitter instance
    @modules_info: LoadedModules instance

    """
    # ldr offset pad
    offset = 0xC
    addr = LDR_AD + peb_ldr_data_offset
    ldrdata = PEB_LDR_DATA(jitter.vm, addr)

    main_pe = modules_info.name2module.get(main_pe_name, None)
    ntdll_pe = modules_info.name2module.get("ntdll.dll", None)


    size = 0
    if main_pe:
        size += ListEntry.sizeof() * 2
        main_addr_entry = modules_info.module2entry[main_pe]
    if ntdll_pe:
        size += ListEntry.sizeof()
        ntdll_addr_entry = modules_info.module2entry[ntdll_pe]

    jitter.vm.add_memory_page(
        addr + offset,
        PAGE_READ | PAGE_WRITE,
        b"\x00" * size,
        "Loader struct"
    )  # (ldrdata.get_size() - offset))

    last_module = modules_info.module2entry[
        modules_info.modules[-1]]

    if main_pe:
        ldrdata.InLoadOrderModuleList.flink = main_addr_entry
        ldrdata.InLoadOrderModuleList.blink = last_module


        ldrdata.InMemoryOrderModuleList.flink = main_addr_entry + \
            LdrDataEntry.get_type().get_offset("InMemoryOrderLinks")
        ldrdata.InMemoryOrderModuleList.blink = last_module + \
            LdrDataEntry.get_type().get_offset("InMemoryOrderLinks")
    if ntdll_pe:
        ldrdata.InInitializationOrderModuleList.flink = ntdll_addr_entry + \
            LdrDataEntry.get_type().get_offset("InInitializationOrderLinks")
        ldrdata.InInitializationOrderModuleList.blink = last_module + \
                LdrDataEntry.get_type().get_offset("InInitializationOrderLinks")

    # Add dummy dll base
    jitter.vm.add_memory_page(peb_ldr_data_address + 0x24,
                              PAGE_READ | PAGE_WRITE, pck32(0),
                              "Loader struct dummy dllbase")


class LoadedModules(object):

    """Class representing modules in memory"""

    def __init__(self):
        self.modules = []
        self.name2module = {}
        self.module2entry = {}
        self.module2name = {}

    def add(self, name, module, module_entry):
        """Track a new module
        @name: module name (with extension)
        @module: module object
        @module_entry: address of the module entry
        """

        self.modules.append(module)
        self.name2module[name] = module
        self.module2entry[module] = module_entry
        self.module2name[module] = name

    def __repr__(self):
        return "\n".join(str(x) for x in viewitems(self.name2module))


def create_modules_chain(jitter, name2module):
    """
    Create the modules entries. Those modules are not linked in this function.

    @jitter: jitter instance
    @name2module: dict containing association between name and its pe instance
    """

    modules_info = LoadedModules()
    base_addr = LDR_AD + modules_list_offset  # XXXX
    offset_name = 0x500
    offset_path = 0x600

    out = ""
    for i, (fname, pe_obj) in enumerate(viewitems(name2module), 1):
        if pe_obj is None:
            log.warning("Unknown module: omitted from link list (%r)",
                        fname)
            continue
        addr = base_addr + i * 0x1000
        bpath = fname.replace('/', '\\')
        bname_str = os.path.split(fname)[1].lower()
        bname_unicode = bname_str.encode("utf-16le")
        log.info("Add module %x %r", pe_obj.NThdr.ImageBase, bname_str)

        modules_info.add(bname_str, pe_obj, addr)

        # Allocate a partial LdrDataEntry (0-Flags)
        jitter.vm.add_memory_page(
            addr,
            PAGE_READ | PAGE_WRITE,
            b"\x00" * LdrDataEntry.get_offset("Flags"),
            "Module info %r" % bname_str
        )

        LdrEntry = LdrDataEntry(jitter.vm, addr)

        LdrEntry.DllBase = pe_obj.NThdr.ImageBase
        LdrEntry.EntryPoint = pe_obj.Opthdr.AddressOfEntryPoint
        LdrEntry.SizeOfImage = pe_obj.NThdr.sizeofimage
        LdrEntry.FullDllName.length = len(bname_unicode)
        LdrEntry.FullDllName.maxlength = len(bname_unicode) + 2
        LdrEntry.FullDllName.data = addr + offset_path
        LdrEntry.BaseDllName.length = len(bname_unicode)
        LdrEntry.BaseDllName.maxlength = len(bname_unicode) + 2
        LdrEntry.BaseDllName.data = addr + offset_name

        jitter.vm.add_memory_page(
            addr + offset_name,
            PAGE_READ | PAGE_WRITE,
            bname_unicode + b"\x00" * 2,
            "Module name %r" % bname_str
        )

        if isinstance(bpath, bytes):
            bpath = bpath.decode('utf8')
        bpath_unicode = bpath.encode('utf-16le')
        jitter.vm.add_memory_page(
            addr + offset_path,
            PAGE_READ | PAGE_WRITE,
            bpath_unicode + b"\x00" * 2,
            "Module path %r" % bname_str
        )

    return modules_info


def set_link_list_entry(jitter, loaded_modules, modules_info, offset):
    for i, module in enumerate(loaded_modules):
        cur_module_entry = modules_info.module2entry[module]
        prev_module = loaded_modules[(i - 1) % len(loaded_modules)]
        next_module = loaded_modules[(i + 1) % len(loaded_modules)]
        prev_module_entry = modules_info.module2entry[prev_module]
        next_module_entry = modules_info.module2entry[next_module]
        if i == 0:
            prev_module_entry = peb_ldr_data_address + 0xC
        if i == len(loaded_modules) - 1:
            next_module_entry = peb_ldr_data_address + 0xC

        list_entry = ListEntry(jitter.vm, cur_module_entry + offset)
        list_entry.flink = next_module_entry + offset
        list_entry.blink = prev_module_entry + offset



def fix_InLoadOrderModuleList(jitter, modules_info):
    """Fix InLoadOrderModuleList double link list. First module is the main pe,
    then ntdll, kernel32.

    @jitter: the jitter instance
    @modules_info: the LoadedModules instance
    """

    log.debug("Fix InLoadOrderModuleList")
    main_pe = modules_info.name2module.get(main_pe_name, None)
    kernel32_pe = modules_info.name2module.get("kernel32.dll", None)
    ntdll_pe = modules_info.name2module.get("ntdll.dll", None)
    special_modules = [main_pe, kernel32_pe, ntdll_pe]
    if not all(special_modules):
        log.warn(
            'No main pe, ldr data will be unconsistant %r', special_modules)
        loaded_modules = modules_info.modules
    else:
        loaded_modules = [module for module in modules_info.modules
                          if module not in special_modules]
        loaded_modules[0:0] = [main_pe]
        loaded_modules[1:1] = [ntdll_pe]
        loaded_modules[2:2] = [kernel32_pe]

    set_link_list_entry(jitter, loaded_modules, modules_info, 0x0)


def fix_InMemoryOrderModuleList(jitter, modules_info):
    """Fix InMemoryOrderLinks double link list. First module is the main pe,
    then ntdll, kernel32.

    @jitter: the jitter instance
    @modules_info: the LoadedModules instance
    """

    log.debug("Fix InMemoryOrderModuleList")
    main_pe = modules_info.name2module.get(main_pe_name, None)
    kernel32_pe = modules_info.name2module.get("kernel32.dll", None)
    ntdll_pe = modules_info.name2module.get("ntdll.dll", None)
    special_modules = [main_pe, kernel32_pe, ntdll_pe]
    if not all(special_modules):
        log.warn('No main pe, ldr data will be unconsistant')
        loaded_modules = modules_info.modules
    else:
        loaded_modules = [module for module in modules_info.modules
                          if module not in special_modules]
        loaded_modules[0:0] = [main_pe]
        loaded_modules[1:1] = [ntdll_pe]
        loaded_modules[2:2] = [kernel32_pe]

    set_link_list_entry(jitter, loaded_modules, modules_info, 0x8)


def fix_InInitializationOrderModuleList(jitter, modules_info):
    """Fix InInitializationOrderModuleList double link list. First module is the
    ntdll, then kernel32.

    @jitter: the jitter instance
    @modules_info: the LoadedModules instance

    """

    log.debug("Fix InInitializationOrderModuleList")
    main_pe = modules_info.name2module.get(main_pe_name, None)
    kernel32_pe = modules_info.name2module.get("kernel32.dll", None)
    ntdll_pe = modules_info.name2module.get("ntdll.dll", None)
    special_modules = [main_pe, kernel32_pe, ntdll_pe]
    if not all(special_modules):
        log.warn('No main pe, ldr data will be unconsistant')
        loaded_modules = modules_info.modules
    else:
        loaded_modules = [module for module in modules_info.modules
                          if module not in special_modules]
        loaded_modules[0:0] = [ntdll_pe]
        loaded_modules[1:1] = [kernel32_pe]

    set_link_list_entry(jitter, loaded_modules, modules_info, 0x10)


def add_process_env(jitter):
    """
    Build a process environment structure
    @jitter: jitter instance
    """

    env_unicode = 'ALLUSEESPROFILE=C:\\Documents and Settings\\All Users\x00'.encode('utf-16le')
    env_unicode += b"\x00" * 0x10
    jitter.vm.add_memory_page(
        process_environment_address,
        PAGE_READ | PAGE_WRITE,
        env_unicode,
        "Process environment"
    )
    jitter.vm.set_mem(process_environment_address, env_unicode)


def add_process_parameters(jitter):
    """
    Build a process parameters structure
    @jitter: jitter instance
    """

    o = b""
    o += pck32(0x1000)  # size
    o += b"E" * (0x48 - len(o))
    o += pck32(process_environment_address)
    jitter.vm.add_memory_page(
        process_parameters_address,
        PAGE_READ | PAGE_WRITE,
        o, "Process parameters"
    )


# http://blog.fireeye.com/research/2010/08/download_exec_notes.html
seh_count = 0


def init_seh(jitter):
    """
    Build the modules entries and create double links
    @jitter: jitter instance
    """

    global seh_count
    seh_count = 0
    tib_ad = jitter.cpu.get_segm_base(jitter.cpu.FS)
    build_teb(jitter, tib_ad)
    build_peb(jitter, peb_address)

    modules_info = create_modules_chain(jitter, name2module)
    fix_InLoadOrderModuleList(jitter, modules_info)
    fix_InMemoryOrderModuleList(jitter, modules_info)
    fix_InInitializationOrderModuleList(jitter, modules_info)

    build_ldr_data(jitter, modules_info)
    add_process_env(jitter)
    add_process_parameters(jitter)



def regs2ctxt(jitter, context_address):
    """
    Build x86_32 cpu context for exception handling
    @jitter: jitload instance
    """

    ctxt = ContextException(jitter.vm, context_address)
    ctxt.memset(b"\x00")
    # ContextFlags
    # XXX

    # DRX
    ctxt.dr0 = 0
    ctxt.dr1 = 0
    ctxt.dr2 = 0
    ctxt.dr3 = 0
    ctxt.dr4 = 0
    ctxt.dr5 = 0

    # Float context
    # XXX

    # Segment selectors
    ctxt.gs = jitter.cpu.GS
    ctxt.fs = jitter.cpu.FS
    ctxt.es = jitter.cpu.ES
    ctxt.ds = jitter.cpu.DS

    # Gpregs
    ctxt.edi = jitter.cpu.EDI
    ctxt.esi = jitter.cpu.ESI
    ctxt.ebx = jitter.cpu.EBX
    ctxt.edx = jitter.cpu.EDX
    ctxt.ecx = jitter.cpu.ECX
    ctxt.eax = jitter.cpu.EAX
    ctxt.ebp = jitter.cpu.EBP
    ctxt.eip = jitter.cpu.EIP

    # CS
    ctxt.cs = jitter.cpu.CS

    # Eflags
    # XXX TODO real eflag

    # ESP
    ctxt.esp = jitter.cpu.ESP

    # SS
    ctxt.ss = jitter.cpu.SS


def ctxt2regs(jitter, ctxt_ptr):
    """
    Restore x86_32 registers from an exception context
    @ctxt: the serialized context
    @jitter: jitload instance
    """

    ctxt = ContextException(jitter.vm, ctxt_ptr)

    # Selectors
    jitter.cpu.GS = ctxt.gs
    jitter.cpu.FS = ctxt.fs
    jitter.cpu.ES = ctxt.es
    jitter.cpu.DS = ctxt.ds

    # Gpregs
    jitter.cpu.EDI = ctxt.edi
    jitter.cpu.ESI = ctxt.esi
    jitter.cpu.EBX = ctxt.ebx
    jitter.cpu.EDX = ctxt.edx
    jitter.cpu.ECX = ctxt.ecx
    jitter.cpu.EAX = ctxt.eax
    jitter.cpu.EBP = ctxt.ebp
    jitter.cpu.EIP = ctxt.eip

    # CS
    jitter.cpu.CS = ctxt.cs

    # Eflag
    # XXX TODO

    # ESP
    jitter.cpu.ESP = ctxt.esp
    # SS
    jitter.cpu.SS = ctxt.ss


def fake_seh_handler(jitter, except_code, previous_seh=None):
    """
    Create an exception context
    @jitter: jitter instance
    @except_code: x86 exception code
    @previous_seh: (optional) last SEH address when multiple SEH are used
    """
    global seh_count
    log.info('Exception at %x %r', jitter.cpu.EIP, seh_count)
    seh_count += 1

    # Get space on stack for exception handling
    new_ESP = jitter.cpu.ESP - 0x3c8
    exception_base_address = new_ESP
    exception_record_address = exception_base_address + 0xe8
    context_address = exception_base_address + 0xfc
    fake_seh_address = exception_base_address + 0x14

    # Save a CONTEXT
    regs2ctxt(jitter, context_address)
    jitter.cpu.ESP = new_ESP

    # Get current seh (fs:[0])
    tib = NT_TIB(jitter.vm, tib_address)
    seh = tib.ExceptionList.deref
    if previous_seh:
        # Recursive SEH
        while seh.get_addr() != previous_seh:
            seh = seh.Next.deref
        seh = seh.Next.deref

    log.debug(
        'seh_ptr %x { old_seh %r eh %r} ctx_addr %x',
        seh.get_addr(),
        seh.Next,
        seh.Handler,
        context_address
    )

    # Write exception_record
    except_record = EXCEPTION_RECORD(jitter.vm, exception_record_address)
    except_record.memset(b"\x00")
    except_record.ExceptionCode = except_code
    except_record.ExceptionAddress = jitter.cpu.EIP

    # Prepare the stack
    jitter.push_uint32_t(context_address)               # Context
    jitter.push_uint32_t(seh.get_addr())                # SEH
    jitter.push_uint32_t(except_record.get_addr())      # ExceptRecords
    jitter.push_uint32_t(return_from_exception)         # Ret address

    # Set fake new current seh for exception
    log.debug("Fake seh ad %x", fake_seh_address)
    fake_seh = EXCEPTION_REGISTRATION_RECORD(jitter.vm, fake_seh_address)
    fake_seh.Next.val = tib.ExceptionList.val
    fake_seh.Handler = 0xaaaaaaaa
    tib.ExceptionList.val = fake_seh.get_addr()
    dump_seh(jitter)

    # Remove exceptions
    jitter.vm.set_exception(0)
    jitter.cpu.set_exception(0)

    # XXX set ebx to nul?
    jitter.cpu.EBX = 0

    log.debug('Jumping at %r', seh.Handler)
    return seh.Handler.val


def dump_seh(jitter):
    """
    Walk and dump the SEH entries
    @jitter: jitter instance
    """
    log.debug('Dump_seh. Tib_address: %x', tib_address)
    cur_seh_ptr = NT_TIB(jitter.vm, tib_address).ExceptionList
    loop = 0
    while cur_seh_ptr and jitter.vm.is_mapped(cur_seh_ptr.val,
                                              len(cur_seh_ptr)):
        if loop > MAX_SEH:
            log.debug("Too many seh, quit")
            return
        err = cur_seh_ptr.deref
        log.debug('\t' * (loop + 1) + 'seh_ptr: %x { prev_seh: %r eh %r }',
                 err.get_addr(), err.Next, err.Handler)
        cur_seh_ptr = err.Next
        loop += 1


def set_win_fs_0(jitter, fs=4):
    """
    Set FS segment selector and create its corresponding segment
    @jitter: jitter instance
    @fs: segment selector value
    """
    jitter.cpu.FS = fs
    jitter.cpu.set_segm_base(fs, tib_address)
    segm_to_do = set([x86_regs.FS])
    return segm_to_do


def return_from_seh(jitter):
    """Handle the return from an exception handler
    @jitter: jitter instance"""

    # Get object addresses
    seh_address = jitter.vm.get_u32(jitter.cpu.ESP + 0x4)
    context_address = jitter.vm.get_u32(jitter.cpu.ESP + 0x8)

    # Get registers changes
    log.debug('Context address: %x', context_address)
    status = jitter.cpu.EAX
    ctxt2regs(jitter, context_address)

    # Rebuild SEH (remove fake SEH)
    tib = NT_TIB(jitter.vm, tib_address)
    seh = tib.ExceptionList.deref
    log.debug('Old seh: %x New seh: %x', seh.get_addr(), seh.Next.val)
    tib.ExceptionList.val = seh.Next.val
    dump_seh(jitter)

    # Handle returned values
    if status == 0x0:
        # ExceptionContinueExecution
        log.debug('SEH continue')
        jitter.pc = jitter.cpu.EIP
        log.debug('Context::Eip: %x', jitter.pc)

    elif status == 1:
        # ExceptionContinueSearch
        log.debug("Delegate to the next SEH handler")
        # exception_base_address: context_address - 0xfc
        # -> exception_record_address: exception_base_address + 0xe8
        exception_record = EXCEPTION_RECORD(jitter.vm,
                                            context_address - 0xfc + 0xe8)

        pc = fake_seh_handler(jitter, exception_record.ExceptionCode,
                              seh_address)
        jitter.pc = pc

    else:
        # https://msdn.microsoft.com/en-us/library/aa260344%28v=vs.60%29.aspx
        # But the type _EXCEPTION_DISPOSITION may take 2 others values:
        #  - ExceptionNestedException = 2
        #  - ExceptionCollidedUnwind = 3
        raise ValueError("Valid values are ExceptionContinueExecution and "
                         "ExceptionContinueSearch")

    # Jitter's breakpoint compliant
    return True
