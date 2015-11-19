#!/usr/bin/env python
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

from elfesteem import pe_init

from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.core.utils import pck32, upck32
import miasm2.arch.x86.regs as x86_regs


# Constants Windows
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_ACCESS_VIOLATION = 0xc0000005
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xc0000094
EXCEPTION_PRIV_INSTRUCTION = 0xc0000096
EXCEPTION_ILLEGAL_INSTRUCTION = 0xc000001d


log = logging.getLogger("seh_helper")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

FS_0_AD = 0x7ff70000
PEB_AD = 0x7ffdf000
LDR_AD = 0x340000

MAX_MODULES = 0x40

# fs:[0] Page (TIB)
tib_address = FS_0_AD
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

default_seh = PEB_AD + 0x20000

process_environment_address = 0x10000
process_parameters_address = 0x200000

context_address = 0x201000
exception_record_address = context_address + 0x1000
return_from_exception = 0x6eadbeef

FAKE_SEH_B_AD = context_address + 0x2000

cur_seh_ad = FAKE_SEH_B_AD

name2module = []
main_pe = None
main_pe_name = "c:\\xxx\\toto.exe"

MAX_SEH = 5


def build_teb(jitter, teb_address):
    """
    Build TEB informations using following structure:

    +0x000 NtTib                     : _NT_TIB
    +0x01c EnvironmentPointer        : Ptr32 Void
    +0x020 ClientId                  : _CLIENT_ID
    +0x028 ActiveRpcHandle           : Ptr32 Void
    +0x02c ThreadLocalStoragePointer : Ptr32 Void
    +0x030 ProcessEnvironmentBlock   : Ptr32 _PEB
    +0x034 LastErrorValue            : Uint4B
    ...
    @jitter: jitter instance
    @teb_address: the TEB address
    """

    o = ""
    o += pck32(default_seh)
    o += (0x18 - len(o)) * "\x00"
    o += pck32(tib_address)

    o += (0x30 - len(o)) * "\x00"
    o += pck32(peb_address)
    o += pck32(0x11223344)

    jitter.vm.add_memory_page(teb_address, PAGE_READ | PAGE_WRITE, o)


def build_peb(jitter, peb_address):
    """
    Build PEB informations using following structure:

    +0x000 InheritedAddressSpace    : UChar
    +0x001 ReadImageFileExecOptions : UChar
    +0x002 BeingDebugged            : UChar
    +0x003 SpareBool                : UChar
    +0x004 Mutant                   : Ptr32 Void
    +0x008 ImageBaseAddress         : Ptr32 Void
    +0x00c Ldr                      : Ptr32 _PEB_LDR_DATA
    +0x010 processparameter

    @jitter: jitter instance
    @peb_address: the PEB address
    """

    offset = peb_address + 8
    o = ""
    if main_pe:
        o += pck32(main_pe.NThdr.ImageBase)
    else:
        offset += 4
    o += pck32(peb_ldr_data_address)
    o += pck32(process_parameters_address)
    jitter.vm.add_memory_page(offset, PAGE_READ | PAGE_WRITE, o)


def build_ldr_data(jitter, modules_info):
    """
    Build Loader informations using following structure:

    +0x000 Length                          : Uint4B
    +0x004 Initialized                     : UChar
    +0x008 SsHandle                        : Ptr32 Void
    +0x00c InLoadOrderModuleList           : _LIST_ENTRY
    +0x014 InMemoryOrderModuleList         : _LIST_ENTRY
    +0x01C InInitializationOrderModuleList         : _LIST_ENTRY

    @jitter: jitter instance
    @modules_info: LoadedModules instance

    """
    # ldr offset pad
    offset = LDR_AD + peb_ldr_data_offset + 0xC

    # get main pe info
    main_pe = modules_info.name2module.get(main_pe_name, None)
    if not main_pe:
        log.warn('No main pe, ldr data will be unconsistant')
        offset, data = offset + 8, ""
    else:
        main_addr_entry = modules_info.module2entry[main_pe]
        log.info('Ldr %x', main_addr_entry)
        data = pck32(main_addr_entry) + pck32(0)
        data += pck32(main_addr_entry + 0x8) + pck32(0)  # XXX TODO fix prev

    ntdll_pe = modules_info.name2module.get("ntdll.dll", None)
    if not ntdll_pe:
        log.warn('No ntdll, ldr data will be unconsistant')
    else:
        ntdll_addr_entry = modules_info.module2entry[ntdll_pe]
        data += pck32(ntdll_addr_entry + 0x10) + pck32(0)  # XXX TODO fix prev

    if data:
        jitter.vm.add_memory_page(offset, PAGE_READ | PAGE_WRITE, data)


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
        return "\n".join([str(x) for x in self.name2module.iteritems()])


def create_modules_chain(jitter, name2module):
    """
    Create the modules entries. Those modules are not linked in this function.

    kd> dt nt!_LDR_DATA_TABLE_ENTRY
    +0x000 InLoadOrderLinks : _LIST_ENTRY
    +0x008 InMemoryOrderLinks : _LIST_ENTRY
    +0x010 InInitializationOrderLinks : _LIST_ENTRY
    +0x018 DllBase : Ptr32 Void
    +0x01c EntryPoint : Ptr32 Void
    +0x020 SizeOfImage : Uint4B
    +0x024 FullDllName : _UNICODE_STRING
    +0x02c BaseDllName : _UNICODE_STRING
    +0x034 Flags : Uint4B
    +0x038 LoadCount : Uint2B
    +0x03a TlsIndex : Uint2B
    +0x03c HashLinks : _LIST_ENTRY
    +0x03c SectionPointer : Ptr32 Void
    +0x040 CheckSum : Uint4B
    +0x044 TimeDateStamp : Uint4B
    +0x044 LoadedImports : Ptr32 Void
    +0x048 EntryPointActivationContext : Ptr32 Void
    +0x04c PatchInformation : Ptr32 Void

    @jitter: jitter instance
    @name2module: dict containing association between name and its pe instance
    """

    modules_info = LoadedModules()
    base_addr = LDR_AD + modules_list_offset  # XXXX
    offset_name = 0x500
    offset_path = 0x600

    dummy_e = pe_init.PE()
    dummy_e.NThdr.ImageBase = 0
    dummy_e.Opthdr.AddressOfEntryPoint = 0
    dummy_e.NThdr.sizeofimage = 0

    out = ""
    for i, (fname, pe_obj) in enumerate([("", dummy_e)] + name2module.items()):
        if pe_obj is None:
            log.warning("Unknown module: ommited from link list (%r)",
                        fname)
            continue
        addr = base_addr + i * 0x1000
        bpath = fname.replace('/', '\\')
        bname_str = os.path.split(fname)[1].lower()
        bname = "\x00".join(bname_str) + "\x00"
        log.info("Add module %x %r", pe_obj.NThdr.ImageBase, bname_str)

        modules_info.add(bname_str, pe_obj, addr)

        m_o = ""
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(pe_obj.NThdr.ImageBase)
        m_o += pck32(pe_obj.rva2virt(pe_obj.Opthdr.AddressOfEntryPoint))
        m_o += pck32(pe_obj.NThdr.sizeofimage)
        m_o += struct.pack('HH', len(bname), len(bname) + 2)
        m_o += pck32(addr + offset_path)
        m_o += struct.pack('HH', len(bname), len(bname) + 2)
        m_o += pck32(addr + offset_name)
        jitter.vm.add_memory_page(addr, PAGE_READ | PAGE_WRITE, m_o)

        m_o = ""
        m_o += bname
        m_o += "\x00" * 3
        jitter.vm.add_memory_page(
            addr + offset_name, PAGE_READ | PAGE_WRITE, m_o)

        m_o = ""
        m_o += "\x00".join(bpath) + "\x00"
        m_o += "\x00" * 3
        jitter.vm.add_memory_page(
            addr + offset_path, PAGE_READ | PAGE_WRITE, m_o)

    return modules_info


def fix_InLoadOrderModuleList(jitter, modules_info):
    """Fix InLoadOrderModuleList double link list. First module is the main pe,
    then ntdll, kernel32. dummy is last pe.

    @jitter: the jitter instance
    @modules_info: the LoadedModules instance
    """

    log.debug("Fix InLoadOrderModuleList")
    main_pe = modules_info.name2module.get(main_pe_name, None)
    kernel32_pe = modules_info.name2module.get("kernel32.dll", None)
    ntdll_pe = modules_info.name2module.get("ntdll.dll", None)
    dummy_pe = modules_info.name2module.get("", None)
    special_modules = [main_pe, kernel32_pe, ntdll_pe, dummy_pe]
    if not all(special_modules):
        log.warn('No main pe, ldr data will be unconsistant %r', special_modules)
        loaded_modules = modules_info.modules
    else:
        loaded_modules = [module for module in modules_info.modules
                          if module not in special_modules]
        loaded_modules[0:0] = [main_pe]
        loaded_modules[1:1] = [ntdll_pe]
        loaded_modules[2:2] = [kernel32_pe]
        loaded_modules.append(dummy_pe)

    for i, module in enumerate(loaded_modules):
        cur_module_entry = modules_info.module2entry[module]
        prev_module = loaded_modules[(i - 1) % len(loaded_modules)]
        next_module = loaded_modules[(i + 1) % len(loaded_modules)]
        prev_module_entry = modules_info.module2entry[prev_module]
        next_module_entry = modules_info.module2entry[next_module]
        jitter.vm.set_mem(cur_module_entry,
                          (pck32(next_module_entry) +
                           pck32(prev_module_entry)))


def fix_InMemoryOrderModuleList(jitter, modules_info):
    """Fix InMemoryOrderLinks double link list. First module is the main pe,
    then ntdll, kernel32. dummy is last pe.

    @jitter: the jitter instance
    @modules_info: the LoadedModules instance
    """

    log.debug("Fix InMemoryOrderModuleList")
    main_pe = modules_info.name2module.get(main_pe_name, None)
    kernel32_pe = modules_info.name2module.get("kernel32.dll", None)
    ntdll_pe = modules_info.name2module.get("ntdll.dll", None)
    dummy_pe = modules_info.name2module.get("", None)
    special_modules = [main_pe, kernel32_pe, ntdll_pe, dummy_pe]
    if not all(special_modules):
        log.warn('No main pe, ldr data will be unconsistant')
        loaded_modules = modules_info.modules
    else:
        loaded_modules = [module for module in modules_info.modules
                          if module not in special_modules]
        loaded_modules[0:0] = [main_pe]
        loaded_modules[1:1] = [ntdll_pe]
        loaded_modules[2:2] = [kernel32_pe]
        loaded_modules.append(dummy_pe)

    for i, module in enumerate(loaded_modules):
        cur_module_entry = modules_info.module2entry[module]
        prev_module = loaded_modules[(i - 1) % len(loaded_modules)]
        next_module = loaded_modules[(i + 1) % len(loaded_modules)]
        prev_module_entry = modules_info.module2entry[prev_module]
        next_module_entry = modules_info.module2entry[next_module]
        jitter.vm.set_mem(cur_module_entry + 0x8,
                          (pck32(next_module_entry + 0x8) +
                           pck32(prev_module_entry + 0x8)))


def fix_InInitializationOrderModuleList(jitter, modules_info):
    """Fix InInitializationOrderModuleList double link list. First module is the
    ntdll, then kernel32. dummy is last pe.

    @jitter: the jitter instance
    @modules_info: the LoadedModules instance

    """

    log.debug("Fix InInitializationOrderModuleList")
    main_pe = modules_info.name2module.get(main_pe_name, None)
    kernel32_pe = modules_info.name2module.get("kernel32.dll", None)
    ntdll_pe = modules_info.name2module.get("ntdll.dll", None)
    dummy_pe = modules_info.name2module.get("", None)
    special_modules = [main_pe, kernel32_pe, ntdll_pe, dummy_pe]
    if not all(special_modules):
        log.warn('No main pe, ldr data will be unconsistant')
        loaded_modules = modules_info.modules
    else:
        loaded_modules = [module for module in modules_info.modules
                          if module not in special_modules]
        loaded_modules[0:0] = [ntdll_pe]
        loaded_modules[1:1] = [kernel32_pe]
        loaded_modules.append(dummy_pe)

    for i, module in enumerate(loaded_modules):
        cur_module_entry = modules_info.module2entry[module]
        prev_module = loaded_modules[(i - 1) % len(loaded_modules)]
        next_module = loaded_modules[(i + 1) % len(loaded_modules)]
        prev_module_entry = modules_info.module2entry[prev_module]
        next_module_entry = modules_info.module2entry[next_module]
        jitter.vm.set_mem(cur_module_entry + 0x10,
                          (pck32(next_module_entry + 0x10) +
                           pck32(prev_module_entry + 0x10)))


def add_process_env(jitter):
    """
    Build a process environement structure
    @jitter: jitter instance
    """

    env_str = 'ALLUSEESPROFILE=C:\\Documents and Settings\\All Users\x00'
    env_str = '\x00'.join(env_str)
    env_str += "\x00" * 0x10
    jitter.vm.add_memory_page(process_environment_address,
                              PAGE_READ | PAGE_WRITE,
                              env_str)
    jitter.vm.set_mem(process_environment_address, env_str)


def add_process_parameters(jitter):
    """
    Build a process parameters structure
    @jitter: jitter instance
    """

    o = ""
    o += pck32(0x1000)  # size
    o += "E" * (0x48 - len(o))
    o += pck32(process_environment_address)
    jitter.vm.add_memory_page(process_parameters_address,
                              PAGE_READ | PAGE_WRITE,
                              o)


all_seh_ad = dict([(x, None)
                  for x in xrange(FAKE_SEH_B_AD, FAKE_SEH_B_AD + 0x1000, 0x20)])
# http://blog.fireeye.com/research/2010/08/download_exec_notes.html
seh_count = 0


def init_seh(jitter):
    """
    Build the modules entries and create double links
    @jitter: jitter instance
    """

    global seh_count
    seh_count = 0
    build_teb(jitter, FS_0_AD)
    build_peb(jitter, peb_address)

    modules_info = create_modules_chain(jitter, name2module)
    fix_InLoadOrderModuleList(jitter, modules_info)
    fix_InMemoryOrderModuleList(jitter, modules_info)
    fix_InInitializationOrderModuleList(jitter, modules_info)

    build_ldr_data(jitter, modules_info)
    add_process_env(jitter)
    add_process_parameters(jitter)

    jitter.vm.add_memory_page(default_seh, PAGE_READ | PAGE_WRITE, pck32(
        0xffffffff) + pck32(0x41414141) + pck32(0x42424242))

    jitter.vm.add_memory_page(
        context_address, PAGE_READ | PAGE_WRITE, '\x00' * 0x2cc)
    jitter.vm.add_memory_page(
        exception_record_address, PAGE_READ | PAGE_WRITE, '\x00' * 200)

    jitter.vm.add_memory_page(
        FAKE_SEH_B_AD, PAGE_READ | PAGE_WRITE, 0x10000 * "\x00")

# http://www.codeproject.com/KB/system/inject2exe.aspx#RestorethefirstRegistersContext5_1


def regs2ctxt(jitter):
    """
    Build x86_32 cpu context for exception handling
    @jitter: jitload instance
    """

    ctxt = []
    # ContextFlags
    ctxt += [pck32(0x0)]
    # DRX
    ctxt += [pck32(0x0)] * 6
    # Float context
    ctxt += ['\x00' * 112]
    # Segment selectors
    ctxt += [pck32(reg) for reg in (jitter.cpu.GS, jitter.cpu.FS,
                                    jitter.cpu.ES, jitter.cpu.DS)]
    # Gpregs
    ctxt += [pck32(reg) for reg in (jitter.cpu.EDI, jitter.cpu.ESI,
                                    jitter.cpu.EBX, jitter.cpu.EDX,
                                    jitter.cpu.ECX, jitter.cpu.EAX,
                                    jitter.cpu.EBP, jitter.cpu.EIP)]
    # CS
    ctxt += [pck32(jitter.cpu.CS)]
    # Eflags
    # XXX TODO real eflag
    ctxt += [pck32(0x0)]
    # ESP
    ctxt += [pck32(jitter.cpu.ESP)]
    # SS
    ctxt += [pck32(jitter.cpu.SS)]
    return "".join(ctxt)


def ctxt2regs(ctxt, jitter):
    """
    Restore x86_32 registers from an exception context
    @ctxt: the serialized context
    @jitter: jitload instance
    """

    ctxt = ctxt[:]
    # ContextFlags
    ctxt = ctxt[4:]
    # DRX XXX TODO
    ctxt = ctxt[4 * 6:]
    # Float context XXX TODO
    ctxt = ctxt[112:]
    # gs
    jitter.cpu.GS = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    # fs
    jitter.cpu.FS = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    # es
    jitter.cpu.ES = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    # ds
    jitter.cpu.DS = upck32(ctxt[:4])
    ctxt = ctxt[4:]

    # Gpregs
    jitter.cpu.EDI = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    jitter.cpu.ESI = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    jitter.cpu.EBX = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    jitter.cpu.EDX = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    jitter.cpu.ECX = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    jitter.cpu.EAX = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    jitter.cpu.EBP = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    jitter.cpu.EIP = upck32(ctxt[:4])
    ctxt = ctxt[4:]

    # CS
    jitter.cpu.CS = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    # Eflag XXX TODO
    ctxt = ctxt[4:]
    # ESP
    jitter.cpu.ESP = upck32(ctxt[:4])
    ctxt = ctxt[4:]


def fake_seh_handler(jitter, except_code):
    """
    Create an exception context
    @jitter: jitter instance
    @except_code: x86 exception code
    """

    global seh_count, context_address
    regs = jitter.cpu.get_gpreg()
    log.warning('Exception at %x %r', jitter.cpu.EIP, seh_count)
    seh_count += 1

    # Help lambda
    p = lambda s: struct.pack('I', s)

    # Forge a CONTEXT
    ctxt = regs2ctxt(jitter)

    # Get current seh (fs:[0])
    seh_ptr = upck32(jitter.vm.get_mem(tib_address, 4))

    # Retrieve seh fields
    old_seh, eh, safe_place = struct.unpack(
        'III', jitter.vm.get_mem(seh_ptr, 0xc))

    # Get space on stack for exception handling
    jitter.cpu.ESP -= 0x3c8
    exception_base_address = jitter.cpu.ESP
    exception_record_address = exception_base_address + 0xe8
    context_address = exception_base_address + 0xfc
    fake_seh_address = exception_base_address + 0x14

    log.info('seh_ptr %x { old_seh %x eh %x safe_place %x} ctx_addr %x',
             seh_ptr, old_seh, eh, safe_place, context_address)

    # Write context
    jitter.vm.set_mem(context_address, ctxt)

    # Write exception_record

    """
    #http://msdn.microsoft.com/en-us/library/aa363082(v=vs.85).aspx

    typedef struct _EXCEPTION_RECORD {
      DWORD                    ExceptionCode;
      DWORD                    ExceptionFlags;
      struct _EXCEPTION_RECORD *ExceptionRecord;
      PVOID                    ExceptionAddress;
      DWORD                    NumberParameters;
      ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    } EXCEPTION_RECORD, *PEXCEPTION_RECORD;
    """

    jitter.vm.set_mem(exception_record_address,
                      pck32(except_code) + pck32(0) + pck32(0) +
                      pck32(jitter.cpu.EIP) + pck32(0))

    # Prepare the stack
    jitter.push_uint32_t(context_address)               # Context
    jitter.push_uint32_t(seh_ptr)                       # SEH
    jitter.push_uint32_t(exception_record_address)      # ExceptRecords
    jitter.push_uint32_t(return_from_exception)         # Ret address

    # Set fake new current seh for exception
    log.info("Fake seh ad %x", fake_seh_address)
    jitter.vm.set_mem(fake_seh_address, pck32(seh_ptr) + pck32(
        0xaaaaaaaa) + pck32(0xaaaaaabb) + pck32(0xaaaaaacc))
    jitter.vm.set_mem(tib_address, pck32(fake_seh_address))

    dump_seh(jitter)

    log.info('Jumping at %x', eh)
    jitter.vm.set_exception(0)
    jitter.cpu.set_exception(0)

    # XXX set ebx to nul?
    jitter.cpu.EBX = 0

    return eh

fake_seh_handler.base = FAKE_SEH_B_AD


def dump_seh(jitter):
    """
    Walk and dump the SEH entries
    @jitter: jitter instance
    """

    log.info('Dump_seh. Tib_address: %x', tib_address)
    cur_seh_ptr = upck32(jitter.vm.get_mem(tib_address, 4))
    indent = 1
    loop = 0
    while True:
        if loop > MAX_SEH:
            log.warn("Too many seh, quit")
            return
        prev_seh, eh = struct.unpack('II', jitter.vm.get_mem(cur_seh_ptr, 8))
        log.info('\t' * indent + 'seh_ptr: %x { prev_seh: %x eh %x }',
                 cur_seh_ptr, prev_seh, eh)
        if prev_seh in [0xFFFFFFFF, 0]:
            break
        cur_seh_ptr = prev_seh
        indent += 1
        loop += 1


def set_win_fs_0(jitter, fs=4):
    """
    Set FS segment selector and create its corresponding segment
    @jitter: jitter instance
    @fs: segment selector value
    """

    regs = jitter.cpu.get_gpreg()
    regs['FS'] = 0x4
    jitter.cpu.set_gpreg(regs)
    jitter.cpu.set_segm_base(regs['FS'], FS_0_AD)
    segm_to_do = set([x86_regs.FS])
    return segm_to_do


def return_from_seh(jitter):
    """Handle the return from an exception handler
    @jitter: jitter instance"""

    # Get current context
    context_address = upck32(jitter.vm.get_mem(jitter.cpu.ESP + 0x8, 4))
    log.info('Context address: %x', context_address)
    jitter.cpu.ESP = upck32(jitter.vm.get_mem(context_address + 0xc4, 4))
    log.info('New esp: %x', jitter.cpu.ESP)

    # Rebuild SEH
    old_seh = upck32(jitter.vm.get_mem(tib_address, 4))
    new_seh = upck32(jitter.vm.get_mem(old_seh, 4))
    log.info('Old seh: %x New seh: %x', old_seh, new_seh)
    jitter.vm.set_mem(tib_address, pck32(new_seh))

    dump_seh(jitter)

    if jitter.cpu.EAX == 0x0:
        # ExceptionContinueExecution
        ctxt_ptr = context_address
        log.info('Seh continues Context: %x', ctxt_ptr)

        # Get registers changes
        ctxt_str = jitter.vm.get_mem(ctxt_ptr, 0x2cc)
        ctxt2regs(ctxt_str, jitter)
        jitter.pc = jitter.cpu.EIP
        log.info('Context::Eip: %x', jitter.pc)

    elif jitter.cpu.EAX == -1:
        raise NotImplementedError("-> seh try to go to the next handler")

    elif jitter.cpu.EAX == 1:
        # ExceptionContinueSearch
        raise NotImplementedError("-> seh, gameover")
