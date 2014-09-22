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
from elfesteem import pe_init
from miasm2.jitter.csts import *
from miasm2.core.utils import *
import miasm2.arch.x86.regs as x86_regs
import os

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
log.setLevel(logging.WARN)

FS_0_AD = 0x7ff70000
PEB_AD = 0x7ffdf000
LDR_AD = 0x340000

MAX_MODULES = 0x40

# fs:[0] Page (TIB)
tib_address = FS_0_AD
peb_address = PEB_AD
peb_ldr_data_offset = 0x1ea0
peb_ldr_data_address = LDR_AD + peb_ldr_data_offset  # PEB_AD + 0x1000


modules_list_offset = 0x1f00

InInitializationOrderModuleList_offset = 0x1ee0  # 0x1f48
InInitializationOrderModuleList_address = LDR_AD + \
    InInitializationOrderModuleList_offset  # PEB_AD + 0x2000

InLoadOrderModuleList_offset = 0x1ee0 + \
    MAX_MODULES * 0x1000  # 0x1f48 + MAX_MODULES*0x1000
InLoadOrderModuleList_address = LDR_AD + \
    InLoadOrderModuleList_offset  # PEB_AD + 0x2000

# in_load_order_module_1 = LDR_AD +
# in_load_order_module_list_offset#PEB_AD + 0x3000
default_seh = PEB_AD + 0x20000

process_environment_address = 0x10000
process_parameters_address = 0x200000

context_address = 0x201000
exception_record_address = context_address + 0x1000
return_from_exception = 0x6eadbeef

FAKE_SEH_B_AD = context_address + 0x2000

cur_seh_ad = FAKE_SEH_B_AD

loaded_modules = ["ntdll.dll", "kernel32.dll"]
main_pe = None
main_pe_name = "c:\\xxx\\toto.exe"


def build_fake_teb():
    """
    +0x000 NtTib                     : _NT_TIB
    +0x01c EnvironmentPointer        : Ptr32 Void
    +0x020 ClientId                  : _CLIENT_ID
    +0x028 ActiveRpcHandle           : Ptr32 Void
    +0x02c ThreadLocalStoragePointer : Ptr32 Void
    +0x030 ProcessEnvironmentBlock   : Ptr32 _PEB
    +0x034 LastErrorValue            : Uint4B
    ...
    """
    o = ""
    o += pck32(default_seh)
    o += (0x18 - len(o)) * "\x00"
    o += pck32(tib_address)

    o += (0x30 - len(o)) * "\x00"
    o += pck32(peb_address)
    o += pck32(0x11223344)

    return o


def build_fake_peb():
    """
    +0x000 InheritedAddressSpace    : UChar
    +0x001 ReadImageFileExecOptions : UChar
    +0x002 BeingDebugged            : UChar
    +0x003 SpareBool                : UChar
    +0x004 Mutant                   : Ptr32 Void
    +0x008 ImageBaseAddress         : Ptr32 Void
    +0x00c Ldr                      : Ptr32 _PEB_LDR_DATA
    +0x010 processparameter
    """

    offset_serverdata = 0x100
    offset_data1 = 0x108
    offset_data2 = 0x110
    o = ""
    o += "\x00" * 0x8
    if main_pe:
        o += pck32(main_pe.NThdr.ImageBase)
    else:
        o += "AAAA"
    o += pck32(peb_ldr_data_address)
    o += pck32(process_parameters_address)

    o += (0x54 - len(o)) * "A"
    o += pck32(peb_address + offset_serverdata)
    o += (0x64 - len(o)) * "E"
    o += pck32(1)  # number of cpu

    o += (offset_serverdata - len(o)) * "B"
    o += pck32(0x33333333)
    o += pck32(peb_address + offset_data1)
    o += (offset_data1 - len(o)) * "C"
    o += pck32(0x44444444)
    o += pck32(peb_address + offset_data2)
    o += (offset_data2 - len(o)) * "D"
    o += pck32(0x55555555)
    o += pck32(0x0077007C)
    return o


def build_fake_ldr_data(modules_info):
    """
    +0x000 Length                          : Uint4B
    +0x004 Initialized                     : UChar
    +0x008 SsHandle                        : Ptr32 Void
    +0x00c InLoadOrderModuleList           : _LIST_ENTRY
    +0x014 InMemoryOrderModuleList         : _LIST_ENTRY
    +0x01C InInitializationOrderModuleList         : _LIST_ENTRY
    """
    o = ""
    # ldr offset pad
    o += "\x00" * peb_ldr_data_offset
    o += "\x00" * 0xc
    # text XXX

    # get main pe info
    m_e = None
    for bname, (addr, e) in modules_info.items():
        if e == main_pe:
            m_e = (e, bname, addr)
            break
    if not m_e:
        log.warn('no main pe, ldr data will be unconsistant')
    else:
        print 'inloadorder first', hex(m_e[2])
        o += pck32(m_e[2]) + pck32(0)

    # get ntdll
    ntdll_e = None
    for bname, (addr, e) in modules_info.items():
        if bname[::2].lower() == "ntdll.dll":
            ntdll_e = (e, bname, addr)
            continue
    if not ntdll_e:
        log.warn('no ntdll, ldr data will be unconsistant')
    else:
        print 'ntdll', hex(ntdll_e[2])
        o += pck32(ntdll_e[2] + 0x8) + pck32(0)  # XXX TODO
        o += pck32(ntdll_e[2] + 0x10) + pck32(0)

    return o

# def build_fake_InInitializationOrderModuleList(modules_name):
#    """
#    +0x000 Flink : Ptr32                                 -+ This distance
#    +0x004 Blink : Ptr32                                  | is eight bytes
#    +0x018 DllBase                        : Ptr32 Void   -+ DllBase
#    +0x01c EntryPoint                     : Ptr32 Void
#    +0x020 SizeOfImage                    : Uint4B
#    +0x024 FullDllName                    : _UNICODE_STRING
#    +0x02c BaseDllName                    : _UNICODE_STRING
#    +0x034 Flags                          : Uint4B
#    +0x038 LoadCount                      : Uint2B
#    +0x03a TlsIndex                       : Uint2B
#    +0x03c HashLinks                      : _LIST_ENTRY
#    +0x03c SectionPointer                 : Ptr32 Void
#    +0x040 CheckSum                       : Uint4B
#    +0x044 TimeDateStamp                  : Uint4B
#    +0x044 LoadedImports                  : Ptr32 Void
#    +0x048 EntryPointActivationContext    : Ptr32 Void
#    +0x04c PatchInformation               : Ptr32 Void
#    """
#
#    o = ""
#    offset_name = 0x700
#    for i, m in enumerate(modules_name):
# fname = os.path.join('win_dll', m)
#        if isinstance(m, tuple):
#            fname, e = m
#        else:
#            fname, e = m, None
#        bname = os.path.split(fname)[1].lower()
#        bname = "\x00".join(bname)+"\x00"
#        print "add module", repr(bname)
#        print hex(InInitializationOrderModuleList_address+i*0x1000)
#        if e == None:
#            e = pe_init.PE(open(fname, 'rb').read())
#
#        next_ad = InInitializationOrderModuleList_address + (i+1)*0x1000
#        if i == len(modules_name) -1:
#            next_ad = InInitializationOrderModuleList_address
#        m_o = ""
#        m_o += pck32(next_ad )
#        m_o += pck32(InInitializationOrderModuleList_address + (i-1)*0x1000)
#        m_o += pck32(next_ad + 8 )
#        m_o += pck32(InInitializationOrderModuleList_address
#            +  (i-1)*0x1000 + 8)
#        m_o += pck32(next_ad + 0x10 )
#        m_o += pck32(InInitializationOrderModuleList_address
#            +  (i-1)*0x1000 + 0x10)
#        m_o += pck32(e.NThdr.ImageBase)
#        m_o += pck32(e.rva2virt(e.Opthdr.AddressOfEntryPoint))
#        m_o += pck32(e.NThdr.sizeofimage)
#
#        m_o += (0x24 - len(m_o))*"A"
#        print hex(len(bname)), repr(bname)
#        m_o += struct.pack('HH', len(bname), len(bname)+2)
#        m_o += pck32(InInitializationOrderModuleList_address
#            +  i*0x1000+offset_name)
#
#        m_o += (0x2C - len(m_o))*"A"
#        m_o += struct.pack('HH', len(bname), len(bname)+2)
#        m_o += pck32(InInitializationOrderModuleList_address
#            +  i*0x1000+offset_name)
#
#        m_o += (offset_name - len(m_o))*"B"
#        m_o += bname
#        m_o += "\x00"*3
#
#
#        m_o += (0x1000 - len(m_o))*"J"
#
#        print "module", "%.8X"%e.NThdr.ImageBase, fname
#
#        o += m_o
#    return o
#
dummy_e = pe_init.PE()
dummy_e.NThdr.ImageBase = 0
dummy_e.Opthdr.AddressOfEntryPoint = 0
dummy_e.NThdr.sizeofimage = 0


def create_modules_chain(myjit, modules_name):
    modules_info = {}
    base_addr = LDR_AD + modules_list_offset  # XXXX
    offset_name = 0x500
    offset_path = 0x600

    out = ""
    for i, m in enumerate([(main_pe_name, main_pe),
        ("", dummy_e)] + modules_name):
        addr = base_addr + i * 0x1000
        # fname = os.path.join('win_dll', m)
        if isinstance(m, tuple):
            fname, e = m
        else:
            fname, e = m, None
        bpath = fname.replace('/', '\\')
        bname = os.path.split(fname)[1].lower()
        bname = "\x00".join(bname) + "\x00"
        # print "add module", repr(bname), repr(bpath)
        # print hex(InInitializationOrderModuleList_address+i*0x1000)
        if e is None:
            if i == 0:
                full_name = fname
            else:
                full_name = os.path.join("win_dll", fname)
            try:
                e = pe_init.PE(open(full_name, 'rb').read())
            except IOError:
                log.error('no main pe, ldr data will be unconsistant!!')
                e = None
        if e is None:
            continue
        print "add module", hex(e.NThdr.ImageBase), repr(bname)

        modules_info[bname] = addr, e

        m_o = ""
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(0)
        m_o += pck32(e.NThdr.ImageBase)
        m_o += pck32(e.rva2virt(e.Opthdr.AddressOfEntryPoint))
        m_o += pck32(e.NThdr.sizeofimage)

        m_o += (0x24 - len(m_o)) * "A"
        print hex(len(bname)), repr(bname)
        m_o += struct.pack('HH', len(bname), len(bname) + 2)
        m_o += pck32(addr + offset_path)

        m_o += (0x2C - len(m_o)) * "A"
        m_o += struct.pack('HH', len(bname), len(bname) + 2)
        m_o += pck32(addr + offset_name)

        m_o += (offset_name - len(m_o)) * "B"
        m_o += bname
        m_o += "\x00" * 3

        m_o += (offset_path - len(m_o)) * "B"
        m_o += "\x00".join(bpath) + "\x00"
        m_o += "\x00" * 3
        # out += m_o
        myjit.vm.vm_set_mem(addr, m_o)
    return modules_info


def fix_InLoadOrderModuleList(myjit, module_info):
    print "fix inloadorder"
    # first binary is PE
    # last is dumm_e
    olist = []
    m_e = None
    d_e = None
    for m in [main_pe_name, ""] + loaded_modules:

        if isinstance(m, tuple):
            fname, e = m
        else:
            fname, e = m, None

        if "/" in fname:
            fname = fname[fname.rfind("/") + 1:]
        bname = '\x00'.join(fname) + '\x00'
        if not bname.lower() in module_info:
            log.warn('module not found, ldr data will be unconsistant')
            continue

        addr, e = module_info[bname.lower()]
    # for bname, (addr, e) in module_info.items():
        print bname
        if e == main_pe:
            m_e = (e, bname, addr)
            continue
        elif e == dummy_e:
            d_e = (e, bname, addr)
            continue
        olist.append((e, bname, addr))
    if not m_e or not d_e:
        log.warn('no main pe, ldr data will be unconsistant')
    else:
        olist[0:0] = [m_e]
    olist.append(d_e)

    last_addr = 0
    for i in xrange(len(olist)):
        e, bname, addr = olist[i]
        p_e, p_bname, p_addr = olist[(i - 1) % len(olist)]
        n_e, n_bname, n_addr = olist[(i + 1) % len(olist)]
        myjit.vm.vm_set_mem(addr + 0, pck32(n_addr) + pck32(p_addr))


def fix_InMemoryOrderModuleList(myjit, module_info):
    # first binary is PE
    # last is dumm_e
    olist = []
    m_e = None
    d_e = None
    for m in [main_pe_name, ""] + loaded_modules:

        if isinstance(m, tuple):
            fname, e = m
        else:
            fname, e = m, None

        if "/" in fname:
            fname = fname[fname.rfind("/") + 1:]
        bname = '\x00'.join(fname) + '\x00'
        if not bname.lower() in module_info:
            log.warn('module not found, ldr data will be unconsistant')
            continue
        addr, e = module_info[bname.lower()]
    # for bname, (addr, e) in module_info.items():
        print bname
        if e == main_pe:
            m_e = (e, bname, addr)
            continue
        elif e == dummy_e:
            d_e = (e, bname, addr)
            continue
        olist.append((e, bname, addr))
    if not m_e or not d_e:
        log.warn('no main pe, ldr data will be unconsistant')
    else:
        olist[0:0] = [m_e]
    olist.append(d_e)

    last_addr = 0

    for i in xrange(len(olist)):
        e, bname, addr = olist[i]
        p_e, p_bname, p_addr = olist[(i - 1) % len(olist)]
        n_e, n_bname, n_addr = olist[(i + 1) % len(olist)]
        myjit.vm.vm_set_mem(
            addr + 0x8, pck32(n_addr + 0x8) + pck32(p_addr + 0x8))


def fix_InInitializationOrderModuleList(myjit, module_info):
    # first binary is ntdll
    # second binary is kernel32
    olist = []
    ntdll_e = None
    kernel_e = None
    for bname, (addr, e) in module_info.items():
        if bname[::2].lower() == "ntdll.dll":
            ntdll_e = (e, bname, addr)
            continue
        elif bname[::2].lower() == "kernel32.dll":
            kernel_e = (e, bname, addr)
            continue
        elif e == dummy_e:
            d_e = (e, bname, addr)
            continue
        elif e == main_pe:
            continue
        olist.append((e, bname, addr))
    if not ntdll_e or not kernel_e or not d_e:
        log.warn('no kernel ntdll, ldr data will be unconsistant')
    else:
        olist[0:0] = [ntdll_e]
        olist[1:1] = [kernel_e]

    olist.append(d_e)

    last_addr = 0
    for i in xrange(len(olist)):
        e, bname, addr = olist[i]
        p_e, p_bname, p_addr = olist[(i - 1) % len(olist)]
        n_e, n_bname, n_addr = olist[(i + 1) % len(olist)]
        myjit.vm.vm_set_mem(
            addr + 0x10, pck32(n_addr + 0x10) + pck32(p_addr + 0x10))


def add_process_env(myjit):
    env_str = 'ALLUSEESPROFILE=C:\\Documents and Settings\\All Users\x00'
    env_str = '\x00'.join(env_str)
    env_str += "\x00" * 0x10
    myjit.vm.vm_add_memory_page(process_environment_address,
                                PAGE_READ | PAGE_WRITE,
                                env_str)
    myjit.vm.vm_set_mem(process_environment_address, env_str)


def add_process_parameters(myjit):
    o = ""
    o += pck32(0x1000)  # size
    o += "E" * (0x48 - len(o))
    o += pck32(process_environment_address)
    myjit.vm.vm_add_memory_page(process_parameters_address,
                                PAGE_READ | PAGE_WRITE,
                                o)


def build_fake_InLoadOrderModuleList(modules_name):
    """
    +0x000 Flink : Ptr32                                 -+ This distance
    +0x004 Blink : Ptr32                                  | is eight bytes
    +0x018 DllBase                        : Ptr32 Void   -+ DllBase -> _IMAGE_DOS_HEADER
    +0x01c EntryPoint                     : Ptr32 Void
    +0x020 SizeOfImage                    : Uint4B
    +0x024 FullDllName                    : _UNICODE_STRING
    +0x02c BaseDllName                    : _UNICODE_STRING
    +0x034 Flags                          : Uint4B
    +0x038 LoadCount                      : Uint2B
    +0x03a TlsIndex                       : Uint2B
    +0x03c HashLinks                      : _LIST_ENTRY
    +0x03c SectionPointer                 : Ptr32 Void
    +0x040 CheckSum                       : Uint4B
    +0x044 TimeDateStamp                  : Uint4B
    +0x044 LoadedImports                  : Ptr32 Void
    +0x048 EntryPointActivationContext    : Ptr32 Void
    +0x04c PatchInformation               : Ptr32 Void
    """

    o = ""
    offset_name = 0x700
    first_name = "\x00".join(main_pe_name + "\x00\x00")

    o = ""
    o += pck32(InLoadOrderModuleList_address)
    o += pck32(InLoadOrderModuleList_address +
               (len(modules_name) - 1) * 0x1000)
    o += pck32(InLoadOrderModuleList_address + 8)
    o += pck32(InLoadOrderModuleList_address +
               (len(modules_name) - 1) * 0x1000 + 8)
    o += pck32(InLoadOrderModuleList_address + 0x10)
    o += pck32(InLoadOrderModuleList_address +
               (len(modules_name) - 1) * 0x1000 + 0x10)

    if main_pe:
        o += pck32(main_pe.NThdr.ImageBase)
        o += pck32(main_pe.rva2virt(main_pe.Opthdr.AddressOfEntryPoint))
    else:
        # no fixed values
        pass

    o += (0x24 - len(o)) * "A"
    o += struct.pack('HH', len(first_name), len(first_name))
    o += pck32(InLoadOrderModuleList_address + offset_name)

    o += (0x2C - len(o)) * "A"
    o += struct.pack('HH', len(first_name), len(first_name))
    o += pck32(InLoadOrderModuleList_address + offset_name)

    o += (offset_name - len(o)) * "B"
    o += first_name
    o += (0x1000 - len(o)) * "C"
    for i, m in enumerate(modules_name):
        # fname = os.path.join('win_dll', m)
        if isinstance(m, tuple):
            fname, e = m
        else:
            fname, e = m, None
        bname = os.path.split(fname)[1].lower()
        bname = "\x00".join(bname) + "\x00"
        print hex(InLoadOrderModuleList_address + i * 0x1000)
        if e is None:
            e = pe_init.PE(open(fname, 'rb').read())

        print "add module", hex(e.NThdr.ImageBase), repr(bname)

        next_ad = InLoadOrderModuleList_address + (i + 1) * 0x1000
        if i == len(modules_name) - 1:
            next_ad = InLoadOrderModuleList_address
        m_o = ""
        m_o += pck32(next_ad)
        m_o += pck32(InLoadOrderModuleList_address + (i - 1) * 0x1000)
        m_o += pck32(next_ad + 8)
        m_o += pck32(InLoadOrderModuleList_address + (i - 1) * 0x1000 + 8)
        m_o += pck32(next_ad + 0x10)
        m_o += pck32(InLoadOrderModuleList_address + (i - 1) * 0x1000 + 0x10)
        m_o += pck32(e.NThdr.ImageBase)
        m_o += pck32(e.rva2virt(e.Opthdr.AddressOfEntryPoint))
        m_o += pck32(e.NThdr.sizeofimage)

        m_o += (0x24 - len(m_o)) * "A"
        print hex(len(bname)), repr(bname)
        m_o += struct.pack('HH', len(bname), len(bname) + 2)
        m_o += pck32(InLoadOrderModuleList_address + i * 0x1000 + offset_name)

        m_o += (0x2C - len(m_o)) * "A"
        m_o += struct.pack('HH', len(bname), len(bname) + 2)
        m_o += pck32(InLoadOrderModuleList_address + i * 0x1000 + offset_name)

        m_o += (offset_name - len(m_o)) * "B"
        m_o += bname
        m_o += "\x00" * 3

        m_o += (0x1000 - len(m_o)) * "J"

        print "module", "%.8X" % e.NThdr.ImageBase, fname

        o += m_o
    return o


all_seh_ad = dict([(x, None)
                  for x in xrange(FAKE_SEH_B_AD, FAKE_SEH_B_AD + 0x1000, 0x20)])
# http://blog.fireeye.com/research/2010/08/download_exec_notes.html


def init_seh(myjit):
    global seh_count
    seh_count = 0
    # myjit.vm.vm_add_memory_page(tib_address, PAGE_READ | PAGE_WRITE,
    # p(default_seh) + p(0) * 11 + p(peb_address))
    myjit.vm.vm_add_memory_page(
        FS_0_AD, PAGE_READ | PAGE_WRITE, build_fake_teb())
    # myjit.vm.vm_add_memory_page(peb_address, PAGE_READ | PAGE_WRITE, p(0) *
    # 3 + p(peb_ldr_data_address))
    myjit.vm.vm_add_memory_page(
        peb_address, PAGE_READ | PAGE_WRITE, build_fake_peb())
    # myjit.vm.vm_add_memory_page(peb_ldr_data_address, PAGE_READ |
    # PAGE_WRITE, p(0) * 3 + p(in_load_order_module_list_address) + p(0) *
    # 0x20)

    """
    ldr_data += "\x00"*(InInitializationOrderModuleList_offset - len(ldr_data))
    ldr_data += build_fake_InInitializationOrderModuleList(loaded_modules)
    ldr_data += "\x00"*(InLoadOrderModuleList_offset - len(ldr_data))
    ldr_data += build_fake_InLoadOrderModuleList(loaded_modules)
    """
    myjit.vm.vm_add_memory_page(
        LDR_AD, PAGE_READ | PAGE_WRITE, "\x00" * MAX_MODULES * 0x1000)
    module_info = create_modules_chain(myjit, loaded_modules)
    fix_InLoadOrderModuleList(myjit, module_info)
    fix_InMemoryOrderModuleList(myjit, module_info)
    fix_InInitializationOrderModuleList(myjit, module_info)

    ldr_data = build_fake_ldr_data(module_info)
    myjit.vm.vm_set_mem(LDR_AD, ldr_data)
    add_process_env(myjit)
    add_process_parameters(myjit)

    # myjit.vm.vm_add_memory_page(in_load_order_module_list_address,
    #     PAGE_READ | PAGE_WRITE, p(0) * 40)
    # myjit.vm.vm_add_memory_page(in_load_order_module_list_address,
    #     PAGE_READ | PAGE_WRITE, build_fake_inordermodule(loaded_modules))
    myjit.vm.vm_add_memory_page(default_seh, PAGE_READ | PAGE_WRITE, pck32(
        0xffffffff) + pck32(0x41414141) + pck32(0x42424242))

    myjit.vm.vm_add_memory_page(
        context_address, PAGE_READ | PAGE_WRITE, '\x00' * 0x2cc)
    myjit.vm.vm_add_memory_page(
        exception_record_address, PAGE_READ | PAGE_WRITE, '\x00' * 200)

    myjit.vm.vm_add_memory_page(
        FAKE_SEH_B_AD, PAGE_READ | PAGE_WRITE, 0x10000 * "\x00")

# http://www.codeproject.com/KB/system/inject2exe.aspx#RestorethefirstRegistersContext5_1


def regs2ctxt(regs):
    ctxt = ""
    ctxt += '\x00\x00\x00\x00'  # ContextFlags
    ctxt += '\x00\x00\x00\x00' * 6  # drX
    ctxt += '\x00' * 112  # float context
    ctxt += '\x00\x00\x00\x00' + '\x3b\x00\x00\x00' + \
        '\x23\x00\x00\x00' + '\x23\x00\x00\x00'  # segment selectors
    ctxt += pck32(regs['EDI']) + pck32(regs['ESI']) + pck32(regs['EBX']) + \
        pck32(regs['EDX']) + pck32(regs['ECX']) + pck32(regs['EAX']) + \
        pck32(regs['EBP']) + pck32(regs['EIP'])  # gpregs
    ctxt += '\x23\x00\x00\x00'  # cs
    ctxt += '\x00\x00\x00\x00'  # eflags
    ctxt += pck32(regs['ESP'])  # esp
    ctxt += '\x23\x00\x00\x00'  # ss segment selector
    return ctxt


def ctxt2regs(ctxt):
    ctxt = ctxt[:]
    regs = {}
    # regs['ctxtsflags'] = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    for i in xrange(8):
        if i in [4, 5]:
            continue
        # regs['dr%d'%i] = upck32(ctxt[:4])
        ctxt = ctxt[4:]

    ctxt = ctxt[112:]  # skip float

    # regs['seg_gs'] = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    # regs['seg_fs'] = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    # regs['seg_es'] = upck32(ctxt[:4])
    ctxt = ctxt[4:]
    # regs['seg_ds'] = upck32(ctxt[:4])
    ctxt = ctxt[4:]

    regs['EDI'], regs['ESI'], regs['EBX'], regs['EDX'], regs['ECX'], regs[
        'EAX'], regs['EBP'], regs['EIP'] = struct.unpack('I' * 8, ctxt[:4 * 8])
    ctxt = ctxt[4 * 8:]

    # regs['seg_cs'] = upck32(ctxt[:4])
    ctxt = ctxt[4:]

    # regs['eflag'] = upck32(ctxt[:4])
    ctxt = ctxt[4:]

    regs['ESP'] = upck32(ctxt[:4])
    ctxt = ctxt[4:]

    for a, b in regs.items():
        print a, hex(b)
    # skip extended
    return regs


def get_free_seh_place():
    global all_seh_ad
    ads = all_seh_ad.keys()
    ads.sort()
    for ad in ads:
        v = all_seh_ad[ad]
        if v is None:
            print 'TAKING SEH', hex(ad)
            all_seh_ad[ad] = True
            return ad
    raise ValueError('too many stacked seh ')


def free_seh_place(ad):
    print 'RELEASING SEH', hex(ad)

    if not ad in all_seh_ad:
        raise ValueError('zarb seh ad!', hex(ad))
    if all_seh_ad[ad] is not True:
        # @wisk typolol
        raise ValueError('seh alreaedy remouvede?!!', hex(ad))
    all_seh_ad[ad] = None


def fake_seh_handler(myjit, except_code):
    global seh_count
    regs = myjit.cpu.vm_get_gpreg()
    print '-> exception at', hex(myjit.cpu.EIP), seh_count
    seh_count += 1

    # Help lambda
    p = lambda s: struct.pack('I', s)

    # dump_gpregs_py()
    # jitarch.dump_gpregs()
    # Forge a CONTEXT
    ctxt = '\x00\x00\x00\x00' + '\x00\x00\x00\x00' * 6 + '\x00' * 112
    ctxt += '\x00\x00\x00\x00' + '\x3b\x00\x00\x00' + '\x23\x00\x00\x00'
    ctxt += '\x23\x00\x00\x00'
    ctxt += pck32(myjit.cpu.EDI) + pck32(myjit.cpu.ESI) + \
            pck32(myjit.cpu.EBX) + pck32(myjit.cpu.EDX) + \
            pck32(myjit.cpu.ECX) + pck32(myjit.cpu.EAX) + \
            pck32(myjit.cpu.EBP) + pck32(myjit.cpu.EIP)
    ctxt += '\x23\x00\x00\x00' + '\x00\x00\x00\x00' + pck32(myjit.cpu.ESP)
    ctxt += '\x23\x00\x00\x00'
    # ctxt = regs2ctxt(regs)

    # Find a room for seh
    # seh = (get_memory_page_max_address_py()+0x1000)&0xfffff000

    # Get current seh (fs:[0])
    seh_ptr = upck32(myjit.vm.vm_get_mem(tib_address, 4))

    # Retrieve seh fields
    old_seh, eh, safe_place = struct.unpack(
        'III', myjit.vm.vm_get_mem(seh_ptr, 0xc))

    print '-> seh_ptr', hex(seh_ptr), '-> { old_seh',
    print hex(old_seh), 'eh', hex(eh), 'safe_place', hex(safe_place), '}'
    # print '-> write SEH at', hex(seh&0xffffffff)

    # Write current seh
    # myjit.vm.vm_add_memory_page(seh, PAGE_READ | PAGE_WRITE, p(old_seh) +
    # p(eh) + p(safe_place) + p(0x99999999))

    # Write context
    myjit.vm.vm_set_mem(context_address, ctxt)

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

    myjit.vm.vm_set_mem(exception_record_address, pck32(except_code) +
                        pck32(0) + pck32(0) + pck32(myjit.cpu.EIP) +
                        pck32(0) + pck32(0))

    # Prepare the stack
    myjit.vm_push_uint32_t(context_address)               # Context
    myjit.vm_push_uint32_t(seh_ptr)                       # SEH
    myjit.vm_push_uint32_t(exception_record_address)      # ExceptRecords
    myjit.vm_push_uint32_t(return_from_exception)         # Ret address

    # Set fake new current seh for exception
    fake_seh_ad = get_free_seh_place()
    print hex(fake_seh_ad)
    myjit.vm.vm_set_mem(fake_seh_ad, pck32(seh_ptr) + pck32(
        0xaaaaaaaa) + pck32(0xaaaaaabb) + pck32(0xaaaaaacc))
    myjit.vm.vm_set_mem(tib_address, pck32(fake_seh_ad))

    dump_seh(myjit)

    print '-> jumping at', hex(eh)
    myjit.vm.vm_set_exception(0)
    myjit.cpu.vm_set_exception(0)

    # XXX set ebx to nul?
    myjit.cpu.EBX = 0

    return eh

fake_seh_handler.base = FAKE_SEH_B_AD


def dump_seh(myjit):
    print 'dump_seh:'
    print '-> tib_address:', hex(tib_address)
    cur_seh_ptr = upck32(myjit.vm.vm_get_mem(tib_address, 4))
    indent = 1
    loop = 0
    while True:
        if loop > 5:
            print "too many seh, quit"
            return
        prev_seh, eh = struct.unpack('II', myjit.vm.vm_get_mem(cur_seh_ptr, 8))
        print '\t' * indent + 'seh_ptr:', hex(cur_seh_ptr),
        print ' -> { prev_seh:', hex(prev_seh), 'eh:', hex(eh), '}'
        if prev_seh in [0xFFFFFFFF, 0]:
            break
        cur_seh_ptr = prev_seh
        indent += 1
        loop += 1


def set_win_fs_0(myjit, fs=4):
    regs = myjit.cpu.vm_get_gpreg()
    regs['FS'] = 0x4
    myjit.cpu.vm_set_gpreg(regs)
    myjit.cpu.vm_set_segm_base(regs['FS'], FS_0_AD)
    segm_to_do = set([x86_regs.FS])
    return segm_to_do


def add_modules_info(pe_in, pe_in_name="toto.exe", all_pe=None):
    global main_pe, main_pe_name, loaded_modules
    if all_pe is None:
        all_pe = []
    main_pe = pe_in
    main_pe_name = pe_in_name
    loaded_modules = all_pe


def return_from_seh(myjit):
    "Handle return after a call to fake seh handler"

    # Get current context
    myjit.cpu.ESP = upck32(myjit.vm.vm_get_mem(context_address + 0xc4, 4))
    logging.info('-> new esp: %x' % myjit.cpu.ESP)

    # Rebuild SEH
    old_seh = upck32(myjit.vm.vm_get_mem(tib_address, 4))
    new_seh = upck32(myjit.vm.vm_get_mem(old_seh, 4))
    logging.info('-> old seh: %x' % old_seh)
    logging.info('-> new seh: %x' % new_seh)
    myjit.vm.vm_set_mem(tib_address, pck32(new_seh))

    dump_seh(myjit)

    # Release SEH
    free_seh_place(old_seh)

    if myjit.cpu.EAX == 0x0:
        # ExceptionContinueExecution
        print '-> seh continues'
        ctxt_ptr = context_address
        print '-> context:', hex(ctxt_ptr)

        # Get registers changes
        ctxt_str = myjit.vm.vm_get_mem(ctxt_ptr, 0x2cc)
        regs = ctxt2regs(ctxt_str)
        myjit.pc = regs["EIP"]
        for reg_name, reg_value in regs.items():
            setattr(myjit.cpu, reg_name, reg_value)

        logging.info('-> context::Eip: %x' % myjit.pc)

    elif myjit.cpu.EAX == -1:
        raise NotImplementedError("-> seh try to go to the next handler")

    elif myjit.cpu.EAX == 1:
        # ExceptionContinueSearch
        raise NotImplementedError("-> seh, gameover")
