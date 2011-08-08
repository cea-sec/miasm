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
#from codenat import *
from to_c_helper import *
import to_c_helper

FS_0_AD = 0x7ff70000
PEB_AD = 0x11110000

# fs:[0] Page (TIB)
tib_address = FS_0_AD
peb_address = PEB_AD
peb_ldr_data_address = PEB_AD + 0x1000
in_load_order_module_list_address = PEB_AD + 0x2000
in_load_order_module_1 = PEB_AD + 0x3000
default_seh = PEB_AD + 0x10000


context_address = 0xdeada000
exception_record_address = 0xdeadb000
return_from_exception = 0x6eadbeef

FAKE_SEH_B_AD = 0x11bb0000

cur_seh_ad = FAKE_SEH_B_AD
default_image_base = 0x400000


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
    o += pdw(default_seh)
    o += (0x18 - len(o)) *"\x00"
    o += pdw(tib_address)

    o += (0x30 - len(o)) *"\x00"
    o += pdw(peb_address)
    o += pdw(0x11223344)

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
    """
    o = ""
    o += "\x00"*0x8
    o += pdw(default_image_base)
    o += pdw(peb_ldr_data_address)
    return o


def build_fake_ldr_data():
    """
    +0x000 Length                          : Uint4B
    +0x004 Initialized                     : UChar
    +0x008 SsHandle                        : Ptr32 Void
    +0x00c InLoadOrderModuleList           : _LIST_ENTRY
    +0x014 InMemoryOrderModuleList         : _LIST_ENTRY
    """
    o = ""
    o += "\x00"*0xc
    #text XXX
    o += pdw(in_load_order_module_list_address) + pdw(0)
    o += pdw(in_load_order_module_list_address+8) + pdw(0)
    o += pdw(in_load_order_module_list_address+0x10) + pdw(0)
    return o


def build_fake_inordermodule(modules_name):
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
    o += pdw(in_load_order_module_1  )
    o += pdw(0)
    o += pdw(in_load_order_module_1+8  )
    o += pdw(0)
    o += pdw(in_load_order_module_1+0x10)
    o += pdw(0)
    o += pdw(default_image_base)
    o += (0x1000 - len(o))*"I"
        
    for i, m in enumerate(modules_name):
        #fname = os.path.join('win_dll', m)
        fname = m
        e = pe_init.PE(open(fname, 'rb').read())
        m_o = ""
        m_o += pdw(in_load_order_module_1 + (i+1)*0x1000 )
        m_o += pdw(in_load_order_module_1 + (i-1)*0x1000)
        m_o += pdw(in_load_order_module_1 + (i+1)*0x1000 + 8 )
        m_o += pdw(in_load_order_module_1 + (i-1)*0x1000 + 8)
        m_o += pdw(in_load_order_module_1 + (i+1)*0x1000 + 0x10 )
        m_o += pdw(in_load_order_module_1 + (i-1)*0x1000 + 0x10)
        m_o += pdw(e.NThdr.ImageBase)
        m_o += pdw(e.rva2virt(e.Opthdr.AddressOfEntryPoint))
        m_o += pdw(e.NThdr.sizeofimage)
        m_o += (0x1000 - len(m_o))*"J"

        print "module", "%.8X"%e.NThdr.ImageBase, fname
        
        o += m_o
    return o


    
all_seh_ad = dict([(x, None) for x in xrange(FAKE_SEH_B_AD, FAKE_SEH_B_AD+0x1000, 0x20)])
#http://blog.fireeye.com/research/2010/08/download_exec_notes.html
def init_seh():
    global seh_count
    seh_count = 0
    
    #vm_add_memory_page(tib_address, PAGE_READ | PAGE_WRITE, p(default_seh) + p(0) * 11 + p(peb_address))
    vm_add_memory_page(FS_0_AD, PAGE_READ | PAGE_WRITE, build_fake_teb())
    #vm_add_memory_page(peb_address, PAGE_READ | PAGE_WRITE, p(0) * 3 + p(peb_ldr_data_address))
    vm_add_memory_page(peb_address, PAGE_READ | PAGE_WRITE, build_fake_peb())
    #vm_add_memory_page(peb_ldr_data_address, PAGE_READ | PAGE_WRITE, p(0) * 3 + p(in_load_order_module_list_address) + p(0) * 0x20)
    vm_add_memory_page(peb_ldr_data_address, PAGE_READ | PAGE_WRITE, build_fake_ldr_data())

    #vm_add_memory_page(in_load_order_module_list_address, PAGE_READ | PAGE_WRITE, p(0) * 40)
    vm_add_memory_page(in_load_order_module_list_address, PAGE_READ | PAGE_WRITE, build_fake_inordermodule(["win_dll/kernel32.dll", "win_dll/kernel32.dll"]))
    vm_add_memory_page(default_seh, PAGE_READ | PAGE_WRITE, p(0xffffffff) + p(0x41414141) + p(0x42424242))

    vm_add_memory_page(context_address, PAGE_READ | PAGE_WRITE, '\x00' * 0x2cc)
    vm_add_memory_page(exception_record_address, PAGE_READ | PAGE_WRITE, '\x00' * 200)

    vm_add_memory_page(FAKE_SEH_B_AD, PAGE_READ | PAGE_WRITE, 0x10000*"\x00")

#http://www.codeproject.com/KB/system/inject2exe.aspx#RestorethefirstRegistersContext5_1
def regs2ctxt(regs):
    ctxt = ""
    ctxt += '\x00\x00\x00\x00'  #ContextFlags
    ctxt += '\x00\x00\x00\x00' * 6 #drX
    ctxt += '\x00' * 112 #float context
    ctxt += '\x00\x00\x00\x00' + '\x3b\x00\x00\x00' + '\x23\x00\x00\x00' + '\x23\x00\x00\x00' #segment selectors
    ctxt += p(regs['edi']) + p(regs['esi']) + p(regs['ebx']) + p(regs['edx']) + p(regs['ecx']) + p(regs['eax']) + p(regs['ebp']) + p(regs['eip']) #gpregs
    ctxt += '\x23\x00\x00\x00' #cs
    ctxt += '\x00\x00\x00\x00' #eflags
    ctxt += p(regs['esp'])  #esp
    ctxt += '\x23\x00\x00\x00' #ss segment selector
    return ctxt


def ctxt2regs(ctxt):
    ctxt = ctxt[:]
    regs = {}
    #regs['ctxtsflags'] = updw(ctxt[:4])
    ctxt = ctxt[4:]
    for i in xrange(8):
        if i in [4, 5]:
            continue
        #regs['dr%d'%i] = updw(ctxt[:4])
        ctxt = ctxt[4:]

    ctxt = ctxt[112:] #skip float

    #regs['seg_gs'] = updw(ctxt[:4])
    ctxt = ctxt[4:]
    #regs['seg_fs'] = updw(ctxt[:4])
    ctxt = ctxt[4:]
    #regs['seg_es'] = updw(ctxt[:4])
    ctxt = ctxt[4:]
    #regs['seg_ds'] = updw(ctxt[:4])
    ctxt = ctxt[4:]
    
    regs['edi'], regs['esi'], regs['ebx'], regs['edx'], regs['ecx'], regs['eax'], regs['ebp'], regs['eip']  = struct.unpack('LLLLLLLL', ctxt[:4*8])
    ctxt = ctxt[4*8:]

    #regs['seg_cs'] = updw(ctxt[:4])
    ctxt = ctxt[4:]
    
    #regs['eflag'] = updw(ctxt[:4])
    ctxt = ctxt[4:]
    
    regs['esp'] = updw(ctxt[:4])
    ctxt = ctxt[4:]

    for a, b in regs.items():
        print a, hex(b)
    #skip extended
    return regs


def get_free_seh_place():
    global all_seh_ad
    ads = all_seh_ad.keys()
    ads.sort()
    for ad in ads:
        v = all_seh_ad[ad]
        if v == None:
            print 'TAKING SEH', hex(ad)
            all_seh_ad[ad] = True
            return ad
    raise ValueError('too many stacked seh ')

def free_seh_place(ad):
    print 'RELEASING SEH', hex(ad)

    if not ad in all_seh_ad:
        raise ValueError('zarb seh ad!', hex(ad))
    if all_seh_ad[ad] != True:
        raise ValueError('seh alreaedy remouvede?!!', hex(ad))
    all_seh_ad[ad] = None

def fake_seh_handler(except_code):
    global seh_count
    regs = vm_get_gpreg()
    print '-> exception at', hex(regs['eip']), seh_count
    seh_count += 1
    
    # Help lambda
    p = lambda s: struct.pack('L', s)
    
    dump_gpregs_py()
    # Forge a CONTEXT
    ctxt =  '\x00\x00\x00\x00' + '\x00\x00\x00\x00' * 6 + '\x00' * 112 + '\x00\x00\x00\x00' + '\x3b\x00\x00\x00' + '\x23\x00\x00\x00' + '\x23\x00\x00\x00' + p(regs['edi']) + p(regs['esi']) + p(regs['ebx']) + p(regs['edx']) + p(regs['ecx']) + p(regs['eax']) + p(regs['ebp']) + p(regs['eip']) + '\x23\x00\x00\x00' + '\x00\x00\x00\x00' + p(regs['esp']) + '\x23\x00\x00\x00'
    #ctxt = regs2ctxt(regs)
    
    # Find a room for seh
    #seh = (get_memory_page_max_address_py()+0x1000)&0xfffff000

    # Get current seh (fs:[0])
    seh_ptr = vm_read_dword(tib_address)
    
    # Retrieve seh fields
    old_seh, eh, safe_place = struct.unpack('LLL', vm_get_str(seh_ptr, 0xc))
    
    print '-> seh_ptr', hex(seh_ptr), '-> { old_seh', hex(old_seh), 'eh', hex(eh), 'safe_place', hex(safe_place), '}'
    #print '-> write SEH at', hex(seh&0xffffffff)
    
    # Write current seh
    #vm_add_memory_page(seh, PAGE_READ | PAGE_WRITE, p(old_seh) + p(eh) + p(safe_place) + p(0x99999999))
    
    # Write context
    vm_set_mem(context_address, ctxt)

    # Write exception_record

    """
    #http://msdn.microsoft.com/en-us/library/aa363082(v=vs.85).aspx
    
    typedef struct _EXCEPTION_RECORD {
      DWORD                    ExceptionCode;
      DWORD                    ExceptionFlags;
      struct _EXCEPTION_RECORD *ExceptionRecord;
      PVOID                    ExceptionAddress;
      DWORD                    NumberParameters;
      ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    } EXCEPTION_RECORD, *PEXCEPTION_RECORD;
    """
    
    vm_set_mem(exception_record_address, p(except_code) + p(0) + p(0)  + p(regs['eip']) + p(0) + p(0) )

    # Prepare the stack
    vm_push_uint32_t(context_address)               # Context
    vm_push_uint32_t(seh_ptr)                       # SEH
    vm_push_uint32_t(exception_record_address)      # ExceptRecords
    vm_push_uint32_t(return_from_exception)         # Ret address
    
    
    
    # Set fake new current seh for exception

    fake_seh_ad = get_free_seh_place()
    print hex(fake_seh_ad)
    vm_set_mem(fake_seh_ad, p(seh_ptr) + p(0xaaaaaaaa) + p(0xaaaaaabb) + p(0xaaaaaacc))
    vm_set_mem(tib_address, p(fake_seh_ad))
    
    dump_seh()
    
    print '-> jumping at', hex(eh)
    to_c_helper.vm_reset_exception()
    
    
    regs = vm_get_gpreg()
    #XXX set ebx to nul?
    regs['ebx'] = 0
    vm_set_gpreg(regs)
    
    return eh
    
fake_seh_handler.base = FAKE_SEH_B_AD


def dump_seh():
	print 'dump_seh:'
	print '-> tib_address:', hex(tib_address)

	cur_seh_ptr = vm_read_dword(tib_address)

	indent = 1
	loop = 0
	while True:
		#if loop > 3:
                #		djawidj
		prev_seh, eh = struct.unpack('LL', vm_get_str(cur_seh_ptr, 8))
		print '\t' * indent + 'seh_ptr:', hex(cur_seh_ptr), ' -> { prev_seh:', hex(prev_seh), 'eh:', hex(eh), '}'
		if prev_seh in [0xFFFFFFFF, 0]:
			break
		cur_seh_ptr = prev_seh
		indent += 1
		loop += 1
