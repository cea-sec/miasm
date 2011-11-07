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
PEB_AD = 0x140000

# fs:[0] Page (TIB)
tib_address = FS_0_AD
peb_address = PEB_AD
peb_ldr_data_address = PEB_AD + 0x1000
in_load_order_module_list_address = PEB_AD + 0x2000
in_load_order_module_1 = PEB_AD + 0x3000
default_seh = PEB_AD + 0x20000


context_address = 0x200000
exception_record_address = context_address+0x1000
return_from_exception = 0x6eadbeef

FAKE_SEH_B_AD = context_address+0x2000

cur_seh_ad = FAKE_SEH_B_AD

loaded_modules = ["win_dll/kernel32.dll", "win_dll/ntdll.dll"]
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

    offset_serverdata = 0x100
    offset_data1 = 0x108
    offset_data2 = 0x110
    o = ""
    o += "\x00"*0x8
    if main_pe:
        o += pdw(main_pe.NThdr.ImageBase)
    else:
        o += "AAAA"
    o += pdw(peb_ldr_data_address)

    o += (0x54 - len(o)) *"A"
    o += pdw(peb_address+offset_serverdata)
    o += (offset_serverdata - len(o)) *"B"
    o += pdw(0x33333333)
    o += pdw(peb_address+offset_data1)
    o += (offset_data1 - len(o)) *"C"
    o += pdw(0x44444444)
    o += pdw(peb_address+offset_data2)
    o += (offset_data2 - len(o)) *"D"
    o += pdw(0x55555555)
    o += pdw(0x0077007C)
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

    first_name = "\x00".join(main_pe_name+"\x00\x00")
    offset_name = 0x700

    o = ""
    o += pdw(in_load_order_module_1  )
    o += pdw(0)
    o += pdw(in_load_order_module_1+8  )
    o += pdw(0)
    o += pdw(in_load_order_module_1+0x10)
    o += pdw(0)

    if main_pe:
        o += pdw(main_pe.NThdr.ImageBase)
        o += pdw(main_pe.rva2virt(main_pe.Opthdr.AddressOfEntryPoint))
    else:
        # no fixed values
        pass

    o += (0x24 - len(o))*"A"
    o += struct.pack('HH', len(first_name), len(first_name))
    o += pdw(in_load_order_module_list_address+offset_name)

    o += (0x2C - len(o))*"A"
    o += struct.pack('HH', len(first_name), len(first_name))
    o += pdw(in_load_order_module_list_address+offset_name)

    o += (offset_name - len(o))*"B"
    o += first_name
    o += (0x1000 - len(o))*"C"
    for i, m in enumerate(modules_name):
        #fname = os.path.join('win_dll', m)
        fname = m
        bname = os.path.split(fname)[1].upper()
        bname = "\x00".join(bname+"\x00\x00")
        print "add module", repr(bname)
        print hex(in_load_order_module_1+i*0x1000)
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

        m_o += (0x24 - len(m_o))*"A"
        m_o += struct.pack('HH', len(bname), len(bname))
        m_o += pdw(in_load_order_module_1+i*0x1000+offset_name)
        
        m_o += (0x2C - len(m_o))*"A"
        m_o += struct.pack('HH', len(bname), len(bname))
        m_o += pdw(in_load_order_module_1+i*0x1000+offset_name)

        m_o += (offset_name - len(m_o))*"B"
        m_o += bname


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
    vm_add_memory_page(in_load_order_module_list_address, PAGE_READ | PAGE_WRITE, build_fake_inordermodule(loaded_modules))
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
    
    regs['edi'], regs['esi'], regs['ebx'], regs['edx'], regs['ecx'], regs['eax'], regs['ebp'], regs['eip']  = struct.unpack('I'*8, ctxt[:4*8])
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
    p = lambda s: struct.pack('I', s)
    
    dump_gpregs_py()
    # Forge a CONTEXT
    ctxt =  '\x00\x00\x00\x00' + '\x00\x00\x00\x00' * 6 + '\x00' * 112 + '\x00\x00\x00\x00' + '\x3b\x00\x00\x00' + '\x23\x00\x00\x00' + '\x23\x00\x00\x00' + p(regs['edi']) + p(regs['esi']) + p(regs['ebx']) + p(regs['edx']) + p(regs['ecx']) + p(regs['eax']) + p(regs['ebp']) + p(regs['eip']) + '\x23\x00\x00\x00' + '\x00\x00\x00\x00' + p(regs['esp']) + '\x23\x00\x00\x00'
    #ctxt = regs2ctxt(regs)
    
    # Find a room for seh
    #seh = (get_memory_page_max_address_py()+0x1000)&0xfffff000

    # Get current seh (fs:[0])
    seh_ptr = vm_read_dword(tib_address)
    
    # Retrieve seh fields
    old_seh, eh, safe_place = struct.unpack('III', vm_get_str(seh_ptr, 0xc))
    
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
		prev_seh, eh = struct.unpack('II', vm_get_str(cur_seh_ptr, 8))
		print '\t' * indent + 'seh_ptr:', hex(cur_seh_ptr), ' -> { prev_seh:', hex(prev_seh), 'eh:', hex(eh), '}'
		if prev_seh in [0xFFFFFFFF, 0]:
			break
		cur_seh_ptr = prev_seh
		indent += 1
		loop += 1
