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
from to_c_helper import *
import struct
from Crypto.Hash import MD5
import inspect
from zlib import crc32
import seh_helper
handle_toolhelpsnapshot = 0xaaaa00
toolhelpsnapshot_info = {}
handle_curprocess = 0xaaaa01
dbg_present = 0

tickcount =0

dw_pid_dummy1 = 0x111
dw_pid_explorer = 0x222
dw_pid_dummy2 = 0x333
dw_pid_cur = 0x444


module_fname_nux = None
module_name = "test.exe\x00"
module_path = "c:\\mydir\\"+module_name
module_filesize = None
getversion = 0x0A280105

getforegroundwindow =  0x333333


cryptcontext_hwnd = 0x44400
cryptcontext_bnum = 0x44000
cryptcontext_num = 0

cryptcontext = {}

phhash_crypt_md5 = 0x55555

file_hwnd_num = 0x66600
files_hwnd = {}
file_offsets = {}

windowlong_dw = 0x77700


module_cur_hwnd = 0x88800

module_file_nul = 0x999000
runtime_dll = None
current_pe = None

"""
typedef struct tagPROCESSENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  TCHAR     szExeFile[MAX_PATH];
} PROCESSENTRY32, *PPROCESSENTRY32;
"""


def whoami():
    return inspect.stack()[1][3]


class hobj:
    pass


class mdl:
    def __init__(self, ad, l):
        self.ad = ad
        self.l = l
    def __str__(self):
        return struct.pack('LL', self.ad, self.l)

def get_str_ansi(ad_str):
    l = 0
    tmp = ad_str
    while vm_get_str(tmp, 1) != "\x00":
        tmp +=1
        l+=1
    return vm_get_str(ad_str, l)
    
def get_str_unic(ad_str):
    l = 0
    tmp = ad_str
    while vm_get_str(tmp, 2) != "\x00\x00":
        tmp +=2
        l+=2
    return vm_get_str(ad_str, l)


def kernel32_GlobalAlloc():
    ret_ad = vm_pop_uint32_t()
    uflags = vm_pop_uint32_t()
    msize = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(uflags), hex(msize), ')'
    max_ad = get_memory_page_from_min_ad_py(msize)

    vm_add_memory_page(max_ad, PAGE_READ|PAGE_WRITE, "\x00"*msize)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = max_ad
    vm_set_gpreg(regs)


def kernel32_GlobalFree():
    ret_ad = vm_pop_uint32_t()
    ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(ad), ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)

def kernel32_IsDebuggerPresent():
    ret_ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = dbg_present
    vm_set_gpreg(regs)


def kernel32_CreateToolhelp32Snapshot():
    ret_ad = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()
    th32processid = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(dwflags), hex(th32processid), ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = handle_toolhelpsnapshot
    vm_set_gpreg(regs)

def kernel32_GetCurrentProcess():
    ret_ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = handle_curprocess
    vm_set_gpreg(regs)

def kernel32_GetCurrentProcessId():
    ret_ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = dw_pid_cur
    vm_set_gpreg(regs)


process_list = [
    [
        0x40,               #DWORD     dwSize;             
        0,                  #DWORD     cntUsage;           
        dw_pid_dummy1,       #DWORD     th32ProcessID;      
        0x11111111,         #ULONG_PTR th32DefaultHeapID;  
        0x11111112,         #DWORD     th32ModuleID;       
        1,                  #DWORD     cntThreads;         
        dw_pid_explorer,    #DWORD     th32ParentProcessID;
        0xbeef,             #LONG      pcPriClassBase;     
        0x0,                #DWORD     dwFlags;            
        "dummy1.exe"          #TCHAR     szExeFile[MAX_PATH];
        ],
    [
        0x40,               #DWORD     dwSize;             
        0,                  #DWORD     cntUsage;           
        dw_pid_explorer,    #DWORD     th32ProcessID;      
        0x11111111,         #ULONG_PTR th32DefaultHeapID;  
        0x11111112,         #DWORD     th32ModuleID;       
        1,                  #DWORD     cntThreads;         
        4,                  #DWORD     th32ParentProcessID;
        0xbeef,             #LONG      pcPriClassBase;     
        0x0,                #DWORD     dwFlags;            
        "explorer.exe"      #TCHAR     szExeFile[MAX_PATH];
        ],

    [
        0x40,               #DWORD     dwSize;             
        0,                  #DWORD     cntUsage;           
        dw_pid_dummy2,       #DWORD     th32ProcessID;      
        0x11111111,         #ULONG_PTR th32DefaultHeapID;  
        0x11111112,         #DWORD     th32ModuleID;       
        1,                  #DWORD     cntThreads;         
        dw_pid_explorer,    #DWORD     th32ParentProcessID;
        0xbeef,             #LONG      pcPriClassBase;     
        0x0,                #DWORD     dwFlags;            
        "dummy2.exe"          #TCHAR     szExeFile[MAX_PATH];
        ],

    [
        0x40,               #DWORD     dwSize;             
        0,                  #DWORD     cntUsage;           
        dw_pid_cur,         #DWORD     th32ProcessID;      
        0x11111111,         #ULONG_PTR th32DefaultHeapID;  
        0x11111112,         #DWORD     th32ModuleID;       
        1,                  #DWORD     cntThreads;         
        dw_pid_explorer,    #DWORD     th32ParentProcessID;
        0xbeef,             #LONG      pcPriClassBase;     
        0x0,                #DWORD     dwFlags;            
        module_name          #TCHAR     szExeFile[MAX_PATH];
        ],


]

def kernel32_Process32First():
    ret_ad = vm_pop_uint32_t()
    s_handle = vm_pop_uint32_t()
    ad_pentry = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(s_handle), hex(ad_pentry), ')'

    pentry = struct.pack('LLLLLLLLL', *process_list[0][:-1])+process_list[0][-1]
    vm_set_mem(ad_pentry, pentry)
    
    toolhelpsnapshot_info[s_handle] = 0

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)


def kernel32_Process32Next():
    ret_ad = vm_pop_uint32_t()
    s_handle = vm_pop_uint32_t()
    ad_pentry = vm_pop_uint32_t()

    toolhelpsnapshot_info[s_handle] +=1
    if toolhelpsnapshot_info[s_handle] >= len(process_list):
        eax = 0
    else:
        eax = 1
        n = toolhelpsnapshot_info[s_handle]
        print whoami(), hex(ret_ad), '(', hex(s_handle), hex(ad_pentry), ')'
        pentry = struct.pack('LLLLLLLLL', *process_list[n][:-1])+process_list[n][-1]
        vm_set_mem(ad_pentry, pentry)
        
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)


    

def kernel32_GetTickCount():
    global tickcount
    ret_ad = vm_pop_uint32_t()
    
    print whoami(), hex(ret_ad), '(', ')'
    tickcount +=1

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = tickcount
    vm_set_gpreg(regs)


def kernel32_GetVersion():
    ret_ad = vm_pop_uint32_t()
    
    print whoami(), hex(ret_ad), '(', ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = getversion
    vm_set_gpreg(regs)


def kernel32_GetPriorityClass():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def kernel32_SetPriorityClass():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()
    dwpclass = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), hex(dwpclass),')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    

def kernel32_CloseHandle():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd),')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)
    

def user32_GetForegroundWindow():
    ret_ad = vm_pop_uint32_t()
    
    print whoami(), hex(ret_ad), '(', ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = getforegroundwindow
    vm_set_gpreg(regs)



def user32_FindWindowA():
    ret_ad = vm_pop_uint32_t()
    pclassname = vm_pop_uint32_t()
    pwindowname = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(pclassname), hex(pwindowname), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def user32_GetTopWindow():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def user32_BlockInput():
    ret_ad = vm_pop_uint32_t()
    b = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(b), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)
    

def advapi32_CryptAcquireContextA():
    ret_ad = vm_pop_uint32_t()
    phprov = vm_pop_uint32_t()
    pszcontainer = vm_pop_uint32_t()
    pszprovider = vm_pop_uint32_t()
    dwprovtype = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(phprov), hex(pszcontainer), hex(pszprovider), hex(dwprovtype), hex(dwflags), ')'

    prov = vm_get_str(pszprovider, 0x100)
    prov = prov[:prov.find('\x00')]
    print 'prov:', prov
                

    vm_set_mem(phprov, pdw(cryptcontext_hwnd))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)


def advapi32_CryptCreateHash():
    global cryptcontext_num
    ret_ad = vm_pop_uint32_t()
    hprov = vm_pop_uint32_t()
    algid = vm_pop_uint32_t()
    hkey = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()
    phhash = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hprov), hex(algid), hex(hkey), hex(dwflags), hex(phhash), ')'

    cryptcontext_num +=1

    if algid == 0x00008003:
        print 'algo is MD5'
        vm_set_mem(phhash, pdw(cryptcontext_bnum+cryptcontext_num))
        cryptcontext[cryptcontext_bnum+cryptcontext_num] = hobj()
        cryptcontext[cryptcontext_bnum+cryptcontext_num].h = MD5.new()
    else:
        raise ValueError('un impl algo1')
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)
    
def advapi32_CryptHashData():
    global cryptcontext
    ret_ad = vm_pop_uint32_t()
    hhash = vm_pop_uint32_t()
    pbdata = vm_pop_uint32_t()
    dwdatalen = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hhash), hex(pbdata), hex(dwdatalen), hex(dwflags), ')'

    if not hhash in cryptcontext:
        raise ValueError("unknown crypt context")

    data = vm_get_str(pbdata, dwdatalen)
    print 'will hash'
    print repr(data)
    cryptcontext[hhash].h.update(data)
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)


def advapi32_CryptDeriveKey():
    ret_ad = vm_pop_uint32_t()
    hprov = vm_pop_uint32_t()
    algid = vm_pop_uint32_t()
    hbasedata = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()
    phkey = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hprov), hex(algid), hex(hbasedata), hex(dwflags), hex(phkey), ')'

    if algid == 0x6801:
        print 'using DES'
    else:
        raise ValueError('un impl algo2')        

    h = cryptcontext[hbasedata].h.digest()
    print 'hash', repr(h)
    cryptcontext[hbasedata].h_result = h
    vm_set_mem(phkey, pdw(hbasedata))    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)
    
def advapi32_CryptDestroyHash():
    ret_ad = vm_pop_uint32_t()
    hhash = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hhash), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def advapi32_CryptDecrypt():
    ret_ad = vm_pop_uint32_t()
    hkey = vm_pop_uint32_t()
    hhash = vm_pop_uint32_t()
    final = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()
    pbdata = vm_pop_uint32_t()
    pdwdatalen = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hkey), hex(hhash), hex(final), hex(dwflags), hex(pbdata), hex(pdwdatalen), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

    fdfsd
    
def kernel32_CreateFileA():
    ret_ad = vm_pop_uint32_t()
    lpfilename = vm_pop_uint32_t()
    dwsharedmode = vm_pop_uint32_t()
    lpsecurityattr = vm_pop_uint32_t()
    dwcreationdisposition = vm_pop_uint32_t()
    dwflagsandattr = vm_pop_uint32_t()
    htemplatefile = vm_pop_uint32_t()


    fname = vm_get_str(lpfilename, 0x100)
    fname = fname[:fname.find('\x00')]

    print whoami(), hex(ret_ad), '(', hex(lpfilename), hex(dwsharedmode), hex(lpsecurityattr), hex(dwcreationdisposition), hex(dwflagsandattr), hex(htemplatefile), ')'
    my_CreateFile(ret_ad, fname, dwsharedmode, lpsecurityattr, dwcreationdisposition, dwflagsandattr, htemplatefile)




def kernel32_CreateFileW():
    ret_ad = vm_pop_uint32_t()
    lpfilename = vm_pop_uint32_t()
    dwsharedmode = vm_pop_uint32_t()
    lpsecurityattr = vm_pop_uint32_t()
    dwcreationdisposition = vm_pop_uint32_t()
    dwflagsandattr = vm_pop_uint32_t()
    htemplatefile = vm_pop_uint32_t()

    fname = vm_get_str(lpfilename, 0x100)
    fname = fname[:fname.find('\x00\x00')]
    fname = fname[::2]

    print whoami(), hex(ret_ad), '(', hex(lpfilename), hex(dwsharedmode), hex(lpsecurityattr), hex(dwcreationdisposition), hex(dwflagsandattr), hex(htemplatefile), ')'
    my_CreateFile(ret_ad, fname, dwsharedmode, lpsecurityattr, dwcreationdisposition, dwflagsandattr, htemplatefile)


def my_CreateFile(ret_ad, fname, dwsharedmode, lpsecurityattr, dwcreationdisposition, dwflagsandattr, htemplatefile):
    print whoami(), hex(ret_ad), '(', fname, hex(dwsharedmode), hex(lpsecurityattr), hex(dwcreationdisposition), hex(dwflagsandattr), hex(htemplatefile), ')'

    print 'fname:', fname

    eax = 0xffffffff

    if fname in [r"\\.\SICE", r"\\.\NTICE", r"\\.\Siwvid"]:
        pass
        #eax = files_hwnd[fname] = file_hwnd_num
        #file_hwnd_num += 1
    elif fname == module_path[:-1]:
        eax = module_file_nul
    elif fname in ['NUL']:
        eax = module_cur_hwnd
    else:
        raise ValueError('unknown filename')
    
    

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)

    

def kernel32_ReadFile():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()
    lpbuffer = vm_pop_uint32_t()
    nnumberofbytestoread = vm_pop_uint32_t()
    lpnumberofbytesread = vm_pop_uint32_t()
    lpoverlapped = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), hex(lpbuffer), hex(nnumberofbytestoread), hex(lpnumberofbytesread), hex(lpoverlapped), ')'

    if hwnd == module_cur_hwnd:
        
        pass
    else:
        raise ValueError('unknown hwnd!')

    eax = 0xffffffff

    if hwnd in files_hwnd:
        data = files_hwnd[module_cur_hwnd].read(nnumberofbytestoread)

        if (lpnumberofbytesread):
            vm_set_mem(lpnumberofbytesread, pdw(len(data)))
        vm_set_mem(lpbuffer, data)

    else:
        raise ValueError('unknown filename')


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def kernel32_GetFileSize():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()
    lpfilesizehight = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), hex(lpfilesizehight), ')'

    if hwnd == module_cur_hwnd:
        eax = len(open(module_fname_nux).read())
    else:
        raise ValueError('unknown hwnd!')

    if lpfilesizehight != 0:
        vm_set_mem(lpfilesizehight, pdw(eax&0xffff0000))
            
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)
    


access_dict = {    0x0: 0,
                   0x1: 0,
                   0x2: PAGE_READ,
                   0x4: PAGE_READ | PAGE_WRITE,
                   0x10: PAGE_EXEC,
                   0x20: PAGE_EXEC | PAGE_READ,
                   0x40: PAGE_EXEC | PAGE_READ | PAGE_WRITE,
                   0x80: PAGE_EXEC | PAGE_READ | PAGE_WRITE,
                   # 0x80: PAGE_EXECUTE_WRITECOPY
                   0x100: 0
                   }

access_dict_inv = dict([(x[1], x[0]) for x in access_dict.items()])


def kernel32_VirtualProtect():
    ret_ad = vm_pop_uint32_t()
    lpvoid = vm_pop_uint32_t()
    dwsize = vm_pop_uint32_t()
    flnewprotect = vm_pop_uint32_t()
    lpfloldprotect = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(lpvoid), hex(dwsize), hex(flnewprotect), hex(lpfloldprotect), ')'
    
    # XXX mask hpart
    flnewprotect &= 0xFFF

    if not flnewprotect in access_dict:
        raise ValueError( 'unknown access dw!')
    
    vm_set_mem_access(lpvoid, access_dict[flnewprotect])

    #XXX todo real old protect
    vm_set_mem(lpfloldprotect, pdw(0x40))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)
    dump_memory_page_pool_py()



def kernel32_VirtualAlloc():
    ret_ad = vm_pop_uint32_t()
    lpvoid = vm_pop_uint32_t()
    dwsize = vm_pop_uint32_t()
    alloc_type = vm_pop_uint32_t()
    flprotect = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(lpvoid), hex(dwsize), hex(alloc_type), hex(flprotect), ')'
    

    access_dict = {    0x0: 0,
                       0x1: 0,
                       0x2: PAGE_READ,
                       0x4: PAGE_READ | PAGE_WRITE,
                       0x10: PAGE_EXEC,
                       0x20: PAGE_EXEC | PAGE_READ,
                       0x40: PAGE_EXEC | PAGE_READ | PAGE_WRITE,
                       0x100: 0
                       }

    access_dict_inv = dict([(x[1], x[0]) for x in access_dict.items()])


    if not flprotect in access_dict:
        raise ValueError( 'unknown access dw!')

    max_ad = vm_get_memory_page_max_address()
    max_ad = (max_ad+0xfff) & 0xfffff000


    vm_add_memory_page(max_ad, access_dict[flprotect], "\x00"*dwsize)


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = max_ad
    vm_set_gpreg(regs)
    dump_memory_page_pool_py()
    print 'ret', hex(max_ad), hex(ret_ad)
    #XXX for malware tests
    #vm_set_mem(regs['esp']-0x2C, pdw(0xFFFFFFFF))


def kernel32_VirtualFree():
    ret_ad = vm_pop_uint32_t()
    lpvoid = vm_pop_uint32_t()
    dwsize = vm_pop_uint32_t()
    alloc_type = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(lpvoid), hex(dwsize), hex(alloc_type), ')'
    

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)
    

def user32_GetWindowLongA():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()
    nindex = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), hex(nindex), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = windowlong_dw
    vm_set_gpreg(regs)
    

def user32_SetWindowLongA():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()
    nindex = vm_pop_uint32_t()
    newlong = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), hex(nindex), hex(newlong), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = windowlong_dw
    vm_set_gpreg(regs)
    


def kernel32_GetModuleFileNameA():
    ret_ad = vm_pop_uint32_t()
    hmodule = vm_pop_uint32_t()
    lpfilename = vm_pop_uint32_t()
    nsize = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hmodule), hex(lpfilename), hex(nsize), ')'

    if hmodule in [0]:
        p = module_path[:]
    else:
        raise ValueError('unknown module h')


    if nsize < len(p):
        eax = nsize
        p = p[:nsize]
    else:
        eax = len(p)
    print repr(p)
    vm_set_mem(lpfilename, p)

    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = nsize
    vm_set_gpreg(regs)

lastwin32error = 0
def kernel32_GetLastError():
    ret_ad = vm_pop_uint32_t()
    global lastwin32error
    
    print whoami(), hex(ret_ad), '(',  ')'
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = lastwin32error
    vm_set_gpreg(regs)


def kernel32_LoadLibraryA():
    ret_ad = vm_pop_uint32_t()
    dllname = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(dllname)

    libname = vm_get_str(dllname, 0x100)
    libname = libname[:libname.find('\x00')]
    print repr(libname)

    eax = runtime_dll.lib_get_add_base(libname)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)

def kernel32_GetProcAddress():
    ret_ad = vm_pop_uint32_t()
    libbase = vm_pop_uint32_t()
    fname = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(fname), hex(libbase)
    fname = fname & 0xFFFFFFFF
    if fname < 0x10000:
        fname = fname
    else:
        fname = vm_get_str(fname, 0x100)
        fname = fname[:fname.find('\x00')]
    print repr(fname)

    
    ad = runtime_dll.lib_get_add_func(libbase, fname)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ad
    vm_set_gpreg(regs)



def kernel32_LoadLibraryW():
    ret_ad = vm_pop_uint32_t()
    dllname = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(dllname)

    libname = vm_get_str(dllname, 0x100)
    libname = libname[:libname.find('\x00\x00')]
    libname = libname[::2]
    print repr(libname)

    eax = runtime_dll.lib_get_add_base(libname)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)


def kernel32_GetModuleHandleA():
    ret_ad = vm_pop_uint32_t()
    dllname = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(dllname)

    if dllname:
        libname = get_str_ansi(dllname)
        print libname
        if not libname.lower().endswith('.dll'):
            print 'warning adding .dll to modulename'
            libname += '.dll'
            print libname
        eax = runtime_dll.lib_get_add_base(libname)
    else:
        eax = current_pe.NThdr.ImageBase
        print "default img base" , hex(eax)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)


def kernel32_GetSystemInfo():
    ret_ad = vm_pop_uint32_t()
    sys_ptr = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(sys_ptr)

    vm_set_mem(sys_ptr, "\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x01\x00\xFF\xFF\xFE\x7F\x0F\x00\x00\x00\x04\x00\x00\x00\x4A\x02\x00\x00\x00\x00\x01\x00\x06\x00\x0B\x0F")
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    #regs['eax'] = 0
    vm_set_gpreg(regs)
    

def kernel32_IsWow64Process():
    ret_ad = vm_pop_uint32_t()
    h = vm_pop_uint32_t()
    bool_ptr = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(h), hex(bool_ptr)

    vm_set_mem(bool_ptr, pdw(0))
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)
    
def kernel32_GetCommandLineA():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)

    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

cryptdll_md5_h = {}
def cryptdll_MD5Init():
    global cryptdll_MD5Init
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_ctx = vm_pop_uint32_t()
    index = len(cryptdll_md5_h)
    h = MD5.new()
    cryptdll_md5_h[index] = h

    vm_set_mem(ad_ctx, pdw(index))
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)
    


def cryptdll_MD5Update():
    global cryptdll_MD5Init
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_ctx = vm_pop_uint32_t()
    ad_input = vm_pop_uint32_t()
    inlen = vm_pop_uint32_t()

    index = vm_get_str(ad_ctx, 4)
    index = updw(index)
    if not index in cryptdll_md5_h:
        raise ValueError('unknown h context', index)

    data = vm_get_str(ad_input, inlen)
    cryptdll_md5_h[index].update(data)
    print hexdump(data)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)
    
def cryptdll_MD5Final():
    global cryptdll_MD5Init
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)

    ad_ctx = vm_pop_uint32_t()

    index = vm_get_str(ad_ctx, 4)
    index = updw(index)
    if not index in cryptdll_md5_h:
        raise ValueError('unknown h context', index)
    
    h = cryptdll_md5_h[index].digest()
    vm_set_mem(ad_ctx + 88, h)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)
    
def ntdll_RtlInitAnsiString():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_ctx = vm_pop_uint32_t()
    ad_str = vm_pop_uint32_t()

    s = get_str_ansi(ad_str)
    l = len(s)
    print "string", l, s
    vm_set_mem(ad_ctx, pw(l)+pw(l+1)+pdw(ad_str))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)


def ntdll_RtlAnsiStringToUnicodeString():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_ctxu = vm_pop_uint32_t()
    ad_ctxa = vm_pop_uint32_t()
    alloc_dst = vm_pop_uint32_t()

    
    l1, l2, ptra = struct.unpack('HHL', vm_get_str(ad_ctxa, 8))
    print hex(l1), hex(l2), hex(ptra)

    s = vm_get_str(ptra, l1)
    print s
    s = '\x00'.join(s) + "\x00\x00"
    if alloc_dst:
        ad = get_memory_page_max_address_py()
        ad = (ad + 0xFFF) & ~0xFFF
        vm_add_memory_page(ad , PAGE_READ | PAGE_WRITE, s)

    vm_set_mem(ad_ctxu, pw(len(s))+pw(len(s)+1)+pdw(ad))   
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def ntdll_RtlHashUnicodeString():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_ctxu = vm_pop_uint32_t()
    case_i = vm_pop_uint32_t()
    h_id = vm_pop_uint32_t()
    phout = vm_pop_uint32_t()

    print hex(h_id)
    if h_id != 1:
        raise ValueError('unk hash unicode', h_id)

    l1, l2, ptra = struct.unpack('HHL', vm_get_str(ad_ctxu, 8))
    print hex(l1), hex(l2), hex(ptra)
    s = vm_get_str(ptra, l1)
    print repr(s)
    s = s[::2][:-1]
    print repr(s)
    hv = 0

    if case_i:
        s = s.lower()
    for c in s:
        hv = ((65599*hv)+ord(c) )&0xffffffff
    print "unicode h", hex(hv)
    
    vm_set_mem(phout, pdw(hv))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    
def ntdll_RtlFreeUnicodeString():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_ctxu = vm_pop_uint32_t()
    
    l1, l2, ptra = struct.unpack('HHL', vm_get_str(ad_ctxu, 8))
    print l1, l2, hex(ptra)
    s = vm_get_str(ptra, l1)
    print 'free', repr(s)
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)



def kernel32_RtlMoveMemory():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_dst = vm_pop_uint32_t()
    ad_src = vm_pop_uint32_t()
    m_len = vm_pop_uint32_t()
    
    print hex(ad_dst), hex(ad_src), hex(m_len)
    data = vm_get_str(ad_src, m_len)
    vm_set_mem(ad_dst, data)
    print hexdump(data)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)


def ntdll_RtlAnsiCharToUnicodeChar():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_ad_ch = vm_pop_uint32_t()
    
    print hex(ad_ad_ch)
    ad_ch = updw(vm_get_str(ad_ad_ch, 4))
    print hex(ad_ch)
    
    ch = ord(vm_get_str(ad_ch, 1))
    vm_set_mem(ad_ad_ch, pdw(ad_ch+1))

    print repr(ch), repr(chr(ch))
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ch
    vm_set_gpreg(regs)
    
def ntdll_RtlFindCharInUnicodeString():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    flags = vm_pop_uint32_t()
    main_str_ad = vm_pop_uint32_t()
    search_chars_ad = vm_pop_uint32_t()
    pos_ad = vm_pop_uint32_t()

    print flags
    if flags != 0:
        raise ValueError('unk flags')

    ml1, ml2, mptra = struct.unpack('HHL', vm_get_str(main_str_ad, 8))
    print ml1, ml2, hex(mptra)
    sl1, sl2, sptra = struct.unpack('HHL', vm_get_str(search_chars_ad, 8))
    print sl1, sl2, hex(sptra)
    
    main_data= vm_get_str(mptra, ml1)[:-1]
    search_data= vm_get_str(sptra, sl1)[:-1]

    print repr(main_data[::2])
    print repr(search_data)

    pos = None
    for i, c in enumerate(main_data):
        for s in search_data:
            if s == c:
                pos = i
                break
        if pos:
            break
            
    print pos
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    if pos == None:
        regs['eax'] = 0xC0000225
        vm_set_mem(pos_ad, pdw(0))
    else:
        regs['eax'] = 0
        vm_set_mem(pos_ad, pdw(pos))
    
    vm_set_gpreg(regs)
    print 'ret', hex(regs['eax'])

def ntdll_RtlComputeCrc32():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    dwinit = vm_pop_uint32_t()
    pdata = vm_pop_uint32_t()
    ilen = vm_pop_uint32_t()


    data = vm_get_str(pdata, ilen)
    print hex(dwinit)
    print hexdump(data)
    crc_r = crc32(data, dwinit)
    print "crc32", hex(crc_r)
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = crc_r
    vm_set_gpreg(regs)
    
    
    
def ntdll_RtlExtendedIntegerMultiply():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    b2 = vm_pop_uint32_t()
    b1 = vm_pop_uint32_t()
    bm = vm_pop_uint32_t()
    
    print hex(b1), hex(b2), hex(bm)
    a = (b1<<32)+b2
    a = a*bm
    print hex(a)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = (a&0xffffffff)
    regs['edx'] = (a>>32)&0xffffffff

    vm_set_gpreg(regs)
    
def ntdll_RtlLargeIntegerAdd():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    a2 = vm_pop_uint32_t()
    a1 = vm_pop_uint32_t()    
    b2 = vm_pop_uint32_t()
    b1 = vm_pop_uint32_t()
    
    print hex(a1), hex(a2), hex(b1), hex(b2)
    a = (a1<<32)+a2 + (b1<<32)+b2
    print hex(a)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = (a&0xffffffff)
    regs['edx'] = (a>>32)&0xffffffff

    vm_set_gpreg(regs)
    
def ntdll_RtlLargeIntegerShiftRight():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    a2 = vm_pop_uint32_t()
    a1 = vm_pop_uint32_t()    
    m = vm_pop_uint32_t()
    
    print hex(a1), hex(a2), hex(m)
    a = ((a1<<32)+a2)>>m
    print hex(a)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = (a&0xffffffff)
    regs['edx'] = (a>>32)&0xffffffff

    vm_set_gpreg(regs)

def ntdll_RtlEnlargedUnsignedMultiply():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    a = vm_pop_uint32_t()&0xFFFFFFFF
    b = vm_pop_uint32_t()&0xFFFFFFFF
    
    print hex(a), hex(b)
    a = a*b
    print hex(a)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = (a&0xffffffff)
    regs['edx'] = (a>>32)&0xffffffff

    vm_set_gpreg(regs)

def ntdll_RtlLargeIntegerSubtract():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    a2 = vm_pop_uint32_t()
    a1 = vm_pop_uint32_t()    
    b2 = vm_pop_uint32_t()
    b1 = vm_pop_uint32_t()
    
    print hex(a1), hex(a2), hex(b1), hex(b2)
    a = (a1<<32)+a2 - (b1<<32)+b2
    print hex(a)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = (a&0xffffffff)
    regs['edx'] = (a>>32)&0xffffffff

    vm_set_gpreg(regs)


def ntdll_RtlCompareMemory():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad1 = vm_pop_uint32_t()
    ad2 = vm_pop_uint32_t()
    m_len = vm_pop_uint32_t()
    
    print hex(ad1), hex(ad2), hex(m_len)
    data1 = vm_get_str(ad1, m_len)
    data2 = vm_get_str(ad2, m_len)

    print hexdump(data1)
    print hexdump(data2)
    i = 0
    while data1[i] == data2[i]:
        i+=1
        if i >=m_len:
            break

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = i
    vm_set_gpreg(regs)
    print 'compare ret:', i


def user32_GetMessagePos():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0x00110022
    vm_set_gpreg(regs)
    
def kernel32_Sleep():
    ret_ad = vm_pop_uint32_t()
    t = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(t)
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)

    #XXX for malware tests
    vm_set_mem(regs['esp']-0x20, pdw(0xFFFFFFFF))
        
def ntdll_ZwUnmapViewOfSection():
    ret_ad = vm_pop_uint32_t()
    h = vm_pop_uint32_t()
    ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(h), hex(ad)
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def kernel32_IsBadReadPtr():
    ret_ad = vm_pop_uint32_t()
    lp = vm_pop_uint32_t()
    ucb = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(lp), hex(ucb)
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    

win_event_num = 0x13370
def ntoskrnl_KeInitializeEvent():
    global win_event_num
    ret_ad = vm_pop_uint32_t()
    my_event = vm_pop_uint32_t()
    my_type = vm_pop_uint32_t()
    my_state = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(my_event), hex(my_type), hex(my_state)
    vm_set_mem(my_event, pdw(win_event_num))
    win_event_num +=1

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

    
    


def ntoskrnl_RtlGetVersion():
    ret_ad = vm_pop_uint32_t()
    ptr_version = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(ptr_version)

    s = struct.pack('LLLLL', 0x88000000,0x88000001,0x88000002,0x88000003,0x88000004 )
    vm_set_mem(ptr_version, s)
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    

def hal_ExAcquireFastMutex():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    

nt_mdl = {}
nt_mdl_ad = None
nt_mdl_cur = 0

def mdl2ad(n):
    return nt_mdl_ad+0x10*n

def ad2mdl(ad):
    return ((ad-nt_mdl_ad)&0xFFFFFFFFL)/0x10
    
def ntoskrnl_IoAllocateMdl():
    global nt_mdl, nt_mdl_ad, nt_mdl_cur
    ret_ad = vm_pop_uint32_t()
    v_addr = vm_pop_uint32_t()
    l = vm_pop_uint32_t()
    second_buf = vm_pop_uint32_t()
    chargequota = vm_pop_uint32_t()
    pirp = vm_pop_uint32_t()
    
    print whoami(), hex(ret_ad), hex(v_addr), hex(l), hex(second_buf), hex(chargequota), hex(pirp)
    m = mdl(v_addr, l)
    nt_mdl[nt_mdl_cur] = m
    vm_set_mem(mdl2ad(nt_mdl_cur), str(m))
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = mdl2ad(nt_mdl_cur)
    vm_set_gpreg(regs)

    nt_mdl_cur += 1

def ntoskrnl_MmProbeAndLockPages():
    global nt_mdl, nt_mdl_ad, nt_mdl_cur
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    access_mode = vm_pop_uint32_t()
    op = vm_pop_uint32_t()
    
    print whoami(), hex(ret_ad), hex(p_mdl), hex(access_mode), hex(op)

    if not ad2mdl(p_mdl) in nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    
def ntoskrnl_MmMapLockedPagesSpecifyCache():
    global nt_mdl, nt_mdl_ad, nt_mdl_cur
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    access_mode = vm_pop_uint32_t()
    cache_type = vm_pop_uint32_t()
    base_ad = vm_pop_uint32_t()
    bugcheckonfailure = vm_pop_uint32_t()
    priority = vm_pop_uint32_t()
    
    print whoami(), hex(ret_ad), hex(p_mdl), hex(access_mode), hex(cache_type), hex(base_ad), hex(bugcheckonfailure), hex(priority)
    if not ad2mdl(p_mdl) in nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = nt_mdl[ad2mdl(p_mdl)].ad
    vm_set_gpreg(regs)
    
def ntoskrnl_MmProtectMdlSystemAddress():
    global nt_mdl, nt_mdl_ad, nt_mdl_cur
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    prot = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(p_mdl), hex(prot)
    if not ad2mdl(p_mdl) in nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    
def ntoskrnl_MmUnlockPages():
    global nt_mdl, nt_mdl_ad, nt_mdl_cur
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    print whoami(), hex(ret_ad), hex(p_mdl)
    if not ad2mdl(p_mdl) in nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    

def ntoskrnl_IoFreeMdl():
    global nt_mdl, nt_mdl_ad, nt_mdl_cur
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    print whoami(), hex(ret_ad), hex(p_mdl)
    if not ad2mdl(p_mdl) in nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))
    del(nt_mdl[ad2mdl(p_mdl)])
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    

def hal_ExReleaseFastMutex():
    global nt_mdl, nt_mdl_ad, nt_mdl_cur
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    
def ntoskrnl_RtlQueryRegistryValues():
    global nt_mdl, nt_mdl_ad, nt_mdl_cur
    ret_ad = vm_pop_uint32_t()
    relativeto = vm_pop_uint32_t()
    path = vm_pop_uint32_t()
    querytable = vm_pop_uint32_t()
    context = vm_pop_uint32_t()
    environ = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(relativeto), hex(path), hex(querytable), hex(context), hex(environ)
    p = get_str_unic(path)
    print repr(p[::2])
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    

def ntoskrnl_ExAllocatePoolWithTagPriority():
    global nt_mdl, nt_mdl_ad, nt_mdl_cur
    ret_ad = vm_pop_uint32_t()
    pool_type = vm_pop_uint32_t()
    nbr_of_bytes = vm_pop_uint32_t()
    tag = vm_pop_uint32_t()
    priority = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(pool_type), hex(nbr_of_bytes), hex(tag), hex(priority)

    max_ad = vm_get_memory_page_max_address()
    max_ad = (max_ad+0xfff) & 0xfffff000


    vm_add_memory_page(max_ad, PAGE_READ|PAGE_WRITE, "\x00"*nbr_of_bytes)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = max_ad
    vm_set_gpreg(regs)

    print "ad", hex(max_ad)





def my_lstrcmp(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    ptr_str1 = vm_pop_uint32_t()
    ptr_str2 = vm_pop_uint32_t()
    print "%s (%08x, %08x) (ret @ %08x)" % (funcname,
                                            ptr_str1, ptr_str2,
                                            ret_ad)
    s1 = get_str(ptr_str1)
    s2 = get_str(ptr_str2)
    print '%s (%r, %r)' % (' '*len(funcname), s1, s2)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = cmp(s1, s2)
    vm_set_gpreg(regs)

def kernel32_lstrcmpA():
    my_lstrcmp('lstrcmpA', get_str_ansi)

def kernel32_lstrcmpiA():
    my_lstrcmp('lstrcmpiA', lambda x: get_str_ansi(x).lower())

def kernel32_lstrcmpW():
    my_lstrcmp('lstrcmpA', get_str_unic)

def kernel32_lstrcmpiW():
    my_lstrcmp('lstrcmpiW', lambda x: get_str_unic(x).lower())


def kernel32_SetFileAttributesA():
    ret_ad = vm_pop_uint32_t()
    lpfilename = vm_pop_uint32_t()
    dwfileattributes = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(lpfilename), hex(dwfileattributes)

    if lpfilename:
        fname = get_str_ansi(lpfilename)
        print "filename", repr(fname)
        eax = 1
    else:
        eax = 0
        vm_set_mem(seh_helper.FS_0_AD+0x34, pdw(3))
    

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)

def ntdll_RtlMoveMemory():
    ret_ad = vm_pop_uint32_t()
    dst = vm_pop_uint32_t()
    src = vm_pop_uint32_t()
    l = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(dst), hex(src), hex(l)


    s = vm_get_str(src, l)
    vm_set_mem(dst, s)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def ntdll_ZwQuerySystemInformation():
    ret_ad = vm_pop_uint32_t()
    systeminformationclass = vm_pop_uint32_t()
    systeminformation = vm_pop_uint32_t()
    systeminformationl = vm_pop_uint32_t()
    returnl = vm_pop_uint32_t()
    print whoami(), hex(ret_ad),
    print hex(systeminformationclass), hex(systeminformation), hex(systeminformationl), hex(returnl)

    if systeminformationclass == 2:
        # SYSTEM_PERFORMANCE_INFORMATION
        o = struct.pack('II', 0x22222222, 0x33333333)
        o += "\x00"*systeminformationl
        o = o[:systeminformationl]
        vm_set_mem(systeminformation, o)
    else:
        raise ValueError('unknown sysinfo class', systeminformationclass)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def ntdll_ZwProtectVirtualMemory():
    ret_ad = vm_pop_uint32_t()
    handle = vm_pop_uint32_t()
    lppvoid = vm_pop_uint32_t()
    pdwsize = vm_pop_uint32_t()
    flnewprotect = vm_pop_uint32_t()
    lpfloldprotect = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(handle), hex(lppvoid), hex(pdwsize), hex(flnewprotect), hex(lpfloldprotect), ')'

    ad = updw(vm_get_str(lppvoid, 4))
    dwsize = updw(vm_get_str(pdwsize, 4))
    print 'ad', hex(ad), 'size', hex(dwsize)
    
    # XXX mask hpart
    flnewprotect &= 0xFFF


    if not flnewprotect in access_dict:
        raise ValueError( 'unknown access dw!')
    
    vm_set_mem_access(ad, access_dict[flnewprotect])

    #XXX todo real old protect
    vm_set_mem(lpfloldprotect, pdw(0x40))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)
    dump_memory_page_pool_py()



def ntdll_ZwAllocateVirtualMemory():
    ret_ad = vm_pop_uint32_t()
    handle = vm_pop_uint32_t()
    lppvoid = vm_pop_uint32_t()
    zerobits = vm_pop_uint32_t()
    pdwsize = vm_pop_uint32_t()
    alloc_type = vm_pop_uint32_t()
    flprotect = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(',
    print hex(lppvoid), hex(zerobits), hex(pdwsize), hex(alloc_type), hex(flprotect), ')'
    
    ad = updw(vm_get_str(lppvoid, 4))
    dwsize = updw(vm_get_str(pdwsize, 4))
    print 'ad', hex(ad), 'size', hex(dwsize)


    access_dict = {    0x0: 0,
                       0x1: 0,
                       0x2: PAGE_READ,
                       0x4: PAGE_READ | PAGE_WRITE,
                       0x10: PAGE_EXEC,
                       0x20: PAGE_EXEC | PAGE_READ,
                       0x40: PAGE_EXEC | PAGE_READ | PAGE_WRITE,
                       0x100: 0
                       }

    access_dict_inv = dict([(x[1], x[0]) for x in access_dict.items()])


    if not flprotect in access_dict:
        raise ValueError( 'unknown access dw!')

    max_ad = vm_get_memory_page_max_address()
    max_ad = (max_ad+0xfff) & 0xfffff000


    vm_add_memory_page(max_ad, access_dict[flprotect], "\x00"*dwsize)

    vm_set_mem(lppvoid, pdw(max_ad))


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    dump_memory_page_pool_py()
    print 'ret', hex(max_ad), hex(ret_ad)
    

def ntdll_ZwFreeVirtualMemory():
    ret_ad = vm_pop_uint32_t()
    handle = vm_pop_uint32_t()
    lppvoid = vm_pop_uint32_t()
    pdwsize = vm_pop_uint32_t()
    alloc_type = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(handle), hex(lppvoid), hex(pdwsize), hex(alloc_type), ')'
    
    ad = updw(vm_get_str(lppvoid, 4))
    dwsize = updw(vm_get_str(pdwsize, 4))
    print 'ad', hex(ad), 'size', hex(dwsize)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)


def ntdll_RtlInitString():
    ret_ad = vm_pop_uint32_t()
    pstring = vm_pop_uint32_t()
    source = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(pstring), hex(source), ')'
    
    s = get_str_ansi(source)
    print "str", repr(s)

    l = len(s)+1

    o = struct.pack('HHI', l, l, source)
    vm_set_mem(pstring, o)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)


def ntdll_RtlAnsiStringToUnicodeString():
    ret_ad = vm_pop_uint32_t()
    dst = vm_pop_uint32_t()
    src = vm_pop_uint32_t()
    alloc_str = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(dst), hex(src), hex(alloc_str), ')'

    l1, l2, p_src = struct.unpack('HHI', vm_get_str(src, 0x8))
    print hex(l1), hex(l2), hex(p_src)
    s = get_str_ansi(p_src)
    print "str", repr(s)
    s = ("\x00".join(s+"\x00"))
    l = len(s)+1
    if alloc_str:
        print 'alloc'
        max_ad = vm_get_memory_page_max_address()
        max_ad = (max_ad+0xfff) & 0xfffff000
        vm_add_memory_page(max_ad, PAGE_READ | PAGE_WRITE, "\x00"*l)
    else:
        print 'use buf'
        max_ad = p_src
    
    vm_set_mem(max_ad, s)
    
    o = struct.pack('HHI', l, l, max_ad)
    vm_set_mem(dst, o)
    
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def ntdll_LdrLoadDll():
    ret_ad = vm_pop_uint32_t()
    path = vm_pop_uint32_t()
    flags = vm_pop_uint32_t()
    modname = vm_pop_uint32_t()
    modhandle = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(path), hex(flags), hex(modname), hex(modhandle), ')'
    l1, l2, p_src = struct.unpack('HHI', vm_get_str(modname, 0x8))
    print hex(l1), hex(l2), hex(p_src)
    s = get_str_unic(p_src)
    print repr(s)
    libname = s[::2].lower()
    print repr(libname)

    ad = runtime_dll.lib_get_add_base(libname)
    print "ret", hex(ad)
    vm_set_mem(modhandle, pdw(ad))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def ntdll_RtlFreeUnicodeString():
    ret_ad = vm_pop_uint32_t()
    src = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(src), ')'

    l1, l2, p_src = struct.unpack('HHI', vm_get_str(src, 0x8))
    print hex(l1), hex(l2), hex(p_src)
    s = get_str_unic(p_src)
    print "str", repr(s)
    print repr(s[::2])

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def ntdll_LdrGetProcedureAddress():
    ret_ad = vm_pop_uint32_t()
    libbase = vm_pop_uint32_t()
    pfname = vm_pop_uint32_t()
    opt = vm_pop_uint32_t()
    p_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(libbase), hex(pfname), hex(opt), hex(p_ad)

    l1, l2, p_src = struct.unpack('HHI', vm_get_str(pfname, 0x8))
    print hex(l1), hex(l2), hex(p_src)
    fname = get_str_ansi(p_src)
    print "str", repr(fname)

    ad = runtime_dll.lib_get_add_func(libbase, fname)

    vm_set_mem(p_ad, pdw(ad))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def ntdll_memset():
    ret_ad = vm_pop_uint32_t()
    arg_addr = vm_pop_uint32_t()
    arg_c = vm_pop_uint32_t()
    arg_size = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(arg_addr), arg_c, arg_size, ')'
    vm_set_mem(arg_addr, chr(arg_c)*arg_size)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = arg_addr
    vm_set_gpreg(regs)
