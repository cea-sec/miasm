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
try:
    from Crypto.Hash import MD5
except ImportError:
    print "cannot find crypto MD5, skipping"
import inspect
from zlib import crc32
import seh_helper
import os
import time




def get_next_alloc_addr(size):
    global alloc_ad
    ret = winobjs.alloc_ad
    winobjs.alloc_ad = (winobjs.alloc_ad + size + winobjs.alloc_align)
    winobjs.alloc_ad &= (0xffffffff ^ winobjs.alloc_align)
    return ret

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

class whandle():
    def __init__(self, name, info):
        self.name = name
        self.info = info
    def __repr__(self):
        return '<%r %r %r>'%(self.__class__.__name__, self.name, self.info)


class handle_generator():
    def __init__(self):
        self.offset = 600
        self.all_handles = {}
    def add(self, name, info = None):
        self.offset += 1
        h = whandle(name, info)
        self.all_handles[self.offset] = h

        print repr(self)
        return self.offset

    def __repr__(self):
        out = '<%r\n'%self.__class__.__name__
        ks = self.all_handles.keys()
        ks.sort()

        for k in ks:
            out += "    %r %r\n"%(k, self.all_handles[k])
        out +='>'
        return out

    def __contains__(self, e):
        return e in self.all_handles

    def __getitem__(self, item):
        return self.all_handles.__getitem__(item)



class c_winobjs:
    def __init__(self):
        self.alloc_ad = 0x20000000
        self.alloc_align = 0x4000-1
        self.handle_toolhelpsnapshot = 0xaaaa00
        self.toolhelpsnapshot_info = {}
        self.handle_curprocess = 0xaaaa01
        self.dbg_present = 0
        self.tickcount =0
        self.dw_pid_dummy1 = 0x111
        self.dw_pid_explorer = 0x222
        self.dw_pid_dummy2 = 0x333
        self.dw_pid_cur = 0x444
        self.module_fname_nux = None
        self.module_name = "test.exe\x00"
        self.module_path = "c:\\mydir\\"+self.module_name
        self.hcurmodule = None
        self.module_filesize = None
        self.getversion = 0x0A280105
        self.getforegroundwindow =  0x333333
        self.cryptcontext_hwnd = 0x44400
        self.cryptcontext_bnum = 0x44000
        self.cryptcontext_num = 0
        self.cryptcontext = {}
        self.phhash_crypt_md5 = 0x55555
        self.files_hwnd = {}
        self.windowlong_dw = 0x77700
        self.module_cur_hwnd = 0x88800
        self.module_file_nul = 0x999000
        self.runtime_dll = None
        self.current_pe = None
        self.tls_index = 0xf
        self.tls_values = {}
        self.handle_pool = handle_generator()
        self.hkey_handles = {0x80000001: "hkey_current_user"}

        self.nt_mdl = {}
        self.nt_mdl_ad = None
        self.nt_mdl_cur = 0
        self.win_event_num = 0x13370
        self.cryptdll_md5_h = {}

        self.lastwin32error = 0
        self.mutex = {}
        self.env_variables = {}
winobjs = c_winobjs()





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

def get_str_ansi(ad_str, max_char = None):
    l = 0
    tmp = ad_str
    while vm_get_str(tmp, 1) != "\x00":
        tmp +=1
        l+=1
    return vm_get_str(ad_str, l)

def get_str_unic(ad_str, max_char = None):
    l = 0
    tmp = ad_str
    while vm_get_str(tmp, 2) != "\x00\x00":
        tmp +=2
        l+=2
    return vm_get_str(ad_str, l)

def set_str_ansi(s):
    return s + "\x00"

def set_str_unic(s):
    return "\x00".join(list(s))+'\x00'*3


def kernel32_GlobalAlloc():
    ret_ad = vm_pop_uint32_t()
    uflags = vm_pop_uint32_t()
    msize = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(uflags), hex(msize), ')'

    alloc_addr = get_next_alloc_addr(msize)
    vm_add_memory_page(alloc_addr, PAGE_READ|PAGE_WRITE, "\x00"*msize)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = alloc_addr
    vm_set_gpreg(regs)

def kernel32_LocalFree():
    ret_ad = vm_pop_uint32_t()
    lpvoid = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(lpvoid), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)


def kernel32_LocalAlloc():
    ret_ad = vm_pop_uint32_t()
    uflags = vm_pop_uint32_t()
    msize = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(uflags), hex(msize), ')'
    alloc_addr = get_next_alloc_addr(msize)
    vm_add_memory_page(alloc_addr, PAGE_READ|PAGE_WRITE, "\x00"*msize)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = alloc_addr
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
    regs['eax'] = winobjs.dbg_present
    vm_set_gpreg(regs)


def kernel32_CreateToolhelp32Snapshot():
    ret_ad = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()
    th32processid = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(dwflags), hex(th32processid), ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.handle_toolhelpsnapshot
    vm_set_gpreg(regs)

def kernel32_GetCurrentProcess():
    ret_ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.handle_curprocess
    vm_set_gpreg(regs)

def kernel32_GetCurrentProcessId():
    ret_ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.dw_pid_cur
    vm_set_gpreg(regs)


process_list = [
    [
        0x40,               #DWORD     dwSize;             
        0,                  #DWORD     cntUsage;           
        winobjs.dw_pid_dummy1,       #DWORD     th32ProcessID;      
        0x11111111,         #ULONG_PTR th32DefaultHeapID;  
        0x11111112,         #DWORD     th32ModuleID;       
        1,                  #DWORD     cntThreads;         
        winobjs.dw_pid_explorer,    #DWORD     th32ParentProcessID;
        0xbeef,             #LONG      pcPriClassBase;     
        0x0,                #DWORD     dwFlags;            
        "dummy1.exe"          #TCHAR     szExeFile[MAX_PATH];
        ],
    [
        0x40,               #DWORD     dwSize;             
        0,                  #DWORD     cntUsage;           
        winobjs.dw_pid_explorer,    #DWORD     th32ProcessID;      
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
        winobjs.dw_pid_dummy2,       #DWORD     th32ProcessID;      
        0x11111111,         #ULONG_PTR th32DefaultHeapID;  
        0x11111112,         #DWORD     th32ModuleID;       
        1,                  #DWORD     cntThreads;         
        winobjs.dw_pid_explorer,    #DWORD     th32ParentProcessID;
        0xbeef,             #LONG      pcPriClassBase;     
        0x0,                #DWORD     dwFlags;            
        "dummy2.exe"          #TCHAR     szExeFile[MAX_PATH];
        ],

    [
        0x40,               #DWORD     dwSize;             
        0,                  #DWORD     cntUsage;           
        winobjs.dw_pid_cur,         #DWORD     th32ProcessID;      
        0x11111111,         #ULONG_PTR th32DefaultHeapID;  
        0x11111112,         #DWORD     th32ModuleID;       
        1,                  #DWORD     cntThreads;         
        winobjs.dw_pid_explorer,    #DWORD     th32ParentProcessID;
        0xbeef,             #LONG      pcPriClassBase;     
        0x0,                #DWORD     dwFlags;            
        winobjs.module_name          #TCHAR     szExeFile[MAX_PATH];
        ],


]

def kernel32_Process32First():
    ret_ad = vm_pop_uint32_t()
    s_handle = vm_pop_uint32_t()
    ad_pentry = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(s_handle), hex(ad_pentry), ')'

    pentry = struct.pack('IIIIIIIII', *process_list[0][:-1])+process_list[0][-1]
    vm_set_mem(ad_pentry, pentry)
    winobjs.toolhelpsnapshot_info[s_handle] = 0

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)


def kernel32_Process32Next():
    ret_ad = vm_pop_uint32_t()
    s_handle = vm_pop_uint32_t()
    ad_pentry = vm_pop_uint32_t()

    winobjs.toolhelpsnapshot_info[s_handle] +=1
    if winobjs.toolhelpsnapshot_info[s_handle] >= len(process_list):
        eax = 0
    else:
        eax = 1
        n = winobjs.toolhelpsnapshot_info[s_handle]
        print whoami(), hex(ret_ad), '(', hex(s_handle), hex(ad_pentry), ')'
        pentry = struct.pack('IIIIIIIII', *process_list[n][:-1])+process_list[n][-1]
        vm_set_mem(ad_pentry, pentry)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)




def kernel32_GetTickCount():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), '(', ')'
    winobjs.tickcount +=1

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.tickcount
    vm_set_gpreg(regs)


def kernel32_GetVersion():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), '(', ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.getversion
    vm_set_gpreg(regs)

def my_GetVersionEx(funcname, set_str):
    ret_ad = vm_pop_uint32_t()
    ptr_struct = vm_pop_uint32_t()

    print funcname, hex(ret_ad), '(', ')'

    s = struct.pack("IIIII",
                    0x114, # struct size
                    0x5,   # maj vers
                    0x2, # min vers
                    0x666, # build nbr
                    0x2,   # platform id
                    ) + set_str("Service pack 4")
    vm_set_mem(ptr_struct, s)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def kernel32_GetVersionExA():
    my_GetVersionEx(whoami(), set_str_ansi)
def kernel32_GetVersionExW():
    my_GetVersionEx(whoami(), set_str_unic)


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
    regs['eax'] = winobjs.getforegroundwindow
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
    vm_set_mem(phprov, pdw(winobjs.cryptcontext_hwnd))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)


def advapi32_CryptCreateHash():
    ret_ad = vm_pop_uint32_t()
    hprov = vm_pop_uint32_t()
    algid = vm_pop_uint32_t()
    hkey = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()
    phhash = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hprov), hex(algid), hex(hkey), hex(dwflags), hex(phhash), ')'

    winobjs.cryptcontext_num +=1

    if algid == 0x00008003:
        print 'algo is MD5'
        vm_set_mem(phhash, pdw(winobjs.cryptcontext_bnum+winobjs.cryptcontext_num))
        winobjs.cryptcontext[winobjs.cryptcontext_bnum+winobjs.cryptcontext_num] = hobj()
        winobjs.cryptcontext[winobjs.cryptcontext_bnum+winobjs.cryptcontext_num].h = MD5.new()
    else:
        raise ValueError('un impl algo1')
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def advapi32_CryptHashData():
    ret_ad = vm_pop_uint32_t()
    hhash = vm_pop_uint32_t()
    pbdata = vm_pop_uint32_t()
    dwdatalen = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hhash), hex(pbdata), hex(dwdatalen), hex(dwflags), ')'

    if not hhash in winobjs.cryptcontext:
        raise ValueError("unknown crypt context")

    data = vm_get_str(pbdata, dwdatalen)
    print 'will hash'
    print repr(data)
    winobjs.cryptcontext[hhash].h.update(data)
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
    h = winobjs.cryptcontext[hbasedata].h.digest()
    print 'hash', repr(h)
    winobjs.cryptcontext[hbasedata].h_result = h
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

def kernel32_CreateFile(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    lpfilename = vm_pop_uint32_t()
    access = vm_pop_uint32_t()
    dwsharedmode = vm_pop_uint32_t()
    lpsecurityattr = vm_pop_uint32_t()
    dwcreationdisposition = vm_pop_uint32_t()
    dwflagsandattr = vm_pop_uint32_t()
    htemplatefile = vm_pop_uint32_t()



    print funcname, hex(ret_ad), hex(lpfilename), hex(access), hex(dwsharedmode), hex(lpsecurityattr), hex(dwcreationdisposition), hex(dwflagsandattr), hex(htemplatefile)

    fname = get_str(lpfilename)
    print 'fname', fname

    eax = 0xffffffff

    if fname.upper() in [r"\\.\SICE", r"\\.\NTICE", r"\\.\SIWVID"]:
        pass
    elif fname.upper() in ['NUL']:
        eax = winobjs.module_cur_hwnd
    else:
        # nuxify path
        fname = fname.replace('\\', "/").lower()
        # go in sandbox files
        f = os.path.join('file_sb', fname)
        if access & 0x80000000:
            # read
            if not os.access(f, os.R_OK):
                raise ValueError("file doesn't exit", f)
        h = open(f, 'rb+')
        eax = winobjs.handle_pool.add(f, h)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)


def kernel32_CreateFileA():
    kernel32_CreateFile(whoami(), get_str_ansi)



def kernel32_ReadFile():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()
    lpbuffer = vm_pop_uint32_t()
    nnumberofbytestoread = vm_pop_uint32_t()
    lpnumberofbytesread = vm_pop_uint32_t()
    lpoverlapped = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), hex(lpbuffer), hex(nnumberofbytestoread), hex(lpnumberofbytesread), hex(lpoverlapped), ')'

    if hwnd == winobjs.module_cur_hwnd:
        pass
    elif hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown hwnd!')

    eax = 0xffffffff
    data = None
    if hwnd in winobjs.files_hwnd:
        data = winobjs.files_hwnd[winobjs.module_cur_hwnd].read(nnumberofbytestoread)
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        data = wh.info.read(nnumberofbytestoread)
    else:
        raise ValueError('unknown filename')

    if data != None:
        if (lpnumberofbytesread):
            vm_set_mem(lpnumberofbytesread, pdw(len(data)))
        vm_set_mem(lpbuffer, data)


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def kernel32_GetFileSize():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()
    lpfilesizehight = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), hex(lpfilesizehight), ')'

    if hwnd == winobjs.module_cur_hwnd:
        eax = len(open(winobjs.module_fname_nux).read())
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        print wh
        eax = len(open(wh.name).read())
    else:
        raise ValueError('unknown hwnd!')

    if lpfilesizehight != 0:
        vm_set_mem(lpfilesizehight, pdw(eax&0xffff0000))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)


def kernel32_FlushInstructionCache():
    ret_ad = vm_pop_uint32_t()
    hprocess = vm_pop_uint32_t()
    lpbasead = vm_pop_uint32_t()
    dwsize = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(hprocess), hex(lpbasead), hex(dwsize)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0x1337
    vm_set_gpreg(regs)



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
    if lpfloldprotect:
        vm_set_mem(lpfloldprotect, pdw(0x40))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)
    #dump_memory_page_pool_py()



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


    if lpvoid ==  0:
        alloc_addr = get_next_alloc_addr(dwsize)
        vm_add_memory_page(alloc_addr, access_dict[flprotect], "\x00"*dwsize)
    else:
        alloc_addr = lpvoid
        vm_set_mem_access(lpvoid, access_dict[flprotect])




    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = alloc_addr
    vm_set_gpreg(regs)
    dump_memory_page_pool_py()
    print 'ret', hex(alloc_addr), hex(ret_ad)


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
    regs['eax'] = winobjs.windowlong_dw
    vm_set_gpreg(regs)

def user32_SetWindowLongA():
    ret_ad = vm_pop_uint32_t()
    hwnd = vm_pop_uint32_t()
    nindex = vm_pop_uint32_t()
    newlong = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hwnd), hex(nindex), hex(newlong), ')'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.windowlong_dw
    vm_set_gpreg(regs)




def kernel32_GetModuleFileName(funcname, set_str):
    ret_ad = vm_pop_uint32_t()
    hmodule = vm_pop_uint32_t()
    lpfilename = vm_pop_uint32_t()
    nsize = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', hex(hmodule), hex(lpfilename), hex(nsize), ')'

    if hmodule in [0, winobjs.hcurmodule]:
        p = winobjs.module_path[:]
    elif winobjs.runtime_dll and hmodule in winobjs.runtime_dll.name2off.values() :
        name_inv = dict([(x[1], x[0]) for x in winobjs.runtime_dll.name2off.items()])
        p = name_inv[hmodule]
    else:
        print ValueError('unknown module h', hex(hmodule))
        p = None


    if p == None:
        l = 0
    elif nsize < len(p):
        p = p[:nsize]
        l = len(p)
    else:
        l = len(p)

    print repr(p)
    if p:
        vm_set_mem(lpfilename, set_str(p))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = l
    vm_set_gpreg(regs)


def kernel32_GetModuleFileNameA():
    kernel32_GetModuleFileName(whoami(), set_str_ansi)
def kernel32_GetModuleFileNameW():
    kernel32_GetModuleFileName(whoami(), set_str_unic)



def kernel32_CreateMutex(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    mutexattr = vm_pop_uint32_t()
    initowner = vm_pop_uint32_t()
    lpname = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(mutexattr), hex(initowner), hex(lpname)

    if lpname:
        name = get_str(lpname)
        print repr(name)
    else:
        name = None
    if name in winobjs.mutex:
        ret = 0
    else:
        winobjs.mutex[name] = id(name)
        ret = winobjs.mutex[name]
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)


def kernel32_CreateMutexA():
    kernel32_CreateMutex(whoami(), get_str_ansi)
def kernel32_CreateMutexW():
    kernel32_CreateMutex(whoami(), get_str_unic)


def shell32_SHGetSpecialFolderLocation():
    ret_ad = vm_pop_uint32_t()
    hwndowner = vm_pop_uint32_t()
    nfolder = vm_pop_uint32_t()
    ppidl = vm_pop_uint32_t()
    print whoami(), hex(hwndowner), hex(nfolder), hex(ppidl)

    vm_set_mem(ppidl, pdw(nfolder))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def kernel32_SHGetPathFromIDList(funcname, set_str):
    ret_ad = vm_pop_uint32_t()
    pidl = vm_pop_uint32_t()
    ppath = vm_pop_uint32_t()
    print whoami(), hex(pidl), hex(ppath)

    if pidl == 7:# CSIDL_STARTUP:
        s = "c:\\doc\\user\\startmenu\\programs\\startup"
        s = set_str(s)
    else:
        raise ValueError('pidl not implemented', pidl)
    vm_set_mem(ppath, s)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def shell32_SHGetPathFromIDListW():
    kernel32_SHGetPathFromIDList(whoami(), set_str_unic)
def shell32_SHGetPathFromIDListA():
    kernel32_SHGetPathFromIDList(whoami(), set_str_ansi)


def kernel32_GetLastError():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), '(',  ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.lastwin32error
    vm_set_gpreg(regs)

def kernel32_SetLastError():
    ret_ad = vm_pop_uint32_t()
    e = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(e)

    #lasterr addr
    ad = seh_helper.FS_0_AD + 0x34
    vm_set_mem(ad, pdw(e))

    winobjs.lastwin32error = e
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def kernel32_LoadLibraryA():
    ret_ad = vm_pop_uint32_t()
    dllname = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(dllname)

    libname = get_str_ansi(dllname, 0x100)
    print repr(libname)

    eax = winobjs.runtime_dll.lib_get_add_base(libname)
    print "ret", hex(eax)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)

def kernel32_GetProcAddress():
    ret_ad = vm_pop_uint32_t()
    libbase = vm_pop_uint32_t()
    fname = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(libbase), hex(fname)
    fname = fname & 0xFFFFFFFF
    if fname < 0x10000:
        fname = fname
    else:
        fname = get_str_ansi(fname, 0x100)
        if not fname:
            fname = None
    print repr(fname)
    if fname != None:
        ad = winobjs.runtime_dll.lib_get_add_func(libbase, fname)
    else:
        ad = 0
    ad = winobjs.runtime_dll.lib_get_add_func(libbase, fname)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ad
    vm_set_gpreg(regs)



def kernel32_LoadLibraryW():
    ret_ad = vm_pop_uint32_t()
    dllname = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(dllname)

    libname = get_str_unic(dllname, 0x100)[::2]
    print repr(libname)

    eax = winobjs.runtime_dll.lib_get_add_base(libname)
    print "ret", hex(eax)
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
        print repr(libname)
        if libname:
            eax = winobjs.runtime_dll.lib_get_add_base(libname)
        else:
            print 'unknown module!'
            eax = 0
    else:
        eax = winobjs.current_pe.NThdr.ImageBase
        print "default img base" , hex(eax)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)

def kernel32_VirtualLock():
    ret_ad = vm_pop_uint32_t()
    lpaddress = vm_pop_uint32_t()
    dwsize = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(lpaddress), hex(dwsize)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
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

    s = winobjs.module_path

    alloc_addr = get_next_alloc_addr(0x1000)
    vm_add_memory_page(alloc_addr, PAGE_READ|PAGE_WRITE, s)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = alloc_addr
    vm_set_gpreg(regs)

def cryptdll_MD5Init():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_ctx = vm_pop_uint32_t()
    index = len(winobjs.cryptdll_md5_h)
    h = MD5.new()
    winobjs.cryptdll_md5_h[index] = h

    vm_set_mem(ad_ctx, pdw(index))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)


def cryptdll_MD5Update():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    ad_ctx = vm_pop_uint32_t()
    ad_input = vm_pop_uint32_t()
    inlen = vm_pop_uint32_t()

    index = vm_get_str(ad_ctx, 4)
    index = updw(index)
    if not index in winobjs.cryptdll_md5_h:
        raise ValueError('unknown h context', index)

    data = vm_get_str(ad_input, inlen)
    winobjs.cryptdll_md5_h[index].update(data)
    print hexdump(data)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    vm_set_gpreg(regs)

def cryptdll_MD5Final():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)

    ad_ctx = vm_pop_uint32_t()

    index = vm_get_str(ad_ctx, 4)
    index = updw(index)
    if not index in winobjs.cryptdll_md5_h:
        raise ValueError('unknown h context', index)
    h = winobjs.cryptdll_md5_h[index].digest()
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
    ad_ctxu = vm_pop_uint32_t()
    ad_ctxa = vm_pop_uint32_t()
    alloc_dst = vm_pop_uint32_t()

    print whoami(), hex(ret_ad)

    l1, l2, ptra = struct.unpack('HHL', vm_get_str(ad_ctxa, 8))
    print hex(l1), hex(l2), hex(ptra)

    s = vm_get_str(ptra, l1)
    print s
    s = '\x00'.join(s) + "\x00\x00"
    if alloc_dst:
        alloc_addr = get_next_alloc_addr(0x1000)
        vm_add_memory_page(alloc_addr , PAGE_READ | PAGE_WRITE, s)

    vm_set_mem(ad_ctxu, pw(len(s))+pw(len(s)+1)+pdw(alloc_addr))
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

def ntoskrnl_KeInitializeEvent():
    ret_ad = vm_pop_uint32_t()
    my_event = vm_pop_uint32_t()
    my_type = vm_pop_uint32_t()
    my_state = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(my_event), hex(my_type), hex(my_state)
    vm_set_mem(my_event, pdw(winobjs.win_event_num))
    winobjs.win_event_num +=1

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def ntoskrnl_RtlGetVersion():
    ret_ad = vm_pop_uint32_t()
    ptr_version = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(ptr_version)

    s = struct.pack("IIIII",
                    0x114, # struct size
                    0x5,   # maj vers
                    0x2, # min vers
                    0x666, # build nbr
                    0x2,   # platform id
                    ) + set_str_unic("Service pack 4")

    vm_set_mem(ptr_version, s)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def ntoskrnl_RtlVerifyVersionInfo():
    ret_ad = vm_pop_uint32_t()
    ptr_version = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(ptr_version)

    s = vm_get_str(ptr_version, 0x5*4)
    print repr(s)
    s_size, s_majv, s_minv, s_buildn, s_platform = struct.unpack('IIIII', s)
    print s_size, s_majv, s_minv, s_buildn, s_platform
    fds
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

def mdl2ad(n):
    return winobjs.nt_mdl_ad+0x10*n

def ad2mdl(ad):
    return ((ad-winobjs.nt_mdl_ad)&0xFFFFFFFFL)/0x10

def ntoskrnl_IoAllocateMdl():
    ret_ad = vm_pop_uint32_t()
    v_addr = vm_pop_uint32_t()
    l = vm_pop_uint32_t()
    second_buf = vm_pop_uint32_t()
    chargequota = vm_pop_uint32_t()
    pirp = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(v_addr), hex(l), hex(second_buf), hex(chargequota), hex(pirp)
    m = mdl(v_addr, l)
    winobjs.nt_mdl[winobjs.nt_mdl_cur] = m
    vm_set_mem(mdl2ad(winobjs.nt_mdl_cur), str(m))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = mdl2ad(winobjs.nt_mdl_cur)
    vm_set_gpreg(regs)

    winobjs.nt_mdl_cur += 1

def ntoskrnl_MmProbeAndLockPages():
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    access_mode = vm_pop_uint32_t()
    op = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(p_mdl), hex(access_mode), hex(op)

    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def ntoskrnl_MmMapLockedPagesSpecifyCache():
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    access_mode = vm_pop_uint32_t()
    cache_type = vm_pop_uint32_t()
    base_ad = vm_pop_uint32_t()
    bugcheckonfailure = vm_pop_uint32_t()
    priority = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(p_mdl), hex(access_mode), hex(cache_type), hex(base_ad), hex(bugcheckonfailure), hex(priority)
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.nt_mdl[ad2mdl(p_mdl)].ad
    vm_set_gpreg(regs)

def ntoskrnl_MmProtectMdlSystemAddress():
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    prot = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(p_mdl), hex(prot)
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def ntoskrnl_MmUnlockPages():
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    print whoami(), hex(ret_ad), hex(p_mdl)
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def ntoskrnl_IoFreeMdl():
    ret_ad = vm_pop_uint32_t()
    p_mdl = vm_pop_uint32_t()&0xffffffff
    print whoami(), hex(ret_ad), hex(p_mdl)
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))
    del(winobjs.nt_mdl[ad2mdl(p_mdl)])
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def hal_ExReleaseFastMutex():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
def ntoskrnl_RtlQueryRegistryValues():
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
    ret_ad = vm_pop_uint32_t()
    pool_type = vm_pop_uint32_t()
    nbr_of_bytes = vm_pop_uint32_t()
    tag = vm_pop_uint32_t()
    priority = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(pool_type), hex(nbr_of_bytes), hex(tag), hex(priority)

    alloc_addr = get_next_alloc_addr(nbr_of_bytes)
    vm_add_memory_page(alloc_addr, PAGE_READ|PAGE_WRITE, "\x00"*nbr_of_bytes)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = alloc_addr
    vm_set_gpreg(regs)

    print "ad", hex(alloc_addr)





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
    my_lstrcmp(whoami(), get_str_ansi)

def kernel32_lstrcmpiA():
    my_lstrcmp(whoami(), lambda x: get_str_ansi(x).lower())

def kernel32_lstrcmpW():
    my_lstrcmp(whoami(), get_str_unic)

def kernel32_lstrcmpiW():
    my_lstrcmp(whoami(), lambda x: get_str_unic(x).lower())

def kernel32_lstrcmpi():
    my_lstrcmp(whoami(), lambda x: get_str_ansi(x).lower())



def my_strcpy(funcname, get_str, set_str):
    ret_ad = vm_pop_uint32_t()
    ptr_str1 = vm_pop_uint32_t()
    ptr_str2 = vm_pop_uint32_t()
    print "%s (%08x, %08x) (ret @ %08x)" % (funcname,
                                            ptr_str1, ptr_str2,
                                            ret_ad)
    s2 = get_str(ptr_str2)
    print '%s (%r)' % (funcname, s2)
    vm_set_mem(ptr_str1, set_str(s2))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ptr_str1
    vm_set_gpreg(regs)

def kernel32_lstrcpyW():
    my_strcpy(whoami(), get_str_unic, lambda x:x+"\x00\x00")

def kernel32_lstrcpyA():
    my_strcpy(whoami(), get_str_ansi, lambda x:x+"\x00")

def kernel32_lstrcpy():
    my_strcpy(whoami(), get_str_ansi, lambda x:x+"\x00")


def kernel32_lstrcpyn():
    ret_ad = vm_pop_uint32_t()
    ptr_str1 = vm_pop_uint32_t()
    ptr_str2 = vm_pop_uint32_t()
    mlen = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), hex(ptr_str1), hex(ptr_str2), hex(mlen)

    s2 = get_str_ansi(ptr_str2)
    print repr(s2)
    s2 = s2[:mlen]
    vm_set_mem(ptr_str1, s2)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ptr_str1
    vm_set_gpreg(regs)

def my_strlen(funcname, get_str, mylen):
    ret_ad = vm_pop_uint32_t()
    arg_src = vm_pop_uint32_t()

    print funcname, hex(ret_ad), '(', hex(arg_src),   ')'
    src = get_str(arg_src)
    print funcname, repr(src)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = mylen(src)
    vm_set_gpreg(regs)

def kernel32_lstrlenA():
    my_strlen(whoami(), get_str_ansi, lambda x:len(x))
def kernel32_lstrlenW():
    my_strlen(whoami(), get_str_unic, lambda x:len(x[::2]))


def my_lstrcat(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    ptr_str1 = vm_pop_uint32_t()
    ptr_str2 = vm_pop_uint32_t()
    print "%s (%08x, %08x) (ret @ %08x)" % (funcname,
                                            ptr_str1, ptr_str2,
                                            ret_ad)
    s1 = get_str(ptr_str1)
    s2 = get_str(ptr_str2)
    print '%s (%r, %r)' % (whoami(), s1, s2)

    s = s1+s2
    print repr(s)
    vm_set_mem(ptr_str1, s1+s2)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ptr_str1
    vm_set_gpreg(regs)

def kernel32_lstrcatA():
    my_lstrcat(whoami(), get_str_ansi)
def kernel32_lstrcatW():
    my_lstrcat(whoami(), get_str_unic)


def kernel32_GetUserGeoID():
    ret_ad = vm_pop_uint32_t()
    geoclass = vm_pop_uint32_t()
    print whoami(), hex(geoclass)

    if geoclass == 14:
        ret = 12345678
    elif geoclass == 16:
        ret = 55667788
    else:
        raise ValueError('unknown geolcass')

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)


def my_GetVolumeInformation(funcname, get_str, set_str):
    ret_ad = vm_pop_uint32_t()
    lprootpathname = vm_pop_uint32_t()
    lpvolumenamebuffer = vm_pop_uint32_t()
    nvolumenamesize = vm_pop_uint32_t()
    lpvolumeserialnumber = vm_pop_uint32_t()
    lpmaximumcomponentlength = vm_pop_uint32_t()
    lpfilesystemflags = vm_pop_uint32_t()
    lpfilesystemnamebuffer = vm_pop_uint32_t()
    nfilesystemnamesize = vm_pop_uint32_t()

    print funcname,hex(lprootpathname),hex(lpvolumenamebuffer),\
        hex(nvolumenamesize),hex(lpvolumeserialnumber),\
        hex(lpmaximumcomponentlength),hex(lpfilesystemflags),\
        hex(lpfilesystemnamebuffer),hex(nfilesystemnamesize)

    if lprootpathname:
        s = get_str(lprootpathname)
        print repr(s)

    if lpvolumenamebuffer:
        s = "volumename"
        s = s[:nvolumenamesize]
        vm_set_mem(lpvolumenamebuffer, set_str(s))

    if lpvolumeserialnumber:
        vm_set_mem(lpvolumeserialnumber, pdw(11111111))
    if lpmaximumcomponentlength:
        vm_set_mem(lpmaximumcomponentlength, pdw(0xff))
    if lpfilesystemflags:
        vm_set_mem(lpfilesystemflags, pdw(22222222))

    if lpfilesystemnamebuffer:
        s = "filesystemname"
        s = s[:nfilesystemnamesize]
        vm_set_mem(lpfilesystemnamebuffer, set_str(s))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def kernel32_GetVolumeInformationA():
    my_GetVolumeInformation(whoami(), get_str_ansi, lambda x:x+"\x00")
def kernel32_GetVolumeInformationW():
    my_GetVolumeInformation(whoami(), get_str_unic, set_str_unic)

def kernel32_MultiByteToWideChar():
    ret_ad = vm_pop_uint32_t()
    codepage = vm_pop_uint32_t()
    dwflags = vm_pop_uint32_t()
    lpmultibytestr = vm_pop_uint32_t()
    cbmultibyte = vm_pop_uint32_t()
    lpwidecharstr = vm_pop_uint32_t()
    cchwidechar = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), \
        hex(codepage),hex(dwflags),hex(lpmultibytestr),hex(cbmultibyte),hex(lpwidecharstr),hex(cchwidechar)
    src = get_str_ansi(lpmultibytestr)+'\x00'
    l = len(src)
    print repr(src)

    src = "\x00".join(list(src))
    print repr(src), hex(len(src))
    vm_set_mem(lpwidecharstr, src)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = l
    vm_set_gpreg(regs)

def my_GetEnvironmentVariable(funcname, get_str, set_str, mylen):
    ret_ad = vm_pop_uint32_t()
    lpname = vm_pop_uint32_t()
    lpbuffer = vm_pop_uint32_t()
    nsize = vm_pop_uint32_t()

    print funcname,hex(lpname), hex(lpbuffer), hex(nsize)
    s = get_str(lpname)
    if get_str == get_str_unic:
        s = s[::2]
    if s in winobjs.env_variables:
        v = set_str(winobjs.env_variables[s])
    else:
        print 'WARNING unknown env variable', repr(s)
        v = ""
    print 'return', repr(v)
    vm_set_mem(lpbuffer, v)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = mylen(v)
    vm_set_gpreg(regs)

def my_GetSystemDirectory(funcname, set_str):
    ret_ad = vm_pop_uint32_t()
    lpbuffer = vm_pop_uint32_t()
    usize = vm_pop_uint32_t()
    print "%s (%08x, %08x) (ret @ %08x)" % (whoami(),
                                            lpbuffer,usize,
                                            ret_ad)

    s = "c:\\windows\\system32"
    l = len(s)
    s = set_str(s)
    vm_set_mem(lpbuffer, s)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = l
    vm_set_gpreg(regs)


def kernel32_GetSystemDirectoryA():
    my_GetSystemDirectory(whoami(), set_str_ansi)
def kernel32_GetSystemDirectoryW():
    my_GetSystemDirectory(whoami(), set_str_unic)


def my_CreateDirectory(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    lppath = vm_pop_uint32_t()
    secattrib = vm_pop_uint32_t()
    print "%s (%08x, %08x) (ret @ %08x)" % (funcname,
                                            lppath,secattrib,
                                            ret_ad)
    p = get_str(lppath)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0x1337
    vm_set_gpreg(regs)

def kernel32_CreateDirectoryW():
    my_CreateDirectory(whoami(), get_str_unic)
def kernel32_CreateDirectoryW():
    my_CreateDirectory(whoami(), get_str_ansi)



def kernel32_GetEnvironmentVariableA():
    my_GetEnvironmentVariable(whoami(),
                              get_str_ansi,
                              lambda x:x+"\x00",
                              lambda x:len(x))

def kernel32_GetEnvironmentVariableW():
    my_GetEnvironmentVariable(whoami(),
                              get_str_unic,
                              lambda x:"\x00".join(list(x+"\x00")),
                              lambda x:len(x[::2]))

def my_CreateEvent(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    lpeventattributes = vm_pop_uint32_t()
    bmanualreset = vm_pop_uint32_t()
    binitialstate = vm_pop_uint32_t()
    lpname = vm_pop_uint32_t()

    print funcname, hex(lpeventattributes), hex(bmanualreset), hex(binitialstate), hex(lpname)
    s = get_str(lpname)
    print repr(s)
    if not s in winobjs.events_pool:
        winobjs.events_pool[s] = (bmanualreset, binitialstate)
    else:
        print 'WARNING: known event'

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = id(s)
    vm_set_gpreg(regs)

def kernel32_CreateEventA():
    my_CreateEvent(whoami(), get_str_ansi)
def kernel32_CreateEventA():
    my_CreateEvent(whoami(), get_str_unic)



def kernel32_WaitForSingleObject():
    ret_ad = vm_pop_uint32_t()
    handle = vm_pop_uint32_t()
    dwms = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(handle), hex(dwms)

    t_start = time.time()*1000
    while True:
        if dwms and dwms+t_start > time.time()*1000:
            ret = 0x102
            break
        for k, v in winobjs.events_pool.items():
            if k != handle:
                continue
            if winobjs.events_pool[k][1] == 1:
                ret = 0
                break
        time.sleep(0.1)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)


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

    alloc_addr = get_next_alloc_addr(dwsize)
    vm_add_memory_page(alloc_addr, access_dict[flprotect], "\x00"*dwsize)
    vm_set_mem(lppvoid, pdw(alloc_addr))


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)
    dump_memory_page_pool_py()
    print 'ret', hex(alloc_addr), hex(ret_ad)

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
        alloc_addr = get_next_alloc_addr(l)
        vm_add_memory_page(alloc_addr, PAGE_READ | PAGE_WRITE, "\x00"*l)
    else:
        print 'use buf'
        alloc_addr = p_src
    vm_set_mem(alloc_addr, s)
    o = struct.pack('HHI', l, l, alloc_addr)
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

    ad = winobjs.runtime_dll.lib_get_add_base(libname)
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

    ad = winobjs.runtime_dll.lib_get_add_func(libbase, fname)

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



def shlwapi_PathFindExtensionA():
    ret_ad = vm_pop_uint32_t()
    path_ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(path_ad)
    path = get_str_ansi(path_ad)
    print repr(path)
    i = path.rfind('.')
    if i == -1:
        i = path_ad + len(path)
    else:
        i = path_ad + i
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = i
    vm_set_gpreg(regs)

def shlwapi_PathIsPrefixW():
    ret_ad = vm_pop_uint32_t()
    ptr_prefix = vm_pop_uint32_t()
    ptr_path = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(ptr_prefix), hex(ptr_path)
    prefix = get_str_unic(ptr_prefix)
    path = get_str_unic(ptr_path)
    print repr(prefix), repr(path)

    if path.startswith(prefix):
        ret = 1
    else:
        ret = 0
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)



def shlwapi_PathIsFileSpec(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    path_ad = vm_pop_uint32_t()

    print funcname, hex(ret_ad), hex(path_ad)
    path = get_str(path_ad)
    print repr(path)
    if path.find(':') != -1 and path.find('\\') != -1:
        ret = 0
    else:
        ret = 1

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)

def shlwapi_PathGetDriveNumber(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    path_ad = vm_pop_uint32_t()

    print funcname, hex(ret_ad), hex(path_ad)
    path = get_str(path_ad)
    print repr(path)
    l = ord(path[0].upper()) - ord('A')
    if 0 <=l <=25:
        ret = l
    else:
        ret = -1

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)

def shlwapi_PathGetDriveNumberA():
    shlwapi_PathGetDriveNumber(whoami(), get_str_ansi)

def shlwapi_PathGetDriveNumberW():
    shlwapi_PathGetDriveNumber(whoami(), get_str_unic)



def shlwapi_PathIsFileSpecA():
    shlwapi_PathIsFileSpec(whoami(), get_str_ansi)

def shlwapi_PathIsFileSpecW():
    shlwapi_PathIsFileSpec(whoami(), get_str_unic)


def shlwapi_StrToIntA():
    ret_ad = vm_pop_uint32_t()
    i_str_ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(i_str_ad)
    i_str = get_str_ansi(i_str_ad)
    print repr(i_str)
    try:
        i = int(i_str)
    except:
        print 'WARNING cannot convert int'
        i = 0

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = i
    vm_set_gpreg(regs)

def shlwapi_StrToInt64Ex(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    pstr = vm_pop_uint32_t()
    flags = vm_pop_uint32_t()
    pret = vm_pop_uint32_t()

    print funcname, hex(ret_ad), hex(pstr), hex(flags), hex(pret)
    i_str = get_str(pstr)
    if get_str is get_str_unic:
        i_str = i_str[::2]
    print repr(i_str)

    if flags == 0:
        r = int(i_str)
    elif flags == 1:
        r = int(i_str, 16)
    else:
        raise ValueError('cannot decode int')

    vm_set_mem(pret, struct.pack('q', r))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def shlwapi_StrToInt64ExA():
    shlwapi_StrToInt64Ex(whoami(), get_str_ansi)
def shlwapi_StrToInt64ExW():
    shlwapi_StrToInt64Ex(whoami(), get_str_unic)



def user32_IsCharAlpha(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    c = vm_pop_uint32_t()

    print funcname, hex(ret_ad), hex(c)
    try:
        c = chr(c)
    except:
        print 'bad char', c
        c = "\x00"
    if c.isalpha():
        ret = 1
    else:
        ret = 0
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)

def user32_IsCharAlphaA():
    user32_IsCharAlpha(whoami(), get_str_ansi)
def user32_IsCharAlphaW():
    user32_IsCharAlpha(whoami(), get_str_unic)

def user32_IsCharAlphaNumericA():
    ret_ad = vm_pop_uint32_t()
    c = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(c)
    c = chr(c)
    if c.isalnum():
        ret = 1
    else:
        ret = 0
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)


def shlwapi_StrCmpNIA():
    ret_ad = vm_pop_uint32_t()
    ptr_str1 = vm_pop_uint32_t()
    ptr_str2 = vm_pop_uint32_t()
    nchar = vm_pop_uint32_t()
    print whoami(), hex(ptr_str1), hex(ptr_str2)

    s1 = get_str_ansi(ptr_str1).lower()
    s2 = get_str_ansi(ptr_str2).lower()
    s1 = s1[:nchar]
    s2 = s2[:nchar]

    print repr(s1), repr(s2)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = cmp(s1, s2)
    vm_set_gpreg(regs)


def advapi32_RegOpenKeyEx(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    hkey = vm_pop_uint32_t()
    subkey = vm_pop_uint32_t()
    reserved = vm_pop_uint32_t()
    access = vm_pop_uint32_t()
    phandle = vm_pop_uint32_t()

    print funcname, hex(hkey), hex(subkey), hex(reserved), hex(access), hex(phandle)
    if subkey:
        s_subkey = get_str(subkey).lower()
    else:
        s_subkey = ""
    print repr(s_subkey)


    ret_hkey = 0
    ret = 2
    if hkey in winobjs.hkey_handles:
        if s_subkey:
            if id(s_subkey) in winobjs.hkey_handles:
                ret_hkey = id(s_subkey)
                ret = 0

    print 'set hkey', hex(ret_hkey)
    vm_set_mem(phandle, pdw(ret_hkey))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)

def advapi32_RegOpenKeyExA():
    advapi32_RegOpenKeyEx(whoami(), get_str_ansi)

def advapi32_RegOpenKeyExW():
    advapi32_RegOpenKeyEx(whoami(), lambda x:get_str_unic(x)[::2])


def advapi32_RegSetValue(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    hkey = vm_pop_uint32_t()
    psubkey = vm_pop_uint32_t()
    valuetype = vm_pop_uint32_t()
    pvalue = vm_pop_uint32_t()
    length = vm_pop_uint32_t()

    print funcname, hex(hkey), hex(psubkey), hex(valuetype), hex(pvalue), hex(length)

    if psubkey:
        subkey = get_str(psubkey).lower()
    else:
        subkey = ""
    print repr(subkey)

    if pvalue:
        value = vm_get_str(pvalue, length)
    else:
        value = None
    print repr(value)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def advapi32_RegSetValueA():
    advapi32_RegSetValue(whoami(), get_str_ansi)
def advapi32_RegSetValueW():
    advapi32_RegSetValue(whoami(), get_str_unic)

def kernel32_GetThreadLocale():
    ret_ad = vm_pop_uint32_t()

    print whoami()

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0x40c
    vm_set_gpreg(regs)


def kernel32_GetLocaleInfo(funcname, set_str):
    ret_ad = vm_pop_uint32_t()
    localeid = vm_pop_uint32_t()
    lctype = vm_pop_uint32_t()
    lplcdata = vm_pop_uint32_t()
    cchdata = vm_pop_uint32_t()

    print funcname, hex(localeid), hex(lctype), hex(lplcdata), hex(cchdata)

    buf = None
    ret = 0
    if localeid == 0x40c:
        if lctype == 0x3:
            buf = "ENGLISH"
            buf = buf[:cchdata-1]
            print 'SET', buf
            vm_set_mem(lplcdata, set_str(buf))
            ret = len(buf)
    else:
        raise ValueError('unimpl localeid')


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)

def kernel32_GetLocaleInfoA():
    kernel32_GetLocaleInfo(whoami(), set_str_ansi)

def kernel32_GetLocaleInfoW():
    kernel32_GetLocaleInfo(whoami(), set_str_unic)



def kernel32_TlsAlloc():
    ret_ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad)

    winobjs.tls_index += 1
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.tls_index
    vm_set_gpreg(regs)


def kernel32_TlsSetValue():
    ret_ad = vm_pop_uint32_t()
    tlsindex = vm_pop_uint32_t()
    tlsvalue = vm_pop_uint32_t()

    print whoami(), hex(tlsindex), hex(tlsvalue)

    winobjs.tls_values[tlsindex] = tlsvalue
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def kernel32_TlsGetValue():
    ret_ad = vm_pop_uint32_t()
    tlsindex = vm_pop_uint32_t()

    print whoami(), hex(tlsindex)

    if not tlsindex in winobjs.tls_values:
        raise ValueError("unknown tls val", repr(tlsindex))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = winobjs.tls_values[tlsindex]
    vm_set_gpreg(regs)


def user32_GetKeyboardType():
    ret_ad = vm_pop_uint32_t()
    typeflag = vm_pop_uint32_t()

    print whoami(), hex(typeflag)

    ret = 0
    if typeflag == 0:
        ret = 4
    else:
        raise ValueError('unimpl keyboard type')

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)

def kernel32_GetStartupInfo(funcname, set_str):
    ret_ad = vm_pop_uint32_t()
    ptr = vm_pop_uint32_t()

    print funcname, hex(ptr)


    s = "\x00"*0x2c+"\x81\x00\x00\x00"+"\x0a"

    vm_set_mem(ptr, s)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ptr
    vm_set_gpreg(regs)


def kernel32_GetStartupInfoA():
    kernel32_GetStartupInfo(whoami(), set_str_ansi)

def kernel32_GetStartupInfoW():
    kernel32_GetStartupInfo(whoami(), set_str_unic)

def kernel32_GetCurrentThreadId():
    ret_ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0x113377
    vm_set_gpreg(regs)



def kernel32_InitializeCriticalSection():
    ret_ad = vm_pop_uint32_t()
    lpcritic = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(lpcritic)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def user32_GetSystemMetrics():
    ret_ad = vm_pop_uint32_t()
    nindex = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(nindex)

    ret = 0
    if nindex in [0x2a, 0x4a]:
        ret = 0
    else:
        raise ValueError('unimpl index')

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)

def wsock32_WSAStartup():
    ret_ad = vm_pop_uint32_t()
    version = vm_pop_uint32_t()
    pwsadata = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(version), hex(pwsadata)


    vm_set_mem(pwsadata, "\x01\x01\x02\x02WinSock 2.0\x00")

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def kernel32_GetLocalTime():
    ret_ad = vm_pop_uint32_t()
    lpsystemtime = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(lpsystemtime)

    s = struct.pack('HHHHHHHH',
                    2011, # year
                    10,   # month
                    5,    # dayofweek
                    7,    # day
                    13,   # hour
                    37,   # minutes
                    00,   # seconds
                    999, # millisec
                    )
    vm_set_mem(lpsystemtime, s)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = lpsystemtime
    vm_set_gpreg(regs)

def kernel32_GetSystemTime():
    ret_ad = vm_pop_uint32_t()
    lpsystemtime = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(lpsystemtime)

    s = struct.pack('HHHHHHHH',
                    2011, # year
                    10,   # month
                    5,    # dayofweek
                    7,    # day
                    13,   # hour
                    37,   # minutes
                    00,   # seconds
                    999, # millisec
                    )
    vm_set_mem(lpsystemtime, s)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = lpsystemtime
    vm_set_gpreg(regs)

def kernel32_CreateFileMapping(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    hfile = vm_pop_uint32_t()
    lpattr = vm_pop_uint32_t()
    flprotect = vm_pop_uint32_t()
    dwmaximumsizehigh = vm_pop_uint32_t()
    dwmaximumsizelow = vm_pop_uint32_t()
    lpname = vm_pop_uint32_t()

    print funcname, hex(ret_ad), hex(hfile), hex(lpattr), hex(flprotect), hex(dwmaximumsizehigh), hex(dwmaximumsizelow)

    if lpname:
        f = get_str(lpname)
    else:
        f = None
    print repr(f)


    if not hfile in winobjs.handle_pool:
        raise ValueError('unknown handle')

    eax = winobjs.handle_pool.add('filemapping', hfile)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = eax
    vm_set_gpreg(regs)

def kernel32_CreateFileMappingA():
    kernel32_CreateFileMapping(whoami(), get_str_ansi)

def kernel32_CreateFileMappingW():
    kernel32_CreateFileMapping(whoami(), get_str_unic)




def kernel32_MapViewOfFile():
    ret_ad = vm_pop_uint32_t()
    hfile = vm_pop_uint32_t()
    flprotect = vm_pop_uint32_t()
    dwfileoffsethigh = vm_pop_uint32_t()
    dwfileoffsetlow = vm_pop_uint32_t()
    length = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(hfile), hex(flprotect), hex(dwfileoffsethigh), hex(dwfileoffsetlow), hex(length)

    if not hfile in winobjs.handle_pool:
        raise ValueError('unknown handle')
    hmap = winobjs.handle_pool[hfile]
    print hmap
    if not hmap.info in winobjs.handle_pool:
        raise ValueError('unknown file handle')

    hfile_o = winobjs.handle_pool[hmap.info]
    print hfile_o
    fd = hfile_o.info
    fd.seek( (dwfileoffsethigh << 32) | dwfileoffsetlow)
    if length:
        data = fd.read(length)
    else:
        data = fd.read()

    print 'mapp total:', hex(len(data))
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


    alloc_addr = get_next_alloc_addr(len(data))
    vm_add_memory_page(alloc_addr, access_dict[flprotect], data)

    dump_memory_page_pool_py()

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = alloc_addr
    vm_set_gpreg(regs)


def kernel32_UnmapViewOfFile():
    ret_ad = vm_pop_uint32_t()
    ad = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(ad)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)


def kernel32_GetDriveType(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    pathname = vm_pop_uint32_t()

    print funcname, hex(pathname)

    p = get_str(pathname)
    print repr(p)
    p = p.upper()

    ret = 0
    if p[0] == "C":
        ret = 3

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)

def kernel32_GetDriveTypeA():
    kernel32_GetDriveType(whoami(), get_str_ansi)

def kernel32_GetDriveTypeW():
    kernel32_GetDriveType(whoami(), get_str_unic)


def kernel32_GetDiskFreeSpace(funcname, get_str):
    ret_ad = vm_pop_uint32_t()
    lprootpathname = vm_pop_uint32_t()
    lpsectorpercluster = vm_pop_uint32_t()
    lpbytespersector = vm_pop_uint32_t()
    lpnumberoffreeclusters = vm_pop_uint32_t()
    lptotalnumberofclusters = vm_pop_uint32_t()

    print funcname, hex(ret_ad), hex(lprootpathname), hex(lpsectorpercluster), hex(lpbytespersector), hex(lpnumberoffreeclusters), hex(lptotalnumberofclusters)

    if lprootpathname:
        rootpath = get_str(lprootpathname)
    else:
        rootpath = ""
    print repr(rootpath)

    vm_set_mem(lpsectorpercluster, pdw(8))
    vm_set_mem(lpbytespersector, pdw(0x200))
    vm_set_mem(lpnumberoffreeclusters, pdw(0x222222))
    vm_set_mem(lptotalnumberofclusters, pdw(0x333333))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)

def kernel32_GetDiskFreeSpaceA():
    kernel32_GetDiskFreeSpace(whoami(), get_str_ansi)
def kernel32_GetDiskFreeSpaceW():
    kernel32_GetDiskFreeSpace(whoami(), get_str_unic)

def kernel32_VirtualQuery():
    ret_ad = vm_pop_uint32_t()
    ad = vm_pop_uint32_t()
    lpbuffer = vm_pop_uint32_t()
    dwl = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(ad), hex(lpbuffer), hex(dwl)

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


    all_mem = vm_get_all_memory()
    found = None
    for basead, m in all_mem.items():
        if basead <= ad < basead + m['size']:
            found = ad, m
            break
    if not found:
        raise ValueError('cannot find mem', hex(ad))

    if dwl != 0x1c:
        raise ValueError('strange mem len', hex(dwl))
    s = struct.pack('IIIIIII',
                    ad,
                    basead,
                    access_dict_inv[m['access']],
                    m['size'],
                    0x1000,
                    access_dict_inv[m['access']],
                    0x01000000)
    vm_set_mem(lpbuffer, s)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = dwl
    vm_set_gpreg(regs)

def kernel32_GetProcessAffinityMask():
    ret_ad = vm_pop_uint32_t()
    hprocess = vm_pop_uint32_t()
    procaffmask = vm_pop_uint32_t()
    systemaffmask = vm_pop_uint32_t()

    print whoami(), hex(ret_ad), hex(hprocess), hex(procaffmask), hex(systemaffmask)
    vm_set_mem(procaffmask, pdw(1))
    vm_set_mem(systemaffmask, pdw(1))

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1
    vm_set_gpreg(regs)
