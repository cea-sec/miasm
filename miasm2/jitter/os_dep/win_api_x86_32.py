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
import struct
try:
    from Crypto.Hash import MD5, SHA
except ImportError:
    print "cannot find crypto, skipping"
import inspect
from zlib import crc32
import os
import stat
import time
from miasm2.jitter.csts import *
from miasm2.core.utils import *
import string


MAX_PATH = 260


def get_next_alloc_addr(size):
    global alloc_ad
    ret = winobjs.alloc_ad
    winobjs.alloc_ad = (winobjs.alloc_ad + size + winobjs.alloc_align - 1)
    winobjs.alloc_ad &= (0xffffffff ^ (winobjs.alloc_align - 1))
    return ret


def alloc_mem(myjit, msize):
    alloc_addr = get_next_alloc_addr(msize)
    myjit.vm.vm_add_memory_page(
        alloc_addr, PAGE_READ | PAGE_WRITE, "\x00" * msize)
    return alloc_addr

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


access_dict = {0x0: 0,
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
        return '<%r %r %r>' % (self.__class__.__name__, self.name, self.info)


class handle_generator():

    def __init__(self):
        self.offset = 600
        self.all_handles = {}

    def add(self, name, info=None):
        self.offset += 1
        h = whandle(name, info)
        self.all_handles[self.offset] = h

        print repr(self)
        return self.offset

    def __repr__(self):
        out = '<%r\n' % self.__class__.__name__
        ks = self.all_handles.keys()
        ks.sort()

        for k in ks:
            out += "    %r %r\n" % (k, self.all_handles[k])
        out += '>'
        return out

    def __contains__(self, e):
        return e in self.all_handles

    def __getitem__(self, item):
        return self.all_handles.__getitem__(item)

    def __delitem__(self, item):
        self.all_handles.__delitem__(item)


class c_winobjs:

    def __init__(self):
        self.alloc_ad = 0x20000000
        self.alloc_align = 0x1000
        self.handle_toolhelpsnapshot = 0xaaaa00
        self.toolhelpsnapshot_info = {}
        self.handle_curprocess = 0xaaaa01
        self.dbg_present = 0
        self.tickcount = 0
        self.dw_pid_dummy1 = 0x111
        self.dw_pid_explorer = 0x222
        self.dw_pid_dummy2 = 0x333
        self.dw_pid_cur = 0x444
        self.module_fname_nux = None
        self.module_name = "test.exe"
        self.module_path = "c:\\mydir\\" + self.module_name
        self.hcurmodule = None
        self.module_filesize = None
        self.getversion = 0x0A280105
        self.getforegroundwindow = 0x333333
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
        self.handle_mapped = {}
        self.hkey_handles = {0x80000001: "hkey_current_user"}

        self.nt_mdl = {}
        self.nt_mdl_ad = None
        self.nt_mdl_cur = 0
        self.win_event_num = 0x13370
        self.cryptdll_md5_h = {}

        self.lastwin32error = 0
        self.mutex = {}
        self.env_variables = {}
        self.events_pool = {}
        self.find_data = None
winobjs = c_winobjs()


process_list = [
    [
        0x40,  # DWORD     dwSize;
        0,  # DWORD     cntUsage;
        winobjs.dw_pid_dummy1,  # DWORD     th32ProcessID;
        0x11111111,  # ULONG_PTR th32DefaultHeapID;
        0x11111112,  # DWORD     th32ModuleID;
        1,  # DWORD     cntThreads;
        winobjs.dw_pid_explorer,  # DWORD     th32ParentProcessID;
        0xbeef,  # LONG      pcPriClassBase;
        0x0,  # DWORD     dwFlags;
        "dummy1.exe"  # TCHAR     szExeFile[MAX_PATH];
    ],
    [
        0x40,  # DWORD     dwSize;
        0,  # DWORD     cntUsage;
        winobjs.dw_pid_explorer,  # DWORD     th32ProcessID;
        0x11111111,  # ULONG_PTR th32DefaultHeapID;
        0x11111112,  # DWORD     th32ModuleID;
        1,  # DWORD     cntThreads;
        4,  # DWORD     th32ParentProcessID;
        0xbeef,  # LONG      pcPriClassBase;
        0x0,  # DWORD     dwFlags;
        "explorer.exe"  # TCHAR     szExeFile[MAX_PATH];
    ],

    [
        0x40,  # DWORD     dwSize;
        0,  # DWORD     cntUsage;
        winobjs.dw_pid_dummy2,  # DWORD     th32ProcessID;
        0x11111111,  # ULONG_PTR th32DefaultHeapID;
        0x11111112,  # DWORD     th32ModuleID;
        1,  # DWORD     cntThreads;
        winobjs.dw_pid_explorer,  # DWORD     th32ParentProcessID;
        0xbeef,  # LONG      pcPriClassBase;
        0x0,  # DWORD     dwFlags;
        "dummy2.exe"  # TCHAR     szExeFile[MAX_PATH];
    ],

    [
        0x40,  # DWORD     dwSize;
        0,  # DWORD     cntUsage;
        winobjs.dw_pid_cur,  # DWORD     th32ProcessID;
        0x11111111,  # ULONG_PTR th32DefaultHeapID;
        0x11111112,  # DWORD     th32ModuleID;
        1,  # DWORD     cntThreads;
        winobjs.dw_pid_explorer,  # DWORD     th32ParentProcessID;
        0xbeef,  # LONG      pcPriClassBase;
        0x0,  # DWORD     dwFlags;
        winobjs.module_name  # TCHAR     szExeFile[MAX_PATH];
    ],


]


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


def get_str_ansi(myjit, ad_str, max_char=None):
    l = 0
    tmp = ad_str
    while ((max_char is None or l < max_char) and
        myjit.vm.vm_get_mem(tmp, 1) != "\x00"):
        tmp += 1
        l += 1
    return myjit.vm.vm_get_mem(ad_str, l)


def get_str_unic(myjit, ad_str, max_char=None):
    l = 0
    tmp = ad_str
    while ((max_char is None or l < max_char) and
        myjit.vm.vm_get_mem(tmp, 2) != "\x00\x00"):
        tmp += 2
        l += 2
    s = myjit.vm.vm_get_mem(ad_str, l)
    s = s[::2]  # TODO: real unicode decoding
    return s


def set_str_ansi(s):
    return s + "\x00"


def set_str_unic(s):
    return "\x00".join(list(s)) + '\x00' * 3


def kernel32_HeapAlloc(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    heap, flags, size = args

    alloc_addr = alloc_mem(myjit, size)

    myjit.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_HeapFree(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    heap, flags, pmem = args

    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_GlobalAlloc(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    uflags, msize = args
    alloc_addr = get_next_alloc_addr(msize)
    myjit.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_LocalFree(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    lpvoid, = args
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_LocalAlloc(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    uflags, msize = args
    alloc_addr = alloc_mem(myjit, msize)
    myjit.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_GlobalFree(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    ad, = args
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_IsDebuggerPresent(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, winobjs.dbg_present)


def kernel32_CreateToolhelp32Snapshot(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    dwflags, th32processid = args
    myjit.func_ret_stdcall(ret_ad, winobjs.handle_toolhelpsnapshot)


def kernel32_GetCurrentProcess(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, winobjs.handle_curprocess)


def kernel32_GetCurrentProcessId(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, winobjs.dw_pid_cur)


def kernel32_Process32First(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    s_handle, ad_pentry = args

    pentry = struct.pack(
        'IIIIIIIII', *process_list[0][:-1]) + process_list[0][-1]
    myjit.vm.vm_set_mem(ad_pentry, pentry)
    winobjs.toolhelpsnapshot_info[s_handle] = 0

    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_Process32Next(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    s_handle, ad_pentry = args

    winobjs.toolhelpsnapshot_info[s_handle] += 1
    if winobjs.toolhelpsnapshot_info[s_handle] >= len(process_list):
        ret = 0
    else:
        ret = 1
        n = winobjs.toolhelpsnapshot_info[s_handle]
        #print whoami(), hex(ret_ad), '(', hex(s_handle), hex(ad_pentry), ')'
        pentry = struct.pack(
            'IIIIIIIII', *process_list[n][:-1]) + process_list[n][-1]
        myjit.vm.vm_set_mem(ad_pentry, pentry)
    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetTickCount(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    winobjs.tickcount += 1
    myjit.func_ret_stdcall(ret_ad, winobjs.tickcount)


def kernel32_GetVersion(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, winobjs.getversion)


def kernel32_GetVersionEx(myjit, set_str = set_str_unic):
    ret_ad, args = myjit.func_args_stdcall(1)
    ptr_struct, = args

    s = struct.pack("IIIII",
                    0x114,  # struct size
                    0x5,   # maj vers
                    0x2,  # min vers
                    0xa28,  # build nbr
                    0x2,   # platform id
                    )
    t = set_str("Service pack 4")
    t = s + (t + '\x00' * 128 * 2)[:128 * 2]
    t += struct.pack('HHHBB', 3, 0, 0x100, 1, 0)
    s = t
    myjit.vm.vm_set_mem(ptr_struct, s)
    myjit.func_ret_stdcall(ret_ad, 1)


kernel32_GetVersionExA = lambda myjit: kernel32_GetVersionEx(myjit, set_str_ansi)
kernel32_GetVersionExW = lambda myjit: kernel32_GetVersionEx(myjit, set_str_unic)


def kernel32_GetPriorityClass(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    hwnd, = args
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_SetPriorityClass(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    hwnd, dwpclass = args
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_CloseHandle(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    hwnd, = args
    myjit.func_ret_stdcall(ret_ad, 1)


def user32_GetForegroundWindow(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, winobjs.getforegroundwindow)


def user32_FindWindowA(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    pclassname, pwindowname = args
    myjit.func_ret_stdcall(ret_ad, 0)


def user32_GetTopWindow(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    hwnd, = args
    myjit.func_ret_stdcall(ret_ad, 0)


def user32_BlockInput(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    b, = args
    myjit.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptAcquireContext(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(5)
    phprov, pszcontainer, pszprovider, dwprovtype, dwflags = args

    if pszprovider:
        prov = get_str(myjit, pszprovider)
    else:
        prov = "NONE"
    print 'prov:', prov
    myjit.vm.vm_set_mem(phprov, pck32(winobjs.cryptcontext_hwnd))

    myjit.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptAcquireContextA(myjit):
    advapi32_CryptAcquireContext(myjit, whoami(), get_str_ansi)


def advapi32_CryptAcquireContextW(myjit):
    advapi32_CryptAcquireContext(myjit, whoami(), get_str_unic)


def advapi32_CryptCreateHash(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    hprov, algid, hkey, dwflags, phhash = args

    winobjs.cryptcontext_num += 1

    if algid == 0x00008003:
        print 'algo is MD5'
        myjit.vm.vm_set_mem(
            phhash, pck32(winobjs.cryptcontext_bnum + winobjs.cryptcontext_num))
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num] = hobj()
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num].h = MD5.new()
    elif algid == 0x00008004:
        print 'algo is SHA1'
        myjit.vm.vm_set_mem(
            phhash, pck32(winobjs.cryptcontext_bnum + winobjs.cryptcontext_num))
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num] = hobj()
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num].h = SHA.new()
    else:
        raise ValueError('un impl algo1')
    myjit.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptHashData(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    hhash, pbdata, dwdatalen, dwflags = args

    if not hhash in winobjs.cryptcontext:
        raise ValueError("unknown crypt context")

    data = myjit.vm.vm_get_mem(pbdata, dwdatalen)
    print 'will hash %X' % dwdatalen
    print repr(data[:10]) + "..."
    winobjs.cryptcontext[hhash].h.update(data)
    myjit.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptGetHashParam(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    hhash, param, pbdata, dwdatalen, dwflags = args

    if not hhash in winobjs.cryptcontext:
        raise ValueError("unknown crypt context")

    if param == 2:
        # XXX todo: save h state?
        h = winobjs.cryptcontext[hhash].h.digest()
    else:
        raise ValueError('not impl', param)
    myjit.vm.vm_set_mem(pbdata, h)
    myjit.vm.vm_set_mem(dwdatalen, pck32(len(h)))

    myjit.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptReleaseContext(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    hhash, flags = args
    myjit.func_ret_stdcall(ret_ad, 0)


def advapi32_CryptDeriveKey(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    hprov, algid, hbasedata, dwflags, phkey = args

    if algid == 0x6801:
        print 'using DES'
    else:
        raise ValueError('un impl algo2')
    h = winobjs.cryptcontext[hbasedata].h.digest()
    print 'hash', repr(h)
    winobjs.cryptcontext[hbasedata].h_result = h
    myjit.vm.vm_set_mem(phkey, pck32(hbasedata))
    myjit.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptDestroyHash(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    hhash, = args
    myjit.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptDecrypt(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    hkey, hhash, final, dwflags, pbdata, pdwdatalen = args
    raise NotImplementedError()
    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_CreateFile(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(7)
    (lpfilename, access, dwsharedmode, lpsecurityattr,
     dwcreationdisposition, dwflagsandattr, htemplatefile) = args

    fname = get_str(myjit, lpfilename)
    print 'fname', fname
    fname_o = fname[:]
    ret = 0xffffffff

    # test if file is original binary
    f = fname_o
    """
    if "\\" in fname_o:
        f = fname_o[fname_o.rfind('\\')+1:]
    else:
        f = fname_o
    """
    print f.lower(), winobjs.module_path.lower()
    is_original_file = f.lower() == winobjs.module_path.lower()

    if fname.upper() in [r"\\.\SICE", r"\\.\NTICE", r"\\.\SIWVID"]:
        pass
    elif fname.upper() in ['NUL']:
        ret = winobjs.module_cur_hwnd
    else:
        # nuxify path
        fname = fname.replace('\\', "/").lower()
        # go in sandbox files
        f = os.path.join('file_sb', fname)
        if access & 0x80000000:
            # read
            if dwcreationdisposition == 2:
                # create_always
                if os.access(f, os.R_OK):
                    # but file exist
                    pass
                else:
                    raise NotImplementedError("Untested case")  # to test
                    h = open(f, 'rb+')
            elif dwcreationdisposition == 3:
                # open_existing
                if os.access(f, os.R_OK):
                    s = os.stat(f)
                    if stat.S_ISDIR(s.st_mode):
                        ret = winobjs.handle_pool.add(f, 0x1337)
                    else:
                        h = open(f, 'rb+')
                        ret = winobjs.handle_pool.add(f, h)
                else:
                    print "FILE %r DOES NOT EXIST!" % fname
                    pass
            elif dwcreationdisposition == 1:
                # create new
                if os.access(f, os.R_OK):
                    # file exist
                    # ret = 80
                    winobjs.lastwin32error = 80
                    pass
                else:
                    open(f, 'w')
                    h = open(f, 'rb+')
                    ret = winobjs.handle_pool.add(f, h)
            else:
                raise NotImplementedError("Untested case")
        elif access & 0x40000000:
            # write
            if dwcreationdisposition == 3:
                # open existing
                if is_original_file:
                    # cannot open self in write mode!
                    pass
                elif os.access(f, os.R_OK):
                    s = os.stat(f)
                    if stat.S_ISDIR(s.st_mode):
                        # open dir
                        ret = winobjs.handle_pool.add(f, 0x1337)
                    else:
                        h = open(f, 'rb+')
                        ret = winobjs.handle_pool.add(f, h)
                else:
                    raise NotImplementedError("Untested case")  # to test
            elif dwcreationdisposition == 5:
                # truncate_existing
                if is_original_file:
                    pass
                else:
                    raise NotImplementedError("Untested case")  # to test
            else:
                # raise NotImplementedError("Untested case") # to test
                h = open(f, 'w')
                ret = winobjs.handle_pool.add(f, h)
        else:
            raise NotImplementedError("Untested case")

        # h = open(f, 'rb+')
        # ret = winobjs.handle_pool.add(f, h)
    print 'ret', hex(ret)
    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_CreateFileA(myjit):
    kernel32_CreateFile(myjit, whoami(), get_str_ansi)


def kernel32_CreateFileW(myjit):
    kernel32_CreateFile(myjit, whoami(), lambda x, y: get_str_unic(myjit, y))


def kernel32_ReadFile(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    (hwnd, lpbuffer, nnumberofbytestoread,
     lpnumberofbytesread, lpoverlapped) = args

    if hwnd == winobjs.module_cur_hwnd:
        pass
    elif hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown hwnd!')

    eax = 0xffffffff
    data = None
    if hwnd in winobjs.files_hwnd:
        data = winobjs.files_hwnd[
            winobjs.module_cur_hwnd].read(nnumberofbytestoread)
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        data = wh.info.read(nnumberofbytestoread)
    else:
        raise ValueError('unknown filename')

    if data is not None:
        if (lpnumberofbytesread):
            myjit.vm.vm_set_mem(lpnumberofbytesread, pck32(len(data)))
        myjit.vm.vm_set_mem(lpbuffer, data)

    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_GetFileSize(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    hwnd, lpfilesizehight = args

    if hwnd == winobjs.module_cur_hwnd:
        ret = len(open(winobjs.module_fname_nux).read())
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        print wh
        ret = len(open(wh.name).read())
    else:
        raise ValueError('unknown hwnd!')

    if lpfilesizehight != 0:
        myjit.vm.vm_set_mem(lpfilesizehight, pck32(ret))
    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetFileSizeEx(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    hwnd, lpfilesizehight = args

    if hwnd == winobjs.module_cur_hwnd:
        l = len(open(winobjs.module_fname_nux).read())
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        print wh
        l = len(open(wh.name).read())
    else:
        raise ValueError('unknown hwnd!')

    if lpfilesizehight == 0:
        raise NotImplementedError("Untested case")
    myjit.vm.vm_set_mem(lpfilesizehight, pck32(
        l & 0xffffffff) + pck32((l >> 32) & 0xffffffff))
    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_FlushInstructionCache(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    hprocess, lpbasead, dwsize = args
    myjit.func_ret_stdcall(ret_ad, 0x1337)


def kernel32_VirtualProtect(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    lpvoid, dwsize, flnewprotect, lpfloldprotect = args

    # XXX mask hpart
    flnewprotect &= 0xFFF

    if not flnewprotect in access_dict:
        raise ValueError('unknown access dw!')
    myjit.vm.vm_set_mem_access(lpvoid, access_dict[flnewprotect])

    # XXX todo real old protect
    if lpfloldprotect:
        myjit.vm.vm_set_mem(lpfloldprotect, pck32(0x40))

    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_VirtualAlloc(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    lpvoid, dwsize, alloc_type, flprotect = args

    access_dict = {0x0: 0,
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
        raise ValueError('unknown access dw!')

    if lpvoid == 0:
        alloc_addr = get_next_alloc_addr(dwsize)
        myjit.vm.vm_add_memory_page(
            alloc_addr, access_dict[flprotect], "\x00" * dwsize)
    else:
        all_mem = myjit.vm.vm_get_all_memory()
        if lpvoid in all_mem:
            alloc_addr = lpvoid
            myjit.vm.vm_set_mem_access(lpvoid, access_dict[flprotect])
        else:
            alloc_addr = get_next_alloc_addr(dwsize)
            # alloc_addr = lpvoid
            myjit.vm.vm_add_memory_page(
                alloc_addr, access_dict[flprotect], "\x00" * dwsize)

    print 'Memory addr:', hex(alloc_addr)
    myjit.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_VirtualFree(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    lpvoid, dwsize, alloc_type = args
    myjit.func_ret_stdcall(ret_ad, 0)


def user32_GetWindowLongA(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    hwnd, nindex = args
    myjit.func_ret_stdcall(ret_ad, winobjs.windowlong_dw)


def user32_SetWindowLongA(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    hwnd, nindex, newlong = args
    myjit.func_ret_stdcall(ret_ad, winobjs.windowlong_dw)


def kernel32_GetModuleFileName(myjit, funcname, set_str):
    ret_ad, args = myjit.func_args_stdcall(3)
    hmodule, lpfilename, nsize = args

    if hmodule in [0, winobjs.hcurmodule]:
        p = winobjs.module_path[:]
    elif (winobjs.runtime_dll and
        hmodule in winobjs.runtime_dll.name2off.values()):
        name_inv = dict([(x[1], x[0])
                        for x in winobjs.runtime_dll.name2off.items()])
        p = name_inv[hmodule]
    else:
        print ValueError('unknown module h', hex(hmodule))
        p = None

    if p is None:
        l = 0
    elif nsize < len(p):
        p = p[:nsize]
        l = len(p)
    else:
        l = len(p)

    print repr(p)
    if p:
        myjit.vm.vm_set_mem(lpfilename, set_str(p))

    myjit.func_ret_stdcall(ret_ad, l)


def kernel32_GetModuleFileNameA(myjit):
    kernel32_GetModuleFileName(myjit, whoami(), set_str_ansi)


def kernel32_GetModuleFileNameW(myjit):
    kernel32_GetModuleFileName(myjit, whoami(), set_str_unic)


def kernel32_CreateMutex(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(3)
    print funcname
    mutexattr, initowner, lpname = args

    if lpname:
        name = get_str(myjit, lpname)
        print repr(name)
    else:
        name = None
    if initowner:
        if name in winobjs.mutex:
            raise NotImplementedError("Untested case")
            ret = 0
        else:
            winobjs.mutex[name] = id(name)
            ret = winobjs.mutex[name]
    else:
        if name in winobjs.mutex:
            raise NotImplementedError("Untested case")
            ret = 0
        else:
            winobjs.mutex[name] = id(name)
            ret = winobjs.mutex[name]
    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_CreateMutexA(myjit):
    kernel32_CreateMutex(myjit, whoami(), get_str_ansi)


def kernel32_CreateMutexW(myjit):
    kernel32_CreateMutex(myjit, whoami(), get_str_unic)


def shell32_SHGetSpecialFolderLocation(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    hwndowner, nfolder, ppidl = args
    myjit.vm.vm_set_mem(ppidl, pck32(nfolder))
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_SHGetPathFromIDList(myjit, funcname, set_str):
    ret_ad, args = myjit.func_args_stdcall(2)
    pidl, ppath = args

    if pidl == 7:  # CSIDL_STARTUP:
        s = "c:\\doc\\user\\startmenu\\programs\\startup"
        s = set_str(s)
    else:
        raise ValueError('pidl not implemented', pidl)
    myjit.vm.vm_set_mem(ppath, s)
    myjit.func_ret_stdcall(ret_ad, 1)


def shell32_SHGetPathFromIDListW(myjit):
    kernel32_SHGetPathFromIDList(myjit, whoami(), set_str_unic)


def shell32_SHGetPathFromIDListA(myjit):
    kernel32_SHGetPathFromIDList(myjit, whoami(), set_str_ansi)


def kernel32_GetLastError(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, winobjs.lastwin32error)


def kernel32_SetLastError(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    e, = args
    # lasterr addr
    # ad = seh_helper.FS_0_AD + 0x34
    # myjit.vm.vm_set_mem(ad, pck32(e))
    winobjs.lastwin32error = e
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_RestoreLastError(myjit):
    kernel32_SetLastError(myjit)


def kernel32_LoadLibraryA(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    dllname, = args

    libname = get_str_ansi(myjit, dllname, 0x100)
    print repr(libname)

    ret = winobjs.runtime_dll.lib_get_add_base(libname)
    print "ret", hex(ret)
    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_LoadLibraryExA(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    dllname, hfile, flags = args

    if hfile != 0:
        raise NotImplementedError("Untested case")
    libname = get_str_ansi(myjit, dllname, 0x100)
    print repr(libname)

    ret = winobjs.runtime_dll.lib_get_add_base(libname)
    print "ret", hex(ret)
    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetProcAddress(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    libbase, fname = args
    fname = fname & 0xFFFFFFFF
    if fname < 0x10000:
        fname = fname
    else:
        fname = get_str_ansi(myjit, fname, 0x100)
        if not fname:
            fname = None
    print repr(fname)
    if fname is not None:
        ad = winobjs.runtime_dll.lib_get_add_func(libbase, fname)
    else:
        ad = 0
    ad = winobjs.runtime_dll.lib_get_add_func(libbase, fname)

    myjit.func_ret_stdcall(ret_ad, ad)


def kernel32_LoadLibraryW(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    dllname, = args

    libname = get_str_unic(myjit, dllname, 0x100)
    print repr(libname)

    ret = winobjs.runtime_dll.lib_get_add_base(libname)
    print "ret", hex(ret)
    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetModuleHandle(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(1)
    dllname, = args

    if dllname:
        libname = get_str(myjit, dllname)
        print repr(libname)
        if libname:
            ret = winobjs.runtime_dll.lib_get_add_base(libname)
        else:
            print 'unknown module!'
            ret = 0
    else:
        ret = winobjs.current_pe.NThdr.ImageBase
        print "default img base", hex(ret)
    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetModuleHandleA(myjit):
    kernel32_GetModuleHandle(myjit, whoami(), get_str_ansi)


def kernel32_GetModuleHandleW(myjit):
    kernel32_GetModuleHandle(myjit, whoami(), get_str_unic)


def kernel32_VirtualLock(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    lpaddress, dwsize = args
    myjit.func_ret_stdcall(ret_ad, 1)


class systeminfo:
    oemId = 0
    dwPageSize = 0x1000
    lpMinimumApplicationAddress = 0x10000
    lpMaximumApplicationAddress = 0x7ffeffff
    dwActiveProcessorMask = 0x1
    numberOfProcessors = 0x1
    ProcessorsType = 586
    dwAllocationgranularity = 0x10000
    wProcessorLevel = 0x6
    ProcessorRevision = 0xf0b

    def pack(self):
        return struct.pack('IIIIIIIIHH',
                           self.oemId,
                           self.dwPageSize,
                           self.lpMinimumApplicationAddress,
                           self.lpMaximumApplicationAddress,
                           self.dwActiveProcessorMask,
                           self.numberOfProcessors,
                           self.ProcessorsType,
                           self.dwAllocationgranularity,
                           self.wProcessorLevel,
                           self.ProcessorRevision)


def kernel32_GetSystemInfo(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    sys_ptr, = args
    sysinfo = systeminfo()
    myjit.vm.vm_set_mem(sys_ptr, sysinfo.pack())
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_IsWow64Process(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    h, bool_ptr = args

    myjit.vm.vm_set_mem(bool_ptr, pck32(0))
    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_GetCommandLineA(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    s = winobjs.module_path + '\x00'
    s = '"%s"' % s
    alloc_addr = alloc_mem(myjit, 0x1000)
    myjit.vm.vm_set_mem(alloc_addr, s)
    myjit.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_GetCommandLineW(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    s = winobjs.module_path + '\x00'
    s = set_str_unic('"%s"' % s)
    alloc_addr = alloc_mem(myjit, 0x1000)
    myjit.vm.vm_set_mem(alloc_addr, s)
    myjit.func_ret_stdcall(ret_ad, alloc_addr)


def shell32_CommandLineToArgvW(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    pcmd, pnumargs = args
    cmd = get_str_unic(myjit, pcmd)
    print repr(cmd)
    tks = cmd.split(' ')
    addr = alloc_mem(myjit, len(cmd) * 2 + 4 * len(tks))
    addr_ret = alloc_mem(myjit, 4 * (len(tks) + 1))
    o = 0
    for i, t in enumerate(tks):
        x = set_str_unic(t) + "\x00\x00"
        myjit.vm.vm_set_mem(addr_ret + 4 * i, pck32(addr + o))
        myjit.vm.vm_set_mem(addr + o, x)
        o += len(x) + 2

    myjit.vm.vm_set_mem(addr_ret + 4 * i, pck32(0))
    myjit.vm.vm_set_mem(pnumargs, pck32(len(tks)))
    myjit.func_ret_stdcall(ret_ad, addr_ret)


def cryptdll_MD5Init(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    ad_ctx, = args
    index = len(winobjs.cryptdll_md5_h)
    h = MD5.new()
    winobjs.cryptdll_md5_h[index] = h

    myjit.vm.vm_set_mem(ad_ctx, pck32(index))
    myjit.func_ret_stdcall(ret_ad, 0)


def cryptdll_MD5Update(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    ad_ctx, ad_input, inlen = args

    index = myjit.vm.vm_get_mem(ad_ctx, 4)
    index = upck32(index)
    if not index in winobjs.cryptdll_md5_h:
        raise ValueError('unknown h context', index)

    data = myjit.vm.vm_get_mem(ad_input, inlen)
    winobjs.cryptdll_md5_h[index].update(data)
    print hexdump(data)

    myjit.func_ret_stdcall(ret_ad, 0)


def cryptdll_MD5Final(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    ad_ctx, = args

    index = myjit.vm.vm_get_mem(ad_ctx, 4)
    index = upck32(index)
    if not index in winobjs.cryptdll_md5_h:
        raise ValueError('unknown h context', index)
    h = winobjs.cryptdll_md5_h[index].digest()
    myjit.vm.vm_set_mem(ad_ctx + 88, h)
    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlInitAnsiString(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    ad_ctx, ad_str = args

    s = get_str_ansi(myjit, ad_str)
    l = len(s)
    print "string", l, s
    myjit.vm.vm_set_mem(ad_ctx, pck16(l) + pck16(l + 1) + pck32(ad_str))
    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlHashUnicodeString(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    ad_ctxu, case_i, h_id, phout = args

    print hex(h_id)
    if h_id != 1:
        raise ValueError('unk hash unicode', h_id)

    l1, l2, ptra = struct.unpack('HHL', myjit.vm.vm_get_mem(ad_ctxu, 8))
    print hex(l1), hex(l2), hex(ptra)
    s = myjit.vm.vm_get_mem(ptra, l1)
    print repr(s)
    s = s[:-1]
    print repr(s)
    hv = 0

    if case_i:
        s = s.lower()
    for c in s:
        hv = ((65599 * hv) + ord(c)) & 0xffffffff
    print "unicode h", hex(hv)
    myjit.vm.vm_set_mem(phout, pck32(hv))
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_RtlMoveMemory(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    ad_dst, ad_src, m_len = args
    data = myjit.vm.vm_get_mem(ad_src, m_len)
    myjit.vm.vm_set_mem(ad_dst, data)
    print hexdump(data)

    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlAnsiCharToUnicodeChar(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    ad_ad_ch, = args
    ad_ch = upck32(myjit.vm.vm_get_mem(ad_ad_ch, 4))
    print hex(ad_ch)
    ch = ord(myjit.vm.vm_get_mem(ad_ch, 1))
    myjit.vm.vm_set_mem(ad_ad_ch, pck32(ad_ch + 1))

    print repr(ch), repr(chr(ch))
    myjit.func_ret_stdcall(ret_ad, ch)


def ntdll_RtlFindCharInUnicodeString(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    flags, main_str_ad, search_chars_ad, pos_ad = args

    print flags
    if flags != 0:
        raise ValueError('unk flags')

    ml1, ml2, mptra = struct.unpack('HHL', myjit.vm.vm_get_mem(main_str_ad, 8))
    print ml1, ml2, hex(mptra)
    sl1, sl2, sptra = struct.unpack(
        'HHL', myjit.vm.vm_get_mem(search_chars_ad, 8))
    print sl1, sl2, hex(sptra)
    main_data = myjit.vm.vm_get_mem(mptra, ml1)[:-1]
    search_data = myjit.vm.vm_get_mem(sptra, sl1)[:-1]

    print repr(main_data)
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
    if pos is None:
        ret = 0xC0000225
        myjit.vm.vm_set_mem(pos_ad, pck32(0))
    else:
        ret = 0
        myjit.vm.vm_set_mem(pos_ad, pck32(pos))

    myjit.func_ret_stdcall(ret_ad, ret)


def ntdll_RtlComputeCrc32(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    dwinit, pdata, ilen = args

    data = myjit.vm.vm_get_mem(pdata, ilen)
    print hex(dwinit)
    print hexdump(data)
    crc_r = crc32(data, dwinit)
    print "crc32", hex(crc_r)
    myjit.func_ret_stdcall(ret_ad, crc_r)


def ntdll_RtlExtendedIntegerMultiply(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    b2, b1, bm = args
    a = (b1 << 32) + b2
    a = a * bm
    print hex(a)
    myjit.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlLargeIntegerAdd(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    a2, a1, b2, b1 = args
    a = (a1 << 32) + a2 + (b1 << 32) + b2
    print hex(a)
    myjit.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlLargeIntegerShiftRight(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    a2, a1, m = args
    a = ((a1 << 32) + a2) >> m
    print hex(a)
    myjit.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlEnlargedUnsignedMultiply(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    a, b = args
    a = a * b
    print hex(a)
    myjit.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlLargeIntegerSubtract(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    a2, a1, b2, b1 = args
    a = (a1 << 32) + a2 - (b1 << 32) + b2
    print hex(a)
    myjit.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlCompareMemory(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    ad1, ad2, m_len = args
    data1 = myjit.vm.vm_get_mem(ad1, m_len)
    data2 = myjit.vm.vm_get_mem(ad2, m_len)

    print hexdump(data1)
    print hexdump(data2)
    i = 0
    while data1[i] == data2[i]:
        i += 1
        if i >= m_len:
            break

    myjit.func_ret_stdcall(ret_ad, i)


def user32_GetMessagePos(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, 0x00110022)


def kernel32_Sleep(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    t, = args
    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_ZwUnmapViewOfSection(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    h, ad = args
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_IsBadReadPtr(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    lp, ucb = args
    myjit.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_KeInitializeEvent(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    my_event, my_type, my_state = args
    myjit.vm.vm_set_mem(my_event, pck32(winobjs.win_event_num))
    winobjs.win_event_num += 1

    myjit.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_RtlGetVersion(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    ptr_version, = args

    s = struct.pack("IIIII",
                    0x114,  # struct size
                    0x5,   # maj vers
                    0x2,  # min vers
                    0x666,  # build nbr
                    0x2,   # platform id
                    ) + set_str_unic("Service pack 4")

    myjit.vm.vm_set_mem(ptr_version, s)
    myjit.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_RtlVerifyVersionInfo(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    ptr_version, = args

    s = myjit.vm.vm_get_mem(ptr_version, 0x5 * 4)
    print repr(s)
    s_size, s_majv, s_minv, s_buildn, s_platform = struct.unpack('IIIII', s)
    print s_size, s_majv, s_minv, s_buildn, s_platform
    raise NotImplementedError("Untested case")
    myjit.vm.vm_set_mem(ptr_version, s)
    myjit.func_ret_stdcall(ret_ad, 0)


def hal_ExAcquireFastMutex(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, 0)


def mdl2ad(n):
    return winobjs.nt_mdl_ad + 0x10 * n


def ad2mdl(ad):
    return ((ad - winobjs.nt_mdl_ad) & 0xFFFFFFFFL) / 0x10


def ntoskrnl_IoAllocateMdl(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    v_addr, l, second_buf, chargequota, pirp = args
    m = mdl(v_addr, l)
    winobjs.nt_mdl[winobjs.nt_mdl_cur] = m
    myjit.vm.vm_set_mem(mdl2ad(winobjs.nt_mdl_cur), str(m))
    myjit.func_ret_stdcall(ret_ad, mdl2ad(winobjs.nt_mdl_cur))
    winobjs.nt_mdl_cur += 1


def ntoskrnl_MmProbeAndLockPages(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    p_mdl, access_mode, op = args

    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))
    myjit.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_MmMapLockedPagesSpecifyCache(myjit):
    ret_ad, args = myjit.func_args_stdcall(6)
    p_mdl, access_mode, cache_type, base_ad, bugcheckonfailure, priority = args
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    myjit.func_ret_stdcall(ret_ad, winobjs.nt_mdl[ad2mdl(p_mdl)].ad)


def ntoskrnl_MmProtectMdlSystemAddress(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    p_mdl, prot = args
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    myjit.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_MmUnlockPages(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    p_mdl, = args
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    myjit.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_IoFreeMdl(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    p_mdl, = args
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))
    del(winobjs.nt_mdl[ad2mdl(p_mdl)])
    myjit.func_ret_stdcall(ret_ad, 0)


def hal_ExReleaseFastMutex(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_RtlQueryRegistryValues(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    relativeto, path, querytable, context, environ = args
    p = get_str_unic(myjit, path)
    print repr(p)
    myjit.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_ExAllocatePoolWithTagPriority(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    pool_type, nbr_of_bytes, tag, priority = args

    alloc_addr = get_next_alloc_addr(nbr_of_bytes)
    myjit.vm.vm_add_memory_page(
        alloc_addr, PAGE_READ | PAGE_WRITE, "\x00" * nbr_of_bytes)

    print "ad", hex(alloc_addr)
    myjit.func_ret_stdcall(ret_ad, alloc_addr)


def my_lstrcmp(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(2)
    ptr_str1, ptr_str2 = args
    s1 = get_str(ptr_str1)
    s2 = get_str(ptr_str2)
    print '%s (%r, %r)' % (' ' * len(funcname), s1, s2)
    myjit.func_ret_stdcall(ret_ad, cmp(s1, s2))


def kernel32_lstrcmpA(myjit):
    my_lstrcmp(myjit, whoami(), lambda x: get_str_ansi(myjit, x))


def kernel32_lstrcmpiA(myjit):
    my_lstrcmp(myjit, whoami(), lambda x: get_str_ansi(myjit, x).lower())


def kernel32_lstrcmpW(myjit):
    my_lstrcmp(myjit, whoami(), lambda x: get_str_unic(myjit, x))


def kernel32_lstrcmpiW(myjit):
    my_lstrcmp(myjit, whoami(), lambda x: get_str_unic(myjit, x).lower())


def kernel32_lstrcmpi(myjit):
    my_lstrcmp(myjit, whoami(), lambda x: get_str_ansi(myjit, x).lower())


def my_strcpy(myjit, funcname, get_str, set_str):
    ret_ad, args = myjit.func_args_stdcall(2)
    ptr_str1, ptr_str2 = args
    s2 = get_str(myjit, ptr_str2)
    print '%s (%r)' % (funcname, s2)
    myjit.vm.vm_set_mem(ptr_str1, set_str(s2))
    myjit.func_ret_stdcall(ret_ad, ptr_str1)


def kernel32_lstrcpyW(myjit):
    my_strcpy(myjit, whoami(), get_str_unic,
              lambda x: set_str_unic(x) + "\x00\x00")


def kernel32_lstrcpyA(myjit):
    my_strcpy(myjit, whoami(), get_str_ansi, lambda x: x + "\x00")


def kernel32_lstrcpy(myjit):
    my_strcpy(myjit, whoami(), get_str_ansi, lambda x: x + "\x00")


def kernel32_lstrcpyn(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    ptr_str1, ptr_str2, mlen = args
    s2 = get_str_ansi(myjit, ptr_str2)
    print repr(s2)
    s2 = s2[:mlen]
    myjit.vm.vm_set_mem(ptr_str1, s2)

    myjit.func_ret_stdcall(ret_ad, ptr_str1)


def my_strlen(myjit, funcname, get_str, mylen):
    ret_ad, args = myjit.func_args_stdcall(1)
    arg_src, = args
    src = get_str(myjit, arg_src)
    print funcname, repr(src)
    myjit.func_ret_stdcall(ret_ad, mylen(src))


def kernel32_lstrlenA(myjit):
    my_strlen(myjit, whoami(), get_str_ansi, lambda x: len(x))


def kernel32_lstrlenW(myjit):
    my_strlen(myjit, whoami(), get_str_unic, lambda x: len(x))


def kernel32_lstrlen(myjit):
    my_strlen(myjit, whoami(), get_str_ansi, lambda x: len(x))


def my_lstrcat(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(3)
    ptr_str1, ptr_str2 = args
    s1 = get_str(myjit, ptr_str1)
    s2 = get_str(myjit, ptr_str2)
    print '%s (%r, %r)' % (whoami(), s1, s2)

    s = s1 + s2
    print repr(s)
    myjit.vm.vm_set_mem(ptr_str1, s1 + s2)
    myjit.func_ret_stdcall(ret_ad, ptr_str1)


def kernel32_lstrcatA(myjit):
    my_lstrcat(myjit, whoami(), get_str_ansi)


def kernel32_lstrcatW(myjit):
    my_lstrcat(myjit, whoami(), get_str_unic)


def kernel32_GetUserGeoID(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    geoclass, = args
    if geoclass == 14:
        ret = 12345678
    elif geoclass == 16:
        ret = 55667788
    else:
        raise ValueError('unknown geolcass')

    myjit.func_ret_stdcall(ret_ad, ret)


def my_GetVolumeInformation(myjit, funcname, get_str, set_str):
    ret_ad, args = myjit.func_args_stdcall(8)
    (lprootpathname, lpvolumenamebuffer, nvolumenamesize,
     lpvolumeserialnumber, lpmaximumcomponentlength, lpfilesystemflags,
     lpfilesystemnamebuffer, nfilesystemnamesize) = args

    print funcname, hex(lprootpathname), hex(lpvolumenamebuffer), \
        hex(nvolumenamesize), hex(lpvolumeserialnumber), \
        hex(lpmaximumcomponentlength), hex(lpfilesystemflags), \
        hex(lpfilesystemnamebuffer), hex(nfilesystemnamesize)

    if lprootpathname:
        s = get_str(myjit, lprootpathname)
        print repr(s)

    if lpvolumenamebuffer:
        s = "volumename"
        s = s[:nvolumenamesize]
        myjit.vm.vm_set_mem(lpvolumenamebuffer, set_str(s))

    if lpvolumeserialnumber:
        myjit.vm.vm_set_mem(lpvolumeserialnumber, pck32(11111111))
    if lpmaximumcomponentlength:
        myjit.vm.vm_set_mem(lpmaximumcomponentlength, pck32(0xff))
    if lpfilesystemflags:
        myjit.vm.vm_set_mem(lpfilesystemflags, pck32(22222222))

    if lpfilesystemnamebuffer:
        s = "filesystemname"
        s = s[:nfilesystemnamesize]
        myjit.vm.vm_set_mem(lpfilesystemnamebuffer, set_str(s))

    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_GetVolumeInformationA(myjit):
    my_GetVolumeInformation(
        myjit, whoami(), get_str_ansi, lambda x: x + "\x00")


def kernel32_GetVolumeInformationW(myjit):
    my_GetVolumeInformation(myjit, whoami(), get_str_unic, set_str_unic)


def kernel32_MultiByteToWideChar(myjit):
    ret_ad, args = myjit.func_args_stdcall(6)
    (codepage, dwflags, lpmultibytestr,
     cbmultibyte, lpwidecharstr, cchwidechar) = args

    print whoami(), hex(ret_ad), \
        hex(codepage), hex(dwflags), hex(lpmultibytestr), hex(
            cbmultibyte), hex(lpwidecharstr), hex(cchwidechar)
    src = get_str_ansi(myjit, lpmultibytestr) + '\x00'
    l = len(src)
    print repr(src)

    src = "\x00".join(list(src))
    print repr(src), hex(len(src))
    myjit.vm.vm_set_mem(lpwidecharstr, src)
    myjit.func_ret_stdcall(ret_ad, l)


def my_GetEnvironmentVariable(myjit, funcname, get_str, set_str, mylen):
    ret_ad, args = myjit.func_args_stdcall(3)
    lpname, lpbuffer, nsize = args

    s = get_str(myjit, lpname)
    if get_str == get_str_unic:
        s = s
    print 'variable', repr(s)
    if s in winobjs.env_variables:
        v = set_str(winobjs.env_variables[s])
    else:
        print 'WARNING unknown env variable', repr(s)
        v = ""
    print 'return', repr(v)
    myjit.vm.vm_set_mem(lpbuffer, v)
    myjit.func_ret_stdcall(ret_ad, mylen(v))


def my_GetSystemDirectory(myjit, funcname, set_str):
    ret_ad, args = myjit.func_args_stdcall(2)
    lpbuffer, usize = args
    print funcname

    s = "c:\\windows\\system32"
    l = len(s)
    s = set_str(s)
    myjit.vm.vm_set_mem(lpbuffer, s)

    myjit.func_ret_stdcall(ret_ad, l)


def kernel32_GetSystemDirectoryA(myjit):
    my_GetSystemDirectory(myjit, whoami(), set_str_ansi)


def kernel32_GetSystemDirectoryW(myjit):
    my_GetSystemDirectory(myjit, whoami(), set_str_unic)


def my_CreateDirectory(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(2)
    lppath, secattrib = args
    p = get_str(myjit, lppath)
    myjit.func_ret_stdcall(ret_ad, 0x1337)


def kernel32_CreateDirectoryW(myjit):
    my_CreateDirectory(myjit, whoami(), get_str_unic)


def kernel32_CreateDirectoryA(myjit):
    my_CreateDirectory(myjit, whoami(), get_str_ansi)


def kernel32_GetEnvironmentVariableA(myjit):
    my_GetEnvironmentVariable(myjit, whoami(),
                              get_str_ansi,
                              lambda x: x + "\x00",
                              lambda x: len(x))


def kernel32_GetEnvironmentVariableW(myjit):
    my_GetEnvironmentVariable(myjit, whoami(),
                              get_str_unic,
                              lambda x: "\x00".join(list(x + "\x00")),
                              lambda x: len(x))


def my_CreateEvent(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(4)
    lpeventattributes, bmanualreset, binitialstate, lpname = args
    if lpname:
        s = get_str(myjit, lpname)
    else:
        s = None
    print repr(s)
    if not s in winobjs.events_pool:
        winobjs.events_pool[s] = (bmanualreset, binitialstate)
    else:
        print 'WARNING: known event'

    myjit.func_ret_stdcall(ret_ad, id(s))


def kernel32_CreateEventA(myjit):
    my_CreateEvent(myjit, whoami(), get_str_ansi)


def kernel32_CreateEventW(myjit):
    my_CreateEvent(myjit, whoami(), get_str_unic)


def kernel32_WaitForSingleObject(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    handle, dwms = args

    print whoami(), hex(ret_ad), hex(handle), hex(dwms)

    t_start = time.time() * 1000
    found = False
    while True:
        if dwms and dwms + t_start > time.time() * 1000:
            ret = 0x102
            break
        for k, v in winobjs.events_pool.items():
            if k != handle:
                continue
            found = True
            if winobjs.events_pool[k][1] == 1:
                ret = 0
                break
        if not found:
            print 'unknown handle'
            ret = 0xffffffff
            break
        time.sleep(0.1)
    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_SetFileAttributesA(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    lpfilename, dwfileattributes = args
    print whoami(), hex(ret_ad), hex(lpfilename), hex(dwfileattributes)

    if lpfilename:
        fname = get_str_ansi(myjit, lpfilename)
        print "filename", repr(fname)
        ret = 1
    else:
        ret = 0
        myjit.vm.vm_set_mem(seh_helper.FS_0_AD + 0x34, pck32(3))

    myjit.func_ret_stdcall(ret_ad, ret)


def ntdll_RtlMoveMemory(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    dst, src, l = args
    s = myjit.vm.vm_get_mem(src, l)
    myjit.vm.vm_set_mem(dst, s)

    myjit.func_ret_stdcall(ret_ad, 1)


def ntdll_ZwQuerySystemInformation(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    (systeminformationclass, systeminformation,
     systeminformationl, returnl) = args
    if systeminformationclass == 2:
        # SYSTEM_PERFORMANCE_INFORMATION
        o = struct.pack('II', 0x22222222, 0x33333333)
        o += "\x00" * systeminformationl
        o = o[:systeminformationl]
        myjit.vm.vm_set_mem(systeminformation, o)
    else:
        raise ValueError('unknown sysinfo class', systeminformationclass)

    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_ZwProtectVirtualMemory(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    handle, lppvoid, pdwsize, flnewprotect, lpfloldprotect = args

    ad = upck32(myjit.vm.vm_get_mem(lppvoid, 4))
    dwsize = upck32(myjit.vm.vm_get_mem(pdwsize, 4))
    print 'ad', hex(ad), 'size', hex(dwsize)
    # XXX mask hpart
    flnewprotect &= 0xFFF

    if not flnewprotect in access_dict:
        raise ValueError('unknown access dw!')
    myjit.vm.vm_set_mem_access(ad, access_dict[flnewprotect])

    # XXX todo real old protect
    myjit.vm.vm_set_mem(lpfloldprotect, pck32(0x40))

    dump_memory_page_pool_py()
    myjit.func_ret_stdcall(ret_ad, 1)


def ntdll_ZwAllocateVirtualMemory(myjit):
    ret_ad, args = myjit.func_args_stdcall(6)
    handle, lppvoid, zerobits, pdwsize, alloc_type, flprotect = args

    ad = upck32(myjit.vm.vm_get_mem(lppvoid, 4))
    dwsize = upck32(myjit.vm.vm_get_mem(pdwsize, 4))
    print 'ad', hex(ad), 'size', hex(dwsize)

    access_dict = {0x0: 0,
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
        raise ValueError('unknown access dw!')

    alloc_addr = get_next_alloc_addr(dwsize)
    myjit.vm.vm_add_memory_page(
        alloc_addr, access_dict[flprotect], "\x00" * dwsize)
    myjit.vm.vm_set_mem(lppvoid, pck32(alloc_addr))

    print 'ret', hex(alloc_addr)
    dump_memory_page_pool_py()
    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_ZwFreeVirtualMemory(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    handle, lppvoid, pdwsize, alloc_type = args
    ad = upck32(myjit.vm.vm_get_mem(lppvoid, 4))
    dwsize = upck32(myjit.vm.vm_get_mem(pdwsize, 4))
    print 'ad', hex(ad), 'size', hex(dwsize)

    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlInitString(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    pstring, source = args
    s = get_str_ansi(myjit, source)
    print "str", repr(s)

    l = len(s) + 1

    o = struct.pack('HHI', l, l, source)
    myjit.vm.vm_set_mem(pstring, o)

    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlAnsiStringToUnicodeString(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    dst, src, alloc_str = args

    l1, l2, p_src = struct.unpack('HHI', myjit.vm.vm_get_mem(src, 0x8))
    print hex(l1), hex(l2), hex(p_src)
    s = get_str_ansi(myjit, p_src)
    print "str", repr(s)
    s = ("\x00".join(s + "\x00"))
    l = len(s) + 1
    if alloc_str:
        print 'alloc'
        alloc_addr = get_next_alloc_addr(l)
        myjit.vm.vm_add_memory_page(
            alloc_addr, PAGE_READ | PAGE_WRITE, "\x00" * l)
    else:
        print 'use buf'
        alloc_addr = p_src
    myjit.vm.vm_set_mem(alloc_addr, s)
    o = struct.pack('HHI', l, l, alloc_addr)
    myjit.vm.vm_set_mem(dst, o)
    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_LdrLoadDll(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    path, flags, modname, modhandle = args

    print whoami(), hex(ret_ad),
    print '(', hex(path), hex(flags), hex(modname), hex(modhandle), ')'
    l1, l2, p_src = struct.unpack('HHI', myjit.vm.vm_get_mem(modname, 0x8))
    print hex(l1), hex(l2), hex(p_src)
    s = get_str_unic(myjit, p_src)
    print repr(s)
    libname = s.lower()
    print repr(libname)

    ad = winobjs.runtime_dll.lib_get_add_base(libname)
    print "ret", hex(ad)
    myjit.vm.vm_set_mem(modhandle, pck32(ad))

    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlFreeUnicodeString(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    src, = args

    l1, l2, p_src = struct.unpack('HHI', myjit.vm.vm_get_mem(src, 0x8))
    print hex(l1), hex(l2), hex(p_src)
    s = get_str_unic(myjit, p_src)
    print "str", repr(s)
    print repr(s)

    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_LdrGetProcedureAddress(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    libbase, pfname, opt, p_ad = args

    l1, l2, p_src = struct.unpack('HHI', myjit.vm.vm_get_mem(pfname, 0x8))
    print hex(l1), hex(l2), hex(p_src)
    fname = get_str_ansi(myjit, p_src)
    print "str", repr(fname)

    ad = winobjs.runtime_dll.lib_get_add_func(libbase, fname)

    myjit.vm.vm_set_mem(p_ad, pck32(ad))

    myjit.func_ret_stdcall(ret_ad, 0)


def ntdll_memset(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    arg_addr, arg_c, arg_size = args

    myjit.vm.vm_set_mem(arg_addr, chr(arg_c) * arg_size)
    myjit.func_ret_stdcall(ret_ad, arg_addr)


def msvcrt_memset(myjit):
    ret_ad, args = myjit.func_args_cdecl(3)
    arg_addr, arg_c, arg_size = args

    myjit.vm.vm_set_mem(arg_addr, chr(arg_c) * arg_size)
    myjit.func_ret_cdecl(ret_ad, arg_addr)


def msvcrt_memcpy(myjit):
    ret_ad, args = myjit.func_args_cdecl(3)
    dst, src, size = args

    s = myjit.vm.vm_get_mem(src, size)
    myjit.vm.vm_set_mem(dst, s)
    myjit.func_ret_cdecl(ret_ad, dst)


def msvcrt_memcmp(myjit):
    ret_ad, args = myjit.func_args_cdecl(3)
    ps1, ps2, size = args

    s1 = myjit.vm.vm_get_mem(ps1, size)
    s2 = myjit.vm.vm_get_mem(ps2, size)
    ret = cmp(s1, s2)
    myjit.func_ret_cdecl(ret_ad, ret)


def shlwapi_PathFindExtensionA(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    path_ad, = args

    path = get_str_ansi(myjit, path_ad)
    print repr(path)
    i = path.rfind('.')
    if i == -1:
        i = path_ad + len(path)
    else:
        i = path_ad + i
    myjit.func_ret_stdcall(ret_ad, i)


def shlwapi_PathRemoveFileSpecW(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    path_ad, = args

    path = get_str_unic(myjit, path_ad)
    print repr(path)
    i = path.rfind('\\')
    if i == -1:
        i = 0
    myjit.vm.vm_set_mem(path_ad + i * 2, "\x00\x00")
    path = get_str_unic(myjit, path_ad)
    print repr(path)
    myjit.func_ret_stdcall(ret_ad, 1)


def shlwapi_PathIsPrefixW(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    ptr_prefix, ptr_path = args
    prefix = get_str_unic(myjit, ptr_prefix)
    path = get_str_unic(myjit, ptr_path)
    print repr(prefix), repr(path)

    if path.startswith(prefix):
        ret = 1
    else:
        ret = 0
    myjit.func_ret_stdcall(ret_ad, ret)


def shlwapi_PathIsDirectoryW(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    ppath, = args
    fname = get_str_unic(myjit, ppath)

    fname = fname.replace('\\', "/").lower()
    f = os.path.join('file_sb', fname)

    s = os.stat(f)
    ret = 0
    if stat.S_ISDIR(s.st_mode):
        ret = 1

    myjit.func_ret_cdecl(ret_ad, ret)


def shlwapi_PathIsFileSpec(funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(1)
    path_ad, = args
    path = get_str(myjit, path_ad)
    print repr(path)
    if path.find(':') != -1 and path.find('\\') != -1:
        ret = 0
    else:
        ret = 1

    myjit.func_ret_stdcall(ret_ad, ret)


def shlwapi_PathGetDriveNumber(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(1)
    path_ad, = args
    path = get_str(myjit, path_ad)
    print repr(path)
    l = ord(path[0].upper()) - ord('A')
    if 0 <= l <= 25:
        ret = l
    else:
        ret = -1

    myjit.func_ret_stdcall(ret_ad, ret)


def shlwapi_PathGetDriveNumberA(myjit):
    shlwapi_PathGetDriveNumber(myjit, whoami(), get_str_ansi)


def shlwapi_PathGetDriveNumberW(myjit):
    shlwapi_PathGetDriveNumber(myjit, whoami(), get_str_unic)


def shlwapi_PathIsFileSpecA(myjit):
    shlwapi_PathIsFileSpec(whoami(), get_str_ansi)


def shlwapi_PathIsFileSpecW(myjit):
    shlwapi_PathIsFileSpec(whoami(), get_str_unic)


def shlwapi_StrToIntA(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    i_str_ad, = args
    i_str = get_str_ansi(myjit, i_str_ad)
    print repr(i_str)
    try:
        i = int(i_str)
    except:
        print 'WARNING cannot convert int'
        i = 0

    myjit.func_ret_stdcall(ret_ad, i)


def shlwapi_StrToInt64Ex(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(3)
    pstr, flags, pret = args
    i_str = get_str(myjit, pstr)
    if get_str is get_str_unic:
        i_str = i_str
    print repr(i_str)

    if flags == 0:
        r = int(i_str)
    elif flags == 1:
        r = int(i_str, 16)
    else:
        raise ValueError('cannot decode int')

    myjit.vm.vm_set_mem(pret, struct.pack('q', r))

    myjit.func_ret_stdcall(ret_ad, i)


def shlwapi_StrToInt64ExA(myjit):
    shlwapi_StrToInt64Ex(myjit, whoami(), get_str_ansi)


def shlwapi_StrToInt64ExW(myjit):
    shlwapi_StrToInt64Ex(myjit, whoami(), get_str_unic)


def user32_IsCharAlpha(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(1)
    c, = args
    try:
        c = chr(c)
    except:
        print 'bad char', c
        c = "\x00"
    if c.isalpha(myjit):
        ret = 1
    else:
        ret = 0
    myjit.func_ret_stdcall(ret_ad, ret)


def user32_IsCharAlphaA(myjit):
    user32_IsCharAlpha(myjit, whoami(), get_str_ansi)


def user32_IsCharAlphaW(myjit):
    user32_IsCharAlpha(myjit, whoami(), get_str_unic)


def user32_IsCharAlphaNumericA(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    c, = args
    c = chr(c)
    if c.isalnum(myjit):
        ret = 1
    else:
        ret = 0
    myjit.func_ret_stdcall(ret_ad, ret)


def shlwapi_StrCmpNIA(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    ptr_str1, ptr_str2, nchar = args
    s1 = get_str_ansi(myjit, ptr_str1).lower()
    s2 = get_str_ansi(myjit, ptr_str2).lower()
    s1 = s1[:nchar]
    s2 = s2[:nchar]

    print repr(s1), repr(s2)
    myjit.func_ret_stdcall(ret_ad, cmp(s1, s2))


def advapi32_RegOpenKeyEx(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(5)
    hkey, subkey, reserved, access, phandle = args
    if subkey:
        s_subkey = get_str(myjit, subkey).lower()
    else:
        s_subkey = ""
    print hex(hkey)
    print repr(s_subkey)
    print winobjs.hkey_handles

    ret_hkey = 0
    ret = 2
    if hkey in winobjs.hkey_handles:
        if s_subkey:
            h = hash(s_subkey) & 0xffffffff
            print hex(h)
            if h in winobjs.hkey_handles:
                ret_hkey = h
                ret = 0
        else:
            print 'unknown skey'

    print 'set hkey', hex(ret_hkey)
    myjit.vm.vm_set_mem(phandle, pck32(ret_hkey))

    myjit.func_ret_stdcall(ret_ad, ret)


def advapi32_RegOpenKeyExA(myjit):
    advapi32_RegOpenKeyEx(myjit, whoami(), get_str_ansi)


def advapi32_RegOpenKeyExW(myjit):
    advapi32_RegOpenKeyEx(myjit, whoami(), get_str_unic)


def advapi32_RegSetValue(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(5)
    hkey, psubkey, valuetype, pvalue, length = args
    if psubkey:
        subkey = get_str(myjit, psubkey).lower()
    else:
        subkey = ""
    print repr(subkey)

    if pvalue:
        value = myjit.vm.vm_get_mem(pvalue, length)
    else:
        value = None
    print repr(value)
    myjit.func_ret_stdcall(ret_ad, 0)


def advapi32_RegSetValueA(myjit):
    advapi32_RegSetValue(myjit, whoami(), get_str_ansi)


def advapi32_RegSetValueW(myjit):
    advapi32_RegSetValue(myjit, whoami(), get_str_unic)


def kernel32_GetThreadLocale(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, 0x40c)


def kernel32_GetLocaleInfo(myjit, funcname, set_str):
    ret_ad, args = myjit.func_args_stdcall(4)
    localeid, lctype, lplcdata, cchdata = args

    buf = None
    ret = 0
    if localeid == 0x40c:
        if lctype == 0x3:
            buf = "ENGLISH"
            buf = buf[:cchdata - 1]
            print 'SET', buf
            myjit.vm.vm_set_mem(lplcdata, set_str(buf))
            ret = len(buf)
    else:
        raise ValueError('unimpl localeid')

    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetLocaleInfoA(myjit):
    kernel32_GetLocaleInfo(myjit, whoami(), set_str_ansi)


def kernel32_GetLocaleInfoW(myjit):
    kernel32_GetLocaleInfo(myjit, whoami(), set_str_unic)


def kernel32_TlsAlloc(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    winobjs.tls_index += 1
    myjit.func_ret_stdcall(ret_ad, winobjs.tls_index)


def kernel32_TlsFree(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_TlsSetValue(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    tlsindex, tlsvalue = args
    winobjs.tls_values[tlsindex] = tlsvalue
    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_TlsGetValue(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    tlsindex, = args

    print whoami(), hex(tlsindex)

    if not tlsindex in winobjs.tls_values:
        raise ValueError("unknown tls val", repr(tlsindex))
    myjit.func_ret_stdcall(ret_ad, winobjs.tls_values[tlsindex])


def user32_GetKeyboardType(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    typeflag, = args

    ret = 0
    if typeflag == 0:
        ret = 4
    else:
        raise ValueError('unimpl keyboard type')

    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetStartupInfo(myjit, funcname, set_str):
    ret_ad, args = myjit.func_args_stdcall(1)
    ptr, = args

    print funcname, hex(ptr)

    s = "\x00" * 0x2c + "\x81\x00\x00\x00" + "\x0a"

    myjit.vm.vm_set_mem(ptr, s)
    myjit.func_ret_stdcall(ret_ad, ptr)


def kernel32_GetStartupInfoA(myjit):
    kernel32_GetStartupInfo(myjit, whoami(), set_str_ansi)


def kernel32_GetStartupInfoW(myjit):
    kernel32_GetStartupInfo(myjit, whoami(), set_str_unic)


def kernel32_GetCurrentThreadId(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, 0x113377)


def kernel32_InitializeCriticalSection(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    lpcritic, = args
    myjit.func_ret_stdcall(ret_ad, 0)


def user32_GetSystemMetrics(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    nindex, = args

    ret = 0
    if nindex in [0x2a, 0x4a]:
        ret = 0
    else:
        raise ValueError('unimpl index')
    myjit.func_ret_stdcall(ret_ad, ret)


def wsock32_WSAStartup(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    version, pwsadata = args
    myjit.vm.vm_set_mem(pwsadata, "\x01\x01\x02\x02WinSock 2.0\x00")

    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_GetLocalTime(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    lpsystemtime, = args

    s = struct.pack('HHHHHHHH',
                    2011,  # year
                    10,   # month
                    5,    # dayofweek
                    7,    # day
                    13,   # hour
                    37,   # minutes
                    00,   # seconds
                    999,  # millisec
                    )
    myjit.vm.vm_set_mem(lpsystemtime, s)
    myjit.func_ret_stdcall(ret_ad, lpsystemtime)


def kernel32_GetSystemTime(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    lpsystemtime, = args

    print whoami(), hex(ret_ad), hex(lpsystemtime)

    s = struct.pack('HHHHHHHH',
                    2011,  # year
                    10,   # month
                    5,    # dayofweek
                    7,    # day
                    13,   # hour
                    37,   # minutes
                    00,   # seconds
                    999,  # millisec
                    )
    myjit.vm.vm_set_mem(lpsystemtime, s)
    myjit.func_ret_stdcall(ret_ad, lpsystemtime)


def kernel32_CreateFileMapping(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(6)
    hfile, lpattr, flprotect, dwmaximumsizehigh, dwmaximumsizelow, lpname = args

    if lpname:
        f = get_str(myjit, lpname)
    else:
        f = None
    print repr(f)

    if not hfile in winobjs.handle_pool:
        raise ValueError('unknown handle')

    ret = winobjs.handle_pool.add('filemapping', hfile)

    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_CreateFileMappingA(myjit):
    kernel32_CreateFileMapping(myjit, whoami(), get_str_ansi)


def kernel32_CreateFileMappingW(myjit):
    kernel32_CreateFileMapping(myjit, whoami(), get_str_unic)


def kernel32_MapViewOfFile(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    hfile, flprotect, dwfileoffsethigh, dwfileoffsetlow, length = args

    if not hfile in winobjs.handle_pool:
        raise ValueError('unknown handle')
    hmap = winobjs.handle_pool[hfile]
    print hmap
    if not hmap.info in winobjs.handle_pool:
        raise ValueError('unknown file handle')

    hfile_o = winobjs.handle_pool[hmap.info]
    print hfile_o
    fd = hfile_o.info
    fd.seek((dwfileoffsethigh << 32) | dwfileoffsetlow)
    if length:
        data = fd.read(length)
    else:
        data = fd.read()
    length = len(data)

    print 'mapp total:', hex(len(data))
    access_dict = {0x0: 0,
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
        raise ValueError('unknown access dw!')

    alloc_addr = alloc_mem(myjit, len(data))
    myjit.vm.vm_set_mem(alloc_addr, data)

    winobjs.handle_mapped[
        alloc_addr] = hfile_o, dwfileoffsethigh, dwfileoffsetlow, length
    print 'return', hex(alloc_addr)

    myjit.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_UnmapViewOfFile(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    ad, = args

    if not ad in winobjs.handle_mapped:
        raise NotImplementedError("Untested case")
    """
    hfile_o, dwfileoffsethigh, dwfileoffsetlow, length = winobjs.handle_mapped[ad]
    off = (dwfileoffsethigh<<32) | dwfileoffsetlow
    s = myjit.vm.vm_get_mem(ad, length)
    hfile_o.info.seek(off)
    hfile_o.info.write(s)
    hfile_o.info.close()
    """
    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_GetDriveType(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(1)
    pathname, = args

    print funcname, hex(pathname)

    p = get_str(myjit, pathname)
    print repr(p)
    p = p.upper()

    ret = 0
    if p[0] == "C":
        ret = 3

    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetDriveTypeA(myjit):
    kernel32_GetDriveType(myjit, whoami(), get_str_ansi)


def kernel32_GetDriveTypeW(myjit):
    kernel32_GetDriveType(myjit, whoami(), get_str_unic)


def kernel32_GetDiskFreeSpace(myjit, funcname, get_str):
    ret_ad, args = myjit.func_args_stdcall(5)
    (lprootpathname, lpsectorpercluster, lpbytespersector,
     lpnumberoffreeclusters, lptotalnumberofclusters) = args

    if lprootpathname:
        rootpath = get_str(myjit, lprootpathname)
    else:
        rootpath = ""
    print repr(rootpath)

    myjit.vm.vm_set_mem(lpsectorpercluster, pck32(8))
    myjit.vm.vm_set_mem(lpbytespersector, pck32(0x200))
    myjit.vm.vm_set_mem(lpnumberoffreeclusters, pck32(0x222222))
    myjit.vm.vm_set_mem(lptotalnumberofclusters, pck32(0x333333))
    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_GetDiskFreeSpaceA(myjit):
    kernel32_GetDiskFreeSpace(myjit, whoami(), get_str_ansi)


def kernel32_GetDiskFreeSpaceW(myjit):
    kernel32_GetDiskFreeSpace(myjit, whoami(), get_str_unic)


def kernel32_VirtualQuery(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    ad, lpbuffer, dwl = args

    access_dict = {0x0: 0,
                   0x1: 0,
                   0x2: PAGE_READ,
                   0x4: PAGE_READ | PAGE_WRITE,
                   0x10: PAGE_EXEC,
                   0x20: PAGE_EXEC | PAGE_READ,
                   0x40: PAGE_EXEC | PAGE_READ | PAGE_WRITE,
                   0x100: 0
                       }
    access_dict_inv = dict([(x[1], x[0]) for x in access_dict.items()])

    all_mem = myjit.vm.vm_get_all_memory()
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
    myjit.vm.vm_set_mem(lpbuffer, s)

    myjit.func_ret_stdcall(ret_ad, dwl)


def kernel32_GetProcessAffinityMask(myjit):
    ret_ad, args = myjit.func_args_stdcall(3)
    hprocess, procaffmask, systemaffmask = args
    myjit.vm.vm_set_mem(procaffmask, pck32(1))
    myjit.vm.vm_set_mem(systemaffmask, pck32(1))

    myjit.func_ret_stdcall(ret_ad, 1)


def msvcrt_rand(myjit):
    ret_ad, args = myjit.func_args_cdecl(0)
    myjit.func_ret_stdcall(ret_ad, 0x666)


def kernel32_SetFilePointer(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    hwnd, distance, p_distance_high, movemethod = args

    if hwnd == winobjs.module_cur_hwnd:
        pass
    elif hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown hwnd!')

    eax = 0xffffffff
    data = None
    if hwnd in winobjs.files_hwnd:
        winobjs.files_hwnd[winobjs.module_cur_hwnd].seek(distance)
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        data = wh.info.seek(distance)
    else:
        raise ValueError('unknown filename')
    myjit.func_ret_stdcall(ret_ad, distance)


def kernel32_SetFilePointerEx(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    hwnd, distance_l, distance_h, pnewfileptr, movemethod = args

    distance = distance_l | (distance_h << 32)
    if distance:
        TODO_XXX

    if pnewfileptr:
        TODO_XXX
    if hwnd == winobjs.module_cur_hwnd:
        pass
    elif hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown hwnd!')

    eax = 0xffffffff
    data = None
    if hwnd in winobjs.files_hwnd:
        winobjs.files_hwnd[winobjs.module_cur_hwnd].seek(distance)
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        data = wh.info.seek(distance)
    else:
        raise ValueError('unknown filename')
    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_SetEndOfFile(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    hwnd, = args
    if hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        wh.info.seek(0, 2)
    else:
        raise ValueError('unknown filename')
    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_FlushFileBuffers(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    hwnd, = args
    if hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown filename')
    myjit.func_ret_stdcall(ret_ad, 1)


def kernel32_WriteFile(myjit):
    ret_ad, args = myjit.func_args_stdcall(5)
    (hwnd, lpbuffer, nnumberofbytestowrite,
     lpnumberofbyteswrite, lpoverlapped) = args

    data = myjit.vm.vm_get_mem(lpbuffer, nnumberofbytestowrite)

    if hwnd == winobjs.module_cur_hwnd:
        pass
    elif hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown hwnd!')

    eax = 0xffffffff
    if hwnd in winobjs.files_hwnd:
        winobjs.files_hwnd[winobjs.module_cur_hwnd].write(data)
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        wh.info.write(data)
    else:
        raise ValueError('unknown filename')

    if (lpnumberofbyteswrite):
        myjit.vm.vm_set_mem(lpnumberofbyteswrite, pck32(len(data)))

    myjit.func_ret_stdcall(ret_ad, 1)


def user32_IsCharUpperA(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    c, = args

    if c & 0x20:
        ret = 0
    else:
        ret = 1
    myjit.func_ret_stdcall(ret_ad, ret)


def user32_IsCharLowerA(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    c, = args

    if c & 0x20:
        ret = 1
    else:
        ret = 0

    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetSystemDefaultLangID(myjit):
    ret_ad, args = myjit.func_args_stdcall(0)
    myjit.func_ret_stdcall(ret_ad, 0x409)  # encglish


def msvcrt_malloc(myjit):
    ret_ad, args = myjit.func_args_cdecl(1)
    msize, = args
    addr = alloc_mem(myjit, msize)
    myjit.func_ret_cdecl(ret_ad, addr)


def msvcrt_free(myjit):
    ret_ad, args = myjit.func_args_cdecl(1)
    ptr, = args
    myjit.func_ret_cdecl(ret_ad, 0)


def msvcrt_fopen(myjit):
    ret_ad, args = myjit.func_args_cdecl(2)
    fname, rw = args

    fname = get_str_ansi(myjit, fname)
    rw = get_str_ansi(myjit, rw)
    print fname, rw
    if rw in ['rb', 'wb+']:
        fname = fname.replace('\\', "/").lower()
        f = os.path.join('file_sb', fname)
        h = open(f, rw)
        eax = winobjs.handle_pool.add(f, h)
        alloc_addr = alloc_mem(myjit, 0x20)
        myjit.vm.vm_set_mem(alloc_addr, pck32(0x11112222) + pck32(
            0) + pck32(0) + pck32(0) + pck32(eax))  # pck32(0x11112222)
    else:
        raise NotImplementedError("Untested case")

    myjit.func_ret_cdecl(ret_ad, alloc_addr)


def msvcrt_fseek(myjit):
    ret_ad, args = myjit.func_args_cdecl(3)
    stream, offset, orig = args
    fd = upck32(myjit.vm.vm_get_mem(stream + 0x10, 4))
    print hex(fd)

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    o.info.seek(offset, orig)
    myjit.func_ret_cdecl(ret_ad, 0)


def msvcrt_ftell(myjit):
    ret_ad, args = myjit.func_args_cdecl(1)
    stream, = args
    fd = upck32(myjit.vm.vm_get_mem(stream + 0x10, 4))
    print hex(fd)

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    off = o.info.tell()
    myjit.func_ret_cdecl(ret_ad, off)


def msvcrt_rewind(myjit):
    ret_ad, args = myjit.func_args_cdecl(1)
    stream, = args
    fd = upck32(myjit.vm.vm_get_mem(stream + 0x10, 4))
    print hex(fd)

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    off = o.info.seek(0, 0)
    myjit.func_ret_cdecl(ret_ad, 0)


def msvcrt_fread(myjit):
    ret_ad, args = myjit.func_args_cdecl(4)
    buf, size, nmemb, stream = args
    fd = upck32(myjit.vm.vm_get_mem(stream + 0x10, 4))
    print hex(fd)
    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")

    data = winobjs.handle_pool[fd].info.read(size * nmemb)
    myjit.vm.vm_set_mem(buf, data)
    myjit.func_ret_cdecl(ret_ad, nmemb)


def msvcrt_fclose(myjit):
    ret_ad, args = myjit.func_args_cdecl(1)
    stream, = args
    fd = upck32(myjit.vm.vm_get_mem(stream + 0x10, 4))
    print hex(fd)

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    off = o.info.close()
    myjit.func_ret_cdecl(ret_ad, 0)


def msvcrt_atexit(myjit):
    ret_ad, args = myjit.func_args_cdecl(1)
    func, = args
    myjit.func_ret_cdecl(ret_ad, 0)


def user32_MessageBoxA(myjit):
    ret_ad, args = myjit.func_args_stdcall(4)
    hwnd, lptext, lpcaption, utype = args

    text = get_str_ansi(myjit, lptext)
    caption = get_str_ansi(myjit, lpcaption)

    print 'Caption:', repr(caption), 'Text:', repr(text)

    myjit.func_ret_stdcall(ret_ad, 0)


def kernel32_myGetTempPath(myjit, func):
    ret_ad, args = myjit.func_args_stdcall(2)
    l, buf = args

    l = 'c:\\temp\\'
    myjit.vm.vm_set_mem(buf, func(l + '\x00'))
    myjit.func_ret_stdcall(ret_ad, len(l))


def kernel32_GetTempPathA(myjit):
    kernel32_myGetTempPath(myjit, set_str_ansi)


def kernel32_GetTempPathW(myjit):
    kernel32_myGetTempPath(myjit, set_str_unic)


temp_num = 0


def kernel32_GetTempFileNameA(myjit):
    global temp_num
    ret_ad, args = myjit.func_args_stdcall(4)
    path, ext, unique, buf = args

    temp_num += 1
    if ext:
        ext = get_str_ansi(myjit, ext)
    else:
        ext = 'tmp'
    if path:
        path = get_str_ansi(myjit, path)
    else:
        path = "xxx"
    print ext, path
    fname = path + "\\" + "temp%.4d" % temp_num + "." + ext
    print fname
    myjit.vm.vm_set_mem(buf, fname)

    myjit.func_ret_stdcall(ret_ad, 0)


class win32_find_data:
    fileattrib = 0
    creationtime = 0
    lastaccesstime = 0
    lastwritetime = 0
    filesizehigh = 0
    filesizelow = 0
    dwreserved0 = 0
    dwreserved1 = 0x1337beef
    cfilename = ""
    alternamefilename = ""

    def __init__(self, **kargs):
        for k, v in kargs.items():
            setattr(self, k, v)

    def toStruct(self):
        s = struct.pack('=IQQQIIII',
                        self.fileattrib,
                        self.creationtime,
                        self.lastaccesstime,
                        self.lastwritetime,
                        self.filesizehigh,
                        self.filesizelow,
                        self.dwreserved0,
                        self.dwreserved1)
        fname = self.cfilename + '\x00' * win_api_x86_32.MAX_PATH
        fname = fname[:win_api_x86_32.MAX_PATH]
        s += fname
        fname = self.alternamefilename + '\x00' * 14
        fname = fname[:14]
        s += fname
        return s


class find_data_mngr:

    def __init__(self):
        self.patterns = {}
        self.flist = []
        # handle number -> (flist index, current index in list)
        self.handles = {}

    def add_list(self, pattern, flist):
        index = len(self.flist)
        self.flist.append(flist)

        self.patterns[pattern] = index

    def findfirst(self, pattern):
        assert(pattern in self.patterns)
        findex = self.patterns[pattern]
        h = len(self.handles) + 1
        self.handles[h] = [findex, 0]
        return h

    def findnext(self, h):
        assert(h in self.handles)
        findex, index = self.handles[h]
        if index >= len(self.flist[findex]):
            return None
        fname = self.flist[findex][index]
        self.handles[h][1] += 1

        return fname


def kernel32_FindFirstFileA(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    pfilepattern, pfindfiledata = args

    filepattern = get_str_ansi(myjit, pfilepattern)
    print repr(filepattern)
    h = winobjs.find_data.findfirst(filepattern)

    fname = winobjs.find_data.findnext(h)
    fdata = win32_find_data(cfilename=fname)

    myjit.vm.vm_set_mem(pfindfiledata, fdata.toStruct())
    myjit.func_ret_stdcall(ret_ad, h)


def kernel32_FindNextFileA(myjit):
    ret_ad, args = myjit.func_args_stdcall(2)
    handle, pfindfiledata = args

    fname = winobjs.find_data.findnext(handle)
    if fname is None:
        ret = 0
    else:
        ret = 1
        fdata = win32_find_data(cfilename=fname)
        myjit.vm.vm_set_mem(pfindfiledata, fdata.toStruct())

    myjit.func_ret_stdcall(ret_ad, ret)


def kernel32_GetNativeSystemInfo(myjit):
    ret_ad, args = myjit.func_args_stdcall(1)
    sys_ptr, = args
    sysinfo = systeminfo()
    myjit.vm.vm_set_mem(sys_ptr, sysinfo.pack())
    myjit.func_ret_stdcall(ret_ad, 0)


def raw2guid(r):
    o = struct.unpack('IHHHBBBBBB', r)
    return '{%.8X-%.4X-%.4X-%.4X-%.2X%.2X%.2X%.2X%.2X%.2X}' % o


digs = string.digits + string.lowercase


def int2base(x, base):
    if x < 0:
        sign = -1
    elif x == 0:
        return '0'
    else:
        sign = 1
    x *= sign
    digits = []
    while x:
        digits.append(digs[x % base])
        x /= base
    if sign < 0:
        digits.append('-')
    digits.reverse()
    return ''.join(digits)


def msvcrt__ultow(myjit):
    ret_ad, args = myjit.func_args_cdecl(3)
    value, p, radix = args

    value &= 0xFFFFFFFF
    if not radix in [10, 16, 20]:
        TODO_TEST
    s = int2base(value, radix)
    myjit.vm.vm_set_mem(p, set_str_unic(s + "\x00"))
    myjit.func_ret_cdecl(ret_ad, p)


def msvcrt_myfopen(myjit, func):
    ret_ad, args = myjit.func_args_cdecl(2)
    pfname, pmode = args


    fname = func(myjit, pfname)
    rw = func(myjit, pmode)
    print repr(fname)
    print repr(rw)

    if rw in ['r', 'rb', 'wb+']:
        fname = fname.replace('\\', "/").lower()
        f = os.path.join('file_sb', fname)
        h = open(f, rw)
        eax = winobjs.handle_pool.add(f, h)
        dwsize = 0x20
        alloc_addr = alloc_mem(myjit, dwsize)
        pp = pck32(0x11112222)+pck32(0)+pck32(0)+pck32(0)+pck32(eax)#pdw(0x11112222)
        myjit.vm.vm_set_mem(alloc_addr, pp)


    else:
        raise ValueError('unknown access mode %s'%rw)

    myjit.func_ret_cdecl(ret_ad, alloc_addr)

def msvcrt__wfopen(myjit):
    msvcrt_myfopen(myjit, get_str_unic)

def msvcrt_fopen(myjit):
    msvcrt_myfopen(myjit, get_str_ansi)
