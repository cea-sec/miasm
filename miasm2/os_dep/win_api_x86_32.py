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
from miasm2.os_dep.common import *
import string
import logging

log = logging.getLogger("win_api_x86_32")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


MAX_PATH = 260


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

        log.debug(repr(self))
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
        self.heap = heap()
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




def kernel32_HeapAlloc(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    heap, flags, size = args

    alloc_addr = winobjs.heap.alloc(jitter, size)

    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_HeapFree(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    heap, flags, pmem = args

    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GlobalAlloc(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    uflags, msize = args
    alloc_addr = winobjs.heap.alloc(jitter, msize)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_LocalFree(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    lpvoid, = args
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_LocalAlloc(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    uflags, msize = args
    alloc_addr = winobjs.heap.alloc(jitter, msize)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_GlobalFree(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    ad, = args
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_IsDebuggerPresent(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.dbg_present)


def kernel32_CreateToolhelp32Snapshot(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    dwflags, th32processid = args
    jitter.func_ret_stdcall(ret_ad, winobjs.handle_toolhelpsnapshot)


def kernel32_GetCurrentProcess(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.handle_curprocess)


def kernel32_GetCurrentProcessId(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.dw_pid_cur)


def kernel32_Process32First(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    s_handle, ad_pentry = args

    pentry = struct.pack(
        'IIIIIIIII', *process_list[0][:-1]) + process_list[0][-1]
    jitter.vm.set_mem(ad_pentry, pentry)
    winobjs.toolhelpsnapshot_info[s_handle] = 0

    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_Process32Next(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    s_handle, ad_pentry = args

    winobjs.toolhelpsnapshot_info[s_handle] += 1
    if winobjs.toolhelpsnapshot_info[s_handle] >= len(process_list):
        ret = 0
    else:
        ret = 1
        n = winobjs.toolhelpsnapshot_info[s_handle]
        pentry = struct.pack(
            'IIIIIIIII', *process_list[n][:-1]) + process_list[n][-1]
        jitter.vm.set_mem(ad_pentry, pentry)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetTickCount(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    winobjs.tickcount += 1
    jitter.func_ret_stdcall(ret_ad, winobjs.tickcount)


def kernel32_GetVersion(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.getversion)


def kernel32_GetVersionEx(jitter, set_str = set_str_unic):
    ret_ad, args = jitter.func_args_stdcall(1)
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
    jitter.vm.set_mem(ptr_struct, s)
    jitter.func_ret_stdcall(ret_ad, 1)


kernel32_GetVersionExA = lambda jitter: kernel32_GetVersionEx(jitter, set_str_ansi)
kernel32_GetVersionExW = lambda jitter: kernel32_GetVersionEx(jitter, set_str_unic)


def kernel32_GetPriorityClass(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    hwnd, = args
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_SetPriorityClass(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    hwnd, dwpclass = args
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_CloseHandle(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    hwnd, = args
    jitter.func_ret_stdcall(ret_ad, 1)


def user32_GetForegroundWindow(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.getforegroundwindow)


def user32_FindWindowA(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    pclassname, pwindowname = args
    jitter.func_ret_stdcall(ret_ad, 0)


def user32_GetTopWindow(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    hwnd, = args
    jitter.func_ret_stdcall(ret_ad, 0)


def user32_BlockInput(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    b, = args
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptAcquireContext(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(5)
    phprov, pszcontainer, pszprovider, dwprovtype, dwflags = args

    if pszprovider:
        prov = get_str(jitter, pszprovider)
    else:
        prov = "NONE"
    log.debug('prov: %r'%prov)
    jitter.vm.set_mem(phprov, pck32(winobjs.cryptcontext_hwnd))

    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptAcquireContextA(jitter):
    advapi32_CryptAcquireContext(jitter, whoami(), get_str_ansi)


def advapi32_CryptAcquireContextW(jitter):
    advapi32_CryptAcquireContext(jitter, whoami(), get_str_unic)


def advapi32_CryptCreateHash(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
    hprov, algid, hkey, dwflags, phhash = args

    winobjs.cryptcontext_num += 1

    if algid == 0x00008003:
        log.debug('algo is MD5')
        jitter.vm.set_mem(
            phhash, pck32(winobjs.cryptcontext_bnum + winobjs.cryptcontext_num))
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num] = hobj()
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num].h = MD5.new()
    elif algid == 0x00008004:
        log.debug('algo is SHA1')
        jitter.vm.set_mem(
            phhash, pck32(winobjs.cryptcontext_bnum + winobjs.cryptcontext_num))
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num] = hobj()
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num].h = SHA.new()
    else:
        raise ValueError('un impl algo1')
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptHashData(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    hhash, pbdata, dwdatalen, dwflags = args

    if not hhash in winobjs.cryptcontext:
        raise ValueError("unknown crypt context")

    data = jitter.vm.get_mem(pbdata, dwdatalen)
    log.debug('will hash %X' % dwdatalen)
    log.debug(repr(data[:10]) + "...")
    winobjs.cryptcontext[hhash].h.update(data)
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptGetHashParam(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
    hhash, param, pbdata, dwdatalen, dwflags = args

    if not hhash in winobjs.cryptcontext:
        raise ValueError("unknown crypt context")

    if param == 2:
        # XXX todo: save h state?
        h = winobjs.cryptcontext[hhash].h.digest()
    else:
        raise ValueError('not impl', param)
    jitter.vm.set_mem(pbdata, h)
    jitter.vm.set_mem(dwdatalen, pck32(len(h)))

    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptReleaseContext(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    hhash, flags = args
    jitter.func_ret_stdcall(ret_ad, 0)


def advapi32_CryptDeriveKey(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
    hprov, algid, hbasedata, dwflags, phkey = args

    if algid == 0x6801:
        log.debug('using DES')
    else:
        raise ValueError('un impl algo2')
    h = winobjs.cryptcontext[hbasedata].h.digest()
    log.debug('hash %r'% h)
    winobjs.cryptcontext[hbasedata].h_result = h
    jitter.vm.set_mem(phkey, pck32(hbasedata))
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptDestroyHash(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    hhash, = args
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptDecrypt(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
    hkey, hhash, final, dwflags, pbdata, pdwdatalen = args
    raise NotImplementedError()
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_CreateFile(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(7)
    (lpfilename, access, dwsharedmode, lpsecurityattr,
     dwcreationdisposition, dwflagsandattr, htemplatefile) = args

    fname = get_str(jitter, lpfilename)
    log.debug('fname %s' % fname )
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
    log.debug("%r %r"%(f.lower(), winobjs.module_path.lower()))
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
        if access & 0x80000000 or access == 1:
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
                    log.warning("FILE %r DOES NOT EXIST!" % fname)
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
            elif dwcreationdisposition == 4:
                # open_always
                if os.access(f, os.R_OK):
                    s = os.stat(f)
                    if stat.S_ISDIR(s.st_mode):
                        ret = winobjs.handle_pool.add(f, 0x1337)
                    else:
                        h = open(f, 'rb+')
                        ret = winobjs.handle_pool.add(f, h)
                else:
                    raise NotImplementedError("Untested case")
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
    log.debug('ret %x' % ret)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_CreateFileA(jitter):
    kernel32_CreateFile(jitter, whoami(), get_str_ansi)


def kernel32_CreateFileW(jitter):
    kernel32_CreateFile(jitter, whoami(), lambda x, y: get_str_unic(jitter, y))


def kernel32_ReadFile(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
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
            jitter.vm.set_mem(lpnumberofbytesread, pck32(len(data)))
        jitter.vm.set_mem(lpbuffer, data)

    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GetFileSize(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    hwnd, lpfilesizehight = args

    if hwnd == winobjs.module_cur_hwnd:
        ret = len(open(winobjs.module_fname_nux).read())
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        ret = len(open(wh.name).read())
    else:
        raise ValueError('unknown hwnd!')

    if lpfilesizehight != 0:
        jitter.vm.set_mem(lpfilesizehight, pck32(ret))
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetFileSizeEx(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    hwnd, lpfilesizehight = args

    if hwnd == winobjs.module_cur_hwnd:
        l = len(open(winobjs.module_fname_nux).read())
    elif hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        l = len(open(wh.name).read())
    else:
        raise ValueError('unknown hwnd!')

    if lpfilesizehight == 0:
        raise NotImplementedError("Untested case")
    jitter.vm.set_mem(lpfilesizehight, pck32(
        l & 0xffffffff) + pck32((l >> 32) & 0xffffffff))
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_FlushInstructionCache(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    hprocess, lpbasead, dwsize = args
    jitter.func_ret_stdcall(ret_ad, 0x1337)


def kernel32_VirtualProtect(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    lpvoid, dwsize, flnewprotect, lpfloldprotect = args

    # XXX mask hpart
    flnewprotect &= 0xFFF

    if not flnewprotect in access_dict:
        raise ValueError('unknown access dw!')
    jitter.vm.set_mem_access(lpvoid, access_dict[flnewprotect])

    # XXX todo real old protect
    if lpfloldprotect:
        jitter.vm.set_mem(lpfloldprotect, pck32(0x40))

    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_VirtualAlloc(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
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
        alloc_addr = winobjs.heap.next_addr(dwsize)
        jitter.vm.add_memory_page(
            alloc_addr, access_dict[flprotect], "\x00" * dwsize)
    else:
        all_mem = jitter.vm.get_all_memory()
        if lpvoid in all_mem:
            alloc_addr = lpvoid
            jitter.vm.set_mem_access(lpvoid, access_dict[flprotect])
        else:
            alloc_addr = winobjs.heap.next_addr(dwsize)
            # alloc_addr = lpvoid
            jitter.vm.add_memory_page(
                alloc_addr, access_dict[flprotect], "\x00" * dwsize)

    log.debug('Memory addr: %x' %alloc_addr)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_VirtualFree(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    lpvoid, dwsize, alloc_type = args
    jitter.func_ret_stdcall(ret_ad, 0)


def user32_GetWindowLongA(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    hwnd, nindex = args
    jitter.func_ret_stdcall(ret_ad, winobjs.windowlong_dw)


def user32_SetWindowLongA(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    hwnd, nindex, newlong = args
    jitter.func_ret_stdcall(ret_ad, winobjs.windowlong_dw)


def kernel32_GetModuleFileName(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(3)
    hmodule, lpfilename, nsize = args

    if hmodule in [0, winobjs.hcurmodule]:
        p = winobjs.module_path[:]
    elif (winobjs.runtime_dll and
        hmodule in winobjs.runtime_dll.name2off.values()):
        name_inv = dict([(x[1], x[0])
                        for x in winobjs.runtime_dll.name2off.items()])
        p = name_inv[hmodule]
    else:
        log.warning('unknown module %x' % hmodule)
        p = None

    if p is None:
        l = 0
    elif nsize < len(p):
        p = p[:nsize]
        l = len(p)
    else:
        l = len(p)

    if p:
        jitter.vm.set_mem(lpfilename, set_str(p))

    jitter.func_ret_stdcall(ret_ad, l)


def kernel32_GetModuleFileNameA(jitter):
    kernel32_GetModuleFileName(jitter, whoami(), set_str_ansi)


def kernel32_GetModuleFileNameW(jitter):
    kernel32_GetModuleFileName(jitter, whoami(), set_str_unic)


def kernel32_CreateMutex(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(3)
    mutexattr, initowner, lpname = args

    if lpname:
        name = get_str(jitter, lpname)
        log.debug(name)
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
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_CreateMutexA(jitter):
    kernel32_CreateMutex(jitter, whoami(), get_str_ansi)


def kernel32_CreateMutexW(jitter):
    kernel32_CreateMutex(jitter, whoami(), get_str_unic)


def shell32_SHGetSpecialFolderLocation(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    hwndowner, nfolder, ppidl = args
    jitter.vm.set_mem(ppidl, pck32(nfolder))
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_SHGetPathFromIDList(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(2)
    pidl, ppath = args

    if pidl == 7:  # CSIDL_STARTUP:
        s = "c:\\doc\\user\\startmenu\\programs\\startup"
        s = set_str(s)
    else:
        raise ValueError('pidl not implemented', pidl)
    jitter.vm.set_mem(ppath, s)
    jitter.func_ret_stdcall(ret_ad, 1)


def shell32_SHGetPathFromIDListW(jitter):
    kernel32_SHGetPathFromIDList(jitter, whoami(), set_str_unic)


def shell32_SHGetPathFromIDListA(jitter):
    kernel32_SHGetPathFromIDList(jitter, whoami(), set_str_ansi)


def kernel32_GetLastError(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.lastwin32error)


def kernel32_SetLastError(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    e, = args
    # lasterr addr
    # ad = seh_helper.FS_0_AD + 0x34
    # jitter.vm.set_mem(ad, pck32(e))
    winobjs.lastwin32error = e
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_RestoreLastError(jitter):
    kernel32_SetLastError(jitter)


def kernel32_LoadLibraryA(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    dllname, = args

    libname = get_str_ansi(jitter, dllname, 0x100)
    log.info(libname)

    ret = winobjs.runtime_dll.lib_get_add_base(libname)
    log.info("ret %x" %ret)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_LoadLibraryExA(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    dllname, hfile, flags = args

    if hfile != 0:
        raise NotImplementedError("Untested case")
    libname = get_str_ansi(jitter, dllname, 0x100)
    log.info(libname)

    ret = winobjs.runtime_dll.lib_get_add_base(libname)
    log.info("ret %x" % ret)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetProcAddress(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    libbase, fname = args
    fname = fname & 0xFFFFFFFF
    if fname < 0x10000:
        fname = fname
    else:
        fname = get_str_ansi(jitter, fname, 0x100)
        if not fname:
            fname = None
    log.info(fname)
    if fname is not None:
        ad = winobjs.runtime_dll.lib_get_add_func(libbase, fname)
    else:
        ad = 0
    ad = winobjs.runtime_dll.lib_get_add_func(libbase, fname)

    jitter.func_ret_stdcall(ret_ad, ad)


def kernel32_LoadLibraryW(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    dllname, = args

    libname = get_str_unic(jitter, dllname, 0x100)
    log.info(libname)

    ret = winobjs.runtime_dll.lib_get_add_base(libname)
    log.info("ret %x", ret)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetModuleHandle(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(1)
    dllname, = args

    if dllname:
        libname = get_str(jitter, dllname)
        log.info(libname)
        if libname:
            ret = winobjs.runtime_dll.lib_get_add_base(libname)
        else:
            log.warning('unknown module!')
            ret = 0
    else:
        ret = winobjs.current_pe.NThdr.ImageBase
        log.debug("default img base %x", ret)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetModuleHandleA(jitter):
    kernel32_GetModuleHandle(jitter, whoami(), get_str_ansi)


def kernel32_GetModuleHandleW(jitter):
    kernel32_GetModuleHandle(jitter, whoami(), get_str_unic)


def kernel32_VirtualLock(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    lpaddress, dwsize = args
    jitter.func_ret_stdcall(ret_ad, 1)


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


def kernel32_GetSystemInfo(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    sys_ptr, = args
    sysinfo = systeminfo()
    jitter.vm.set_mem(sys_ptr, sysinfo.pack())
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_IsWow64Process(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    h, bool_ptr = args

    jitter.vm.set_mem(bool_ptr, pck32(0))
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GetCommandLineA(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    s = winobjs.module_path + '\x00'
    s = '"%s"' % s
    alloc_addr = winobjs.heap.alloc(jitter, 0x1000)
    jitter.vm.set_mem(alloc_addr, s)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_GetCommandLineW(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    s = winobjs.module_path + '\x00'
    s = set_str_unic('"%s"' % s)
    alloc_addr = winobjs.heap.alloc(jitter, 0x1000)
    jitter.vm.set_mem(alloc_addr, s)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def shell32_CommandLineToArgvW(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    pcmd, pnumargs = args
    cmd = get_str_unic(jitter, pcmd)
    log.debug(cmd)
    tks = cmd.split(' ')
    addr = winobjs.heap.alloc(jitter, len(cmd) * 2 + 4 * len(tks))
    addr_ret = winobjs.heap.alloc(jitter, 4 * (len(tks) + 1))
    o = 0
    for i, t in enumerate(tks):
        x = set_str_unic(t) + "\x00\x00"
        jitter.vm.set_mem(addr_ret + 4 * i, pck32(addr + o))
        jitter.vm.set_mem(addr + o, x)
        o += len(x) + 2

    jitter.vm.set_mem(addr_ret + 4 * i, pck32(0))
    jitter.vm.set_mem(pnumargs, pck32(len(tks)))
    jitter.func_ret_stdcall(ret_ad, addr_ret)


def cryptdll_MD5Init(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    ad_ctx, = args
    index = len(winobjs.cryptdll_md5_h)
    h = MD5.new()
    winobjs.cryptdll_md5_h[index] = h

    jitter.vm.set_mem(ad_ctx, pck32(index))
    jitter.func_ret_stdcall(ret_ad, 0)


def cryptdll_MD5Update(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    ad_ctx, ad_input, inlen = args

    index = jitter.vm.get_mem(ad_ctx, 4)
    index = upck32(index)
    if not index in winobjs.cryptdll_md5_h:
        raise ValueError('unknown h context', index)

    data = jitter.vm.get_mem(ad_input, inlen)
    winobjs.cryptdll_md5_h[index].update(data)
    log.debug(hexdump(data))

    jitter.func_ret_stdcall(ret_ad, 0)


def cryptdll_MD5Final(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    ad_ctx, = args

    index = jitter.vm.get_mem(ad_ctx, 4)
    index = upck32(index)
    if not index in winobjs.cryptdll_md5_h:
        raise ValueError('unknown h context', index)
    h = winobjs.cryptdll_md5_h[index].digest()
    jitter.vm.set_mem(ad_ctx + 88, h)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlInitAnsiString(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    ad_ctx, ad_str = args

    s = get_str_ansi(jitter, ad_str)
    l = len(s)
    jitter.vm.set_mem(ad_ctx, pck16(l) + pck16(l + 1) + pck32(ad_str))
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlHashUnicodeString(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    ad_ctxu, case_i, h_id, phout = args

    if h_id != 1:
        raise ValueError('unk hash unicode', h_id)

    l1, l2, ptra = struct.unpack('HHL', jitter.vm.get_mem(ad_ctxu, 8))
    s = jitter.vm.get_mem(ptra, l1)
    s = s[:-1]
    hv = 0

    if case_i:
        s = s.lower()
    for c in s:
        hv = ((65599 * hv) + ord(c)) & 0xffffffff
    jitter.vm.set_mem(phout, pck32(hv))
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_RtlMoveMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    ad_dst, ad_src, m_len = args
    data = jitter.vm.get_mem(ad_src, m_len)
    jitter.vm.set_mem(ad_dst, data)

    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlAnsiCharToUnicodeChar(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    ad_ad_ch, = args
    ad_ch = upck32(jitter.vm.get_mem(ad_ad_ch, 4))
    ch = ord(jitter.vm.get_mem(ad_ch, 1))
    jitter.vm.set_mem(ad_ad_ch, pck32(ad_ch + 1))

    jitter.func_ret_stdcall(ret_ad, ch)


def ntdll_RtlFindCharInUnicodeString(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    flags, main_str_ad, search_chars_ad, pos_ad = args

    if flags != 0:
        raise ValueError('unk flags')

    ml1, ml2, mptra = struct.unpack('HHL', jitter.vm.get_mem(main_str_ad, 8))
    sl1, sl2, sptra = struct.unpack(
        'HHL', jitter.vm.get_mem(search_chars_ad, 8))
    main_data = jitter.vm.get_mem(mptra, ml1)[:-1]
    search_data = jitter.vm.get_mem(sptra, sl1)[:-1]

    pos = None
    for i, c in enumerate(main_data):
        for s in search_data:
            if s == c:
                pos = i
                break
        if pos:
            break
    if pos is None:
        ret = 0xC0000225
        jitter.vm.set_mem(pos_ad, pck32(0))
    else:
        ret = 0
        jitter.vm.set_mem(pos_ad, pck32(pos))

    jitter.func_ret_stdcall(ret_ad, ret)


def ntdll_RtlComputeCrc32(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    dwinit, pdata, ilen = args

    data = jitter.vm.get_mem(pdata, ilen)
    crc_r = crc32(data, dwinit)
    jitter.func_ret_stdcall(ret_ad, crc_r)


def ntdll_RtlExtendedIntegerMultiply(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    b2, b1, bm = args
    a = (b1 << 32) + b2
    a = a * bm
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlLargeIntegerAdd(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    a2, a1, b2, b1 = args
    a = (a1 << 32) + a2 + (b1 << 32) + b2
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlLargeIntegerShiftRight(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    a2, a1, m = args
    a = ((a1 << 32) + a2) >> m
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlEnlargedUnsignedMultiply(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    a, b = args
    a = a * b
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlLargeIntegerSubtract(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    a2, a1, b2, b1 = args
    a = (a1 << 32) + a2 - (b1 << 32) + b2
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlCompareMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    ad1, ad2, m_len = args
    data1 = jitter.vm.get_mem(ad1, m_len)
    data2 = jitter.vm.get_mem(ad2, m_len)

    i = 0
    while data1[i] == data2[i]:
        i += 1
        if i >= m_len:
            break

    jitter.func_ret_stdcall(ret_ad, i)


def user32_GetMessagePos(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0x00110022)


def kernel32_Sleep(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    t, = args
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_ZwUnmapViewOfSection(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    h, ad = args
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_IsBadReadPtr(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    lp, ucb = args
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_KeInitializeEvent(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    my_event, my_type, my_state = args
    jitter.vm.set_mem(my_event, pck32(winobjs.win_event_num))
    winobjs.win_event_num += 1

    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_RtlGetVersion(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    ptr_version, = args

    s = struct.pack("IIIII",
                    0x114,  # struct size
                    0x5,   # maj vers
                    0x2,  # min vers
                    0x666,  # build nbr
                    0x2,   # platform id
                    ) + set_str_unic("Service pack 4")

    jitter.vm.set_mem(ptr_version, s)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_RtlVerifyVersionInfo(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    ptr_version, = args

    s = jitter.vm.get_mem(ptr_version, 0x5 * 4)
    s_size, s_majv, s_minv, s_buildn, s_platform = struct.unpack('IIIII', s)
    raise NotImplementedError("Untested case")
    jitter.vm.set_mem(ptr_version, s)
    jitter.func_ret_stdcall(ret_ad, 0)


def hal_ExAcquireFastMutex(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0)


def mdl2ad(n):
    return winobjs.nt_mdl_ad + 0x10 * n


def ad2mdl(ad):
    return ((ad - winobjs.nt_mdl_ad) & 0xFFFFFFFFL) / 0x10


def ntoskrnl_IoAllocateMdl(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
    v_addr, l, second_buf, chargequota, pirp = args
    m = mdl(v_addr, l)
    winobjs.nt_mdl[winobjs.nt_mdl_cur] = m
    jitter.vm.set_mem(mdl2ad(winobjs.nt_mdl_cur), str(m))
    jitter.func_ret_stdcall(ret_ad, mdl2ad(winobjs.nt_mdl_cur))
    winobjs.nt_mdl_cur += 1


def ntoskrnl_MmProbeAndLockPages(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    p_mdl, access_mode, op = args

    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_MmMapLockedPagesSpecifyCache(jitter):
    ret_ad, args = jitter.func_args_stdcall(6)
    p_mdl, access_mode, cache_type, base_ad, bugcheckonfailure, priority = args
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    jitter.func_ret_stdcall(ret_ad, winobjs.nt_mdl[ad2mdl(p_mdl)].ad)


def ntoskrnl_MmProtectMdlSystemAddress(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    p_mdl, prot = args
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_MmUnlockPages(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    p_mdl, = args
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))

    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_IoFreeMdl(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    p_mdl, = args
    if not ad2mdl(p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(p_mdl))
    del(winobjs.nt_mdl[ad2mdl(p_mdl)])
    jitter.func_ret_stdcall(ret_ad, 0)


def hal_ExReleaseFastMutex(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_RtlQueryRegistryValues(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
    relativeto, path, querytable, context, environ = args
    p = get_str_unic(jitter, path)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_ExAllocatePoolWithTagPriority(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    pool_type, nbr_of_bytes, tag, priority = args

    alloc_addr = winobjs.heap.next_addr(nbr_of_bytes)
    jitter.vm.add_memory_page(
        alloc_addr, PAGE_READ | PAGE_WRITE, "\x00" * nbr_of_bytes)

    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def my_lstrcmp(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(2)
    ptr_str1, ptr_str2 = args
    s1 = get_str(ptr_str1)
    s2 = get_str(ptr_str2)
    jitter.func_ret_stdcall(ret_ad, cmp(s1, s2))


def kernel32_lstrcmpA(jitter):
    my_lstrcmp(jitter, whoami(), lambda x: get_str_ansi(jitter, x))


def kernel32_lstrcmpiA(jitter):
    my_lstrcmp(jitter, whoami(), lambda x: get_str_ansi(jitter, x).lower())


def kernel32_lstrcmpW(jitter):
    my_lstrcmp(jitter, whoami(), lambda x: get_str_unic(jitter, x))


def kernel32_lstrcmpiW(jitter):
    my_lstrcmp(jitter, whoami(), lambda x: get_str_unic(jitter, x).lower())


def kernel32_lstrcmpi(jitter):
    my_lstrcmp(jitter, whoami(), lambda x: get_str_ansi(jitter, x).lower())


def my_strcpy(jitter, funcname, get_str, set_str):
    ret_ad, args = jitter.func_args_stdcall(2)
    ptr_str1, ptr_str2 = args
    s2 = get_str(jitter, ptr_str2)
    jitter.vm.set_mem(ptr_str1, set_str(s2))
    jitter.func_ret_stdcall(ret_ad, ptr_str1)


def kernel32_lstrcpyW(jitter):
    my_strcpy(jitter, whoami(), get_str_unic,
              lambda x: set_str_unic(x) + "\x00\x00")


def kernel32_lstrcpyA(jitter):
    my_strcpy(jitter, whoami(), get_str_ansi, lambda x: x + "\x00")


def kernel32_lstrcpy(jitter):
    my_strcpy(jitter, whoami(), get_str_ansi, lambda x: x + "\x00")


def kernel32_lstrcpyn(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    ptr_str1, ptr_str2, mlen = args
    s2 = get_str_ansi(jitter, ptr_str2)
    s2 = s2[:mlen]
    jitter.vm.set_mem(ptr_str1, s2)

    jitter.func_ret_stdcall(ret_ad, ptr_str1)


def my_strlen(jitter, funcname, get_str, mylen):
    ret_ad, args = jitter.func_args_stdcall(1)
    arg_src, = args
    src = get_str(jitter, arg_src)
    jitter.func_ret_stdcall(ret_ad, mylen(src))


def kernel32_lstrlenA(jitter):
    my_strlen(jitter, whoami(), get_str_ansi, lambda x: len(x))


def kernel32_lstrlenW(jitter):
    my_strlen(jitter, whoami(), get_str_unic, lambda x: len(x))


def kernel32_lstrlen(jitter):
    my_strlen(jitter, whoami(), get_str_ansi, lambda x: len(x))


def my_lstrcat(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(3)
    ptr_str1, ptr_str2 = args
    s1 = get_str(jitter, ptr_str1)
    s2 = get_str(jitter, ptr_str2)

    s = s1 + s2
    jitter.vm.set_mem(ptr_str1, s1 + s2)
    jitter.func_ret_stdcall(ret_ad, ptr_str1)


def kernel32_lstrcatA(jitter):
    my_lstrcat(jitter, whoami(), get_str_ansi)


def kernel32_lstrcatW(jitter):
    my_lstrcat(jitter, whoami(), get_str_unic)


def kernel32_GetUserGeoID(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    geoclass, = args
    if geoclass == 14:
        ret = 12345678
    elif geoclass == 16:
        ret = 55667788
    else:
        raise ValueError('unknown geolcass')

    jitter.func_ret_stdcall(ret_ad, ret)


def my_GetVolumeInformation(jitter, funcname, get_str, set_str):
    ret_ad, args = jitter.func_args_stdcall(8)
    (lprootpathname, lpvolumenamebuffer, nvolumenamesize,
     lpvolumeserialnumber, lpmaximumcomponentlength, lpfilesystemflags,
     lpfilesystemnamebuffer, nfilesystemnamesize) = args


    if lprootpathname:
        s = get_str(jitter, lprootpathname)

    if lpvolumenamebuffer:
        s = "volumename"
        s = s[:nvolumenamesize]
        jitter.vm.set_mem(lpvolumenamebuffer, set_str(s))

    if lpvolumeserialnumber:
        jitter.vm.set_mem(lpvolumeserialnumber, pck32(11111111))
    if lpmaximumcomponentlength:
        jitter.vm.set_mem(lpmaximumcomponentlength, pck32(0xff))
    if lpfilesystemflags:
        jitter.vm.set_mem(lpfilesystemflags, pck32(22222222))

    if lpfilesystemnamebuffer:
        s = "filesystemname"
        s = s[:nfilesystemnamesize]
        jitter.vm.set_mem(lpfilesystemnamebuffer, set_str(s))

    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GetVolumeInformationA(jitter):
    my_GetVolumeInformation(
        jitter, whoami(), get_str_ansi, lambda x: x + "\x00")


def kernel32_GetVolumeInformationW(jitter):
    my_GetVolumeInformation(jitter, whoami(), get_str_unic, set_str_unic)


def kernel32_MultiByteToWideChar(jitter):
    ret_ad, args = jitter.func_args_stdcall(6)
    (codepage, dwflags, lpmultibytestr,
     cbmultibyte, lpwidecharstr, cchwidechar) = args

    src = get_str_ansi(jitter, lpmultibytestr) + '\x00'
    l = len(src)

    src = "\x00".join(list(src))
    jitter.vm.set_mem(lpwidecharstr, src)
    jitter.func_ret_stdcall(ret_ad, l)


def my_GetEnvironmentVariable(jitter, funcname, get_str, set_str, mylen):
    ret_ad, args = jitter.func_args_stdcall(3)
    lpname, lpbuffer, nsize = args

    s = get_str(jitter, lpname)
    if get_str == get_str_unic:
        s = s
    log.debug('variable %r' % s)
    if s in winobjs.env_variables:
        v = set_str(winobjs.env_variables[s])
    else:
        log.warning('WARNING unknown env variable %r' % s)
        v = ""
    jitter.vm.set_mem(lpbuffer, v)
    jitter.func_ret_stdcall(ret_ad, mylen(v))


def my_GetSystemDirectory(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(2)
    lpbuffer, usize = args

    s = "c:\\windows\\system32"
    l = len(s)
    s = set_str(s)
    jitter.vm.set_mem(lpbuffer, s)

    jitter.func_ret_stdcall(ret_ad, l)


def kernel32_GetSystemDirectoryA(jitter):
    my_GetSystemDirectory(jitter, whoami(), set_str_ansi)


def kernel32_GetSystemDirectoryW(jitter):
    my_GetSystemDirectory(jitter, whoami(), set_str_unic)


def my_CreateDirectory(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(2)
    lppath, secattrib = args
    p = get_str(jitter, lppath)
    jitter.func_ret_stdcall(ret_ad, 0x1337)


def kernel32_CreateDirectoryW(jitter):
    my_CreateDirectory(jitter, whoami(), get_str_unic)


def kernel32_CreateDirectoryA(jitter):
    my_CreateDirectory(jitter, whoami(), get_str_ansi)


def kernel32_GetEnvironmentVariableA(jitter):
    my_GetEnvironmentVariable(jitter, whoami(),
                              get_str_ansi,
                              lambda x: x + "\x00",
                              lambda x: len(x))


def kernel32_GetEnvironmentVariableW(jitter):
    my_GetEnvironmentVariable(jitter, whoami(),
                              get_str_unic,
                              lambda x: "\x00".join(list(x + "\x00")),
                              lambda x: len(x))


def my_CreateEvent(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(4)
    lpeventattributes, bmanualreset, binitialstate, lpname = args
    if lpname:
        s = get_str(jitter, lpname)
    else:
        s = None
    if not s in winobjs.events_pool:
        winobjs.events_pool[s] = (bmanualreset, binitialstate)
    else:
        log.warning('WARNING: known event')

    jitter.func_ret_stdcall(ret_ad, id(s))


def kernel32_CreateEventA(jitter):
    my_CreateEvent(jitter, whoami(), get_str_ansi)


def kernel32_CreateEventW(jitter):
    my_CreateEvent(jitter, whoami(), get_str_unic)


def kernel32_WaitForSingleObject(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    handle, dwms = args

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
            log.warning('unknown handle')
            ret = 0xffffffff
            break
        time.sleep(0.1)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_SetFileAttributesA(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    lpfilename, dwfileattributes = args

    if lpfilename:
        fname = get_str_ansi(jitter, lpfilename)
        ret = 1
    else:
        ret = 0
        jitter.vm.set_mem(seh_helper.FS_0_AD + 0x34, pck32(3))

    jitter.func_ret_stdcall(ret_ad, ret)


def ntdll_RtlMoveMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    dst, src, l = args
    s = jitter.vm.get_mem(src, l)
    jitter.vm.set_mem(dst, s)

    jitter.func_ret_stdcall(ret_ad, 1)


def ntdll_ZwQuerySystemInformation(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    (systeminformationclass, systeminformation,
     systeminformationl, returnl) = args
    if systeminformationclass == 2:
        # SYSTEM_PERFORMANCE_INFORMATION
        o = struct.pack('II', 0x22222222, 0x33333333)
        o += "\x00" * systeminformationl
        o = o[:systeminformationl]
        jitter.vm.set_mem(systeminformation, o)
    else:
        raise ValueError('unknown sysinfo class', systeminformationclass)

    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_ZwProtectVirtualMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
    handle, lppvoid, pdwsize, flnewprotect, lpfloldprotect = args

    ad = upck32(jitter.vm.get_mem(lppvoid, 4))
    dwsize = upck32(jitter.vm.get_mem(pdwsize, 4))
    # XXX mask hpart
    flnewprotect &= 0xFFF

    if not flnewprotect in access_dict:
        raise ValueError('unknown access dw!')
    jitter.vm.set_mem_access(ad, access_dict[flnewprotect])

    # XXX todo real old protect
    jitter.vm.set_mem(lpfloldprotect, pck32(0x40))

    dump_memory_page_pool_py()
    jitter.func_ret_stdcall(ret_ad, 1)


def ntdll_ZwAllocateVirtualMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(6)
    handle, lppvoid, zerobits, pdwsize, alloc_type, flprotect = args

    ad = upck32(jitter.vm.get_mem(lppvoid, 4))
    dwsize = upck32(jitter.vm.get_mem(pdwsize, 4))

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

    alloc_addr = winobjs.heap.next_addr(dwsize)
    jitter.vm.add_memory_page(
        alloc_addr, access_dict[flprotect], "\x00" * dwsize)
    jitter.vm.set_mem(lppvoid, pck32(alloc_addr))

    dump_memory_page_pool_py()
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_ZwFreeVirtualMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    handle, lppvoid, pdwsize, alloc_type = args
    ad = upck32(jitter.vm.get_mem(lppvoid, 4))
    dwsize = upck32(jitter.vm.get_mem(pdwsize, 4))

    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlInitString(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    pstring, source = args
    s = get_str_ansi(jitter, source)

    l = len(s) + 1

    o = struct.pack('HHI', l, l, source)
    jitter.vm.set_mem(pstring, o)

    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlAnsiStringToUnicodeString(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    dst, src, alloc_str = args

    l1, l2, p_src = struct.unpack('HHI', jitter.vm.get_mem(src, 0x8))
    s = get_str_ansi(jitter, p_src)
    s = ("\x00".join(s + "\x00"))
    l = len(s) + 1
    if alloc_str:
        alloc_addr = winobjs.heap.next_addr(l)
        jitter.vm.add_memory_page(
            alloc_addr, PAGE_READ | PAGE_WRITE, "\x00" * l)
    else:
        alloc_addr = p_src
    jitter.vm.set_mem(alloc_addr, s)
    o = struct.pack('HHI', l, l, alloc_addr)
    jitter.vm.set_mem(dst, o)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_LdrLoadDll(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    path, flags, modname, modhandle = args

    l1, l2, p_src = struct.unpack('HHI', jitter.vm.get_mem(modname, 0x8))
    s = get_str_unic(jitter, p_src)
    libname = s.lower()

    ad = winobjs.runtime_dll.lib_get_add_base(libname)
    jitter.vm.set_mem(modhandle, pck32(ad))

    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlFreeUnicodeString(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    src, = args

    l1, l2, p_src = struct.unpack('HHI', jitter.vm.get_mem(src, 0x8))
    s = get_str_unic(jitter, p_src)

    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_LdrGetProcedureAddress(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    libbase, pfname, opt, p_ad = args

    l1, l2, p_src = struct.unpack('HHI', jitter.vm.get_mem(pfname, 0x8))
    fname = get_str_ansi(jitter, p_src)

    ad = winobjs.runtime_dll.lib_get_add_func(libbase, fname)

    jitter.vm.set_mem(p_ad, pck32(ad))

    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_memset(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    arg_addr, arg_c, arg_size = args

    jitter.vm.set_mem(arg_addr, chr(arg_c) * arg_size)
    jitter.func_ret_stdcall(ret_ad, arg_addr)


def msvcrt_memset(jitter):
    ret_ad, args = jitter.func_args_cdecl(3)
    arg_addr, arg_c, arg_size = args

    jitter.vm.set_mem(arg_addr, chr(arg_c) * arg_size)
    jitter.func_ret_cdecl(ret_ad, arg_addr)


def msvcrt_memcpy(jitter):
    ret_ad, args = jitter.func_args_cdecl(3)
    dst, src, size = args

    s = jitter.vm.get_mem(src, size)
    jitter.vm.set_mem(dst, s)
    jitter.func_ret_cdecl(ret_ad, dst)


def msvcrt_memcmp(jitter):
    ret_ad, args = jitter.func_args_cdecl(3)
    ps1, ps2, size = args

    s1 = jitter.vm.get_mem(ps1, size)
    s2 = jitter.vm.get_mem(ps2, size)
    ret = cmp(s1, s2)
    jitter.func_ret_cdecl(ret_ad, ret)


def shlwapi_PathFindExtensionA(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    path_ad, = args

    path = get_str_ansi(jitter, path_ad)
    i = path.rfind('.')
    if i == -1:
        i = path_ad + len(path)
    else:
        i = path_ad + i
    jitter.func_ret_stdcall(ret_ad, i)


def shlwapi_PathRemoveFileSpecW(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    path_ad, = args

    path = get_str_unic(jitter, path_ad)
    i = path.rfind('\\')
    if i == -1:
        i = 0
    jitter.vm.set_mem(path_ad + i * 2, "\x00\x00")
    path = get_str_unic(jitter, path_ad)
    jitter.func_ret_stdcall(ret_ad, 1)


def shlwapi_PathIsPrefixW(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    ptr_prefix, ptr_path = args
    prefix = get_str_unic(jitter, ptr_prefix)
    path = get_str_unic(jitter, ptr_path)

    if path.startswith(prefix):
        ret = 1
    else:
        ret = 0
    jitter.func_ret_stdcall(ret_ad, ret)


def shlwapi_PathIsDirectoryW(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    ppath, = args
    fname = get_str_unic(jitter, ppath)

    fname = fname.replace('\\', "/").lower()
    f = os.path.join('file_sb', fname)

    s = os.stat(f)
    ret = 0
    if stat.S_ISDIR(s.st_mode):
        ret = 1

    jitter.func_ret_cdecl(ret_ad, ret)


def shlwapi_PathIsFileSpec(funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(1)
    path_ad, = args
    path = get_str(jitter, path_ad)
    if path.find(':') != -1 and path.find('\\') != -1:
        ret = 0
    else:
        ret = 1

    jitter.func_ret_stdcall(ret_ad, ret)


def shlwapi_PathGetDriveNumber(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(1)
    path_ad, = args
    path = get_str(jitter, path_ad)
    l = ord(path[0].upper()) - ord('A')
    if 0 <= l <= 25:
        ret = l
    else:
        ret = -1

    jitter.func_ret_stdcall(ret_ad, ret)


def shlwapi_PathGetDriveNumberA(jitter):
    shlwapi_PathGetDriveNumber(jitter, whoami(), get_str_ansi)


def shlwapi_PathGetDriveNumberW(jitter):
    shlwapi_PathGetDriveNumber(jitter, whoami(), get_str_unic)


def shlwapi_PathIsFileSpecA(jitter):
    shlwapi_PathIsFileSpec(whoami(), get_str_ansi)


def shlwapi_PathIsFileSpecW(jitter):
    shlwapi_PathIsFileSpec(whoami(), get_str_unic)


def shlwapi_StrToIntA(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    i_str_ad, = args
    i_str = get_str_ansi(jitter, i_str_ad)
    try:
        i = int(i_str)
    except:
        log.warning('WARNING cannot convert int')
        i = 0

    jitter.func_ret_stdcall(ret_ad, i)


def shlwapi_StrToInt64Ex(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(3)
    pstr, flags, pret = args
    i_str = get_str(jitter, pstr)
    if get_str is get_str_unic:
        i_str = i_str

    if flags == 0:
        r = int(i_str)
    elif flags == 1:
        r = int(i_str, 16)
    else:
        raise ValueError('cannot decode int')

    jitter.vm.set_mem(pret, struct.pack('q', r))

    jitter.func_ret_stdcall(ret_ad, i)


def shlwapi_StrToInt64ExA(jitter):
    shlwapi_StrToInt64Ex(jitter, whoami(), get_str_ansi)


def shlwapi_StrToInt64ExW(jitter):
    shlwapi_StrToInt64Ex(jitter, whoami(), get_str_unic)


def user32_IsCharAlpha(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(1)
    c, = args
    try:
        c = chr(c)
    except:
        log.error('bad char %r' % c)
        c = "\x00"
    if c.isalpha(jitter):
        ret = 1
    else:
        ret = 0
    jitter.func_ret_stdcall(ret_ad, ret)


def user32_IsCharAlphaA(jitter):
    user32_IsCharAlpha(jitter, whoami(), get_str_ansi)


def user32_IsCharAlphaW(jitter):
    user32_IsCharAlpha(jitter, whoami(), get_str_unic)


def user32_IsCharAlphaNumericA(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    c, = args
    c = chr(c)
    if c.isalnum(jitter):
        ret = 1
    else:
        ret = 0
    jitter.func_ret_stdcall(ret_ad, ret)


def shlwapi_StrCmpNIA(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    ptr_str1, ptr_str2, nchar = args
    s1 = get_str_ansi(jitter, ptr_str1).lower()
    s2 = get_str_ansi(jitter, ptr_str2).lower()
    s1 = s1[:nchar]
    s2 = s2[:nchar]

    jitter.func_ret_stdcall(ret_ad, cmp(s1, s2))


def advapi32_RegOpenKeyEx(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(5)
    hkey, subkey, reserved, access, phandle = args
    if subkey:
        s_subkey = get_str(jitter, subkey).lower()
    else:
        s_subkey = ""

    ret_hkey = 0
    ret = 2
    if hkey in winobjs.hkey_handles:
        if s_subkey:
            h = hash(s_subkey) & 0xffffffff
            if h in winobjs.hkey_handles:
                ret_hkey = h
                ret = 0
        else:
            log.error('unknown skey')

    jitter.vm.set_mem(phandle, pck32(ret_hkey))

    jitter.func_ret_stdcall(ret_ad, ret)


def advapi32_RegOpenKeyExA(jitter):
    advapi32_RegOpenKeyEx(jitter, whoami(), get_str_ansi)


def advapi32_RegOpenKeyExW(jitter):
    advapi32_RegOpenKeyEx(jitter, whoami(), get_str_unic)


def advapi32_RegSetValue(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(5)
    hkey, psubkey, valuetype, pvalue, length = args
    if psubkey:
        subkey = get_str(jitter, psubkey).lower()
    else:
        subkey = ""

    if pvalue:
        value = jitter.vm.get_mem(pvalue, length)
    else:
        value = None
    jitter.func_ret_stdcall(ret_ad, 0)


def advapi32_RegSetValueA(jitter):
    advapi32_RegSetValue(jitter, whoami(), get_str_ansi)


def advapi32_RegSetValueW(jitter):
    advapi32_RegSetValue(jitter, whoami(), get_str_unic)


def kernel32_GetThreadLocale(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0x40c)


def kernel32_GetLocaleInfo(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(4)
    localeid, lctype, lplcdata, cchdata = args

    buf = None
    ret = 0
    if localeid == 0x40c:
        if lctype == 0x3:
            buf = "ENGLISH"
            buf = buf[:cchdata - 1]
            jitter.vm.set_mem(lplcdata, set_str(buf))
            ret = len(buf)
    else:
        raise ValueError('unimpl localeid')

    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetLocaleInfoA(jitter):
    kernel32_GetLocaleInfo(jitter, whoami(), set_str_ansi)


def kernel32_GetLocaleInfoW(jitter):
    kernel32_GetLocaleInfo(jitter, whoami(), set_str_unic)


def kernel32_TlsAlloc(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    winobjs.tls_index += 1
    jitter.func_ret_stdcall(ret_ad, winobjs.tls_index)


def kernel32_TlsFree(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_TlsSetValue(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    tlsindex, tlsvalue = args
    winobjs.tls_values[tlsindex] = tlsvalue
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_TlsGetValue(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    tlsindex, = args

    if not tlsindex in winobjs.tls_values:
        raise ValueError("unknown tls val", repr(tlsindex))
    jitter.func_ret_stdcall(ret_ad, winobjs.tls_values[tlsindex])


def user32_GetKeyboardType(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    typeflag, = args

    ret = 0
    if typeflag == 0:
        ret = 4
    else:
        raise ValueError('unimpl keyboard type')

    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetStartupInfo(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(1)
    ptr, = args

    s = "\x00" * 0x2c + "\x81\x00\x00\x00" + "\x0a"

    jitter.vm.set_mem(ptr, s)
    jitter.func_ret_stdcall(ret_ad, ptr)


def kernel32_GetStartupInfoA(jitter):
    kernel32_GetStartupInfo(jitter, whoami(), set_str_ansi)


def kernel32_GetStartupInfoW(jitter):
    kernel32_GetStartupInfo(jitter, whoami(), set_str_unic)


def kernel32_GetCurrentThreadId(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0x113377)


def kernel32_InitializeCriticalSection(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    lpcritic, = args
    jitter.func_ret_stdcall(ret_ad, 0)


def user32_GetSystemMetrics(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    nindex, = args

    ret = 0
    if nindex in [0x2a, 0x4a]:
        ret = 0
    else:
        raise ValueError('unimpl index')
    jitter.func_ret_stdcall(ret_ad, ret)


def wsock32_WSAStartup(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    version, pwsadata = args
    jitter.vm.set_mem(pwsadata, "\x01\x01\x02\x02WinSock 2.0\x00")

    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_GetLocalTime(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
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
    jitter.vm.set_mem(lpsystemtime, s)
    jitter.func_ret_stdcall(ret_ad, lpsystemtime)


def kernel32_GetSystemTime(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
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
    jitter.vm.set_mem(lpsystemtime, s)
    jitter.func_ret_stdcall(ret_ad, lpsystemtime)


def kernel32_CreateFileMapping(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(6)
    hfile, lpattr, flprotect, dwmaximumsizehigh, dwmaximumsizelow, lpname = args

    if lpname:
        f = get_str(jitter, lpname)
    else:
        f = None

    if not hfile in winobjs.handle_pool:
        raise ValueError('unknown handle')

    ret = winobjs.handle_pool.add('filemapping', hfile)

    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_CreateFileMappingA(jitter):
    kernel32_CreateFileMapping(jitter, whoami(), get_str_ansi)


def kernel32_CreateFileMappingW(jitter):
    kernel32_CreateFileMapping(jitter, whoami(), get_str_unic)


def kernel32_MapViewOfFile(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
    hfile, flprotect, dwfileoffsethigh, dwfileoffsetlow, length = args

    if not hfile in winobjs.handle_pool:
        raise ValueError('unknown handle')
    hmap = winobjs.handle_pool[hfile]
    if not hmap.info in winobjs.handle_pool:
        raise ValueError('unknown file handle')

    hfile_o = winobjs.handle_pool[hmap.info]
    fd = hfile_o.info
    fd.seek((dwfileoffsethigh << 32) | dwfileoffsetlow)
    if length:
        data = fd.read(length)
    else:
        data = fd.read()
    length = len(data)

    log.debug( 'mapp total: %x' %len(data))
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

    alloc_addr = winobjs.heap.alloc(jitter, len(data))
    jitter.vm.set_mem(alloc_addr, data)

    winobjs.handle_mapped[
        alloc_addr] = hfile_o, dwfileoffsethigh, dwfileoffsetlow, length

    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_UnmapViewOfFile(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    ad, = args

    if not ad in winobjs.handle_mapped:
        raise NotImplementedError("Untested case")
    """
    hfile_o, dwfileoffsethigh, dwfileoffsetlow, length = winobjs.handle_mapped[ad]
    off = (dwfileoffsethigh<<32) | dwfileoffsetlow
    s = jitter.vm.get_mem(ad, length)
    hfile_o.info.seek(off)
    hfile_o.info.write(s)
    hfile_o.info.close()
    """
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GetDriveType(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(1)
    pathname, = args


    p = get_str(jitter, pathname)
    p = p.upper()

    ret = 0
    if p[0] == "C":
        ret = 3

    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetDriveTypeA(jitter):
    kernel32_GetDriveType(jitter, whoami(), get_str_ansi)


def kernel32_GetDriveTypeW(jitter):
    kernel32_GetDriveType(jitter, whoami(), get_str_unic)


def kernel32_GetDiskFreeSpace(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(5)
    (lprootpathname, lpsectorpercluster, lpbytespersector,
     lpnumberoffreeclusters, lptotalnumberofclusters) = args

    if lprootpathname:
        rootpath = get_str(jitter, lprootpathname)
    else:
        rootpath = ""

    jitter.vm.set_mem(lpsectorpercluster, pck32(8))
    jitter.vm.set_mem(lpbytespersector, pck32(0x200))
    jitter.vm.set_mem(lpnumberoffreeclusters, pck32(0x222222))
    jitter.vm.set_mem(lptotalnumberofclusters, pck32(0x333333))
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GetDiskFreeSpaceA(jitter):
    kernel32_GetDiskFreeSpace(jitter, whoami(), get_str_ansi)


def kernel32_GetDiskFreeSpaceW(jitter):
    kernel32_GetDiskFreeSpace(jitter, whoami(), get_str_unic)


def kernel32_VirtualQuery(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
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

    all_mem = jitter.vm.get_all_memory()
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
    jitter.vm.set_mem(lpbuffer, s)

    jitter.func_ret_stdcall(ret_ad, dwl)


def kernel32_GetProcessAffinityMask(jitter):
    ret_ad, args = jitter.func_args_stdcall(3)
    hprocess, procaffmask, systemaffmask = args
    jitter.vm.set_mem(procaffmask, pck32(1))
    jitter.vm.set_mem(systemaffmask, pck32(1))

    jitter.func_ret_stdcall(ret_ad, 1)


def msvcrt_rand(jitter):
    ret_ad, args = jitter.func_args_cdecl(0)
    jitter.func_ret_stdcall(ret_ad, 0x666)


def kernel32_SetFilePointer(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
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
    jitter.func_ret_stdcall(ret_ad, distance)


def kernel32_SetFilePointerEx(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
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
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_SetEndOfFile(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    hwnd, = args
    if hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[hwnd]
        wh.info.seek(0, 2)
    else:
        raise ValueError('unknown filename')
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_FlushFileBuffers(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    hwnd, = args
    if hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown filename')
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_WriteFile(jitter):
    ret_ad, args = jitter.func_args_stdcall(5)
    (hwnd, lpbuffer, nnumberofbytestowrite,
     lpnumberofbyteswrite, lpoverlapped) = args

    data = jitter.vm.get_mem(lpbuffer, nnumberofbytestowrite)

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
        jitter.vm.set_mem(lpnumberofbyteswrite, pck32(len(data)))

    jitter.func_ret_stdcall(ret_ad, 1)


def user32_IsCharUpperA(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    c, = args

    if c & 0x20:
        ret = 0
    else:
        ret = 1
    jitter.func_ret_stdcall(ret_ad, ret)


def user32_IsCharLowerA(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    c, = args

    if c & 0x20:
        ret = 1
    else:
        ret = 0

    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetSystemDefaultLangID(jitter):
    ret_ad, args = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0x409)  # encglish


def msvcrt_malloc(jitter):
    ret_ad, args = jitter.func_args_cdecl(1)
    msize, = args
    addr = winobjs.heap.alloc(jitter, msize)
    jitter.func_ret_cdecl(ret_ad, addr)


def msvcrt_free(jitter):
    ret_ad, args = jitter.func_args_cdecl(1)
    ptr, = args
    jitter.func_ret_cdecl(ret_ad, 0)


def msvcrt_fopen(jitter):
    ret_ad, args = jitter.func_args_cdecl(2)
    fname, rw = args

    fname = get_str_ansi(jitter, fname)
    rw = get_str_ansi(jitter, rw)
    log.debug((fname, rw))
    if rw in ['rb', 'wb+']:
        fname = fname.replace('\\', "/").lower()
        f = os.path.join('file_sb', fname)
        h = open(f, rw)
        eax = winobjs.handle_pool.add(f, h)
        alloc_addr = winobjs.heap.alloc(jitter, 0x20)
        jitter.vm.set_mem(alloc_addr, pck32(0x11112222) + pck32(
            0) + pck32(0) + pck32(0) + pck32(eax))  # pck32(0x11112222)
    else:
        raise NotImplementedError("Untested case")

    jitter.func_ret_cdecl(ret_ad, alloc_addr)


def msvcrt_fseek(jitter):
    ret_ad, args = jitter.func_args_cdecl(3)
    stream, offset, orig = args
    fd = upck32(jitter.vm.get_mem(stream + 0x10, 4))

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    o.info.seek(offset, orig)
    jitter.func_ret_cdecl(ret_ad, 0)


def msvcrt_ftell(jitter):
    ret_ad, args = jitter.func_args_cdecl(1)
    stream, = args
    fd = upck32(jitter.vm.get_mem(stream + 0x10, 4))

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    off = o.info.tell()
    jitter.func_ret_cdecl(ret_ad, off)


def msvcrt_rewind(jitter):
    ret_ad, args = jitter.func_args_cdecl(1)
    stream, = args
    fd = upck32(jitter.vm.get_mem(stream + 0x10, 4))

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    off = o.info.seek(0, 0)
    jitter.func_ret_cdecl(ret_ad, 0)


def msvcrt_fread(jitter):
    ret_ad, args = jitter.func_args_cdecl(4)
    buf, size, nmemb, stream = args
    fd = upck32(jitter.vm.get_mem(stream + 0x10, 4))
    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")

    data = winobjs.handle_pool[fd].info.read(size * nmemb)
    jitter.vm.set_mem(buf, data)
    jitter.func_ret_cdecl(ret_ad, nmemb)


def msvcrt_fclose(jitter):
    ret_ad, args = jitter.func_args_cdecl(1)
    stream, = args
    fd = upck32(jitter.vm.get_mem(stream + 0x10, 4))

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    off = o.info.close()
    jitter.func_ret_cdecl(ret_ad, 0)


def msvcrt_atexit(jitter):
    ret_ad, args = jitter.func_args_cdecl(1)
    func, = args
    jitter.func_ret_cdecl(ret_ad, 0)


def user32_MessageBoxA(jitter):
    ret_ad, args = jitter.func_args_stdcall(4)
    hwnd, lptext, lpcaption, utype = args

    text = get_str_ansi(jitter, lptext)
    caption = get_str_ansi(jitter, lpcaption)

    log.info('Caption: %r Text: %r' %(caption, text))

    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_myGetTempPath(jitter, func):
    ret_ad, args = jitter.func_args_stdcall(2)
    l, buf = args

    l = 'c:\\temp\\'
    jitter.vm.set_mem(buf, func(l + '\x00'))
    jitter.func_ret_stdcall(ret_ad, len(l))


def kernel32_GetTempPathA(jitter):
    kernel32_myGetTempPath(jitter, set_str_ansi)


def kernel32_GetTempPathW(jitter):
    kernel32_myGetTempPath(jitter, set_str_unic)


temp_num = 0


def kernel32_GetTempFileNameA(jitter):
    global temp_num
    ret_ad, args = jitter.func_args_stdcall(4)
    path, ext, unique, buf = args

    temp_num += 1
    if ext:
        ext = get_str_ansi(jitter, ext)
    else:
        ext = 'tmp'
    if path:
        path = get_str_ansi(jitter, path)
    else:
        path = "xxx"
    fname = path + "\\" + "temp%.4d" % temp_num + "." + ext
    jitter.vm.set_mem(buf, fname)

    jitter.func_ret_stdcall(ret_ad, 0)


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


def kernel32_FindFirstFileA(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    pfilepattern, pfindfiledata = args

    filepattern = get_str_ansi(jitter, pfilepattern)
    h = winobjs.find_data.findfirst(filepattern)

    fname = winobjs.find_data.findnext(h)
    fdata = win32_find_data(cfilename=fname)

    jitter.vm.set_mem(pfindfiledata, fdata.toStruct())
    jitter.func_ret_stdcall(ret_ad, h)


def kernel32_FindNextFileA(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    handle, pfindfiledata = args

    fname = winobjs.find_data.findnext(handle)
    if fname is None:
        ret = 0
    else:
        ret = 1
        fdata = win32_find_data(cfilename=fname)
        jitter.vm.set_mem(pfindfiledata, fdata.toStruct())

    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetNativeSystemInfo(jitter):
    ret_ad, args = jitter.func_args_stdcall(1)
    sys_ptr, = args
    sysinfo = systeminfo()
    jitter.vm.set_mem(sys_ptr, sysinfo.pack())
    jitter.func_ret_stdcall(ret_ad, 0)


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


def msvcrt__ultow(jitter):
    ret_ad, args = jitter.func_args_cdecl(3)
    value, p, radix = args

    value &= 0xFFFFFFFF
    if not radix in [10, 16, 20]:
        TODO_TEST
    s = int2base(value, radix)
    jitter.vm.set_mem(p, set_str_unic(s + "\x00"))
    jitter.func_ret_cdecl(ret_ad, p)


def msvcrt_myfopen(jitter, func):
    ret_ad, args = jitter.func_args_cdecl(2)
    pfname, pmode = args


    fname = func(jitter, pfname)
    rw = func(jitter, pmode)
    log.debug(fname)
    log.debug(rw)

    if rw in ['r', 'rb', 'wb+']:
        fname = fname.replace('\\', "/").lower()
        f = os.path.join('file_sb', fname)
        h = open(f, rw)
        eax = winobjs.handle_pool.add(f, h)
        dwsize = 0x20
        alloc_addr = winobjs.heap.alloc(jitter, dwsize)
        pp = pck32(0x11112222)+pck32(0)+pck32(0)+pck32(0)+pck32(eax)#pdw(0x11112222)
        jitter.vm.set_mem(alloc_addr, pp)


    else:
        raise ValueError('unknown access mode %s'%rw)

    jitter.func_ret_cdecl(ret_ad, alloc_addr)

def msvcrt__wfopen(jitter):
    msvcrt_myfopen(jitter, get_str_unic)

def msvcrt_fopen(jitter):
    msvcrt_myfopen(jitter, get_str_ansi)


def msvcrt_strlen(jitter):
    ret_ad, args = jitter.func_args_cdecl(1)
    src, = args

    s = get_str_ansi(jitter, src)
    jitter.func_ret_cdecl(ret_ad, len(s))
