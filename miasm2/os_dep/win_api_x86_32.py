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
import inspect
import os
import stat
import time
import string
import logging
from zlib import crc32

try:
    from Crypto.Hash import MD5, SHA
except ImportError:
    print "cannot find crypto, skipping"

from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
from miasm2.core.utils import pck16, pck32, upck32, hexdump
from miasm2.os_dep.common \
    import heap, set_str_ansi, set_str_unic, get_str_ansi, get_str_unic
from miasm2.os_dep.win_api_x86_32_seh import FS_0_AD

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
    ret_ad, args = jitter.func_args_stdcall(["heap", "flags", "size"])
    alloc_addr = winobjs.heap.alloc(jitter, args.size)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_HeapFree(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["heap", "flags", "pmem"])
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GlobalAlloc(jitter):
    ret_ad, args = jitter.func_args_stdcall(["uflags", "msize"])
    alloc_addr = winobjs.heap.alloc(jitter, args.msize)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_LocalFree(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["lpvoid"])
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_LocalAlloc(jitter):
    ret_ad, args = jitter.func_args_stdcall(["uflags", "msize"])
    alloc_addr = winobjs.heap.alloc(jitter, args.msize)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_GlobalFree(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["addr"])
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_IsDebuggerPresent(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.dbg_present)


def kernel32_CreateToolhelp32Snapshot(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["dwflags", "th32processid"])
    jitter.func_ret_stdcall(ret_ad, winobjs.handle_toolhelpsnapshot)


def kernel32_GetCurrentProcess(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.handle_curprocess)


def kernel32_GetCurrentProcessId(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.dw_pid_cur)


def kernel32_Process32First(jitter):
    ret_ad, args = jitter.func_args_stdcall(["s_handle", "ad_pentry"])

    pentry = struct.pack(
        'IIIIIIIII', *process_list[0][:-1]) + process_list[0][-1]
    jitter.vm.set_mem(args.ad_pentry, pentry)
    winobjs.toolhelpsnapshot_info[args.s_handle] = 0

    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_Process32Next(jitter):
    ret_ad, args = jitter.func_args_stdcall(["s_handle", "ad_pentry"])

    winobjs.toolhelpsnapshot_info[args.s_handle] += 1
    if winobjs.toolhelpsnapshot_info[args.s_handle] >= len(process_list):
        ret = 0
    else:
        ret = 1
        n = winobjs.toolhelpsnapshot_info[args.s_handle]
        pentry = struct.pack(
            'IIIIIIIII', *process_list[n][:-1]) + process_list[n][-1]
        jitter.vm.set_mem(args.ad_pentry, pentry)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetTickCount(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    winobjs.tickcount += 1
    jitter.func_ret_stdcall(ret_ad, winobjs.tickcount)


def kernel32_GetVersion(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.getversion)


def kernel32_GetVersionEx(jitter, set_str=set_str_unic):
    ret_ad, args = jitter.func_args_stdcall(["ptr_struct"])

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
    jitter.vm.set_mem(args.ptr_struct, s)
    jitter.func_ret_stdcall(ret_ad, 1)


kernel32_GetVersionExA = lambda jitter: kernel32_GetVersionEx(jitter,
                                                              set_str_ansi)
kernel32_GetVersionExW = lambda jitter: kernel32_GetVersionEx(jitter,
                                                              set_str_unic)


def kernel32_GetPriorityClass(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hwnd"])
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_SetPriorityClass(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hwnd", "dwpclass"])
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_CloseHandle(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hwnd"])
    jitter.func_ret_stdcall(ret_ad, 1)


def user32_GetForegroundWindow(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.getforegroundwindow)


def user32_FindWindowA(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["pclassname", "pwindowname"])
    jitter.func_ret_stdcall(ret_ad, 0)


def user32_GetTopWindow(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hwnd"])
    jitter.func_ret_stdcall(ret_ad, 0)


def user32_BlockInput(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["blockit"])
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptAcquireContext(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["phprov", "pszcontainer",
                                             "pszprovider", "dwprovtype",
                                             "dwflags"])
    prov = get_str(jitter, args.pszprovider) if args.pszprovider else "NONE"
    log.debug('prov: %r' % prov)
    jitter.vm.set_mem(args.phprov, pck32(winobjs.cryptcontext_hwnd))
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptAcquireContextA(jitter):
    advapi32_CryptAcquireContext(jitter, whoami(), get_str_ansi)


def advapi32_CryptAcquireContextW(jitter):
    advapi32_CryptAcquireContext(jitter, whoami(), get_str_unic)


def advapi32_CryptCreateHash(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hprov", "algid", "hkey",
                                             "dwflags", "phhash"])

    winobjs.cryptcontext_num += 1

    if args.algid == 0x00008003:
        log.debug('algo is MD5')
        jitter.vm.set_mem(
            args.phhash,
            pck32(winobjs.cryptcontext_bnum + winobjs.cryptcontext_num)
        )
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num] = hobj()
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num].h = MD5.new()
    elif args.algid == 0x00008004:
        log.debug('algo is SHA1')
        jitter.vm.set_mem(
            args.phhash,
            pck32(winobjs.cryptcontext_bnum + winobjs.cryptcontext_num)
        )
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num] = hobj()
        winobjs.cryptcontext[
            winobjs.cryptcontext_bnum + winobjs.cryptcontext_num].h = SHA.new()
    else:
        raise ValueError('un impl algo1')
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptHashData(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hhash", "pbdata", "dwdatalen",
                                             "dwflags"])

    if not args.hhash in winobjs.cryptcontext:
        raise ValueError("unknown crypt context")

    data = jitter.vm.get_mem(args.pbdata, args.dwdatalen)
    log.debug('will hash %X' % args.dwdatalen)
    log.debug(repr(data[:10]) + "...")
    winobjs.cryptcontext[args.hhash].h.update(data)
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptGetHashParam(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hhash", "param", "pbdata",
                                             "dwdatalen", "dwflags"])

    if not args.hhash in winobjs.cryptcontext:
        raise ValueError("unknown crypt context")

    if args.param == 2:
        # XXX todo: save h state?
        h = winobjs.cryptcontext[args.hhash].h.digest()
    else:
        raise ValueError('not impl', args.param)
    jitter.vm.set_mem(args.pbdata, h)
    jitter.vm.set_mem(args.dwdatalen, pck32(len(h)))

    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptReleaseContext(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hhash", "flags"])
    jitter.func_ret_stdcall(ret_ad, 0)


def advapi32_CryptDeriveKey(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hprov", "algid", "hbasedata",
                                             "dwflags", "phkey"])

    if args.algid == 0x6801:
        log.debug('using DES')
    else:
        raise ValueError('un impl algo2')
    h = winobjs.cryptcontext[args.hbasedata].h.digest()
    log.debug('hash %r'% h)
    winobjs.cryptcontext[args.hbasedata].h_result = h
    jitter.vm.set_mem(args.phkey, pck32(args.hbasedata))
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptDestroyHash(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hhash"])
    jitter.func_ret_stdcall(ret_ad, 1)


def advapi32_CryptDecrypt(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hkey", "hhash", "final",
                                          "dwflags", "pbdata",
                                          "pdwdatalen"])
    raise ValueError("Not implemented")
    # jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_CreateFile(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["lpfilename", "access",
                                             "dwsharedmode",
                                             "lpsecurityattr",
                                             "dwcreationdisposition",
                                             "dwflagsandattr",
                                             "htemplatefile"])
    fname = get_str(jitter, args.lpfilename)
    log.debug('fname %s' % fname)
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
        if args.access & 0x80000000 or args.access == 1:
            # read
            if args.dwcreationdisposition == 2:
                # create_always
                if os.access(f, os.R_OK):
                    # but file exist
                    pass
                else:
                    raise NotImplementedError("Untested case")  # to test
                    # h = open(f, 'rb+')
            elif args.dwcreationdisposition == 3:
                # open_existing
                if os.access(f, os.R_OK):
                    s = os.stat(f)
                    if stat.S_ISDIR(s.st_mode):
                        ret = winobjs.handle_pool.add(f, 0x1337)
                    else:
                        h = open(f, 'r+b')
                        ret = winobjs.handle_pool.add(f, h)
                else:
                    log.warning("FILE %r DOES NOT EXIST!" % fname)
            elif args.dwcreationdisposition == 1:
                # create new
                if os.access(f, os.R_OK):
                    # file exist
                    # ret = 80
                    winobjs.lastwin32error = 80
                else:
                    open(f, 'w')
                    h = open(f, 'r+b')
                    ret = winobjs.handle_pool.add(f, h)
            elif args.dwcreationdisposition == 4:
                # open_always
                if os.access(f, os.R_OK):
                    s = os.stat(f)
                    if stat.S_ISDIR(s.st_mode):
                        ret = winobjs.handle_pool.add(f, 0x1337)
                    else:
                        h = open(f, 'r+b')
                        ret = winobjs.handle_pool.add(f, h)
                else:
                    raise NotImplementedError("Untested case")
            else:
                raise NotImplementedError("Untested case")
        elif args.access & 0x40000000:
            # write
            if args.dwcreationdisposition == 3:
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
                        h = open(f, 'r+b')
                        ret = winobjs.handle_pool.add(f, h)
                else:
                    raise NotImplementedError("Untested case")  # to test
            elif args.dwcreationdisposition == 5:
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
    ret_ad, args = jitter.func_args_stdcall(["hwnd", "lpbuffer",
                                             "nnumberofbytestoread",
                                             "lpnumberofbytesread",
                                             "lpoverlapped"])
    if args.hwnd == winobjs.module_cur_hwnd:
        pass
    elif args.hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown hwnd!')

    data = None
    if args.hwnd in winobjs.files_hwnd:
        data = winobjs.files_hwnd[
            winobjs.module_cur_hwnd].read(args.nnumberofbytestoread)
    elif args.hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[args.hwnd]
        data = wh.info.read(args.nnumberofbytestoread)
    else:
        raise ValueError('unknown filename')

    if data is not None:
        if (args.lpnumberofbytesread):
            jitter.vm.set_mem(args.lpnumberofbytesread, pck32(len(data)))
        jitter.vm.set_mem(args.lpbuffer, data)

    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GetFileSize(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hwnd", "lpfilesizehight"])

    if args.hwnd == winobjs.module_cur_hwnd:
        ret = len(open(winobjs.module_fname_nux).read())
    elif args.hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[args.hwnd]
        ret = len(open(wh.name).read())
    else:
        raise ValueError('unknown hwnd!')

    if args.lpfilesizehight != 0:
        jitter.vm.set_mem(args.lpfilesizehight, pck32(ret))
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetFileSizeEx(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hwnd", "lpfilesizehight"])

    if args.hwnd == winobjs.module_cur_hwnd:
        l = len(open(winobjs.module_fname_nux).read())
    elif args.hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[args.hwnd]
        l = len(open(wh.name).read())
    else:
        raise ValueError('unknown hwnd!')

    if args.lpfilesizehight == 0:
        raise NotImplementedError("Untested case")
    jitter.vm.set_mem(args.lpfilesizehight, pck32(
        l & 0xffffffff) + pck32((l >> 32) & 0xffffffff))
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_FlushInstructionCache(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hprocess", "lpbasead", "dwsize"])
    jitter.func_ret_stdcall(ret_ad, 0x1337)


def kernel32_VirtualProtect(jitter):
    ret_ad, args = jitter.func_args_stdcall(['lpvoid', 'dwsize',
                                             'flnewprotect',
                                             'lpfloldprotect'])
    # XXX mask hpart
    flnewprotect = args.flnewprotect & 0xFFF
    if not flnewprotect in access_dict:
        raise ValueError('unknown access dw!')
    jitter.vm.set_mem_access(args.lpvoid, access_dict[flnewprotect])

    # XXX todo real old protect
    if args.lpfloldprotect:
        jitter.vm.set_mem(args.lpfloldprotect, pck32(0x40))

    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_VirtualAlloc(jitter):
    ret_ad, args = jitter.func_args_stdcall(['lpvoid', 'dwsize',
                                             'alloc_type', 'flprotect'])

    access_dict = {0x0: 0,
                   0x1: 0,
                   0x2: PAGE_READ,
                   0x4: PAGE_READ | PAGE_WRITE,
                   0x10: PAGE_EXEC,
                   0x20: PAGE_EXEC | PAGE_READ,
                   0x40: PAGE_EXEC | PAGE_READ | PAGE_WRITE,
                   0x100: 0
                       }

    # access_dict_inv = dict([(x[1], x[0]) for x in access_dict.items()])

    if not args.flprotect in access_dict:
        raise ValueError('unknown access dw!')

    if args.lpvoid == 0:
        alloc_addr = winobjs.heap.next_addr(args.dwsize)
        jitter.vm.add_memory_page(
            alloc_addr, access_dict[args.flprotect], "\x00" * args.dwsize)
    else:
        all_mem = jitter.vm.get_all_memory()
        if args.lpvoid in all_mem:
            alloc_addr = args.lpvoid
            jitter.vm.set_mem_access(args.lpvoid, access_dict[args.flprotect])
        else:
            alloc_addr = winobjs.heap.next_addr(args.dwsize)
            # alloc_addr = args.lpvoid
            jitter.vm.add_memory_page(
                alloc_addr, access_dict[args.flprotect], "\x00" * args.dwsize)

    log.debug('Memory addr: %x' %alloc_addr)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_VirtualFree(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["lpvoid", "dwsize", "alloc_type"])
    jitter.func_ret_stdcall(ret_ad, 0)


def user32_GetWindowLongA(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hwnd", "nindex"])
    jitter.func_ret_stdcall(ret_ad, winobjs.windowlong_dw)


def user32_SetWindowLongA(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["hwnd", "nindex", "newlong"])
    jitter.func_ret_stdcall(ret_ad, winobjs.windowlong_dw)


def kernel32_GetModuleFileName(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(["hmodule", "lpfilename", "nsize"])

    if args.hmodule in [0, winobjs.hcurmodule]:
        p = winobjs.module_path[:]
    elif (winobjs.runtime_dll and
        args.hmodule in winobjs.runtime_dll.name2off.values()):
        name_inv = dict([(x[1], x[0])
                        for x in winobjs.runtime_dll.name2off.items()])
        p = name_inv[args.hmodule]
    else:
        log.warning(('Unknown module 0x%x.' + \
                        'Set winobjs.hcurmodule and retry') % args.hmodule)
        p = None

    if p is None:
        l = 0
    elif args.nsize < len(p):
        p = p[:args.nsize]
        l = len(p)
    else:
        l = len(p)

    if p:
        jitter.vm.set_mem(args.lpfilename, set_str(p))

    jitter.func_ret_stdcall(ret_ad, l)


def kernel32_GetModuleFileNameA(jitter):
    kernel32_GetModuleFileName(jitter, whoami(), set_str_ansi)


def kernel32_GetModuleFileNameW(jitter):
    kernel32_GetModuleFileName(jitter, whoami(), set_str_unic)


def kernel32_CreateMutex(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["mutexattr", "initowner",
                                             "lpname"])

    if args.lpname:
        name = get_str(jitter, args.lpname)
        log.debug(name)
    else:
        name = None
    if args.initowner:
        if name in winobjs.mutex:
            raise NotImplementedError("Untested case")
            # ret = 0
        else:
            winobjs.mutex[name] = id(name)
            ret = winobjs.mutex[name]
    else:
        if name in winobjs.mutex:
            raise NotImplementedError("Untested case")
            # ret = 0
        else:
            winobjs.mutex[name] = id(name)
            ret = winobjs.mutex[name]
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_CreateMutexA(jitter):
    kernel32_CreateMutex(jitter, whoami(), get_str_ansi)


def kernel32_CreateMutexW(jitter):
    kernel32_CreateMutex(jitter, whoami(), get_str_unic)


def shell32_SHGetSpecialFolderLocation(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hwndowner", "nfolder", "ppidl"])
    jitter.vm.set_mem(args.ppidl, pck32(args.nfolder))
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_SHGetPathFromIDList(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(["pidl", "ppath"])

    if args.pidl == 7:  # CSIDL_STARTUP:
        s = "c:\\doc\\user\\startmenu\\programs\\startup"
        s = set_str(s)
    else:
        raise ValueError('pidl not implemented', args.pidl)
    jitter.vm.set_mem(args.ppath, s)
    jitter.func_ret_stdcall(ret_ad, 1)


def shell32_SHGetPathFromIDListW(jitter):
    kernel32_SHGetPathFromIDList(jitter, whoami(), set_str_unic)


def shell32_SHGetPathFromIDListA(jitter):
    kernel32_SHGetPathFromIDList(jitter, whoami(), set_str_ansi)


def kernel32_GetLastError(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, winobjs.lastwin32error)


def kernel32_SetLastError(jitter):
    ret_ad, args = jitter.func_args_stdcall(["errcode"])
    # lasterr addr
    # ad = FS_0_AD + 0x34
    # jitter.vm.set_mem(ad, pck32(args.errcode))
    winobjs.lastwin32error = args.errcode
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_RestoreLastError(jitter):
    kernel32_SetLastError(jitter)


def kernel32_LoadLibraryA(jitter):
    ret_ad, args = jitter.func_args_stdcall(["dllname"])

    libname = get_str_ansi(jitter, args.dllname, 0x100)
    log.info(libname)

    ret = winobjs.runtime_dll.lib_get_add_base(libname)
    log.info("ret %x" %ret)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_LoadLibraryExA(jitter):
    ret_ad, args = jitter.func_args_stdcall(["dllname", "hfile", "flags"])

    if args.hfile != 0:
        raise NotImplementedError("Untested case")
    libname = get_str_ansi(jitter, args.dllname, 0x100)
    log.info(libname)

    ret = winobjs.runtime_dll.lib_get_add_base(libname)
    log.info("ret %x" % ret)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetProcAddress(jitter):
    ret_ad, args = jitter.func_args_stdcall(["libbase", "fname"])
    # Ensure high-order WORD is 0
    fname = args.fname & 0xFFFFFFFF
    if fname < 0x10000:
        fname = fname
    else:
        fname = get_str_ansi(jitter, fname, 0x100)
        if not fname:
            fname = None
    log.info(fname)
    if fname is not None:
        ad = winobjs.runtime_dll.lib_get_add_func(args.libbase, fname)
    else:
        ad = 0
    ad = winobjs.runtime_dll.lib_get_add_func(args.libbase, fname)
    jitter.add_breakpoint(ad, jitter.handle_lib)
    jitter.func_ret_stdcall(ret_ad, ad)


def kernel32_LoadLibraryW(jitter):
    ret_ad, args = jitter.func_args_stdcall(["dllname"])

    libname = get_str_unic(jitter, args.dllname, 0x100)
    log.info(libname)

    ret = winobjs.runtime_dll.lib_get_add_base(libname)
    log.info("ret %x", ret)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetModuleHandle(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["dllname"])

    if args.dllname:
        libname = get_str(jitter, args.dllname)
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
    ret_ad, _ = jitter.func_args_stdcall(["lpaddress", "dwsize"])
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
    ret_ad, args = jitter.func_args_stdcall(["sys_ptr"])
    sysinfo = systeminfo()
    jitter.vm.set_mem(args.sys_ptr, sysinfo.pack())
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_IsWow64Process(jitter):
    ret_ad, args = jitter.func_args_stdcall(["process", "bool_ptr"])
    jitter.vm.set_mem(args.bool_ptr, pck32(0))
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GetCommandLineA(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    s = winobjs.module_path + '\x00'
    s = '"%s"' % s
    alloc_addr = winobjs.heap.alloc(jitter, 0x1000)
    jitter.vm.set_mem(alloc_addr, s)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_GetCommandLineW(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    s = winobjs.module_path + '\x00'
    s = set_str_unic('"%s"' % s)
    alloc_addr = winobjs.heap.alloc(jitter, 0x1000)
    jitter.vm.set_mem(alloc_addr, s)
    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def shell32_CommandLineToArgvW(jitter):
    ret_ad, args = jitter.func_args_stdcall(["pcmd", "pnumargs"])
    cmd = get_str_unic(jitter, args.pcmd)
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
    jitter.vm.set_mem(args.pnumargs, pck32(len(tks)))
    jitter.func_ret_stdcall(ret_ad, addr_ret)


def cryptdll_MD5Init(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ad_ctx"])
    index = len(winobjs.cryptdll_md5_h)
    h = MD5.new()
    winobjs.cryptdll_md5_h[index] = h

    jitter.vm.set_mem(args.ad_ctx, pck32(index))
    jitter.func_ret_stdcall(ret_ad, 0)


def cryptdll_MD5Update(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ad_ctx", "ad_input", "inlen"])

    index = jitter.vm.get_mem(args.ad_ctx, 4)
    index = upck32(index)
    if not index in winobjs.cryptdll_md5_h:
        raise ValueError('unknown h context', index)

    data = jitter.vm.get_mem(args.ad_input, args.inlen)
    winobjs.cryptdll_md5_h[index].update(data)
    log.debug(hexdump(data))

    jitter.func_ret_stdcall(ret_ad, 0)


def cryptdll_MD5Final(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ad_ctx"])

    index = jitter.vm.get_mem(args.ad_ctx, 4)
    index = upck32(index)
    if not index in winobjs.cryptdll_md5_h:
        raise ValueError('unknown h context', index)
    h = winobjs.cryptdll_md5_h[index].digest()
    jitter.vm.set_mem(args.ad_ctx + 88, h)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlInitAnsiString(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ad_ctx", "ad_str"])

    s = get_str_ansi(jitter, args.ad_str)
    l = len(s)
    jitter.vm.set_mem(args.ad_ctx,
                      pck16(l) + pck16(l + 1) + pck32(args.ad_str))
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlHashUnicodeString(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ad_ctxu", "case_i", "h_id",
                                             "phout"])

    if args.h_id != 1:
        raise ValueError('unk hash unicode', args.h_id)

    l1, l2, ptra = struct.unpack('HHL', jitter.vm.get_mem(args.ad_ctxu, 8))
    s = jitter.vm.get_mem(ptra, l1)
    s = s[:-1]
    hv = 0

    if args.case_i:
        s = s.lower()
    for c in s:
        hv = ((65599 * hv) + ord(c)) & 0xffffffff
    jitter.vm.set_mem(args.phout, pck32(hv))
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_RtlMoveMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ad_dst", "ad_src", "m_len"])
    data = jitter.vm.get_mem(args.ad_src, args.m_len)
    jitter.vm.set_mem(args.ad_dst, data)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlAnsiCharToUnicodeChar(jitter):
    ret_ad, args = jitter.func_args_stdcall(['ad_ad_ch'])
    ad_ch = upck32(jitter.vm.get_mem(args.ad_ad_ch, 4))
    ch = ord(jitter.vm.get_mem(ad_ch, 1))
    jitter.vm.set_mem(args.ad_ad_ch, pck32(ad_ch + 1))
    jitter.func_ret_stdcall(ret_ad, ch)


def ntdll_RtlFindCharInUnicodeString(jitter):
    ret_ad, args = jitter.func_args_stdcall(["flags", "main_str_ad",
                                             "search_chars_ad", "pos_ad"])

    if args.flags != 0:
        raise ValueError('unk flags')

    ml1, ml2, mptra = struct.unpack('HHL',
                                    jitter.vm.get_mem(args.main_str_ad, 8))
    sl1, sl2, sptra = struct.unpack(
        'HHL', jitter.vm.get_mem(args.search_chars_ad, 8))
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
        jitter.vm.set_mem(args.pos_ad, pck32(0))
    else:
        ret = 0
        jitter.vm.set_mem(args.pos_ad, pck32(pos))

    jitter.func_ret_stdcall(ret_ad, ret)


def ntdll_RtlComputeCrc32(jitter):
    ret_ad, args = jitter.func_args_stdcall(["dwinit", "pdata", "ilen"])
    data = jitter.vm.get_mem(args.pdata, args.ilen)
    crc_r = crc32(data, args.dwinit)
    jitter.func_ret_stdcall(ret_ad, crc_r)


def ntdll_RtlExtendedIntegerMultiply(jitter):
    ret_ad, args = jitter.func_args_stdcall(['multiplicand_low',
                                             'multiplicand_high',
                                             'multiplier'])
    a = (args.multiplicand_high << 32) + args.multiplicand_low
    a = a * args.multiplier
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlLargeIntegerAdd(jitter):
    ret_ad, args = jitter.func_args_stdcall(['a_low', 'a_high',
                                             'b_low', 'b_high'])
    a = (args.a_high << 32) + args.a_low + (args.b_high << 32) + args.b_low
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlLargeIntegerShiftRight(jitter):
    ret_ad, args = jitter.func_args_stdcall(['a_low', 'a_high', 's_count'])
    a = ((args.a_high << 32) + args.a_low) >> args.s_count
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlEnlargedUnsignedMultiply(jitter):
    ret_ad, args = jitter.func_args_stdcall(['a', 'b'])
    a = args.a * args.b
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlLargeIntegerSubtract(jitter):
    ret_ad, args = jitter.func_args_stdcall(['a_low', 'a_high',
                                             'b_low', 'b_high'])
    a = (args.a_high << 32) + args.a_low - (args.b_high << 32) + args.b_low
    jitter.func_ret_stdcall(ret_ad, a & 0xffffffff, (a >> 32) & 0xffffffff)


def ntdll_RtlCompareMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(['ad1', 'ad2', 'm_len'])
    data1 = jitter.vm.get_mem(args.ad1, args.m_len)
    data2 = jitter.vm.get_mem(args.ad2, args.m_len)

    i = 0
    while data1[i] == data2[i]:
        i += 1
        if i >= args.m_len:
            break

    jitter.func_ret_stdcall(ret_ad, i)


def user32_GetMessagePos(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0x00110022)


def kernel32_Sleep(jitter):
    ret_ad, _ = jitter.func_args_stdcall(['t'])
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_ZwUnmapViewOfSection(jitter):
    ret_ad, _ = jitter.func_args_stdcall(['h', 'ad'])
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_IsBadReadPtr(jitter):
    ret_ad, _ = jitter.func_args_stdcall(['lp', 'ucb'])
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_KeInitializeEvent(jitter):
    ret_ad, args = jitter.func_args_stdcall(['my_event', 'my_type',
                                             'my_state'])
    jitter.vm.set_mem(args.my_event, pck32(winobjs.win_event_num))
    winobjs.win_event_num += 1

    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_RtlGetVersion(jitter):
    ret_ad, args = jitter.func_args_stdcall(['ptr_version'])

    s = struct.pack("IIIII",
                    0x114,  # struct size
                    0x5,   # maj vers
                    0x2,  # min vers
                    0x666,  # build nbr
                    0x2,   # platform id
                    ) + set_str_unic("Service pack 4")

    jitter.vm.set_mem(args.ptr_version, s)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_RtlVerifyVersionInfo(jitter):
    ret_ad, args = jitter.func_args_stdcall(['ptr_version'])

    s = jitter.vm.get_mem(args.ptr_version, 0x5 * 4)
    s_size, s_majv, s_minv, s_buildn, s_platform = struct.unpack('IIIII', s)
    raise NotImplementedError("Untested case")
    # jitter.vm.set_mem(args.ptr_version, s)
    # jitter.func_ret_stdcall(ret_ad, 0)


def hal_ExAcquireFastMutex(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0)


def mdl2ad(n):
    return winobjs.nt_mdl_ad + 0x10 * n


def ad2mdl(ad):
    return ((ad - winobjs.nt_mdl_ad) & 0xFFFFFFFFL) / 0x10


def ntoskrnl_IoAllocateMdl(jitter):
    ret_ad, args = jitter.func_args_stdcall(["v_addr", "l", "second_buf",
                                             "chargequota", "pirp"])
    m = mdl(args.v_addr, args.l)
    winobjs.nt_mdl[winobjs.nt_mdl_cur] = m
    jitter.vm.set_mem(mdl2ad(winobjs.nt_mdl_cur), str(m))
    jitter.func_ret_stdcall(ret_ad, mdl2ad(winobjs.nt_mdl_cur))
    winobjs.nt_mdl_cur += 1


def ntoskrnl_MmProbeAndLockPages(jitter):
    ret_ad, args = jitter.func_args_stdcall(["p_mdl", "access_mode", "op"])

    if not ad2mdl(args.p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(args.p_mdl))
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_MmMapLockedPagesSpecifyCache(jitter):
    ret_ad, args = jitter.func_args_stdcall(["p_mdl", "access_mode",
                                             "cache_type", "base_ad",
                                             "bugcheckonfailure",
                                             "priority"])
    if not ad2mdl(args.p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(args.p_mdl))

    jitter.func_ret_stdcall(ret_ad, winobjs.nt_mdl[ad2mdl(args.p_mdl)].ad)


def ntoskrnl_MmProtectMdlSystemAddress(jitter):
    ret_ad, args = jitter.func_args_stdcall(["p_mdl", "prot"])
    if not ad2mdl(args.p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(args.p_mdl))

    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_MmUnlockPages(jitter):
    ret_ad, args = jitter.func_args_stdcall(['p_mdl'])
    if not ad2mdl(args.p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(args.p_mdl))

    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_IoFreeMdl(jitter):
    ret_ad, args = jitter.func_args_stdcall(['p_mdl'])
    if not ad2mdl(args.p_mdl) in winobjs.nt_mdl:
        raise ValueError('unk mdl', hex(args.p_mdl))
    del(winobjs.nt_mdl[ad2mdl(args.p_mdl)])
    jitter.func_ret_stdcall(ret_ad, 0)


def hal_ExReleaseFastMutex(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_RtlQueryRegistryValues(jitter):
    ret_ad, args = jitter.func_args_stdcall(["relativeto", "path",
                                             "querytable",
                                             "context",
                                             "environ"])
    # path = get_str_unic(jitter, args.path)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntoskrnl_ExAllocatePoolWithTagPriority(jitter):
    ret_ad, args = jitter.func_args_stdcall(["pool_type",
                                             "nbr_of_bytes",
                                             "tag", "priority"])
    alloc_addr = winobjs.heap.next_addr(args.nbr_of_bytes)
    jitter.vm.add_memory_page(
        alloc_addr, PAGE_READ | PAGE_WRITE, "\x00" * args.nbr_of_bytes)

    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def my_lstrcmp(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["ptr_str1", "ptr_str2"])
    s1 = get_str(args.ptr_str1)
    s2 = get_str(args.ptr_str2)
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
    ret_ad, args = jitter.func_args_stdcall(["ptr_str1", "ptr_str2"])
    s2 = get_str(jitter, args.ptr_str2)
    jitter.vm.set_mem(args.ptr_str1, set_str(s2))
    jitter.func_ret_stdcall(ret_ad, args.ptr_str1)


def kernel32_lstrcpyW(jitter):
    my_strcpy(jitter, whoami(), get_str_unic,
              lambda x: set_str_unic(x) + "\x00\x00")


def kernel32_lstrcpyA(jitter):
    my_strcpy(jitter, whoami(), get_str_ansi, lambda x: x + "\x00")


def kernel32_lstrcpy(jitter):
    my_strcpy(jitter, whoami(), get_str_ansi, lambda x: x + "\x00")


def kernel32_lstrcpyn(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ptr_str1", "ptr_str2",
                                             "mlen"])
    s2 = get_str_ansi(jitter, args.ptr_str2)
    s2 = s2[:args.mlen]
    jitter.vm.set_mem(args.ptr_str1, s2)
    jitter.func_ret_stdcall(ret_ad, args.ptr_str1)


def my_strlen(jitter, funcname, get_str, mylen):
    ret_ad, args = jitter.func_args_stdcall(["src"])
    src = get_str(jitter, args.src)
    jitter.func_ret_stdcall(ret_ad, mylen(src))


def kernel32_lstrlenA(jitter):
    my_strlen(jitter, whoami(), get_str_ansi, len)


def kernel32_lstrlenW(jitter):
    my_strlen(jitter, whoami(), get_str_unic, len)


def kernel32_lstrlen(jitter):
    my_strlen(jitter, whoami(), get_str_ansi, len)


def my_lstrcat(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(['ptr_str1', 'ptr_str2'])
    s1 = get_str(jitter, args.ptr_str1)
    s2 = get_str(jitter, args.ptr_str2)
    jitter.vm.set_mem(args.ptr_str1, s1 + s2)
    jitter.func_ret_stdcall(ret_ad, args.ptr_str1)


def kernel32_lstrcatA(jitter):
    my_lstrcat(jitter, whoami(), get_str_ansi)


def kernel32_lstrcatW(jitter):
    my_lstrcat(jitter, whoami(), get_str_unic)


def kernel32_GetUserGeoID(jitter):
    ret_ad, args = jitter.func_args_stdcall(["geoclass"])
    if args.geoclass == 14:
        ret = 12345678
    elif args.geoclass == 16:
        ret = 55667788
    else:
        raise ValueError('unknown geolcass')
    jitter.func_ret_stdcall(ret_ad, ret)


def my_GetVolumeInformation(jitter, funcname, get_str, set_str):
    ret_ad, args = jitter.func_args_stdcall(["lprootpathname",
                                             "lpvolumenamebuffer",
                                             "nvolumenamesize",
                                             "lpvolumeserialnumber",
                                             "lpmaximumcomponentlength",
                                             "lpfilesystemflags",
                                             "lpfilesystemnamebuffer",
                                             "nfilesystemnamesize"])
    if args.lprootpathname:
        s = get_str(jitter, args.lprootpathname)

    if args.lpvolumenamebuffer:
        s = "volumename"
        s = s[:args.nvolumenamesize]
        jitter.vm.set_mem(args.lpvolumenamebuffer, set_str(s))

    if args.lpvolumeserialnumber:
        jitter.vm.set_mem(args.lpvolumeserialnumber, pck32(11111111))
    if args.lpmaximumcomponentlength:
        jitter.vm.set_mem(args.lpmaximumcomponentlength, pck32(0xff))
    if args.lpfilesystemflags:
        jitter.vm.set_mem(args.lpfilesystemflags, pck32(22222222))

    if args.lpfilesystemnamebuffer:
        s = "filesystemname"
        s = s[:args.nfilesystemnamesize]
        jitter.vm.set_mem(args.lpfilesystemnamebuffer, set_str(s))

    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GetVolumeInformationA(jitter):
    my_GetVolumeInformation(
        jitter, whoami(), get_str_ansi, lambda x: x + "\x00")


def kernel32_GetVolumeInformationW(jitter):
    my_GetVolumeInformation(jitter, whoami(), get_str_unic, set_str_unic)


def kernel32_MultiByteToWideChar(jitter):
    ret_ad, args = jitter.func_args_stdcall(["codepage", "dwflags",
                                             "lpmultibytestr",
                                             "cbmultibyte",
                                             "lpwidecharstr",
                                             "cchwidechar"])
    src = get_str_ansi(jitter, args.lpmultibytestr) + '\x00'
    l = len(src)

    src = "\x00".join(list(src))
    jitter.vm.set_mem(args.lpwidecharstr, src)
    jitter.func_ret_stdcall(ret_ad, l)


def my_GetEnvironmentVariable(jitter, funcname, get_str, set_str, mylen):
    ret_ad, args = jitter.func_args_stdcall(["lpname", "lpbuffer",
                                             "nsize"])

    s = get_str(jitter, args.lpname)
    if get_str == get_str_unic:
        s = s
    log.debug('variable %r' % s)
    if s in winobjs.env_variables:
        v = set_str(winobjs.env_variables[s])
    else:
        log.warning('WARNING unknown env variable %r' % s)
        v = ""
    jitter.vm.set_mem(args.lpbuffer, v)
    jitter.func_ret_stdcall(ret_ad, mylen(v))


def my_GetSystemDirectory(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(["lpbuffer", "usize"])
    s = "c:\\windows\\system32"
    l = len(s)
    s = set_str(s)
    jitter.vm.set_mem(args.lpbuffer, s)
    jitter.func_ret_stdcall(ret_ad, l)


def kernel32_GetSystemDirectoryA(jitter):
    my_GetSystemDirectory(jitter, whoami(), set_str_ansi)


def kernel32_GetSystemDirectoryW(jitter):
    my_GetSystemDirectory(jitter, whoami(), set_str_unic)


def my_CreateDirectory(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(['lppath', 'secattrib'])
    # path = get_str(jitter, args.lppath)
    jitter.func_ret_stdcall(ret_ad, 0x1337)


def kernel32_CreateDirectoryW(jitter):
    my_CreateDirectory(jitter, whoami(), get_str_unic)


def kernel32_CreateDirectoryA(jitter):
    my_CreateDirectory(jitter, whoami(), get_str_ansi)


def kernel32_GetEnvironmentVariableA(jitter):
    my_GetEnvironmentVariable(jitter, whoami(),
                              get_str_ansi,
                              lambda x: x + "\x00",
                              len)


def kernel32_GetEnvironmentVariableW(jitter):
    my_GetEnvironmentVariable(jitter, whoami(),
                              get_str_unic,
                              lambda x: "\x00".join(list(x + "\x00")),
                              len)


def my_CreateEvent(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["lpeventattributes",
                                             "bmanualreset",
                                             "binitialstate",
                                             "lpname"])
    s = get_str(jitter, args.lpname) if args.lpname else None
    if not s in winobjs.events_pool:
        winobjs.events_pool[s] = (args.bmanualreset, args.binitialstate)
    else:
        log.warning('WARNING: known event')
    jitter.func_ret_stdcall(ret_ad, id(s))


def kernel32_CreateEventA(jitter):
    my_CreateEvent(jitter, whoami(), get_str_ansi)


def kernel32_CreateEventW(jitter):
    my_CreateEvent(jitter, whoami(), get_str_unic)


def kernel32_WaitForSingleObject(jitter):
    ret_ad, args = jitter.func_args_stdcall(['handle', 'dwms'])

    t_start = time.time() * 1000
    found = False
    while True:
        if args.dwms and args.dwms + t_start > time.time() * 1000:
            ret = 0x102
            break
        for key, value in winobjs.events_pool.iteritems():
            if key != args.handle:
                continue
            found = True
            if value[1] == 1:
                ret = 0
                break
        if not found:
            log.warning('unknown handle')
            ret = 0xffffffff
            break
        time.sleep(0.1)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_SetFileAttributesA(jitter):
    ret_ad, args = jitter.func_args_stdcall(["lpfilename",
                                             "dwfileattributes"])
    if args.lpfilename:
        # fname = get_str_ansi(jitter, args.lpfilename)
        ret = 1
    else:
        ret = 0
        jitter.vm.set_mem(FS_0_AD + 0x34, pck32(3))

    jitter.func_ret_stdcall(ret_ad, ret)


def ntdll_RtlMoveMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(["dst", "src", "l"])
    s = jitter.vm.get_mem(args.src, args.l)
    jitter.vm.set_mem(args.dst, s)
    jitter.func_ret_stdcall(ret_ad, 1)


def ntdll_ZwQuerySystemInformation(jitter):
    ret_ad, args = jitter.func_args_stdcall(["systeminformationclass",
                                             "systeminformation",
                                             "systeminformationl",
                                             "returnl"])
    if args.systeminformationclass == 2:
        # SYSTEM_PERFORMANCE_INFORMATION
        o = struct.pack('II', 0x22222222, 0x33333333)
        o += "\x00" * args.systeminformationl
        o = o[:args.systeminformationl]
        jitter.vm.set_mem(args.systeminformation, o)
    else:
        raise ValueError('unknown sysinfo class',
                         args.systeminformationclass)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_ZwProtectVirtualMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(["handle", "lppvoid",
                                             "pdwsize",
                                             "flnewprotect",
                                             "lpfloldprotect"])

    ad = upck32(jitter.vm.get_mem(args.lppvoid, 4))
    # dwsize = upck32(jitter.vm.get_mem(args.pdwsize, 4))
    # XXX mask hpart
    flnewprotect = args.flnewprotect & 0xFFF

    if not flnewprotect in access_dict:
        raise ValueError('unknown access dw!')
    jitter.vm.set_mem_access(ad, access_dict[flnewprotect])

    # XXX todo real old protect
    jitter.vm.set_mem(args.lpfloldprotect, pck32(0x40))

    # dump_memory_page_pool_py()
    jitter.func_ret_stdcall(ret_ad, 1)


def ntdll_ZwAllocateVirtualMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(["handle", "lppvoid",
                                             "zerobits", "pdwsize",
                                             "alloc_type",
                                             "flprotect"])

    # ad = upck32(jitter.vm.get_mem(args.lppvoid, 4))
    dwsize = upck32(jitter.vm.get_mem(args.pdwsize, 4))

    access_dict = {0x0: 0,
                   0x1: 0,
                   0x2: PAGE_READ,
                   0x4: PAGE_READ | PAGE_WRITE,
                   0x10: PAGE_EXEC,
                   0x20: PAGE_EXEC | PAGE_READ,
                   0x40: PAGE_EXEC | PAGE_READ | PAGE_WRITE,
                   0x100: 0
                       }

    # access_dict_inv = dict([(x[1], x[0]) for x in access_dict.items()])

    if not args.flprotect in access_dict:
        raise ValueError('unknown access dw!')

    alloc_addr = winobjs.heap.next_addr(dwsize)
    jitter.vm.add_memory_page(
        alloc_addr, access_dict[args.flprotect], "\x00" * dwsize)
    jitter.vm.set_mem(args.lppvoid, pck32(alloc_addr))

    # dump_memory_page_pool_py()
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_ZwFreeVirtualMemory(jitter):
    ret_ad, args = jitter.func_args_stdcall(["handle", "lppvoid",
                                             "pdwsize", "alloc_type"])
    # ad = upck32(jitter.vm.get_mem(args.lppvoid, 4))
    # dwsize = upck32(jitter.vm.get_mem(args.pdwsize, 4))
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlInitString(jitter):
    ret_ad, args = jitter.func_args_stdcall(["pstring", "source"])
    s = get_str_ansi(jitter, args.source)
    l = len(s) + 1
    o = struct.pack('HHI', l, l, args.source)
    jitter.vm.set_mem(args.pstring, o)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlAnsiStringToUnicodeString(jitter):
    ret_ad, args = jitter.func_args_stdcall(["dst", "src", "alloc_str"])

    l1, l2, p_src = struct.unpack('HHI', jitter.vm.get_mem(args.src, 0x8))
    s = get_str_ansi(jitter, p_src)
    s = ("\x00".join(s + "\x00"))
    l = len(s) + 1
    if args.alloc_str:
        alloc_addr = winobjs.heap.next_addr(l)
        jitter.vm.add_memory_page(
            alloc_addr, PAGE_READ | PAGE_WRITE, "\x00" * l)
    else:
        alloc_addr = p_src
    jitter.vm.set_mem(alloc_addr, s)
    o = struct.pack('HHI', l, l, alloc_addr)
    jitter.vm.set_mem(args.dst, o)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_LdrLoadDll(jitter):
    ret_ad, args = jitter.func_args_stdcall(["path", "flags",
                                             "modname", "modhandle"])

    l1, l2, p_src = struct.unpack('HHI',
                                  jitter.vm.get_mem(args.modname, 0x8))
    s = get_str_unic(jitter, p_src)
    libname = s.lower()

    ad = winobjs.runtime_dll.lib_get_add_base(libname)
    jitter.vm.set_mem(args.modhandle, pck32(ad))

    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_RtlFreeUnicodeString(jitter):
    ret_ad, args = jitter.func_args_stdcall(['src'])
    # l1, l2, p_src = struct.unpack('HHI', jitter.vm.get_mem(args.src, 0x8))
    # s = get_str_unic(jitter, p_src)
    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_LdrGetProcedureAddress(jitter):
    ret_ad, args = jitter.func_args_stdcall(["libbase", "pfname",
                                             "opt", "p_ad"])

    l1, l2, p_src = struct.unpack('HHI', jitter.vm.get_mem(args.pfname, 0x8))
    fname = get_str_ansi(jitter, p_src)

    ad = winobjs.runtime_dll.lib_get_add_func(args.libbase, fname)

    jitter.vm.set_mem(args.p_ad, pck32(ad))

    jitter.func_ret_stdcall(ret_ad, 0)


def ntdll_memset(jitter):
    ret_ad, args = jitter.func_args_stdcall(['addr', 'c', 'size'])
    jitter.vm.set_mem(args.addr, chr(args.c) * args.size)
    jitter.func_ret_stdcall(ret_ad, args.addr)


def msvcrt_memset(jitter):
    ret_ad, args = jitter.func_args_cdecl(['addr', 'c', 'size'])
    jitter.vm.set_mem(args.addr, chr(args.c) * args.size)
    jitter.func_ret_cdecl(ret_ad, args.addr)


def msvcrt_memcpy(jitter):
    ret_ad, args = jitter.func_args_cdecl(['dst', 'src', 'size'])
    s = jitter.vm.get_mem(args.src, args.size)
    jitter.vm.set_mem(args.dst, s)
    jitter.func_ret_cdecl(ret_ad, args.dst)


def msvcrt_memcmp(jitter):
    ret_ad, args = jitter.func_args_cdecl(['ps1', 'ps2', 'size'])
    s1 = jitter.vm.get_mem(args.ps1, args.size)
    s2 = jitter.vm.get_mem(args.ps2, args.size)
    ret = cmp(s1, s2)
    jitter.func_ret_cdecl(ret_ad, ret)


def shlwapi_PathFindExtensionA(jitter):
    ret_ad, args = jitter.func_args_stdcall(['path_ad'])
    path = get_str_ansi(jitter, args.path_ad)
    i = path.rfind('.')
    if i == -1:
        i = args.path_ad + len(path)
    else:
        i = args.path_ad + i
    jitter.func_ret_stdcall(ret_ad, i)


def shlwapi_PathRemoveFileSpecW(jitter):
    ret_ad, args = jitter.func_args_stdcall(['path_ad'])
    path = get_str_unic(jitter, args.path_ad)
    i = path.rfind('\\')
    if i == -1:
        i = 0
    jitter.vm.set_mem(args.path_ad + i * 2, "\x00\x00")
    path = get_str_unic(jitter, args.path_ad)
    jitter.func_ret_stdcall(ret_ad, 1)


def shlwapi_PathIsPrefixW(jitter):
    ret_ad, args = jitter.func_args_stdcall(['ptr_prefix', 'ptr_path'])
    prefix = get_str_unic(jitter, args.ptr_prefix)
    path = get_str_unic(jitter, args.ptr_path)

    if path.startswith(prefix):
        ret = 1
    else:
        ret = 0
    jitter.func_ret_stdcall(ret_ad, ret)


def shlwapi_PathIsDirectoryW(jitter):
    ret_ad, args = jitter.func_args_stdcall(['ptr_path'])
    fname = get_str_unic(jitter, args.ptr_path)

    fname = fname.replace('\\', "/").lower()
    f = os.path.join('file_sb', fname)

    s = os.stat(f)
    ret = 0
    if stat.S_ISDIR(s.st_mode):
        ret = 1

    jitter.func_ret_cdecl(ret_ad, ret)


def shlwapi_PathIsFileSpec(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(['path_ad'])
    path = get_str(jitter, args.path_ad)
    if path.find(':') != -1 and path.find('\\') != -1:
        ret = 0
    else:
        ret = 1

    jitter.func_ret_stdcall(ret_ad, ret)


def shlwapi_PathGetDriveNumber(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(['path_ad'])
    path = get_str(jitter, args.path_ad)
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
    shlwapi_PathIsFileSpec(jitter, whoami(), get_str_ansi)


def shlwapi_PathIsFileSpecW(jitter):
    shlwapi_PathIsFileSpec(jitter, whoami(), get_str_unic)


def shlwapi_StrToIntA(jitter):
    ret_ad, args = jitter.func_args_stdcall(['i_str_ad'])
    i_str = get_str_ansi(jitter, args.i_str_ad)
    try:
        i = int(i_str)
    except:
        log.warning('WARNING cannot convert int')
        i = 0

    jitter.func_ret_stdcall(ret_ad, i)


def shlwapi_StrToInt64Ex(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(['pstr', 'flags', 'pret'])
    i_str = get_str(jitter, args.pstr)
    if get_str is get_str_unic:
        i_str = i_str

    if args.flags == 0:
        r = int(i_str)
    elif args.flags == 1:
        r = int(i_str, 16)
    else:
        raise ValueError('cannot decode int')

    jitter.vm.set_mem(args.pret, struct.pack('q', r))
    jitter.func_ret_stdcall(ret_ad, 1)


def shlwapi_StrToInt64ExA(jitter):
    shlwapi_StrToInt64Ex(jitter, whoami(), get_str_ansi)


def shlwapi_StrToInt64ExW(jitter):
    shlwapi_StrToInt64Ex(jitter, whoami(), get_str_unic)


def user32_IsCharAlpha(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["c"])
    try:
        c = chr(args.c)
    except:
        log.error('bad char %r' % args.c)
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
    ret_ad, args = jitter.func_args_stdcall(["c"])
    c = chr(args.c)
    if c.isalnum(jitter):
        ret = 1
    else:
        ret = 0
    jitter.func_ret_stdcall(ret_ad, ret)


def shlwapi_StrCmpNIA(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ptr_str1", "ptr_str2",
                                             "nchar"])
    s1 = get_str_ansi(jitter, args.ptr_str1).lower()
    s2 = get_str_ansi(jitter, args.ptr_str2).lower()
    s1 = s1[:args.nchar]
    s2 = s2[:args.nchar]
    jitter.func_ret_stdcall(ret_ad, cmp(s1, s2))


def advapi32_RegOpenKeyEx(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["hkey", "subkey",
                                             "reserved", "access",
                                             "phandle"])
    s_subkey = get_str(jitter, args.subkey).lower() if args.subkey else ""

    ret_hkey = 0
    ret = 2
    if args.hkey in winobjs.hkey_handles:
        if s_subkey:
            h = hash(s_subkey) & 0xffffffff
            if h in winobjs.hkey_handles:
                ret_hkey = h
                ret = 0
        else:
            log.error('unknown skey')

    jitter.vm.set_mem(args.phandle, pck32(ret_hkey))

    jitter.func_ret_stdcall(ret_ad, ret)


def advapi32_RegOpenKeyExA(jitter):
    advapi32_RegOpenKeyEx(jitter, whoami(), get_str_ansi)


def advapi32_RegOpenKeyExW(jitter):
    advapi32_RegOpenKeyEx(jitter, whoami(), get_str_unic)


def advapi32_RegSetValue(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["hkey", "psubkey",
                                             "valuetype", "pvalue",
                                             "vlen"])
    # subkey = get_str(jitter, args.psubkey).lower() if args.psubkey else ""
    # value = jitter.vm.get_mem(args.pvalue, args.vlen) if args.pvalue else None
    jitter.func_ret_stdcall(ret_ad, 0)


def advapi32_RegSetValueA(jitter):
    advapi32_RegSetValue(jitter, whoami(), get_str_ansi)


def advapi32_RegSetValueW(jitter):
    advapi32_RegSetValue(jitter, whoami(), get_str_unic)


def kernel32_GetThreadLocale(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0x40c)


def kernel32_GetLocaleInfo(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(["localeid", "lctype",
                                             "lplcdata", "cchdata"])

    buf = None
    ret = 0
    if args.localeid == 0x40c:
        if args.lctype == 0x3:
            buf = "ENGLISH"
            buf = buf[:args.cchdata - 1]
            jitter.vm.set_mem(args.lplcdata, set_str(buf))
            ret = len(buf)
    else:
        raise ValueError('unimpl localeid')

    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetLocaleInfoA(jitter):
    kernel32_GetLocaleInfo(jitter, whoami(), set_str_ansi)


def kernel32_GetLocaleInfoW(jitter):
    kernel32_GetLocaleInfo(jitter, whoami(), set_str_unic)


def kernel32_TlsAlloc(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    winobjs.tls_index += 1
    jitter.func_ret_stdcall(ret_ad, winobjs.tls_index)


def kernel32_TlsFree(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["tlsindex"])
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_TlsSetValue(jitter):
    ret_ad, args = jitter.func_args_stdcall(["tlsindex", "tlsvalue"])
    winobjs.tls_values[args.tlsindex] = args.tlsvalue
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_TlsGetValue(jitter):
    ret_ad, args = jitter.func_args_stdcall(["tlsindex"])
    if not args.tlsindex in winobjs.tls_values:
        raise ValueError("unknown tls val", repr(args.tlsindex))
    jitter.func_ret_stdcall(ret_ad, winobjs.tls_values[args.tlsindex])


def user32_GetKeyboardType(jitter):
    ret_ad, args = jitter.func_args_stdcall(["typeflag"])

    ret = 0
    if args.typeflag == 0:
        ret = 4
    else:
        raise ValueError('unimpl keyboard type')

    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetStartupInfo(jitter, funcname, set_str):
    ret_ad, args = jitter.func_args_stdcall(["ptr"])

    s = "\x00" * 0x2c + "\x81\x00\x00\x00" + "\x0a"

    jitter.vm.set_mem(args.ptr, s)
    jitter.func_ret_stdcall(ret_ad, args.ptr)


def kernel32_GetStartupInfoA(jitter):
    kernel32_GetStartupInfo(jitter, whoami(), set_str_ansi)


def kernel32_GetStartupInfoW(jitter):
    kernel32_GetStartupInfo(jitter, whoami(), set_str_unic)


def kernel32_GetCurrentThreadId(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0x113377)


def kernel32_InitializeCriticalSection(jitter):
    ret_ad, _ = jitter.func_args_stdcall(["lpcritic"])
    jitter.func_ret_stdcall(ret_ad, 0)


def user32_GetSystemMetrics(jitter):
    ret_ad, args = jitter.func_args_stdcall(["nindex"])

    ret = 0
    if args.nindex in [0x2a, 0x4a]:
        ret = 0
    else:
        raise ValueError('unimpl index')
    jitter.func_ret_stdcall(ret_ad, ret)


def wsock32_WSAStartup(jitter):
    ret_ad, args = jitter.func_args_stdcall(["version, pwsadata"])
    jitter.vm.set_mem(args.pwsadata, "\x01\x01\x02\x02WinSock 2.0\x00")
    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_GetLocalTime(jitter):
    ret_ad, args = jitter.func_args_stdcall(["lpsystemtime"])

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
    jitter.vm.set_mem(args.lpsystemtime, s)
    jitter.func_ret_stdcall(ret_ad, args.lpsystemtime)


def kernel32_GetSystemTime(jitter):
    ret_ad, args = jitter.func_args_stdcall(["lpsystemtime"])

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
    jitter.vm.set_mem(args.lpsystemtime, s)
    jitter.func_ret_stdcall(ret_ad, args.lpsystemtime)


def kernel32_CreateFileMapping(jitter, funcname, get_str):
    ret_ad, args = jitter.func_args_stdcall(["hfile", "lpattr", "flprotect",
                                             "dwmaximumsizehigh",
                                             "dwmaximumsizelow", "lpname"])
    # f = get_str(jitter, args.lpname) if args.lpname else None

    if not args.hfile in winobjs.handle_pool:
        raise ValueError('unknown handle')

    ret = winobjs.handle_pool.add('filemapping', args.hfile)
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_CreateFileMappingA(jitter):
    kernel32_CreateFileMapping(jitter, whoami(), get_str_ansi)


def kernel32_CreateFileMappingW(jitter):
    kernel32_CreateFileMapping(jitter, whoami(), get_str_unic)


def kernel32_MapViewOfFile(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hfile", "flprotect",
                                             "dwfileoffsethigh",
                                             "dwfileoffsetlow",
                                             "length"])

    if not args.hfile in winobjs.handle_pool:
        raise ValueError('unknown handle')
    hmap = winobjs.handle_pool[args.hfile]
    if not hmap.info in winobjs.handle_pool:
        raise ValueError('unknown file handle')

    hfile_o = winobjs.handle_pool[hmap.info]
    fd = hfile_o.info
    fd.seek((args.dwfileoffsethigh << 32) | args.dwfileoffsetlow)
    data = fd.read(args.length) if args.length else args.read()
    length = len(data)

    log.debug('mapp total: %x' %len(data))
    access_dict = {0x0: 0,
                   0x1: 0,
                   0x2: PAGE_READ,
                   0x4: PAGE_READ | PAGE_WRITE,
                   0x10: PAGE_EXEC,
                   0x20: PAGE_EXEC | PAGE_READ,
                   0x40: PAGE_EXEC | PAGE_READ | PAGE_WRITE,
                   0x100: 0
                       }
    # access_dict_inv = dict([(x[1], x[0]) for x in access_dict.items()])

    if not args.flprotect in access_dict:
        raise ValueError('unknown access dw!')

    alloc_addr = winobjs.heap.alloc(jitter, len(data))
    jitter.vm.set_mem(alloc_addr, data)

    winobjs.handle_mapped[alloc_addr] = (hfile_o, args.dwfileoffsethigh,
                                         args.dwfileoffsetlow, length)

    jitter.func_ret_stdcall(ret_ad, alloc_addr)


def kernel32_UnmapViewOfFile(jitter):
    ret_ad, args = jitter.func_args_stdcall(['ad'])

    if not args.ad in winobjs.handle_mapped:
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
    ret_ad, args = jitter.func_args_stdcall(['pathname'])

    p = get_str(jitter, args.pathname)
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
    ret_ad, args = jitter.func_args_stdcall(["lprootpathname",
                                             "lpsectorpercluster",
                                             "lpbytespersector",
                                             "lpnumberoffreeclusters",
                                             "lptotalnumberofclusters"])
    # rootpath = (get_str(jitter, args.lprootpathname)
    #             if args.lprootpathname else "")
    jitter.vm.set_mem(args.lpsectorpercluster, pck32(8))
    jitter.vm.set_mem(args.lpbytespersector, pck32(0x200))
    jitter.vm.set_mem(args.lpnumberoffreeclusters, pck32(0x222222))
    jitter.vm.set_mem(args.lptotalnumberofclusters, pck32(0x333333))
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_GetDiskFreeSpaceA(jitter):
    kernel32_GetDiskFreeSpace(jitter, whoami(), get_str_ansi)


def kernel32_GetDiskFreeSpaceW(jitter):
    kernel32_GetDiskFreeSpace(jitter, whoami(), get_str_unic)


def kernel32_VirtualQuery(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ad", "lpbuffer", "dwl"])

    access_dict = {0x0: 0,
                   0x1: 0,
                   0x2: PAGE_READ,
                   0x4: PAGE_READ | PAGE_WRITE,
                   0x10: PAGE_EXEC,
                   0x20: PAGE_EXEC | PAGE_READ,
                   0x40: PAGE_EXEC | PAGE_READ | PAGE_WRITE,
                   0x100: 0
               }
    access_dict_inv = dict([(x[1], x[0]) for x in access_dict.iteritems()])

    all_mem = jitter.vm.get_all_memory()
    found = None
    for basead, m in all_mem.iteritems():
        if basead <= args.ad < basead + m['size']:
            found = args.ad, m
            break
    if not found:
        raise ValueError('cannot find mem', hex(args.ad))

    if args.dwl != 0x1c:
        raise ValueError('strange mem len', hex(args.dwl))
    s = struct.pack('IIIIIII',
                    args.ad,
                    basead,
                    access_dict_inv[m['access']],
                    m['size'],
                    0x1000,
                    access_dict_inv[m['access']],
                    0x01000000)
    jitter.vm.set_mem(args.lpbuffer, s)
    jitter.func_ret_stdcall(ret_ad, args.dwl)


def kernel32_GetProcessAffinityMask(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hprocess",
                                             "procaffmask",
                                             "systemaffmask"])
    jitter.vm.set_mem(args.procaffmask, pck32(1))
    jitter.vm.set_mem(args.systemaffmask, pck32(1))
    jitter.func_ret_stdcall(ret_ad, 1)


def msvcrt_rand(jitter):
    ret_ad, _ = jitter.func_args_cdecl(0)
    jitter.func_ret_stdcall(ret_ad, 0x666)


def kernel32_SetFilePointer(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hwnd", "distance",
                                             "p_distance_high",
                                             "movemethod"])

    if args.hwnd == winobjs.module_cur_hwnd:
        pass
    elif args.hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown hwnd!')

    # data = None
    if args.hwnd in winobjs.files_hwnd:
        winobjs.files_hwnd[winobjs.module_cur_hwnd].seek(args.distance)
    elif args.hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[args.hwnd]
        # data = wh.info.seek(args.distance)
    else:
        raise ValueError('unknown filename')
    jitter.func_ret_stdcall(ret_ad, args.distance)


def kernel32_SetFilePointerEx(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hwnd", "distance_l",
                                             "distance_h",
                                             "pnewfileptr",
                                             "movemethod"])
    distance = args.distance_l | (args.distance_h << 32)
    if distance:
        raise ValueError('Not implemented')
    if args.pnewfileptr:
        raise ValueError('Not implemented')
    if args.hwnd == winobjs.module_cur_hwnd:
        pass
    elif args.hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown hwnd!')

    # data = None
    if args.hwnd in winobjs.files_hwnd:
        winobjs.files_hwnd[winobjs.module_cur_hwnd].seek(distance)
    elif args.hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[args.hwnd]
        # data = wh.info.seek(distance)
    else:
        raise ValueError('unknown filename')
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_SetEndOfFile(jitter):
    ret_ad, args = jitter.func_args_stdcall(['hwnd'])
    if args.hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[args.hwnd]
        wh.info.seek(0, 2)
    else:
        raise ValueError('unknown filename')
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_FlushFileBuffers(jitter):
    ret_ad, args = jitter.func_args_stdcall(['hwnd'])
    if args.hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown filename')
    jitter.func_ret_stdcall(ret_ad, 1)


def kernel32_WriteFile(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hwnd", "lpbuffer",
                                             "nnumberofbytestowrite",
                                             "lpnumberofbyteswrite",
                                             "lpoverlapped"])
    data = jitter.vm.get_mem(args.lpbuffer, args.nnumberofbytestowrite)

    if args.hwnd == winobjs.module_cur_hwnd:
        pass
    elif args.hwnd in winobjs.handle_pool:
        pass
    else:
        raise ValueError('unknown hwnd!')

    if args.hwnd in winobjs.files_hwnd:
        winobjs.files_hwnd[winobjs.module_cur_hwnd].write(data)
    elif args.hwnd in winobjs.handle_pool:
        wh = winobjs.handle_pool[args.hwnd]
        wh.info.write(data)
    else:
        raise ValueError('unknown filename')

    if (args.lpnumberofbyteswrite):
        jitter.vm.set_mem(args.lpnumberofbyteswrite, pck32(len(data)))

    jitter.func_ret_stdcall(ret_ad, 1)


def user32_IsCharUpperA(jitter):
    ret_ad, args = jitter.func_args_stdcall(["c"])
    ret = 0 if args.c & 0x20 else 1
    jitter.func_ret_stdcall(ret_ad, ret)


def user32_IsCharLowerA(jitter):
    ret_ad, args = jitter.func_args_stdcall(["c"])
    ret = 1 if args.c & 0x20 else 0
    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetSystemDefaultLangID(jitter):
    ret_ad, _ = jitter.func_args_stdcall(0)
    jitter.func_ret_stdcall(ret_ad, 0x409)  # encglish


def msvcrt_malloc(jitter):
    ret_ad, args = jitter.func_args_cdecl(["msize"])
    addr = winobjs.heap.alloc(jitter, args.msize)
    jitter.func_ret_cdecl(ret_ad, addr)


def msvcrt_free(jitter):
    ret_ad, _ = jitter.func_args_cdecl(["ptr"])
    jitter.func_ret_cdecl(ret_ad, 0)


def msvcrt_fseek(jitter):
    ret_ad, args = jitter.func_args_cdecl(['stream', 'offset', 'orig'])
    fd = upck32(jitter.vm.get_mem(args.stream + 0x10, 4))

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    o.info.seek(args.offset, args.orig)
    jitter.func_ret_cdecl(ret_ad, 0)


def msvcrt_ftell(jitter):
    ret_ad, args = jitter.func_args_cdecl(["stream"])
    fd = upck32(jitter.vm.get_mem(args.stream + 0x10, 4))

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    off = o.info.tell()
    jitter.func_ret_cdecl(ret_ad, off)


def msvcrt_rewind(jitter):
    ret_ad, args = jitter.func_args_cdecl(["stream"])
    fd = upck32(jitter.vm.get_mem(args.stream + 0x10, 4))
    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    # off = o.info.seek(0, 0)
    jitter.func_ret_cdecl(ret_ad, 0)


def msvcrt_fread(jitter):
    ret_ad, args = jitter.func_args_cdecl(["buf", "size", "nmemb", "stream"])
    fd = upck32(jitter.vm.get_mem(args.stream + 0x10, 4))
    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")

    data = winobjs.handle_pool[fd].info.read(args.size * args.nmemb)
    jitter.vm.set_mem(args.buf, data)
    jitter.func_ret_cdecl(ret_ad, args.nmemb)


def msvcrt_fclose(jitter):
    ret_ad, args = jitter.func_args_cdecl(['stream'])
    fd = upck32(jitter.vm.get_mem(args.stream + 0x10, 4))

    if not fd in winobjs.handle_pool:
        raise NotImplementedError("Untested case")
    o = winobjs.handle_pool[fd]
    # off = o.info.close()
    jitter.func_ret_cdecl(ret_ad, 0)


def msvcrt_atexit(jitter):
    ret_ad, _ = jitter.func_args_cdecl(["func"])
    jitter.func_ret_cdecl(ret_ad, 0)


def user32_MessageBoxA(jitter):
    ret_ad, args = jitter.func_args_stdcall(["hwnd", "lptext",
                                             "lpcaption", "utype"])

    text = get_str_ansi(jitter, args.lptext)
    caption = get_str_ansi(jitter, args.lpcaption)

    log.info('Caption: %r Text: %r' % (caption, text))

    jitter.func_ret_stdcall(ret_ad, 0)


def kernel32_myGetTempPath(jitter, func):
    ret_ad, args = jitter.func_args_stdcall(["l", "buf"])
    l = 'c:\\temp\\'
    jitter.vm.set_mem(args.buf, func(l + '\x00'))
    jitter.func_ret_stdcall(ret_ad, len(l))


def kernel32_GetTempPathA(jitter):
    kernel32_myGetTempPath(jitter, set_str_ansi)


def kernel32_GetTempPathW(jitter):
    kernel32_myGetTempPath(jitter, set_str_unic)


temp_num = 0


def kernel32_GetTempFileNameA(jitter):
    global temp_num
    ret_ad, args = jitter.func_args_stdcall(["path", "ext", "unique", "buf"])

    temp_num += 1
    ext = get_str_ansi(jitter, args.ext) if args.ext else 'tmp'
    path = get_str_ansi(jitter, args.path) if args.path else "xxx"
    fname = path + "\\" + "temp%.4d" % temp_num + "." + ext
    jitter.vm.set_mem(args.buf, fname)

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
        fname = self.cfilename + '\x00' * MAX_PATH
        fname = fname[:MAX_PATH]
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
    ret_ad, args = jitter.func_args_stdcall(["pfilepattern", "pfindfiledata"])

    filepattern = get_str_ansi(jitter, args.pfilepattern)
    h = winobjs.find_data.findfirst(filepattern)

    fname = winobjs.find_data.findnext(h)
    fdata = win32_find_data(cfilename=fname)

    jitter.vm.set_mem(args.pfindfiledata, fdata.toStruct())
    jitter.func_ret_stdcall(ret_ad, h)


def kernel32_FindNextFileA(jitter):
    ret_ad, args = jitter.func_args_stdcall(["handle", "pfindfiledata"])

    fname = winobjs.find_data.findnext(args.handle)
    if fname is None:
        ret = 0
    else:
        ret = 1
        fdata = win32_find_data(cfilename=fname)
        jitter.vm.set_mem(args.pfindfiledata, fdata.toStruct())

    jitter.func_ret_stdcall(ret_ad, ret)


def kernel32_GetNativeSystemInfo(jitter):
    ret_ad, args = jitter.func_args_stdcall(["sys_ptr"])
    sysinfo = systeminfo()
    jitter.vm.set_mem(args.sys_ptr, sysinfo.pack())
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
    ret_ad, args = jitter.func_args_cdecl(["value", "p", "radix"])

    value = args.value & 0xFFFFFFFF
    if not args.radix in [10, 16, 20]:
        raise ValueError("Not tested")
    s = int2base(value, args.radix)
    jitter.vm.set_mem(args.p, set_str_unic(s + "\x00"))
    jitter.func_ret_cdecl(ret_ad, args.p)


def msvcrt_myfopen(jitter, func):
    ret_ad, args = jitter.func_args_cdecl(["pfname", "pmode"])

    fname = func(jitter, args.pfname)
    rw = func(jitter, args.pmode)
    log.debug(fname)
    log.debug(rw)

    if rw in ['r', 'rb', 'wb+']:
        fname = fname.replace('\\', "/").lower()
        f = os.path.join('file_sb', fname)
        h = open(f, rw)
        eax = winobjs.handle_pool.add(f, h)
        dwsize = 0x20
        alloc_addr = winobjs.heap.alloc(jitter, dwsize)
        pp = pck32(0x11112222) + pck32(0) + pck32(0) + pck32(0) + pck32(eax)
        #pdw(0x11112222)
        jitter.vm.set_mem(alloc_addr, pp)


    else:
        raise ValueError('unknown access mode %s'%rw)

    jitter.func_ret_cdecl(ret_ad, alloc_addr)

def msvcrt__wfopen(jitter):
    msvcrt_myfopen(jitter, get_str_unic)

def msvcrt_fopen(jitter):
    msvcrt_myfopen(jitter, get_str_ansi)


def msvcrt_strlen(jitter):
    ret_ad, args = jitter.func_args_cdecl(["src"])

    s = get_str_ansi(jitter, args.src)
    jitter.func_ret_cdecl(ret_ad, len(s))
