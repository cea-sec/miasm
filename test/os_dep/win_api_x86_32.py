#! /usr/bin/env python2
#-*- coding:utf-8 -*-

from builtins import range
import unittest
import logging
from miasm.analysis.machine import Machine
import miasm.os_dep.win_api_x86_32 as winapi
from miasm.os_dep.win_api_x86_32 import get_win_str_a, get_win_str_w
from miasm.core.utils import pck32
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.locationdb import LocationDB

machine = Machine("x86_32")

loc_db = LocationDB()
jit = machine.jitter(loc_db)
jit.init_stack()

heap = winapi.winobjs.heap

class TestWinAPI(unittest.TestCase):

    def test_DebuggingFunctions(self):

        # BOOL WINAPI IsDebuggerPresent(void);
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_IsDebuggerPresent(jit)
        vBool = jit.cpu.EAX
        self.assertFalse(vBool)

    def test_msvcrt_sprintf(self):
        def alloc_str(s):
            s += b"\x00"
            ptr = heap.alloc(jit, len(s))
            jit.vm.set_mem(ptr, s)
            return ptr
        fmt  = alloc_str(b"'%s' %d")
        str_ = alloc_str(b"coucou")
        buf = heap.alloc(jit,1024)

        jit.push_uint32_t(1111)
        jit.push_uint32_t(str_)
        jit.push_uint32_t(fmt)
        jit.push_uint32_t(buf)
        jit.push_uint32_t(0) # ret_ad
        winapi.msvcrt_sprintf(jit)
        ret = get_win_str_a(jit, buf)
        self.assertEqual(ret, "'coucou' 1111")


    def test_msvcrt_swprintf(self):
        def alloc_str(s):
            s = s.encode("utf-16le")
            s += b"\x00\x00"
            ptr = heap.alloc(jit, len(s))
            jit.vm.set_mem(ptr, s)
            return ptr
        fmt  = alloc_str("'%s' %d")
        str_ = alloc_str("coucou")
        buf = heap.alloc(jit,1024)

        jit.push_uint32_t(1111)
        jit.push_uint32_t(str_)
        jit.push_uint32_t(fmt)
        jit.push_uint32_t(buf)
        jit.push_uint32_t(0) # ret_ad
        winapi.msvcrt_swprintf(jit)
        ret = get_win_str_w(jit, buf)
        self.assertEqual(ret, u"'coucou' 1111")


    def test_msvcrt_realloc(self):
        jit.push_uint32_t(10)
        jit.push_uint32_t(0) # ret_ad
        winapi.msvcrt_malloc(jit)
        ptr = jit.cpu.EAX

        jit.push_uint32_t(20)
        jit.push_uint32_t(ptr)
        jit.push_uint32_t(0) # ret_ad
        winapi.msvcrt_realloc(jit)
        ptr2 = jit.cpu.EAX

        self.assertNotEqual(ptr, ptr2)
        self.assertEqual(heap.get_size(jit.vm,ptr2), 20)

    def test_GetCurrentDirectory(self):

        # DWORD WINAPI GetCurrentDirectory(size, buf)

        # Test with a buffer long enough
        addr = 0x80000
        size = len(winapi.winobjs.cur_dir)+1
        jit.vm.add_memory_page(addr, PAGE_READ | PAGE_WRITE, b"\x00" * (size), "")
        jit.push_uint32_t(addr)   # buf
        jit.push_uint32_t(size)   # size
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_GetCurrentDirectoryA(jit)
        dir_ = get_win_str_a(jit, addr)
        size_ret = jit.cpu.EAX
        self.assertEqual(len(dir_), size_ret)

        # Test with a buffer too small
        jit.vm.set_mem(addr, b"\xFF"*size)
        jit.push_uint32_t(addr)   # buf
        jit.push_uint32_t(5)      # size
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_GetCurrentDirectoryA(jit)
        size_ret = jit.cpu.EAX
        self.assertEqual(len(dir_)+1, size_ret)
        dir_short = get_win_str_a(jit, addr)
        self.assertEqual(dir_short, dir_[:4])

    def test_MemoryManagementFunctions(self):

        # HGLOBAL WINAPI GlobalAlloc(_In_ UINT uFlags, _In_ SIZE_T dwBytes);
        jit.push_uint32_t(10)     # dwBytes
        jit.push_uint32_t(0)      # uFlags
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_GlobalAlloc(jit)
        hMem = jit.cpu.EAX
        self.assertTrue(hMem)

        # HGLOBAL WINAPI GlobalFree(_In_ HGLOBAL hMem);
        jit.push_uint32_t(hMem)   # hMem
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_GlobalFree(jit)
        hMem = jit.cpu.EAX
        self.assertFalse(hMem)

        # LPVOID WINAPI HeapAlloc(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes);
        jit.push_uint32_t(10)     # dwBytes
        jit.push_uint32_t(0)      # dwFlags
        jit.push_uint32_t(0)      # hHeap
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_HeapAlloc(jit)
        lpMem = jit.cpu.EAX
        self.assertTrue(lpMem)

        # BOOL WINAPI HeapFree(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ LPVOID lpMem);
        jit.push_uint32_t(lpMem)  # lpMem
        jit.push_uint32_t(0)      # dwFlags
        jit.push_uint32_t(0)      # hHeap
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_HeapFree(jit)
        vBool = jit.cpu.EAX
        self.assertTrue(vBool)

        # HLOCAL WINAPI LocalAlloc(_In_ UINT uFlags, _In_ SIZE_T uBytes);
        jit.push_uint32_t(10)     # uBytes
        jit.push_uint32_t(0)      # uFlags
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_LocalAlloc(jit)
        hMem = jit.cpu.EAX
        self.assertTrue(hMem)

        # HLOCAL WINAPI LocalFree(_In_ HLOCAL hMem);
        jit.push_uint32_t(hMem)   # hMem
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_LocalFree(jit)
        hMem = jit.cpu.EAX
        self.assertFalse(hMem)

    def test_ProcessAndThreadFunctions(self):

        # HANDLE WINAPI GetCurrentProcess(void);
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_GetCurrentProcess(jit)
        hProc = jit.cpu.EAX
        self.assertTrue(hProc)

        # DWORD WINAPI GetCurrentProcessId(void);
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_GetCurrentProcessId(jit)
        dwProc = jit.cpu.EAX
        self.assertTrue(dwProc)

    def test_SystemInformationFunctions(self):

        # DWORD WINAPI GetVersion(void);
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_GetVersion(jit)
        dwVer = jit.cpu.EAX
        self.assertTrue(dwVer)

        # BOOL WINAPI GetVersionEx(_Inout_ LPOSVERSIONINFO lpVersionInfo);
        jit.vm.set_mem(jit.stack_base, pck32(0x9c))
        jit.push_uint32_t(jit.stack_base)      # lpVersionInfo
        jit.push_uint32_t(0)                   # @return
        winapi.kernel32_GetVersionExA(jit)
        vBool = jit.cpu.EAX
        self.assertTrue(vBool)

    def test_TimeFunctions(self):

        # DWORD WINAPI GetTickCount(void);
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_GetTickCount(jit)
        dwTime = jit.cpu.EAX
        self.assertTrue(dwTime)

    def test_ToolHelpFunctions(self):

        # HANDLE WINAPI CreateToolhelp32Snapshot(_In_ DWORD dwFlags, _In_ DWORD th32ProcessID);
        jit.push_uint32_t(0)      # th32ProcessID
        jit.push_uint32_t(0)      # dwFlags
        jit.push_uint32_t(0)      # @return
        winapi.kernel32_CreateToolhelp32Snapshot(jit)
        hSnap = jit.cpu.EAX
        self.assertTrue(hSnap)

        # BOOL WINAPI Process32First(_In_ HANDLE hSnapshot, _Inout_ LPPROCESSENTRY32 lppe);
        jit.push_uint32_t(jit.stack_base)      # lppe
        jit.push_uint32_t(hSnap)               # hSnapshot
        jit.push_uint32_t(0)                   # @return
        winapi.kernel32_Process32First(jit)
        vBool = jit.cpu.EAX
        self.assertTrue(vBool)

        # BOOL WINAPI Process32Next(_In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe);
        for i in range(3, -1, -1):
            jit.push_uint32_t(jit.stack_base)      # lppe
            jit.push_uint32_t(hSnap)               # hSnapshot
            jit.push_uint32_t(0)                   # @return
            winapi.kernel32_Process32Next(jit)
            vBool = jit.cpu.EAX
            if  i: self.assertTrue(vBool)
            else:  self.assertFalse(vBool)

    def test_VirtualXXFunctions(self):
        def call_vprotect(jitter, addr, size, protect):
            jitter.push_uint32_t(0x0)
            jitter.push_uint32_t(protect)
            jitter.push_uint32_t(size)
            jitter.push_uint32_t(addr)
            jitter.push_uint32_t(0)
            winapi.kernel32_VirtualProtect(jitter)

        jit.push_uint32_t(0x2)
        jit.push_uint32_t(0x2)
        jit.push_uint32_t(0x4000)
        jit.push_uint32_t(0x1000)
        jit.push_uint32_t(0)
        winapi.kernel32_VirtualAlloc(jit)
        alloc_addr = jit.cpu.EAX

        self.assertEqual(jit.vm.get_all_memory()[alloc_addr]["size"], 0x4000)
        self.assertEqual(jit.vm.get_all_memory()[alloc_addr]["access"],
                         winapi.ACCESS_DICT[0x2])

        # Full area
        call_vprotect(jit, alloc_addr, 0x4000, 0x1)
        self.assertEqual(jit.vm.get_all_memory()[alloc_addr]["access"],
                         winapi.ACCESS_DICT[0x1])
        # Splits area [0--1000] [1000 -- 3000] [3000 -- 4000]
        call_vprotect(jit, alloc_addr+0x1000, 0x2000, 0x40)
        print(jit.vm)
        for (addr, size, access) in [
                (alloc_addr, 0x1000, 0x1),
                (alloc_addr + 0x1000, 0x2000, 0x40),
                (alloc_addr + 0x3000, 0x1000, 0x1)
        ]:
            self.assertEqual(jit.vm.get_all_memory()[addr]["size"], size)
            self.assertEqual(jit.vm.get_all_memory()[addr]["access"],
                             winapi.ACCESS_DICT[access])
        # Protect over split areas
        call_vprotect(jit, alloc_addr, 0x4000, 0x4)
        for (addr, size) in [
                (alloc_addr, 0x1000),
                (alloc_addr + 0x1000, 0x2000),
                (alloc_addr + 0x3000, 0x1000)
        ]:
            self.assertEqual(jit.vm.get_all_memory()[addr]["size"], size)
            self.assertEqual(jit.vm.get_all_memory()[addr]["access"],
                             winapi.ACCESS_DICT[0x4])

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestWinAPI)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
