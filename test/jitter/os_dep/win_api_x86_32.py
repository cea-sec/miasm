#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest
import logging
from miasm2.analysis.machine import Machine
import miasm2.jitter.os_dep.win_api_x86_32 as winapi

machine = Machine("x86_32")

jit = machine.jitter()
jit.init_stack()


class TestWinAPI(unittest.TestCase):

    def test_DebuggingFunctions(self):

        # BOOL WINAPI IsDebuggerPresent(void);
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_IsDebuggerPresent(jit)
        vBool = jit.cpu.EAX
        self.assertFalse(vBool)

    def test_MemoryManagementFunctions(self):

        # HGLOBAL WINAPI GlobalAlloc(_In_ UINT uFlags, _In_ SIZE_T dwBytes);
        jit.vm_push_uint32_t(10)     # dwBytes
        jit.vm_push_uint32_t(0)      # uFlags
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_GlobalAlloc(jit)
        hMem = jit.cpu.EAX
        self.assertTrue(hMem)

        # HGLOBAL WINAPI GlobalFree(_In_ HGLOBAL hMem);
        jit.vm_push_uint32_t(hMem)   # hMem
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_GlobalFree(jit)
        hMem = jit.cpu.EAX
        self.assertFalse(hMem)

        # LPVOID WINAPI HeapAlloc(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes);
        jit.vm_push_uint32_t(10)     # dwBytes
        jit.vm_push_uint32_t(0)      # dwFlags
        jit.vm_push_uint32_t(0)      # hHeap
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_HeapAlloc(jit)
        lpMem = jit.cpu.EAX
        self.assertTrue(lpMem)

        # BOOL WINAPI HeapFree(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ LPVOID lpMem);
        jit.vm_push_uint32_t(lpMem)  # lpMem
        jit.vm_push_uint32_t(0)      # dwFlags
        jit.vm_push_uint32_t(0)      # hHeap
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_HeapFree(jit)
        vBool = jit.cpu.EAX
        self.assertTrue(vBool)

        # HLOCAL WINAPI LocalAlloc(_In_ UINT uFlags, _In_ SIZE_T uBytes);
        jit.vm_push_uint32_t(10)     # uBytes
        jit.vm_push_uint32_t(0)      # uFlags
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_LocalAlloc(jit)
        hMem = jit.cpu.EAX
        self.assertTrue(hMem)

        # HLOCAL WINAPI LocalFree(_In_ HLOCAL hMem);
        jit.vm_push_uint32_t(hMem)   # hMem
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_LocalFree(jit)
        hMem = jit.cpu.EAX
        self.assertFalse(hMem)

    def test_ProcessAndThreadFunctions(self):

        # HANDLE WINAPI GetCurrentProcess(void);
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_GetCurrentProcess(jit)
        hProc = jit.cpu.EAX
        self.assertTrue(hProc)

        # DWORD WINAPI GetCurrentProcessId(void);
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_GetCurrentProcessId(jit)
        dwProc = jit.cpu.EAX
        self.assertTrue(dwProc)

    def test_SystemInformationFunctions(self):

        # DWORD WINAPI GetVersion(void);
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_GetVersion(jit)
        dwVer = jit.cpu.EAX
        self.assertTrue(dwVer)

        # BOOL WINAPI GetVersionEx(_Inout_ LPOSVERSIONINFO lpVersionInfo);
        jit.vm_push_uint32_t(jit.stack_base)      # lpVersionInfo
        jit.vm_push_uint32_t(0)                   # @return
        winapi.kernel32_GetVersionEx(jit)
        vBool = jit.cpu.EAX
        self.assertTrue(vBool)

    def test_TimeFunctions(self):

        # DWORD WINAPI GetTickCount(void);
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_GetTickCount(jit)
        dwTime = jit.cpu.EAX
        self.assertTrue(dwTime)

    def test_ToolHelpFunctions(self):

        # HANDLE WINAPI CreateToolhelp32Snapshot(_In_ DWORD dwFlags, _In_ DWORD th32ProcessID);
        jit.vm_push_uint32_t(0)      # th32ProcessID
        jit.vm_push_uint32_t(0)      # dwFlags
        jit.vm_push_uint32_t(0)      # @return
        winapi.kernel32_CreateToolhelp32Snapshot(jit)
        hSnap = jit.cpu.EAX
        self.assertTrue(hSnap)

        # BOOL WINAPI Process32First(_In_ HANDLE hSnapshot, _Inout_ LPPROCESSENTRY32 lppe);
        jit.vm_push_uint32_t(jit.stack_base)      # lppe
        jit.vm_push_uint32_t(hSnap)               # hSnapshot
        jit.vm_push_uint32_t(0)                   # @return
        winapi.kernel32_Process32First(jit)
        vBool = jit.cpu.EAX
        self.assertTrue(vBool)

        # BOOL WINAPI Process32Next(_In_ HANDLE hSnapshot, _Out_ LPPROCESSENTRY32 lppe);
        for i in xrange(3, -1, -1):
            jit.vm_push_uint32_t(jit.stack_base)      # lppe
            jit.vm_push_uint32_t(hSnap)               # hSnapshot
            jit.vm_push_uint32_t(0)                   # @return
            winapi.kernel32_Process32Next(jit)
            vBool = jit.cpu.EAX
            if  i: self.assertTrue(vBool)
            else:  self.assertFalse(vBool)


if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestWinAPI)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))

