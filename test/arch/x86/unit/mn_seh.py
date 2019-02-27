#! /usr/bin/env python2
from __future__ import print_function
import sys

from miasm.os_dep.win_api_x86_32_seh import fake_seh_handler, build_teb, \
    set_win_fs_0, return_from_exception, EXCEPTION_PRIV_INSTRUCTION, \
    return_from_seh, DEFAULT_SEH
from miasm.os_dep.win_32_structs import ContextException

from asm_test import Asm_Test_32

from pdb import pm

class Test_SEH(Asm_Test_32):
    """SEH Handling"""

    @staticmethod
    def deal_exception_priv(jitter):
        print('Exception Priv', hex(jitter.cpu.ESP))
        pc = fake_seh_handler(jitter, EXCEPTION_PRIV_INSTRUCTION)
        jitter.pc = pc
        jitter.cpu.EIP = pc
        return True

    def init_machine(self):
        super(Test_SEH, self).init_machine()
        set_win_fs_0(self.myjit)
        tib_ad = self.myjit.cpu.get_segm_base(self.myjit.cpu.FS)
        build_teb(self.myjit, tib_ad)
        self.myjit.add_exception_handler((1 << 17),
                                         Test_SEH.deal_exception_priv)
        self.myjit.add_breakpoint(return_from_exception, return_from_seh)


class Test_SEH_simple(Test_SEH):
    TXT = '''
    main:
       XOR EAX, EAX
       XOR EDX, EDX

       PUSH handler
       PUSH DWORD PTR FS:[EDX]
       MOV DWORD PTR FS:[EDX], ESP

       STI

       MOV EBX, DWORD PTR [ESP]
       MOV DWORD PTR FS:[EDX], EBX
       ADD ESP, 0x8

       RET

    handler:
       MOV ECX, DWORD PTR [ESP+0xC]
       INC DWORD PTR [ECX+0x%08x]
       MOV DWORD PTR [ECX+0x%08x], 0xcafebabe
       XOR EAX, EAX
       RET
    ''' % (ContextException.get_offset("eip"),
           ContextException.get_offset("eax"))

    def check(self):
        assert(self.myjit.cpu.EAX == 0xcafebabe)
        assert(self.myjit.cpu.EBX == DEFAULT_SEH)


class Test_SEH_double(Test_SEH_simple):
    TXT = '''
    main:
       XOR EAX, EAX
       XOR EDX, EDX

       PUSH handler1
       PUSH DWORD PTR FS:[EDX]
       MOV DWORD PTR FS:[EDX], ESP

       PUSH handler2
       PUSH DWORD PTR FS:[EDX]
       MOV DWORD PTR FS:[EDX], ESP

       STI

       MOV EBX, DWORD PTR [ESP]
       MOV DWORD PTR FS:[EDX], EBX
       ADD ESP, 0x8

       MOV EBX, DWORD PTR [ESP]
       MOV DWORD PTR FS:[EDX], EBX
       ADD ESP, 0x8

       RET

    handler1:
       MOV EAX, 0x1
       RET

    handler2:
       MOV ECX, DWORD PTR [ESP+0xC]
       INC DWORD PTR [ECX+0x%08x]
       MOV DWORD PTR [ECX+0x%08x], 0xcafebabe
       XOR EAX, EAX
       RET
    ''' % (ContextException.get_offset("eip"),
           ContextException.get_offset("eax"))


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_SEH_simple, Test_SEH_double]]
