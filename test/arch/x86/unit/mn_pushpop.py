#! /usr/bin/env python
import sys

from asm_test import Asm_Test_16, Asm_Test_32
from miasm2.core.utils import pck16, pck32


def init_regs(test):
    test.myjit.cpu.EAX = 0x11111111
    test.myjit.cpu.EBX = 0x22222222
    test.myjit.cpu.ECX = 0x33333333
    test.myjit.cpu.EDX = 0x44444444
    test.myjit.cpu.ESI = 0x55555555
    test.myjit.cpu.EDI = 0x66666666
    test.myjit.cpu.EBP = 0x77777777
    test.stk_origin = test.myjit.cpu.ESP


class Test_PUSHAD_32(Asm_Test_32):
    MYSTRING = "test pushad 32"

    def prepare(self):
        self.myjit.ir_arch.symbol_pool.add_label("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = ""
        for reg_name in reversed(["EAX", "ECX",
                                  "EDX", "EBX",
                                  "ESP", "EBP",
                                  "ESI", "EDI"]):
            self.buf += pck32(getattr(self.myjit.cpu, reg_name))

    TXT = '''
    main:
       PUSHAD
       JMP lbl_ret
    '''

    def check(self):
        buf = self.myjit.vm.get_mem(self.myjit.cpu.ESP, 0x4 * 8)
        assert(buf == self.buf)


class Test_PUSHA_32(Asm_Test_32):
    MYSTRING = "test pusha 32"

    def prepare(self):
        self.myjit.ir_arch.symbol_pool.add_label("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = ""
        for reg_name in reversed(["AX", "CX",
                                  "DX", "BX",
                                  "SP", "BP",
                                  "SI", "DI"]):
            self.buf += pck16(getattr(self.myjit.cpu, reg_name))

    TXT = '''
    main:
       PUSHA
       JMP lbl_ret
    '''

    def check(self):
        buf = self.myjit.vm.get_mem(self.myjit.cpu.ESP, 0x2 * 8)
        assert(buf == self.buf)


class Test_PUSHA_16(Asm_Test_16):
    MYSTRING = "test pusha 16"

    def prepare(self):
        self.myjit.ir_arch.symbol_pool.add_label("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = ""
        for reg_name in reversed(["AX", "CX",
                                  "DX", "BX",
                                  "SP", "BP",
                                  "SI", "DI"]):
            self.buf += pck16(getattr(self.myjit.cpu, reg_name))

    TXT = '''
    main:
       PUSHA
       JMP lbl_ret
    '''

    def check(self):
        buf = self.myjit.vm.get_mem(self.myjit.cpu.SP, 0x2 * 8)
        assert(buf == self.buf)


class Test_PUSHAD_16(Asm_Test_16):
    MYSTRING = "test pushad 16"

    def prepare(self):
        self.myjit.ir_arch.symbol_pool.add_label("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = ""
        for reg_name in reversed(["EAX", "ECX",
                                  "EDX", "EBX",
                                  "ESP", "EBP",
                                  "ESI", "EDI"]):
            self.buf += pck32(getattr(self.myjit.cpu, reg_name))

    TXT = '''
    main:
       PUSHAD
       JMP lbl_ret
    '''

    def check(self):
        buf = self.myjit.vm.get_mem(self.myjit.cpu.SP, 0x4 * 8)
        assert(buf == self.buf)


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_PUSHA_16, Test_PUSHA_32,
                                        Test_PUSHAD_16, Test_PUSHAD_32
                                        ]
    ]
