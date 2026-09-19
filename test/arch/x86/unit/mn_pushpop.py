#! /usr/bin/env python2

import sys

from asm_test import Asm_Test_16, Asm_Test_32, Asm_Test_64
from miasm.core.utils import pck16, pck32


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
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = b""
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
        assert self.myjit.cpu.ESP == self.stk_origin - 0x4 * 8
        buf = self.myjit.vm.get_mem(self.myjit.cpu.ESP, 0x4 * 8)
        assert(buf == self.buf)


class Test_PUSHA_32(Asm_Test_32):
    MYSTRING = "test pusha 32"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = b""
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
        assert self.myjit.cpu.ESP == self.stk_origin - 0x2 * 8
        buf = self.myjit.vm.get_mem(self.myjit.cpu.ESP, 0x2 * 8)
        assert(buf == self.buf)


class Test_PUSHA_16(Asm_Test_16):
    MYSTRING = "test pusha 16"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = b""
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
        assert self.myjit.cpu.ESP == self.stk_origin - 0x2 * 8
        buf = self.myjit.vm.get_mem(self.myjit.cpu.SP, 0x2 * 8)
        assert(buf == self.buf)


class Test_PUSHAD_16(Asm_Test_16):
    MYSTRING = "test pushad 16"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = b""
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
        assert self.myjit.cpu.ESP == self.stk_origin - 0x4 * 8
        buf = self.myjit.vm.get_mem(self.myjit.cpu.SP, 0x4 * 8)
        assert(buf == self.buf)


class Test_PUSH_mode32_32(Asm_Test_32):
    MYSTRING = "test push mode32 32"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = b""
        self.buf += pck32(0x11223344)

    TXT = '''
    main:
       PUSH 0x11223344
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.ESP == self.stk_origin - 0x4
        buf = self.myjit.vm.get_mem(self.myjit.cpu.ESP, 0x4)
        assert(buf == self.buf)


class Test_PUSH_mode32_16(Asm_Test_32):
    MYSTRING = "test push mode32 16"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = b""
        self.buf += pck16(0x1122)

    TXT = '''
    main:
       PUSHW 0x1122
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.ESP == self.stk_origin - 0x2
        buf = self.myjit.vm.get_mem(self.myjit.cpu.ESP, 0x2)
        assert(buf == self.buf)


class Test_PUSH_mode16_16(Asm_Test_16):
    MYSTRING = "test push mode16 16"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = b""
        self.buf += pck16(0x1122)

    TXT = '''
    main:
       PUSHW 0x1122
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.ESP == self.stk_origin - 0x2
        buf = self.myjit.vm.get_mem(self.myjit.cpu.ESP, 0x2)
        assert(buf == self.buf)


class Test_PUSH_mode16_32(Asm_Test_16):
    MYSTRING = "test push mode16 32"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.buf = b""
        self.buf += pck32(0x11223344)

    TXT = '''
    main:
       .byte 0x66, 0x68, 0x44, 0x33, 0x22, 0x11
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.ESP == self.stk_origin - 0x4
        buf = self.myjit.vm.get_mem(self.myjit.cpu.ESP, 0x4)
        assert(buf == self.buf)

class Test_PUSHFW(Asm_Test_16):
    MYSTRING = "test pushfw"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.myjit.cpu.cf = 1
        self.myjit.cpu.zf = 1

    TXT = '''
    main:
       PUSHFW
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.SP == self.stk_origin - 0x2
        buf = self.myjit.vm.get_mem(self.myjit.cpu.SP, 0x2)
        flags = int.from_bytes(buf, byteorder="little")

        assert(flags & 1 == 1)       # CF
        assert(flags & 0x40 == 0x40) # ZF

class Test_PUSHFD(Asm_Test_32):
    MYSTRING = "test pushfd"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.myjit.cpu.cf = 1
        self.myjit.cpu.zf = 1

    TXT = '''
    main:
       PUSHFD
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.ESP == self.stk_origin - 0x4
        buf = self.myjit.vm.get_mem(self.myjit.cpu.ESP, 0x4)
        eflags = int.from_bytes(buf, byteorder="little")

        assert(eflags & 1 == 1)       # CF
        assert(eflags & 0x40 == 0x40) # ZF

class Test_PUSHFQ(Asm_Test_64):
    MYSTRING = "test pushfq"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        self.myjit.cpu.cf = 1
        self.myjit.cpu.zf = 1

    TXT = '''
    main:
       PUSHFQ
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RSP == self.stk_origin - 0x8
        buf = self.myjit.vm.get_mem(self.myjit.cpu.RSP, 0x8)
        rflags = int.from_bytes(buf, byteorder="little")

        assert(rflags & 1 == 1)       # CF
        assert(rflags & 0x40 == 0x40) # ZF

class Test_PUSHFD_clears_VM_RF(Asm_Test_32):
    MYSTRING = "test pushfd clears VM and RF"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        # VM + RF + IF + ZF + 0b10 (Reserved) + CF
        eflags = 0b0000_0011_0000_0010_0100_0011
        self.myjit.push_uint32_t(eflags)

    TXT = '''
    main:
       POPFD
       PUSHFD
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RSP == self.stk_origin - 0x4
        buf = self.myjit.vm.get_mem(self.myjit.cpu.RSP, 0x4)
        eflags = int.from_bytes(buf, byteorder="little")

        assert(eflags & 1 == 1)           # CF
        assert(eflags & 0x40 == 0x40)     # ZF
        assert(eflags & 0x0001_0000 == 0) # RF
        assert(eflags & 0x0002_0000 == 0) # VM

class Test_PUSHFQ_clears_VM_RF(Asm_Test_64):
    MYSTRING = "test pushfq clears VM and RF"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        init_regs(self)
        # VM + RF + IF + ZF + 0b10 (Reserved) + CF
        rflags = 0b0000_0011_0000_0010_0100_0011
        self.myjit.push_uint64_t(rflags)

    TXT = '''
    main:
       POPFQ
       PUSHFQ
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RSP == self.stk_origin - 0x8
        buf = self.myjit.vm.get_mem(self.myjit.cpu.RSP, 0x8)
        rflags = int.from_bytes(buf, byteorder="little")

        assert(rflags & 1 == 1)           # CF
        assert(rflags & 0x40 == 0x40)     # ZF
        assert(rflags & 0x0001_0000 == 0) # RF
        assert(rflags & 0x0002_0000 == 0) # VM

class Test_POP_mode32_32(Asm_Test_32):
    MYSTRING = "test pop mode32 32"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.value = 0x11223344
        self.myjit.push_uint32_t(self.value)
        init_regs(self)

    TXT = '''
    main:
       POP EAX
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.ESP == self.stk_origin + 0x4
        assert self.myjit.cpu.EAX == self.value


class Test_POP_mode32_16(Asm_Test_32):
    MYSTRING = "test pop mode32 16"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.value = 0x1122
        self.myjit.push_uint16_t(self.value)
        init_regs(self)

    TXT = '''
    main:
       POPW AX
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.ESP == self.stk_origin + 0x2
        assert self.myjit.cpu.AX == self.value


class Test_POP_mode16_16(Asm_Test_16):
    MYSTRING = "test pop mode16 16"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.value = 0x1122
        self.myjit.push_uint16_t(self.value)
        init_regs(self)

    TXT = '''
    main:
       POPW AX
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.ESP == self.stk_origin + 0x2
        assert self.myjit.cpu.AX == self.value


class Test_POP_mode16_32(Asm_Test_16):
    MYSTRING = "test pop mode16 32"

    def prepare(self):
        self.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.value = 0x11223344
        self.myjit.cpu.SP -= 0x4
        self.myjit.vm.set_mem(self.myjit.cpu.SP, pck32(self.value))
        init_regs(self)

    TXT = '''
    main:
       POP EAX
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.ESP == self.stk_origin + 0x4
        assert self.myjit.cpu.EAX == self.value


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_PUSHA_16, Test_PUSHA_32,
                                        Test_PUSHAD_16, Test_PUSHAD_32,
                                        Test_PUSH_mode32_32,
                                        Test_PUSH_mode32_16,
                                        Test_PUSH_mode16_16,
                                        Test_PUSH_mode16_32,
                                        Test_POP_mode32_32,
                                        Test_POP_mode32_16,
                                        Test_POP_mode16_16,
                                        Test_POP_mode16_32,
                                        Test_PUSHFW,
                                        Test_PUSHFD,
                                        Test_PUSHFQ,
                                        Test_PUSHFD_clears_VM_RF,
                                        Test_PUSHFQ_clears_VM_RF,
                                        ]
    ]
