#! /usr/bin/env python2

import sys

from asm_test import Asm_Test_16, Asm_Test_32, Asm_Test_64
from miasm.core.utils import pck16, pck32


class Test_CBW_16(Asm_Test_16):
    MYSTRING = "test CBW 16"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x87654321
        self.myjit.cpu.EDX = 0x11223344

    TXT = '''
    main:
       CBW
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.EAX == 0x87650021
        assert self.myjit.cpu.EDX == 0x11223344


class Test_CBW_16_signed(Asm_Test_16):
    MYSTRING = "test CBW 16 signed"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x87654381
        self.myjit.cpu.EDX = 0x11223344

    TXT = '''
    main:
       CBW
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.EAX == 0x8765FF81
        assert self.myjit.cpu.EDX == 0x11223344


class Test_CBW_32(Asm_Test_32):
    MYSTRING = "test CBW 32"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x87654321
        self.myjit.cpu.EDX = 0x11223344

    TXT = '''
    main:
       CBW
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.EAX == 0x87650021
        assert self.myjit.cpu.EDX == 0x11223344


class Test_CBW_32_signed(Asm_Test_32):
    MYSTRING = "test CBW 32 signed"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x87654381
        self.myjit.cpu.EDX = 0x11223344

    TXT = '''
    main:
       CBW
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.EAX == 0x8765FF81
        assert self.myjit.cpu.EDX == 0x11223344


class Test_CDQ_32(Asm_Test_32):
    MYSTRING = "test cdq 32"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x77654321
        self.myjit.cpu.EDX = 0x11223344

    TXT = '''
    main:
       CDQ
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.EAX == 0x77654321
        assert self.myjit.cpu.EDX == 0x0


class Test_CDQ_32_signed(Asm_Test_32):
    MYSTRING = "test cdq 32 signed"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x87654321
        self.myjit.cpu.EDX = 0x11223344

    TXT = '''
    main:
       CDQ
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.EAX == 0x87654321
        assert self.myjit.cpu.EDX == 0xFFFFFFFF


class Test_CDQ_64(Asm_Test_64):
    MYSTRING = "test cdq 64"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.RAX = 0x1234567877654321
        self.myjit.cpu.RDX = 0x1122334455667788

    TXT = '''
    main:
       CDQ
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x1234567877654321
        assert self.myjit.cpu.RDX == 0x0


class Test_CDQ_64_signed(Asm_Test_64):
    MYSTRING = "test cdq 64 signed"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.RAX = 0x1234567887654321
        self.myjit.cpu.RDX = 0x1122334455667788

    TXT = '''
    main:
       CDQ
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x1234567887654321
        assert self.myjit.cpu.RDX == 0x00000000FFFFFFFF


class Test_CDQE_64(Asm_Test_64):
    MYSTRING = "test cdq 64"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.RAX = 0x1234567877654321
        self.myjit.cpu.RDX = 0x1122334455667788

    TXT = '''
    main:
       CDQE
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x77654321
        assert self.myjit.cpu.RDX == 0x1122334455667788


class Test_CDQE_64_signed(Asm_Test_64):
    MYSTRING = "test cdq 64 signed"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.RAX = 0x1234567887654321
        self.myjit.cpu.RDX = 0x1122334455667788

    TXT = '''
    main:
       CDQE
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0xFFFFFFFF87654321
        assert self.myjit.cpu.RDX == 0x1122334455667788


class Test_CWD_32(Asm_Test_32):
    MYSTRING = "test cdq 32"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x87654321
        self.myjit.cpu.EDX = 0x12345678

    TXT = '''
    main:
       CWD
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x87654321
        assert self.myjit.cpu.RDX == 0x12340000


class Test_CWD_32_signed(Asm_Test_32):
    MYSTRING = "test cdq 32"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x87658321
        self.myjit.cpu.EDX = 0x12345678

    TXT = '''
    main:
       CWD
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x87658321
        assert self.myjit.cpu.RDX == 0x1234FFFF


class Test_CWD_32(Asm_Test_32):
    MYSTRING = "test cdq 32"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x87654321
        self.myjit.cpu.EDX = 0x12345678

    TXT = '''
    main:
       CWD
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x87654321
        assert self.myjit.cpu.RDX == 0x12340000


class Test_CWDE_32(Asm_Test_32):
    MYSTRING = "test cwde 32"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.EAX = 0x87654321
        self.myjit.cpu.EDX = 0x11223344

    TXT = '''
    main:
       CWDE
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x4321
        assert self.myjit.cpu.RDX == 0x11223344


class Test_CWDE_32_signed(Asm_Test_32):
    MYSTRING = "test cwde 32 signed"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.RAX = 0x87658321
        self.myjit.cpu.RDX = 0x11223344

    TXT = '''
    main:
       CWDE
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.EAX == 0xFFFF8321
        assert self.myjit.cpu.RDX == 0x11223344


class Test_CWDE_64(Asm_Test_64):
    MYSTRING = "test cwde 64"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.RAX = 0x1234567887654321
        self.myjit.cpu.RDX = 0x1122334455667788

    TXT = '''
    main:
       CWDE
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x4321
        assert self.myjit.cpu.RDX == 0x1122334455667788


class Test_CWDE_64_signed(Asm_Test_64):
    MYSTRING = "test cwde 64 signed"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.RAX = 0x1234567887658321
        self.myjit.cpu.RDX = 0x1122334455667788

    TXT = '''
    main:
       CWDE
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0xFFFF8321
        assert self.myjit.cpu.RDX == 0x1122334455667788


class Test_CQO_64(Asm_Test_64):
    MYSTRING = "test cwde 64"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.RAX = 0x1234567887654321
        self.myjit.cpu.RDX = 0x1122334455667788

    TXT = '''
    main:
       CQO
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x1234567887654321
        assert self.myjit.cpu.RDX == 0x0


class Test_CQO_64_signed(Asm_Test_64):
    MYSTRING = "test cwde 64 signed"

    def prepare(self):
        self.myjit.lifter.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.RAX = 0x8234567887658321
        self.myjit.cpu.RDX = 0x1122334455667788

    TXT = '''
    main:
       CQO
       JMP lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.RAX == 0x8234567887658321
        assert self.myjit.cpu.RDX == 0xFFFFFFFFFFFFFFFF




if __name__ == "__main__":
    tests = [
        Test_CBW_16,
        Test_CBW_16_signed,

        Test_CBW_32,
        Test_CBW_32_signed,

        Test_CWD_32,
        Test_CWD_32_signed,

        Test_CWDE_32,
        Test_CWDE_32_signed,

        Test_CWDE_64,
        Test_CWDE_64_signed,

        Test_CDQ_32,
        Test_CDQ_32_signed,

        Test_CDQ_64,
        Test_CDQ_64_signed,

        Test_CDQE_64,
        Test_CDQE_64_signed,
    ]
    if sys.argv[1] not in ["gcc"]:
        # TODO XXX CQO use 128 bit not supported in gcc yet!
        tests += [
            Test_CQO_64,
            Test_CQO_64_signed,
        ]

    [
        test(*sys.argv[1:])() for test in tests
    ]
