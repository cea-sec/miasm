#! /usr/bin/env python2

import sys

from asm_test import Asm_Test


# Test from inspired from SimSoC arm tests


class Test_UADD8_1(Asm_Test):
    MYSTRING = "test uadd8 1"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x026080fe
        self.myjit.cpu.R2 = 0x0360fffe

    TXT = '''
    main:
       UADD8 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x05c07ffc
        assert self.myjit.cpu.ge0 == 1
        assert self.myjit.cpu.ge1 == 1
        assert self.myjit.cpu.ge2 == 0
        assert self.myjit.cpu.ge3 == 0


class Test_UADD8_2(Asm_Test):
    MYSTRING = "test uadd8 2"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x02fe01fc
        self.myjit.cpu.R2 = 0xff04fe02

    TXT = '''
    main:
       UADD8 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x0102fffe
        assert self.myjit.cpu.ge0 == 0
        assert self.myjit.cpu.ge1 == 0
        assert self.myjit.cpu.ge2 == 1
        assert self.myjit.cpu.ge3 == 1


class Test_UADD16_1(Asm_Test):
    MYSTRING = "test uadd16 1"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x0002fccc
        self.myjit.cpu.R2 = 0xffff0222

    TXT = '''
    main:
       UADD16 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x0001feee
        assert self.myjit.cpu.ge0 == 0
        assert self.myjit.cpu.ge1 == 0
        assert self.myjit.cpu.ge2 == 1
        assert self.myjit.cpu.ge3 == 1


class Test_UADD16_2(Asm_Test):
    MYSTRING = "test uadd16 2"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x11116666
        self.myjit.cpu.R2 = 0x22227777

    TXT = '''
    main:
       UADD16 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x3333dddd
        assert self.myjit.cpu.ge0 == 0
        assert self.myjit.cpu.ge1 == 0
        assert self.myjit.cpu.ge2 == 0
        assert self.myjit.cpu.ge3 == 0


class Test_UADD16_3(Asm_Test):
    MYSTRING = "test uadd16 3"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0xabcd8000
        self.myjit.cpu.R2 = 0xffffffff

    TXT = '''
    main:
       UADD16 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0xabcc7fff
        assert self.myjit.cpu.ge0 == 1
        assert self.myjit.cpu.ge1 == 1
        assert self.myjit.cpu.ge2 == 1
        assert self.myjit.cpu.ge3 == 1


class Test_UADDSUBX_1(Asm_Test):
    MYSTRING = "test uaddsubx 1"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0xbeefcafe
        self.myjit.cpu.R2 = 0xcafefff1

    TXT = '''
    main:
       UADDSUBX R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0xbee00000
        assert self.myjit.cpu.ge0 == 0
        assert self.myjit.cpu.ge1 == 0
        assert self.myjit.cpu.ge2 == 1
        assert self.myjit.cpu.ge3 == 1


class Test_UADDSUBX_2(Asm_Test):
    MYSTRING = "test uaddsubx 2"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x12345678
        self.myjit.cpu.R2 = 0x56781234

    TXT = '''
    main:
       UADDSUBX R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x24680000
        assert self.myjit.cpu.ge0 == 0
        assert self.myjit.cpu.ge1 == 0
        assert self.myjit.cpu.ge2 == 0
        assert self.myjit.cpu.ge3 == 0


class Test_SADD8_1(Asm_Test):
    MYSTRING = "test sadd8 1"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x026080fe
        self.myjit.cpu.R2 = 0x0360fffe

    TXT = '''
    main:
       SADD8 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x05c07ffc
        assert self.myjit.cpu.ge0 == 0
        assert self.myjit.cpu.ge1 == 0
        assert self.myjit.cpu.ge2 == 1
        assert self.myjit.cpu.ge3 == 1


class Test_SADD8_2(Asm_Test):
    MYSTRING = "test sadd8 2"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x02fe01fc
        self.myjit.cpu.R2 = 0xff04fe02

    TXT = '''
    main:
       SADD8 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x0102fffe
        assert self.myjit.cpu.ge0 == 0
        assert self.myjit.cpu.ge1 == 0
        assert self.myjit.cpu.ge2 == 1
        assert self.myjit.cpu.ge3 == 1


class Test_SADD16_1(Asm_Test):
    MYSTRING = "test sadd16 1"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x0002fccc
        self.myjit.cpu.R2 = 0xffff0222

    TXT = '''
    main:
       SADD16 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x0001feee
        assert self.myjit.cpu.ge0 == 0
        assert self.myjit.cpu.ge1 == 0
        assert self.myjit.cpu.ge2 == 1
        assert self.myjit.cpu.ge3 == 1


class Test_SADD16_2(Asm_Test):
    MYSTRING = "test sadd16 2"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x11116666
        self.myjit.cpu.R2 = 0x22227777

    TXT = '''
    main:
       SADD16 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x3333dddd
        assert self.myjit.cpu.ge0 == 1
        assert self.myjit.cpu.ge1 == 1
        assert self.myjit.cpu.ge2 == 1
        assert self.myjit.cpu.ge3 == 1


class Test_SADD16_3(Asm_Test):
    MYSTRING = "test sadd16 3"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0xabcd8000
        self.myjit.cpu.R2 = 0xffffffff

    TXT = '''
    main:
       SADD16 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0xabcc7fff
        assert self.myjit.cpu.ge0 == 0
        assert self.myjit.cpu.ge1 == 0
        assert self.myjit.cpu.ge2 == 0
        assert self.myjit.cpu.ge3 == 0


class Test_SADDSUBX_1(Asm_Test):
    MYSTRING = "test saddsubx 1"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0xbeefcafe
        self.myjit.cpu.R2 = 0xcafefff1

    TXT = '''
    main:
       SADDSUBX R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0xbee00000
        assert self.myjit.cpu.ge0 == 1
        assert self.myjit.cpu.ge1 == 1
        assert self.myjit.cpu.ge2 == 0
        assert self.myjit.cpu.ge3 == 0


class Test_SADDSUBX_2(Asm_Test):
    MYSTRING = "test saddsubx 2"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x12345678
        self.myjit.cpu.R2 = 0x56781234

    TXT = '''
    main:
       SADDSUBX R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x24680000
        assert self.myjit.cpu.ge0 == 1
        assert self.myjit.cpu.ge1 == 1
        assert self.myjit.cpu.ge2 == 1
        assert self.myjit.cpu.ge3 == 1


class Test_QADD8_1(Asm_Test):
    MYSTRING = "test qadd8 1"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x01f67f80
        self.myjit.cpu.R2 = 0x01087f80

    TXT = '''
    main:
       QADD8 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x02fe7f80



class Test_QADD16_1(Asm_Test):
    MYSTRING = "test qadd16 1"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x0001fff6
        self.myjit.cpu.R2 = 0x00010008

    TXT = '''
    main:
       QADD16 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x0002fffe


class Test_QADD16_2(Asm_Test):
    MYSTRING = "test qadd16 2"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x7fff8000
        self.myjit.cpu.R2 = 0x7fff8000

    TXT = '''
    main:
       QADD16 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x7fff8000



class Test_QSUB8_1(Asm_Test):
    MYSTRING = "test qsub8 1"

    def prepare(self):
        self.myjit.ir_arch.loc_db.add_location("lbl_ret", self.ret_addr)

    def test_init(self):
        self.myjit.cpu.R1 = 0x4f008080
        self.myjit.cpu.R2 = 0x3a80007f

    TXT = '''
    main:
       QSUB8 R0, R1, R2
       B lbl_ret
    '''

    def check(self):
        assert self.myjit.cpu.R0 == 0x157f8080


if __name__ == "__main__":
    [
        test(*sys.argv[1:])() for test in [
            Test_UADD8_1,
            Test_UADD8_2,
            Test_UADD16_1,
            Test_UADD16_2,
            Test_UADD16_3,
            Test_UADDSUBX_1,
            Test_UADDSUBX_2,

            Test_SADD8_1,
            Test_SADD8_2,
            Test_SADD16_1,
            Test_SADD16_2,
            Test_SADD16_3,
            Test_SADDSUBX_1,
            Test_SADDSUBX_2,

            Test_QADD8_1,
            Test_QADD16_1,
            Test_QADD16_2,

            Test_QSUB8_1,


        ]
    ]
