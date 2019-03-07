#! /usr/bin/env python2

import sys

from asm_test import Asm_Test_32


class Test_PCMPEQB(Asm_Test_32):
    TXT = '''
    main:
       CALL    next
       .byte 0x88, 0x78, 0x66, 0x56, 0x44, 0x3F, 0xFF, 0x11
       .byte 0x89, 0x77, 0x66, 0x55, 0xF9, 0x33, 0x22, 0x11
    next:
       POP     EBP
       MOVQ    MM0, QWORD PTR [EBP]
       MOVQ    MM1, MM0
       PCMPEQB MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x11FF3F4456667888
        assert self.myjit.cpu.MM1 == 0xFF00000000FF0000


class Test_PCMPEQW(Asm_Test_32):
    TXT = '''
    main:
       CALL    next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x3F, 0x22, 0x11
       .byte 0x89, 0x77, 0x66, 0x55, 0xF9, 0x33, 0x22, 0x11
    next:
       POP     EBP
       MOVQ    MM0, QWORD PTR [EBP]
       MOVQ    MM1, MM0
       PCMPEQW MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x11223F4455667788
        assert self.myjit.cpu.MM1 == 0xFFFF0000FFFF0000


class Test_PCMPEQD(Asm_Test_32):
    TXT = '''
    main:
       CALL    next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x3F, 0x22, 0x11
       .byte 0x88, 0x77, 0x66, 0x55, 0xF9, 0x33, 0x22, 0x11
    next:
       POP     EBP
       MOVQ    MM0, QWORD PTR [EBP]
       MOVQ    MM1, MM0
       PCMPEQD MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x11223F4455667788
        assert self.myjit.cpu.MM1 == 0x00000000FFFFFFFF


class Test_PCMPEQQ(Asm_Test_32):
    TXT = '''
    main:
       MOVD       XMM0, ESI
       MOVD       XMM1, EDI
       PCMPEQQ    XMM0, XMM1
       JZ         ret
       MOV        EAX, 1
    ret:
       RET
    '''

    def prepare(self):
        val = 1
        self.myjit.cpu.ESI = 0x11223344
        self.myjit.cpu.EDI = 0x11223345
        self.myjit.cpu.XMM0 = val

    def check(self):
        assert self.myjit.cpu.XMM0 == 0xffffffffffffffff0000000000000000
        assert self.myjit.cpu.XMM1 == 0x11223345


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [
        Test_PCMPEQB,
        Test_PCMPEQW,
        Test_PCMPEQD,
        Test_PCMPEQQ,
    ]]
