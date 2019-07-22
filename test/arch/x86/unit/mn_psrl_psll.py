#! /usr/bin/env python2
import sys

from asm_test import Asm_Test_32

class Test_PSRL(Asm_Test_32):
    TXT = '''
    main:
       CALL   next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
    next:
       POP    EBP
       MOVQ   MM0, QWORD PTR [EBP]
       MOVQ   MM1, MM0
       MOVQ   MM2, MM0
       MOVQ   MM3, MM0
       PSRLW  MM1, QWORD PTR [EBP+0x8]
       PSRLD  MM2, QWORD PTR [EBP+0x8]
       PSRLQ  MM3, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.MM1 == 0x0112033405560778
        assert self.myjit.cpu.MM2 == 0x0112233405566778
        assert self.myjit.cpu.MM3 == 0x0112233445566778

class Test_PSLL(Asm_Test_32):
    TXT = '''
    main:
       CALL   next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
    next:
       POP    EBP
       MOVQ   MM0, QWORD PTR [EBP]
       MOVQ   MM1, MM0
       MOVQ   MM2, MM0
       MOVQ   MM3, MM0
       PSLLW  MM1, QWORD PTR [EBP+0x8]
       PSLLD  MM2, QWORD PTR [EBP+0x8]
       PSLLQ  MM3, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.MM1 == 0x1220344056607880
        assert self.myjit.cpu.MM2 == 0x1223344056677880
        assert self.myjit.cpu.MM3 == 0x1223344556677880


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_PSRL, Test_PSLL]]
