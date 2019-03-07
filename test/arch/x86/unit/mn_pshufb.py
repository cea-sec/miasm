#! /usr/bin/env python2
import sys

from asm_test import Asm_Test_32

class Test_PSHUFB(Asm_Test_32):
    TXT = '''
    main:
       CALL   next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0
    next:
       POP    EBP
       MOVQ   MM0, QWORD PTR [EBP]
       MOVQ   MM1, MM0
       PSHUFB MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.MM1 == 0x8877665544332211


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_PSHUFB]]
