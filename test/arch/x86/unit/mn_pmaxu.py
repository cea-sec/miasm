#! /usr/bin/env python2
import sys

from asm_test import Asm_Test_32

class Test_PMAXU(Asm_Test_32):
    TXT = '''
    main:
       CALL   next
       .byte 0x88, 0x76, 0x66, 0x54, 0x44, 0x32, 0x00, 0x10
       .byte 0x87, 0x77, 0x66, 0x55, 0x40, 0x33, 0x22, 0x11
    next:
       POP    EBP
       MOVQ   MM0, QWORD PTR [EBP]
       MOVQ   MM1, MM0
       PMAXUB MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1000324454667688
        assert self.myjit.cpu.MM1 == 0x1122334455667788


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_PMAXU]]
