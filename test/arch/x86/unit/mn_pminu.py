#! /usr/bin/env python2
import sys

from asm_test import Asm_Test_32

class Test_PMINU(Asm_Test_32):
    TXT = '''
    main:
       CALL   next
       .byte 0x88, 0x78, 0x66, 0x56, 0x44, 0x3F, 0xFF, 0x1F
       .byte 0x89, 0x77, 0x66, 0x55, 0xF9, 0x33, 0x22, 0x11
    next:
       POP    EBP
       MOVQ   MM0, QWORD PTR [EBP]
       MOVQ   MM1, MM0
       PMINUB MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1FFF3F4456667888
        assert self.myjit.cpu.MM1 == 0x1122334455667788


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_PMINU]]
