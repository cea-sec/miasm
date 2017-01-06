#! /usr/bin/env python2

import sys

from asm_test import Asm_Test_32

class Test_PEXTRB(Asm_Test_32):
    TXT = '''
    main:
       CALL      next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
    next:
       POP       EBP
       MOV       EAX, 0xFFFFFFFF
       MOVQ      MM0, QWORD PTR [EBP]
       PEXTRW    EAX, MM0, 2
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.EAX == 0x3344


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_PEXTRB]]
