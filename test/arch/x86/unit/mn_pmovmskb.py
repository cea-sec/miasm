#! /usr/bin/env python2

import sys

from asm_test import Asm_Test_32

class Test_PMOVMSKB(Asm_Test_32):
    TXT = '''
    main:
       CALL      next
       .byte 0x88, 0x77, 0xE6, 0x55, 0xC4, 0x33, 0x22, 0x11
       .byte 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA
    next:
       POP       EBP
       MOV       EAX, 0xFFFFFFFF
       MOVQ      MM0, QWORD PTR [EBP]
       MOVQ      MM1, MM0
       PMOVMSKB  EAX, MM1
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x112233C455E67788
        assert self.myjit.cpu.MM1 == 0x112233C455E67788
        assert self.myjit.cpu.EAX == 0x00000015

if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_PMOVMSKB,]]
