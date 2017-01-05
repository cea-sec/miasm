#! /usr/bin/env python2
import sys

from asm_test import Asm_Test_32

class Test_PUNPCKHBW(Asm_Test_32):
    TXT = '''
    main:
       CALL      next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA
    next:
       POP       EBP
       MOVQ      MM0, QWORD PTR [EBP]
       MOVQ      MM1, MM0
       PUNPCKHBW MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.MM1 == 0xAA11BB22CC33DD44


class Test_PUNPCKHWD(Asm_Test_32):
    TXT = '''
    main:
       CALL      next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA
    next:
       POP       EBP
       MOVQ      MM0, QWORD PTR [EBP]
       MOVQ      MM1, MM0
       PUNPCKHWD MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.MM1 == 0xAABB1122CCDD3344



class Test_PUNPCKHDQ(Asm_Test_32):
    TXT = '''
    main:
       CALL      next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA
    next:
       POP       EBP
       MOVQ      MM0, QWORD PTR [EBP]
       MOVQ      MM1, MM0
       PUNPCKHDQ MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.MM1 == 0xAABBCCDD11223344




class Test_PUNPCKLBW(Asm_Test_32):
    TXT = '''
    main:
       CALL      next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA
    next:
       POP       EBP
       MOVQ      MM0, QWORD PTR [EBP]
       MOVQ      MM1, MM0
       PUNPCKLBW MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.MM1 == 0xEE55FF6602770188


class Test_PUNPCKLWD(Asm_Test_32):
    TXT = '''
    main:
       CALL      next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA
    next:
       POP       EBP
       MOVQ      MM0, QWORD PTR [EBP]
       MOVQ      MM1, MM0
       PUNPCKLWD MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.MM1 == 0xEEFF556602017788



class Test_PUNPCKLDQ(Asm_Test_32):
    TXT = '''
    main:
       CALL      next
       .byte 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
       .byte 0x01, 0x02, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA
    next:
       POP       EBP
       MOVQ      MM0, QWORD PTR [EBP]
       MOVQ      MM1, MM0
       PUNPCKLDQ MM1, QWORD PTR [EBP+0x8]
       RET
    '''

    def check(self):
        assert self.myjit.cpu.MM0 == 0x1122334455667788
        assert self.myjit.cpu.MM1 == 0xEEFF020155667788

if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_PUNPCKHBW, Test_PUNPCKHWD, Test_PUNPCKHDQ,
                                        Test_PUNPCKLBW, Test_PUNPCKLWD, Test_PUNPCKLDQ,]]
