#! /usr/bin/env python2

import sys

from asm_test import Asm_Test_32


class Test_DAS(Asm_Test_32):
    TXT = '''
    main:
       MOV     EBP, ESP
       LEA     ESI, DWORD PTR [array_al]
    loop:

       ; load original cf
       LODSB
       MOV     BL, AL
       ; load original af
       LODSB
       SHL     AL, 4
       OR      AL, BL
       MOV     AH, AL
       SAHF
       ; load original al
       LODSB

       DAS
       MOV     BL, AL

       LAHF
       MOV     CL, AH

       ; test cf
       LODSB
       MOV     DL, CL
       AND     DL, 1
       CMP     DL, AL
       JNZ BAD

       MOV     DL, CL
       SHR     DL, 4
       AND     DL, 1
       ; test af
       LODSB
       CMP     DL, AL
       JNZ BAD

       ; test value
       LODSB
       CMP     AL, BL
       JNZ BAD

       CMP     ESI, array_al_end
       JB      loop


    end:
       RET

BAD:
       INT     0x3
       RET

array_al:
.byte 0, 0, 0x05, 0, 0, 0x05
.byte 0, 1, 0x05, 1, 1, 0xFF
.byte 1, 0, 0x05, 1, 0, 0xA5
.byte 1, 1, 0x05, 1, 1, 0x9F
.byte 0, 0, 0x06, 0, 0, 0x06
.byte 0, 1, 0x06, 0, 1, 0x00
.byte 1, 0, 0x06, 1, 0, 0xA6
.byte 1, 1, 0x06, 1, 1, 0xA0
.byte 0, 0, 0x07, 0, 0, 0x07
.byte 0, 1, 0x07, 0, 1, 0x01
.byte 1, 0, 0x07, 1, 0, 0xA7
.byte 1, 1, 0x07, 1, 1, 0xA1
.byte 0, 0, 0x08, 0, 0, 0x08
.byte 0, 1, 0x08, 0, 1, 0x02
.byte 1, 0, 0x08, 1, 0, 0xA8
.byte 1, 1, 0x08, 1, 1, 0xA2
.byte 0, 0, 0x09, 0, 0, 0x09
.byte 0, 1, 0x09, 0, 1, 0x03
.byte 1, 0, 0x09, 1, 0, 0xA9
.byte 1, 1, 0x09, 1, 1, 0xA3
.byte 0, 0, 0x0A, 0, 1, 0x04
.byte 0, 1, 0x0A, 0, 1, 0x04
.byte 1, 0, 0x0A, 1, 1, 0xA4
.byte 1, 1, 0x0A, 1, 1, 0xA4
.byte 0, 0, 0x98, 0, 0, 0x98
.byte 0, 1, 0x98, 0, 1, 0x92
.byte 1, 0, 0x98, 1, 0, 0x38
.byte 1, 1, 0x98, 1, 1, 0x32
.byte 0, 0, 0x99, 0, 0, 0x99
.byte 0, 1, 0x99, 0, 1, 0x93
.byte 1, 0, 0x99, 1, 0, 0x39
.byte 1, 1, 0x99, 1, 1, 0x33
.byte 0, 0, 0x9A, 1, 1, 0x34
.byte 0, 1, 0x9A, 1, 1, 0x34
.byte 1, 0, 0x9A, 1, 1, 0x34
.byte 1, 1, 0x9A, 1, 1, 0x34
array_al_end:
.long 0
    '''
    def check(self):
        pass


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_DAS]]
