#! /usr/bin/env python2
import sys

from asm_test import Asm_Test_32


class Test_DAA(Asm_Test_32):
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

       DAA
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
.byte 0, 1, 0x08, 0, 1, 0x0E
.byte 0, 1, 0x09, 0, 1, 0x0F
.byte 0, 1, 0x0A, 0, 1, 0x10
.byte 0, 1, 0x98, 0, 1, 0x9E
.byte 0, 1, 0x99, 0, 1, 0x9F
.byte 0, 1, 0x9A, 1, 1, 0x00
array_al_end:
.long 0
    '''
    def check(self):
        pass


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_DAA]]
