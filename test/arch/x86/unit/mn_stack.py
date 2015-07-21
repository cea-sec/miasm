#! /usr/bin/env python
from asm_test import Asm_Test


class Test_PUSHPOP(Asm_Test):
    TXT = '''
    main:
       MOV     EBP, ESP
       PUSH    0x11223344
       POP     EAX
       CMP     EBP, ESP
       JNZ     BAD

       PUSHW   0x1122
       POPW    AX
       CMP     EBP, ESP
       JNZ     BAD

       PUSH    SS
       POP     EAX
       CMP     EBP, ESP
       JNZ     BAD

       PUSHW   SS
       POPW    AX
       CMP     EBP, ESP
       JNZ     BAD

       PUSHFD
       POP     EAX
       CMP     EBP, ESP
       JNZ     BAD

       PUSHFW
       POPW    AX
       CMP     EBP, ESP
       JNZ     BAD

       PUSH    EAX
       POPFD
       CMP     EBP, ESP
       JNZ     BAD

       PUSHW   AX
       POPFW
       CMP     EBP, ESP
       JNZ     BAD

       RET

BAD:
       INT     0x3
       RET
    '''
    def check(self):
        assert(self.myjit.cpu.ESP-4 == self.myjit.cpu.EBP)


if __name__ == "__main__":
    [test()() for test in [Test_PUSHPOP]]
