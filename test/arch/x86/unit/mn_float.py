#! /usr/bin/env python
from asm_test import Asm_Test_32


class Test_FADD(Asm_Test_32):
    TXT = '''
    main:
       ; test float
       PUSH 0
       FLD1
       FLD1
       FADD ST, ST(1)
       FIST  DWORD PTR [ESP]
       POP  EAX
       RET
    '''
    def check(self):
        assert(self.myjit.cpu.EAX == 2)


if __name__ == "__main__":
    [test()() for test in [Test_FADD]]
