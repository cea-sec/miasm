#! /usr/bin/env python2

import sys

from asm_test import Asm_Test


class Test_EXTR(Asm_Test):
    TXT = '''
main:
       MOVZ    X1, 0x1
       MOVZ    X2, 0x0
       EXTR    X0, X1, X2, 0x1
       MOVZ    X3, 0x0
       MOVZ    X4, 0x1
       EXTR    X5, X3, X4, 0x0
       RET     LR
    '''
    def check(self):
        # The result is extracted from X1:X2, with X1 as the high part
        assert(self.myjit.cpu.X0 == 0x8000000000000000)
        assert(self.myjit.cpu.X5 == 0x1)


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_EXTR]]
