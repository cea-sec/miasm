#! /usr/bin/env python2

import sys

from asm_test import Asm_Test


class Test_DIV_BY_ZERO(Asm_Test):
    TXT = '''
main:
       MOVZ    X1, 0x7
       MOVZ    X2, 0x0
       MOVZ    X0, 0x55
       UDIV    X0, X1, X2
       MOVZ    X3, 0x55
       SDIV    X3, X1, X2
       RET     LR
    '''
    def check(self):
        assert(self.myjit.cpu.X0 == 0)
        assert(self.myjit.cpu.X3 == 0)


class Test_DIV(Asm_Test):
    TXT = '''
main:
       MOVZ    X1, 0x7
       MOVZ    X2, 0x2
       UDIV    X0, X1, X2
       RET     LR
    '''
    def check(self):
        assert(self.myjit.cpu.X0 == 3)


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_DIV_BY_ZERO, Test_DIV]]
