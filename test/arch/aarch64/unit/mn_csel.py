#! /usr/bin/env python2

import sys

from asm_test import Asm_Test


class Test_CSEL_overflow_set(Asm_Test):
    TXT = '''
main:
       MOVZ    X1, 0x1
       MOVZ    X2, 0x2
       CSEL    X0, X1, X2, VS
       CSEL    X3, X1, X2, VC
       RET     LR
    '''
    OF = 1

    def run(self):
        self.myjit.cpu.of = self.OF
        super(Test_CSEL_overflow_set, self).run()

    def check(self):
        assert(self.myjit.cpu.X0 == 0x1)
        assert(self.myjit.cpu.X3 == 0x2)


class Test_CSEL_overflow_clear(Test_CSEL_overflow_set):
    OF = 0

    def check(self):
        assert(self.myjit.cpu.X0 == 0x2)
        assert(self.myjit.cpu.X3 == 0x1)


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_CSEL_overflow_set, Test_CSEL_overflow_clear]]
