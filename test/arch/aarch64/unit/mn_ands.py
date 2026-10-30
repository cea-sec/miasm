#! /usr/bin/env python2

import sys

from asm_test import Asm_Test


class Test_ANDS(Asm_Test):
    TXT = '''
main:
       MOVZ    X1, 0x3
       MOVZ    X2, 0x1
       ANDS    X0, X1, X2
       RET     LR
    '''
    def run(self):
        # C and V are set before ANDS, which clears them
        self.myjit.cpu.cf = 1
        self.myjit.cpu.of = 1
        super(Test_ANDS, self).run()

    def check(self):
        assert(self.myjit.cpu.X0 == 0x1)
        assert(self.myjit.cpu.nf == 0)
        assert(self.myjit.cpu.zf == 0)
        assert(self.myjit.cpu.cf == 0)
        assert(self.myjit.cpu.of == 0)


class Test_BICS(Test_ANDS):
    TXT = '''
main:
       MOVZ    X1, 0x3
       MOVZ    X2, 0x1
       BICS    X0, X1, X2
       RET     LR
    '''
    def check(self):
        assert(self.myjit.cpu.X0 == 0x2)
        assert(self.myjit.cpu.cf == 0)
        assert(self.myjit.cpu.of == 0)


class Test_TST(Test_ANDS):
    TXT = '''
main:
       MOVZ    X1, 0x3
       MOVZ    X2, 0x1
       TST     X1, X2
       RET     LR
    '''
    def check(self):
        assert(self.myjit.cpu.zf == 0)
        assert(self.myjit.cpu.cf == 0)
        assert(self.myjit.cpu.of == 0)


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_ANDS, Test_BICS, Test_TST]]
