#! /usr/bin/env python2

import sys

from asm_test import Asm_Test
from pdb import pm


class Test_UBFM1(Asm_Test):
    TXT = '''
main:
       MOVZ    X0, 0x5600
       UBFM    X0, X0, 8, 15
       RET     LR
    '''
    def check(self):
        assert(self.myjit.cpu.X0 == 0x56)
        pass

class Test_UBFM2(Asm_Test):
    TXT = '''
main:
       MOVZ    X0, 0x56
       UBFM    X0, X0, 4, 55
       RET     LR
    '''
    def check(self):
        assert(self.myjit.cpu.X0 == 0x5)
        pass


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_UBFM1, Test_UBFM2 ]]
