#! /usr/bin/env python2

import sys

from asm_test import Asm_Test_32

class Test_CPUID(Asm_Test_32):
    """Check for cpuid support (and not for arbitrary returned values)"""
    TXT = '''
    main:
       XOR EAX, EAX
       CPUID
       RET
    '''

    def check(self):
        assert self.myjit.cpu.EAX == 0xa


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_CPUID]]
