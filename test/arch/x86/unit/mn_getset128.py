#! /usr/bin/env python2

import sys

from asm_test import Asm_Test_32


class Test_get_set_128(Asm_Test_32):
    TXT = '''
    main:
       MOVD       XMM0, ESI
       MOVD       XMM1, EDI
       PCMPEQQ    XMM0, XMM1
       JZ         ret
       MOV        EAX, 1

       PUSH       0x11112222
       PUSH       0x33334444
       PUSH       0x55556666
       PUSH       0x77778888
       MOVAPS     XMM2, XMMWORD PTR [ESP]
       ADD        ESP, 0x10
    ret:
       RET
    '''

    def prepare(self):
        val = 1
        self.myjit.cpu.ESI = 0x11223344
        self.myjit.cpu.EDI = 0x11223345
        self.myjit.cpu.XMM0 = val

        # Check 128 get / set
        assert self.myjit.cpu.XMM0 == val
        assert self.myjit.cpu.get_gpreg()['XMM0'] == val

    def check(self):
        assert self.myjit.cpu.XMM0 == 0xffffffffffffffff0000000000000000
        assert self.myjit.cpu.XMM1 == 0x11223345

        # Check 128 get / set
        assert self.myjit.cpu.get_gpreg()['XMM0'] == 0xffffffffffffffff0000000000000000
        assert self.myjit.cpu.get_gpreg()['XMM1'] == 0x11223345

        assert self.myjit.cpu.get_gpreg()['XMM2'] == 0x11112222333344445555666677778888
        assert self.myjit.cpu.get_gpreg()['XMM2'] == 0x11112222333344445555666677778888


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [
        Test_get_set_128,
    ]]
