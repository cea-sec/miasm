#! /usr/bin/env python2
import sys

from miasm.jitter.csts import EXCEPT_INT_XX
from asm_test import Asm_Test_32


class Test_INT(Asm_Test_32):
    TXT = '''
    main:
       MOV ECX, 0x10
    loop:
       INT 0x42
       DEC ECX
       JNZ loop
    ret:
       RET
    '''

    def set_int_num(self, jitter):
        assert jitter.cpu.get_interrupt_num() == 0x42
        self.int_num += 1
        jitter.cpu.set_exception(0)
        return True

    def __init__(self, jitter):
        super(Test_INT, self).__init__(jitter)
        self.int_num = 0
        self.myjit.add_exception_handler(EXCEPT_INT_XX,
                                         self.set_int_num)

    def check(self):
        assert self.int_num == 0x10
        self.myjit.cpu.set_interrupt_num(14)
        assert self.myjit.cpu.get_interrupt_num() == 14


if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_INT]]
