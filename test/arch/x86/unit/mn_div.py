import sys
from asm_test import Asm_Test_64

class Test_DIV(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        MOV RBX, 0x11223344556677
        DIV RBX
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x7F7
        assert self.myjit.cpu.RDX == 0x440

if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [Test_DIV]]
