import sys
from asm_test import Asm_Test_64

class Test_CMOVZ_OK(Asm_Test_64):
    TXT = '''
main:
        MOV   RAX, 0x8877665544332211
        MOV   RBX, RAX
        MOV   RAX, 0xAABBCCDDEEFF0011
        XOR   RCX, RCX
        CMOVZ RAX, RBX
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x8877665544332211


class Test_CMOVZ_KO(Asm_Test_64):
    TXT = '''
main:
        MOV   RAX, 0x8877665544332211
        MOV   RBX, RAX
        MOV   RAX, 0xAABBCCDDEEFF0011
        XOR   RCX, RCX
        INC   RCX
        CMOVZ RAX, RBX
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0xAABBCCDDEEFF0011


class Test_CMOVZ_OK_64_32(Asm_Test_64):
    TXT = '''
main:
        MOV   RAX, 0x8877665544332211
        MOV   RBX, RAX
        MOV   RAX, 0xAABBCCDDEEFF0011
        XOR   RCX, RCX
        CMOVZ EAX, EBX
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x44332211


class Test_CMOVZ_KO_64_32(Asm_Test_64):
    TXT = '''
main:
        MOV   RAX, 0x8877665544332211
        MOV   RBX, RAX
        MOV   RAX, 0xAABBCCDDEEFF0011
        XOR   RCX, RCX
        INC   RCX
        CMOVZ EAX, EBX
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0xEEFF0011



if __name__ == "__main__":
    [
        test(*sys.argv[1:])() for test in [
            Test_CMOVZ_OK,
            Test_CMOVZ_KO,
            Test_CMOVZ_OK_64_32,
            Test_CMOVZ_KO_64_32,
        ]
    ]

