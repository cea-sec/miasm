import sys
from asm_test import Asm_Test_64

class Test_ROR_0(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        ROR RAX, 0
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x8877665544332211


class Test_ROR_8(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        ROR RAX, 8
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x1188776655443322


class Test_ROR_X8(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        MOV CL, 16
        ROR RAX, CL
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x2211887766554433


class Test_SHR_0(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        SHR RAX, 0
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x8877665544332211


class Test_SHR_8(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        SHR RAX, 8
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x88776655443322


class Test_SHR_X8(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        MOV CL, 16
        SHR RAX, CL
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x887766554433



class Test_ROR_0_64_32(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        ROR EAX, 0
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x44332211


class Test_ROR_8_64_32(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        ROR EAX, 8
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x11443322


class Test_ROR_X8_64_32(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        MOV CL, 16
        ROR EAX, CL
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x22114433


class Test_SHR_0_64_32(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        SHR EAX, 0
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x44332211


class Test_SHR_8_64_32(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        SHR EAX, 8
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x443322


class Test_SHR_X8_64_32(Asm_Test_64):
    TXT = '''
main:
        MOV RAX, 0x8877665544332211
        MOV CL, 16
        SHR EAX, CL
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RAX == 0x4433



class Test_SHLD(Asm_Test_64):
    TXT = '''
main:
        MOV         RAX, 0x1234FDB512345678
        MOV         RDX, RAX
        MOV         RAX, 0x21AD96F921AD3D34
        MOV         RSI, RAX
        MOV         RAX, 0x0000000000000021
        MOV         RCX, RAX
        SHLD        EDX, ESI, CL
        RET
    '''
    def check(self):
        assert self.myjit.cpu.RDX == 0x000000002468ACF0


if __name__ == "__main__":
    [
        test(*sys.argv[1:])() for test in [
            Test_ROR_0,
            Test_ROR_8,
            Test_ROR_X8,

            Test_SHR_0,
            Test_SHR_8,
            Test_SHR_X8,

            Test_ROR_0_64_32,
            Test_ROR_8_64_32,
            Test_ROR_X8_64_32,

            Test_SHR_0_64_32,
            Test_SHR_8_64_32,
            Test_SHR_X8_64_32,

            Test_SHLD,
        ]
    ]

