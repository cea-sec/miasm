#! /usr/bin/env python
from asm_test import Asm_Test

class Test_SCAS(Asm_Test):
    MYSTRING = "test string"
    TXT = '''
    main:
       LEA EDI, DWORD PTR [mystr]
       XOR  ECX, ECX
       DEC  ECX
       REPNE SCASB
       NOT ECX
       DEC ECX
       RET

    mystr:
    .string "%s"
    ''' % MYSTRING

    def check(self):
        assert(self.myjit.cpu.ECX == len(self.MYSTRING))
        assert(self.myjit.cpu.EDI == self.myjit.ir_arch.symbol_pool.getby_name('mystr').offset + len(self.MYSTRING)+1)


class Test_MOVS(Asm_Test):
    MYSTRING = "test string"
    TXT = '''
    main:
       LEA ESI, DWORD PTR [mystr]
       LEA EDI, DWORD PTR [buffer]
       MOV ECX, %d
       REPE  MOVSB
       RET

    mystr:
    .string "%s"
    buffer:
    .string "%s"
    ''' % (len(MYSTRING), MYSTRING, " "*len(MYSTRING))

    def check(self):
        assert(self.myjit.cpu.ECX == 0)
        assert(self.myjit.cpu.EDI == self.myjit.ir_arch.symbol_pool.getby_name('buffer').offset + len(self.MYSTRING))
        assert(self.myjit.cpu.ESI == self.myjit.ir_arch.symbol_pool.getby_name('mystr').offset + len(self.MYSTRING))


if __name__ == "__main__":
    [test()() for test in [Test_SCAS, Test_MOVS]]
