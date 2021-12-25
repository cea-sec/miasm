import logging
import time
from miasm.arch.ppc.arch import mn_ppc
from miasm.core.bin_stream import bin_stream_str
from miasm.core.utils import decode_hex, encode_hex
from pdb import pm

def h2i(s):
    return decode_hex(s.replace(' ', ''))

reg_tests = [
    ('b', "XXXXXXXX    ADDI       R1, R1, 0x20", "38210020"),
    ('b', "XXXXXXXX    ADDI       R3, R4, 0x12", "38640012"),
    ('b', "XXXXXXXX    ADDIC      R3, R4, 0x12", "30640012"),
    ('b', "XXXXXXXX    ADDIC      R9, R0, 0xFFFFFFFF", "3120FFFF"),
    ('b', "XXXXXXXX    ADDIC.     R3, R4, 0x12", "34640012"),
    ('b', "XXXXXXXX    ADDIC.     R31, R31, 0xFFFFFFFE", "37fffffe"),
    ('b', "XXXXXXXX    ADDIS      R3, R4, 0x12", "3c640012"),
    ('b', "XXXXXXXX    ADDIS      R9, R9, 0xD76B", "3d29d76b"),
    ('b', "XXXXXXXX    AND        R8, R11, R28", "7d68e038"),
    ('b', "XXXXXXXX    AND.       R11, R9, R0", "7d2b0039"),
    ('b', "XXXXXXXX    ANDC       R0, R17, R19", "7e209878"),
    ('b', "XXXXXXXX    ANDC.      R9, R10, R0", "7d490079"),
    ('b', "XXXXXXXX    ANDI.      R9, R0, 0x1", "70090001"),
    ('b', "XXXXXXXX    ANDIS.     R9, R0, 0x1000", "74091000"),
    ('b', "XXXXXXXX    B          0xBEE0", "4800bee0"),
    ('b', "XXXXXXXX    BA         0xBEE0", "4800bee2"),
    ('b', "XXXXXXXX    BGE        CR0, 0x18", "40a00018"),
    ('b', "XXXXXXXX    BGEA       CR0, 0x18", "40a0001a"),
    ('b', "XXXXXXXX    BGECTR     CR0", "4ca00420"),
    ('b', "XXXXXXXX    BGECTRL    CR0", "4ca00421"),
    ('b', "XXXXXXXX    BGEL       CR0, 0x18", "40a00019"),
    ('b', "XXXXXXXX    BGELA      CR0, 0x18", "40a0001b"),
    ('b', "XXXXXXXX    BGELR      CR0", "4ca00020"),
    ('b', "XXXXXXXX    BGELRL     CR0", "4ca00021"),
    ('b', "XXXXXXXX    CMPLWI     CR7, R5, 0xBEEF", "2b85beef"),
    ('b', "XXXXXXXX    CMPW       CR3, R3, R2", "7d831000"),
    ('b', "XXXXXXXX    CMPWI      CR0, R0, 0x12", "2c000012"),
    ('b', "XXXXXXXX    CRAND      0x3, 0x5, 0x2", "4c651202"),
    ('b', "XXXXXXXX    ISYNC", "4c00012c"),
    ('b', "XXXXXXXX    LBZ        R11, 0xFFFFFFFE(R9)", "8969fffe"),
    ('b', "XXXXXXXX    LBZU       R0, 0x1(R31)", "8c1f0001"),
    ('b', "XXXXXXXX    LBZUX      R0, R31, R3", "7c1f18ee"),
    ('b', "XXXXXXXX    LBZX       R0, R30, R31", "7c1ef8ae"),
    ('b', "XXXXXXXX    LFS        FPR6, 0x1(R1)", "c0c10001"),
    ('b', "XXXXXXXX    LHA        R9, 0x8(R31)", "a93f0008"),
    ('b', "XXXXXXXX    LHAU       R0, 0xFFFFFFFE(R9)", "ac09fffe"),
    ('b', "XXXXXXXX    LHAX       R0, R11, R9", "7c0b4aae"),
    ('b', "XXXXXXXX    LHZ        R0, 0xC(R28)", "a01c000c"),
    ('b', "XXXXXXXX    LHZX       R0, R9, R10", "7c09522e"),
    ('b', "XXXXXXXX    LMW        R14, 0x8(R1)", "b9c10008"),
    ('b', "XXXXXXXX    LSWI       R5, R4, 0xC", "7ca464aa"),
    ('b', "XXXXXXXX    LVEWX      VR0, R1, R2", "7c01108e"),
    ('b', "XXXXXXXX    LVSL       VR0, R1, R2", "7c01100c"),
    ('b', "XXXXXXXX    LVSR       VR0, R1, R2", "7c01104c"),
    ('b', "XXXXXXXX    LWZ        R0, 0x24(R1)", "80010024"),
    ('b', "XXXXXXXX    LWZU       R0, 0x4(R7)", "84070004"),
    ('b', "XXXXXXXX    LWZX       R29, R25, R0", "7fb9002e"),
    ('b', "XXXXXXXX    MCRF       CR1, CR2", "4c880000"),
    ('b', "XXXXXXXX    MFFS       FPR23", "fee0048e"),
    ('b', "XXXXXXXX    MTFSF      0x88, FPR6", "fd10358e"),
    ('b', "XXXXXXXX    MTVSCR     VR0", "10000644"),
    ('b', "XXXXXXXX    MULLI      R0, R2, 0xFFFFFFE7", "1c02ffe7"),
    ('b', "XXXXXXXX    MULLI      R3, R30, 0xC", "1c7e000c"),
    ('b', "XXXXXXXX    NAND       R0, R0, R0", "7c0003b8"),
    ('b', "XXXXXXXX    OR         R8, R0, R9", "7c084b78"),
    ('b', "XXXXXXXX    OR.        R8, R0, R11", "7c085b79"),
    ('b', "XXXXXXXX    ORC        R9, R19, R17", "7e698b38"),
    ('b', "XXXXXXXX    ORI        R0, R0, 0xBEAF", "6000beaf"),
    ('b', "XXXXXXXX    ORI        R0, R9, 0x2", "61200002"),
    ('b', "XXXXXXXX    ORIS       R29, R29, 0x1", "67bd0001"),
    ('b', "XXXXXXXX    RFI", "4c000064"),
    ('b', "XXXXXXXX    RLWIMI     R3, R2, 0x3, 0x1, 0x10", "50431860"),
    ('b', "XXXXXXXX    RLWNM.     R3, R2, R4, 0x1, 0x10", "5c432061"),
    ('b', "XXXXXXXX    SC", "44000002"),
    ('b', "XXXXXXXX    SLW        R11, R23, R31", "7eebf830"),
    ('b', "XXXXXXXX    SRAW       R0, R11, R31", "7d60fe30"),
    ('b', "XXXXXXXX    SRAWI      R0, R10, 0x3", "7d401e70"),
    ('b', "XXXXXXXX    SRW        R0, R23, R10", "7ee05430"),
    ('b', "XXXXXXXX    STB        R0, 0x1020(R30)", "981e1020"),
    ('b', "XXXXXXXX    STBU       R0, 0x1(R11)", "9c0b0001"),
    ('b', "XXXXXXXX    STFS       FPR6, 0x1(R1)", "d0c10001"),
    ('b', "XXXXXXXX    STH        R6, (R3)", "b0c30000"),
    ('b', "XXXXXXXX    STMW       R14, 0x8(R1)", "bdc10008"),
    ('b', "XXXXXXXX    STW        R0, 0x24(R1)", "90010024"),
    ('b', "XXXXXXXX    STWU       R1, 0xFFFFFFE0(R1)", "9421ffe0"),
    ('b', "XXXXXXXX    SUBFIC     R0, R2, 0xFFFFFFE0", "2002ffe0"),
    ('b', "XXXXXXXX    SUBFIC     R11, R31, 0x0", "217f0000"),
    ('b', "XXXXXXXX    TW         0x5, R0, R3", "7ca01808"),
    ('b', "XXXXXXXX    TWI        0x5, R0, 0x12", "0ca00012"),
    ('b', "XXXXXXXX    XORI       R9, R0, 0x62", "68090062"),
    ('b', "XXXXXXXX    XORIS      R10, R10, 0x8000", "6d4a8000"),
]

ts = time.time()
for mode, s, l, in reg_tests:
    print("-" * 80)
    s = s[12:]
    b = h2i(l)
    print("fromstring %r" % s)
    l = mn_ppc.fromstring(s, None, mode)
    for x in mn_ppc.asm(l):
        print('(%r, "XXXXXXXX    %s", "%s"),' % (mode, l, encode_hex(x)))
    print("%s %r" % (mode, b))
    mn = mn_ppc.dis(b, mode)
    print("dis args %s" % [(str(x), x.size) for x in mn.args])
    print(s)
    print(mn)
    assert(str(mn).strip() == s)
    print('fromstring %r' % s)
    l = mn_ppc.fromstring(s, None, mode)
    print('str args %s' % [(str(x), x.size) for x in l.args])
    assert(str(l).strip(' ') == s)
    a = mn_ppc.asm(l)
    print('asm result %s' % [x for x in a])
    print(repr(b))
    print(l.to_html())

    print('test re dis')
    for x in a:
        print(repr(x))
        rl = mn_ppc.dis(x, mode)
        assert(str(rl).strip(' ') == s)
    print("%r %s" % (b, a))
    assert(b in a)
print('TEST time %s' % (time.time() - ts))
