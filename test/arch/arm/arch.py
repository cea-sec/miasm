import os
import time
from miasm2.arch.arm.arch import *

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

if 0:
    a = bs('00')
    b = bs('01')
    c = bs(l=2)
    d = bs(l=4, fname='rd')
    e = bs_name(l=1, name={'ADD': 0, 'SUB': 1})
    assert(isinstance(e, bs_divert))
    scc = bs_mod_name(l=1, mn_mod=['', 'S'])
    f = bs(l=1, cls=(arm_reg,))

    class arm_mov(mn_arm):
        fields = [bs('0000'), bs('0000'), bs('0000')]

    class arm_DATA(mn_arm):
        fields = [bs('1111'), e, scc, f, bs('0')]
    mn = mn_arm.dis(0xF000000)


if 0:
    import cProfile
    cProfile.run('mn_arm.dis("\xe1\xa0\xa0\x06", mode_arm)')
    # l = mn_arm.dis(bin_stream("\xe1\xa0\xa0\x06"), mode_arm)
    # print l
    """
    mode = 64
    l = mn_x86.fromstring("ADC      DWORD PTR [RAX], 0x11223344", mode)
    print 'xx'
    #t= time.time()
    import cProfile
    def f():
        x = l.asm(mode)
        print x
    cProfile.run('f()')
    """


def h2i(s):
    return s.replace(' ', '').decode('hex')


def u16swap(i):
    return struct.unpack('<H', struct.pack('>H', i))[0]

reg_tests_arm = [
    ("001504F4    MOV        R1, LR",
     "0e10a0e1"),
    ("00150500    ADD        R2, R8, R0",
     "002088e0"),
    ("001504E8    MOV        LR, 0x3E8",
     "faefa0e3"),
    ("001504F0    RSB        R0, R0, R3",
     "030060e0"),
    ("000E6F50    MUL        R2, LR, R6",
     "9e0602e0"),
    ("000620D8    MLA        R12, R0, R5, R3",
     "90352ce0"),
    ("00026798    ADDS       R2, R4, R0",
     "002094e0"),
    ("0003EA9C    MVN        R7, R2",
     "0270e0e1"),
    ("C00CD4DC    BL         0x7C",
     "1F0000EB"),
    ("C00CF110    BL         0xFFFFFDEC",
     "7BFFFFEB"),


    ("000829b0    BLNE       0xFFF87110",
     "441cfe1b"),

    ("C00EC608    TEQ        R4, R5",
     "050034e1"),
    ("C00CD53C    CMP        R9, R8",
     "080059e1"),
    ("C00CD5D8    MOV        R1, 0x60000000",
     "0612a0e3"),
    ("C00CEC18    MOV        R2, R1 LSL 0x14",
     "012aa0e1"),
    ("C00CF828    ORR        R0, R2, R1 LSL R0",
     "110082e1"),
    ("C00D8A14    EOR        R7, R2, R7 LSR 0x8",
     "277422e0"),
    ("C00CD2E4    MRS        R1, CPSR_cxsf",
     "00100fe1"),
    ("C019BE2C    MRS        R5, SPSR_cxsf",
     "00504fe1"),
    ("C00CD2F0    MSR        CPSR_cf, R1",
     "01f029e1"),
    ("C00D8A24    LDRB       R2, [R3, 0xFFFFFFFF]",    # LDRB  R2, [R3, #-1]
     "012053e5"),
    ("C01E59F8    LDREQ      R0, [R1, R0 LSL 0x2]",  # LDREQ R0, [R1, R0, LSL 2]
     "00019107"),
    ("C046855C    LDR        R0, [R9, R0 LSL 0x4]",  #
     "000299e7"),
    ('c012a8d8    LDREQ      R0, [R0]',
     '00009005'),
    ("C00D8AA8    LDR        R0, [R2], 0x4",           # LDR   R0, [R2], 4
     "040092e4"),
    ("C00D8A9C    LDR        R0, [PC, 0x514]",
     "14059fe5"),
    ("C03C7A38    LDR        R5, [R0, 0xD4]!",
     "d450b0e5"),
    ("C00EA214    LDMIA      R0, {R0, R1}",               # LDMIA   R0, {R0, R1}
     "030090e8"),
    ("C0121D70    LDMGEIA    R1, {R0, R1}",
     "030091a8"),
    ("C0124E68    LDMIB      R1, {R4, R12}",
     "101091e9"),
    ("C012D2A0    LDMDA      R7, {R0, R2}",
     "050017e8"),
    ("C0130A64    LDMFD      SP, {R0, R1}",
     "03009de8"),
    ("C016AAD0    LDMFD      SP!, {R8}",
     "0001bde8"),
    ("C00E0F98    LDMED      SP, {R4, R6}",
     "50009de9"),
    ("C0161AC0    STMFD      SP!, {R8}",               # stmfd
     "00012de9"),
    ("C00E0710    STMIA      R5, {R8, R9}",
     "000385e8"),
    ("C0460580    STMFA      SP, {R8, R10}",
     "00058de9"),
    ("C04FFBD0    STMEA      SP, {R9, R10}",
     "00068de8"),
    ("C00CEB10    STMDB      R8, {SP, LR}^",
     "006048e9"),
    ("C0129534    STMIB      R6, {R0, R9}",
     "010286e9"),
    ("C01293BC    STMFD      SP!, {R4-R11, LR}",
     "F04F2DE9"),
    ("C02FA8B4    SVCEQ      0x196A0B",
     "0B6a190f"),
    ("C00EF814    SVCMI      0x495020",
     "2050494F"),
    ("C00ED5CC    CDPCS      p3, 0x2, c7, c14, c5, 0x3",
     "65732e2e"),
    ("C00EFE88    CDPVS      p13, 0x2, c6, c0, c15, 0x3",
     "6F6D206e"),
    ("C0148ED0    LDCVS      p11, c5, [R4], 0xFFFFFF94!",  # -0x6C TODO XXX no wb !
     "1B5B346C"),
    ("C00ED374    MRCHI      p15, 0x5, LR, c14, c9, 0x7",
     "f9efbe8e"),
    ("C00F3D24    MCRVS      p0, 0x3, R2, c9, c4, 0x3",
     "7420696e"),
    #("xxxxxxxx    UND        0x0, 0x0",
    # "100000e6"),
    ("xxxxxxxx    BKPT       0x0, 0x0",
     "700020e1"),
    ("c00d153c    LDRH       R2, [R4, 0xCA]",
     "ba2cd4e1"),
    ("c00d18a8    LDRH       R6, [R12]",
     "b060dce1"),
    ("c00d8134    STRH       R3, [R6, 0x2]",
     "b230c6e1"),
    ("c00d80c4    STRH       R3, [R6]",
     "b030c6e1"),

    ("00031F40    LDRD       R8, [R7]",
     "D080C7E1"),

    ("c0104a34    LDRD       R0, [SP, 0x8]",
     "D800CDE1"),
    ("C013DC68    LDRD       R6, [R0, 0xFFFFFFF8]",
     "D86040E1"),

    ("C0120CC0    LDRSB      R1, [SP, 0x8]",
     "D810DDE1"),

    ("C0105C28    LDRSH      R0, [R8, 0xA]",
     "FA00D8E1"),

    ("C00D8FF4    LDRH       R3, [R12, R3]",
     "B3309CE1"),
    ("C012D1A4    LDRSB      R2, [R2, R1]",
     "D12092E1"),

    ("c0115a84    STRD       R0, [SP, 0x18]",
     "F801CDE1"),
    ("c0124a18    STRD       R2, [R0, 0xFFFFFFF8]",
     "F82040E1"),

    ("0002F5A8    MOV        R2, 0x2710",
     "102702E3"),

    ("0002F5B0    UMULL      R2, R3, R3, R2",
     "932283E0"),
    ("C045D260    SMULL      R3, R2, LR, R2",
     "9E32C2E0"),
    ("C03E6440    SMLAL      R2, R0, R1, R0",
     "9120E0E0"),

    ("C00CFA40    BLX        R12",
     "3CFF2FE1"),
    ("C010DE1C    BLX        0x1ECCEA",
     "3AB307FB"),

    ("00013028    MOV        R9, 0x6E75",
     "759E06E3"),

    ("0001302C    MOVT       R9, 0x64",
     "649040E3"),

    ("0004A38C    CLZ        R3, R2",
     "123F6FE1"),

    ("C0132564    BLX        0xFFFCF06C",
     "1B3CFFFA"),

    ("C0297028    QADD       R7, R6, R6",
     "567006E1"),

    ("6330A0E1    MOV        R3, R3 RRX",
     "6330A0E1"),

    ("XXXXXXXX    UXTB       R5, R2",
     "7250EFE6"),

    ("XXXXXXXX    UXTH       R7, R3",
     "7370FFE6"),
    ("XXXXXXXX    UBFX       R1, R2, 0x10, 0x8",
     "5218E7E7"),

    ("XXXXXXXX    UXTB       R0, R2",
     "7200EFE6"),
    ("XXXXXXXX    UXTH       R0, R2",
     "7200FFE6"),


]
ts = time.time()

for s, l in reg_tests_arm:
    print "-" * 80
    s = s[12:]
    b = h2i((l))
    mn = mn_arm.dis(b, mode_arm)
    print [str(x) for x in mn.args]
    print s
    print mn
    assert(str(mn) == s)
    # print hex(b)
    # print [str(x.get()) for x in mn.args]
    l = mn_arm.fromstring(s, mode_arm)
    # print l
    assert(str(l) == s)
    a = mn_arm.asm(l)
    print [x for x in a]
    print repr(b)
    # print mn.args
    assert(b in a)

reg_tests_armt = [
    ("0006ff5c    LSLS       R2, R0, 0x1A",
     "8206"),
    ("0006fe06    LSRS       R3, R3, 0x7",
     "db09"),
    ("0006af9c    ASRS       R0, R2, 0x1",
     "5010"),
    ("0006b1ea    ADDS       R1, R4, R5",
     "6119"),
    ("0006b304    ADDS       R2, R0, 0x1",
     "421c"),
    ("0006bc80    SUBS       R3, R1, 0x1",
     "4b1e"),
    ("0006f1d0    SUBS       R2, R6, R3",
     "f21a"),
    ("0006af30    MOVS       R3, 0x1",
     "0123"),
    ("0006b0ee    CMP        R3, 0x1",
     "012b"),
    ("C0100242    CMP        R2, 0x0",
     "002A"),
    ("0006b0f2    SUBS       R3, 0x1",
     "013b"),
    ("0006b12c    ADDS       R0, 0x4",
     "0430"),

    ("0006b944    ANDS       R2, R5",
     "2a40"),
    ("0014df06    EORS       R2, R0",
     "4240"),
    ("0008b66e    LSLS       R7, R1",
     "8f40"),
    ("002e7e0c    LSRS       R4, R0",
     "c440"),
    ("003258b6    ASRS       R2, R3",
     "1a41"),
    # adcs
    # sbcs
    # rors
    ("0017b754    TST        R0, R2",
     "1042"),
    ("0006e3fc    NEGS       R5, R5",
     "6d42"),
    ("0006b1fc    CMP        R6, R7",
     "be42"),
    ("001845ea    CMN        R3, R0",
     "c342"),
    ("001845ea    ORRS       R0, R4",
     "2043"),
    # muls
    # bic
    ("0006b90e    MVNS       R0, R3",
     "d843"),

    ("0006bcac    CMP        R6, R9",
     "4e45"),
    ("0006bcf0    CMP        R3, R1",
     "8b42"),
    ("0006c26c    CMP        R12, LR",
     "f445"),
    ("0006c8e4    CMP        R8, R2",
     "9045"),
    ("0006af70    MOV        R1, R0",
     "0146"),
    ("0006b3d0    MOV        R1, SP",
     "6946"),
    ("0006b47c    MOV        R8, R0",
     "8046"),
    ("0006bc8e    MOV        R8, SP",
     "e846"),
    ("0006aee0    BX         LR",
     "7047"),
    ("000a9d30    BX         R2",
     "1047"),

    ("0006b2dc    LDR        R0, [PC]",
     "0048"),
    ("00078798    LDR        R3, [PC, 0x4]",
     "014b"),

    ("00072dc2    LDR        R3, [R3, R0]",
     "1b58"),
    ("0008e5d4    LDR        R2, [R4, R0]",
     "2258"),
    ("0018e8ce    LDRB       R3, [R0, R4]",
     "035d"),
    ("0007b976    STR        R6, [R5, R4]",
     "2e51"),
    ("000b5b42    STRB       R7, [R1, R4]",
     "0f55"),

    ("002b02ae    STRH       R1, [R0, R3]",
     "c152"),
    ("002ea7de    LDRH       R5, [R6, R4]",
     "355b"),
    # ldsb
    # ldsh

    ("000a65c6    LDR        R7, [R0, 0x10]",
     "0769"),
    ("0006b308    LDRB       R5, [R1, 0x4]",
     "0d79"),
    ("0006b014    STR        R4, [R4, 0x38]",
     "a463"),
    ("0006b006    STRB       R5, [R0, 0x10]",
     "0574"),

    ("0009b598    STRH       R3, [R4, 0x2]",
     "6380"),
    ("000748da    LDRH       R2, [R6, 0x30]",
     "328E"),

    ("0006aed2    STR        R3, [SP, 0x24]",
     "0993"),
    ("0006ae6c    LDR        R3, [SP, 0x4]",
     "019b"),

    ("0006aed0    ADD        R1, SP, 0x20",
     "08a9"),
    ("000xxxxx    ADD        R1, PC, 0x20",
     "08a1"),

    ("0006aed8    ADD        SP, 0x30",
     "0cb0"),
    ("0006c1b0    SUB        SP, 0x18",
     "86b0"),


    ("0006aeee    POP        {R4, PC}",
     "10bd"),
    ("0006b03a    POP        {R4-R6, PC}",
     "70bd"),
    ("0006aee4    PUSH       {R4, LR}",
     "10b5"),
    ("0006b084    PUSH       {R0, R1, R4-R6, LR}",
     "73b5"),
    ("003139a0    PUSH       {LR}",
     "00b5"),
    ("00220f44    PUSH       {R2, R3}",
     "0cb4"),

    ("00076c54    LDMIA      R1, {R0, R1}",
     "03c9"),
    ("XXXXXXXX    LDMIA      R5!, {R0-R3}",
     "0fcd"),
    ("000a1c16    STMIA      R6!, {R0-R3}",
     "0fc6"),

    ("0006af78    BEQ        0x6",
     "03d0"),
    ("000747b4    BCC        0xFFFFFFE6",
     "f3d3"),
    # swi

    ("0007479c    B          0xE",
     "07e0"),
    ("0006b946    B          0xFFFFFFE4",
     "f2e7"),
    ("C010163C    BLX        0x1F916C",
     "F9F1B6E8"),
    ("C01015E8    BL         0x1F8D5C",
     "F8F1AEFE"),


    #("000xxxxx    BL       0x0",
    # "00F8"),
    #("000xxxxx    BL       0x4000",
    # "04F0"),
    #("000xxxxx    BL       0xFFFFF000",
    # "FFF7"),


    #("0006aea4    MOV      R5, R1",
    # "460d"),

    # adc
    # adc
    ("00000000    UND        ",
     "01de"),

    ("00000000    BLX        R7",
     "B847"),

    ("00000000    CBZ        R4, 0x2E",
     "bcb1"),
    ("00000000    CBNZ       R0, 0x2A",
     "a8b9"),

    ("00000000    SXTB       R2, R1",
     "4AB2"),
    ("00000000    SXTH       R1, R0",
     "01b2"),

    ("00000000    UXTH       R3, R2",
     "93b2"),

    ("00000000    UXTB       R5, R0",
     "C5B2"),
    ("xxxxxxxx    BKPT       0x13",
     "13be"),
    ("xxxxxxxx    SVC        0x13",
     "13df"),

]
print "#" * 40, 'armthumb', '#' * 40

for s, l in reg_tests_armt:
    print "-" * 80
    s = s[12:]
    b = h2i((l))
    print b.encode('hex')
    mn = mn_armt.dis(b, mode_armthumb)
    print [str(x) for x in mn.args]
    print s
    print mn
    assert(str(mn) == s)
    # print hex(b)
    # print [str(x.get()) for x in mn.args]
    l = mn_armt.fromstring(s, mode_armthumb)
    # print l
    assert(str(l) == s)
    a = mn_armt.asm(l)
    print [x for x in a]
    print repr(b)
    # print mn.args
    assert(b in a)

"""
print "*"*30, "START SPECIAL PARSING", "*"*30
parse_tests = [
    "MOV      LR, toto",
    "MOV      LR, 1+toto",
    "MOV      LR, (lend-lstart)^toto<<<R1",
    "MOV      LR, R1 LSL (l_end-l_start)^toto<<<R1",
    "MOV      LR, R1 LSL (l_end-l_start)^toto<<<R1",
    "EOR      R0, R1, toto^titi+1",
    ]

for l in parse_tests:
    print "-"*80
    l = mn_arm.fromstring(l, mode_arm)
    print l.name, ", ".join([str(a) for a in l.args])
"""


print 'TEST time', time.time() - ts

# speed test arm
o = ""
for s, l in reg_tests_arm:
    s = s[12:]
    b = h2i((l))
    o += b

while len(o) < 1000:
    o += o
bs = bin_stream_str(o)
off = 0
instr_num = 0
ts = time.time()
while off < bs.getlen():
    mn = mn_arm.dis(bs, mode_arm, off)
    instr_num += 1
    off += 4
print 'instr per sec:', instr_num / (time.time() - ts)


# speed test thumb
o = ""
for s, l in reg_tests_armt:
    s = s[12:]
    b = h2i((l))
    o += b

while len(o) < 1000:
    o += o
bs = bin_stream_str(o)
off = 0
instr_num = 0
ts = time.time()
while off < bs.getlen():
    mn = mn_armt.dis(bs, mode_armthumb, off)
    # print instr_num, off, str(mn)
    instr_num += 1
    off += mn.l
print 'instr per sec:', instr_num / (time.time() - ts)

import cProfile
cProfile.run(r'mn_arm.dis("\xe1\xa0\xa0\x06", mode_arm)')
