from __future__ import print_function
import time

from miasm.core.utils import decode_hex, encode_hex
from miasm.arch.arm.arch import *
from miasm.core.locationdb import LocationDB
from pdb import pm


loc_db = LocationDB()

def h2i(s):
    return decode_hex(s.replace(' ', ''))


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
    ("C00CD4DC    BL         0x84",
     "1F0000EB"),
    ("C00CF110    BL         0xFFFFFDF4",
     "7BFFFFEB"),


    ("000829b0    BLNE       0xFFF87118",
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
    ('XXXXXXXX    BKPT       0x1234',
     '742321e1'),
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
    ("0002F5B4    UMLAL      R3, R4, R5, LR",
     "953EA4E0"),
    ("C045D260    SMULL      R3, R2, LR, R2",
     "9E32C2E0"),
    ("C03E6440    SMLAL      R2, R0, R1, R0",
     "9120E0E0"),

    ("00003904    SMULBB     R0, R0, R1",
     "800160E1"),
    ("00003904    SMULBT     R0, R0, R1",
     "C00160E1"),

    ("C00CFA40    BLX        R12",
     "3CFF2FE1"),
    ("C010DE1C    BLX        0x1ECCF2",
     "3AB307FB"),

    ("00013028    MOV        R9, 0x6E75",
     "759E06E3"),

    ("0001302C    MOVT       R9, 0x64",
     "649040E3"),

    ("0004A38C    CLZ        R3, R2",
     "123F6FE1"),

    ("C0132564    BLX        0xFFFCF074",
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

    ("XXXXXXXX    BFC        R0, 0x0, 0xD",
     "1f00cce7"),

    ("XXXXXXXX    REV        R0, R2",
     "320FBFE6"),

    ('XXXXXXXX    PLD        [R1]',
     '00F0D1F5'),
    ('XXXXXXXX    PLD        [R1, 0x1C]',
     '1CF0D1F5'),

    ('XXXXXXXX    UXTAB      R5, R2, R8',
     '7850e2e6'),

    ('XXXXXXXX    UXTAB      R5, R2, R8 ROR 0x8',
     '7854e2e6'),


    ('XXXXXXXX    PKHBT      R1, R2, R3 LSL 0x8',
     '131482e6'),
    ('XXXXXXXX    PKHBT      R1, R2, R3',
     '131082e6'),
    ('XXXXXXXX    PKHTB      R1, R2, R3 ASR 0x8',
     '531482e6'),
    ('XXXXXXXX    PKHTB      R1, R2, R3 ASR 0x20',
     '531082e6'),

    ('XXXXXXXX    MRC        p15, 0x0, R0, c1, c1, 0x0',
     '110f11ee'),
    ('XXXXXXXX    MCR        p15, 0x0, R8, c2, c0, 0x0',
     '108f02ee'),
    ('XXXXXXXX    MRCNE      p15, 0x0, R0, c1, c1, 0x0',
     '110f111e'),
    ('XXXXXXXX    MCRCC      p15, 0x0, R8, c2, c0, 0x1',
     '308f023e'),


]
ts = time.time()

for s, l in reg_tests_arm:
    print("-" * 80)
    s = s[12:]
    b = h2i((l))
    mn = mn_arm.dis(b, 'l')
    print([str(x) for x in mn.args])
    print(s)
    print(mn)
    assert(str(mn) == s)
    l = mn_arm.fromstring(s, loc_db, 'l')
    assert(str(l) == s)
    a = mn_arm.asm(l)
    print([x for x in a])
    print(repr(b))
    assert(b in a)
    print(l.to_html())

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
    ("003258b6    RORS       R3, R2",
     "D341"),

    ("0017b754    TST        R0, R2",
     "1042"),
    ("0006e3fc    NEGS       R5, R5",
     "6d42"),
    ("0006b1fc    CMP        R6, R7",
     "be42"),
    ("001845ea    CMN        R3, R0",
     "c342"),
    ("XXXXXXXX    CMN        R0, 0x1",
     "10F1010F"),
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
    ("0006ff5c    SUB        SP, SP, 0x670",
     "ADF5CE6D"),


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

    ("0006af78    BEQ        0xA",
     "03d0"),
    ("000747b4    BCC        0xFFFFFFEA",
     "f3d3"),
    # swi

    ("0007479c    B          0x12",
     "07e0"),
    ("XXXXXXXX    BLT        0xFFFFFFEA",
     "F3DB"),

    ("0006b946    B          0xFFFFFFE8",
     "f2e7"),
    ("C010163C    BLX        0x1F916C",
     "F9F1B6E8"),
    ("C01015E8    BL         0x1F8D60",
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

    ("00000000    BLX        R8",
     "C047"),

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

    ("00000000    UXTAB      R7, R0, R1",
     "50FA81F7"),

    ("00000000    UXTAH      R4, R0, R1",
     "10FA81F4"),

    ("xxxxxxxx    BKPT       0x13",
     "13be"),
    ("xxxxxxxx    SVC        0x13",
     "13df"),

    ("xxxxxxxx    NOP        ",
     "00bf"),

    ("xxxxxxxx    CPSID      AIF",
     "77B6"),
    ("xxxxxxxx    CPSIE      I",
     "62B6"),

    ("xxxxxxxx    WFI        ",
     "30bf"),


    ("xxxxxxxx    PUSH       {R4-R8, LR}",
     "2DE9F041"),
    ("xxxxxxxx    POP        {R4-R8, PC}",
     "BDE8F081"),
    ("xxxxxxxx    MOV        R12, 0x3",
     "4FF0030C"),
    ("xxxxxxxx    MOVS       R12, 0x3",
     "5FF0030C"),
    ("xxxxxxxx    ASR        R7, R3, R6",
     "43FA06F7"),
    ("xxxxxxxx    LSL        LR, R12, R7",
     "0CFA07FE"),
    ("xxxxxxxx    MVN        LR, LR",
     "6FEA0E0E"),
    ("xxxxxxxx    AND        R5, LR, R5",
     "0EEA0505"),
    ("xxxxxxxx    ORR        R5, R8, R5",
     "48EA0505"),
    ("xxxxxxxx    ORR        R5, R8, R5",
     "48EA0505"),
    ("xxxxxxxx    MOV        R0, 0x600",
     "4FF4C060"),
    ("xxxxxxxx    MOV        R0, 0x811",
     "40F61100"),
    ("xxxxxxxx    MOV        R1, R1 LSL 0x10",
     "4FEA0141"),

    ("xxxxxxxx    MOV        R2, R11 LSR 0x1",
     "4FEA5B02"),

    ("xxxxxxxx    ADD        R1, R4, 0x30",
     "04F13001"),

    ("xxxxxxxx    SDIV       R3, R5, R2",
     "95FBF2F3"),

    ("xxxxxxxx    MLS        R5, R2, R3, R5",
     "02FB1355"),

    ("xxxxxxxx    SMLABB     R2, R2, R3, R1",
     "12FB0312"),
    ("xxxxxxxx    SMLABT     R2, R2, R3, R1",
     "12FB1312"),
    ("xxxxxxxx    SMLATB     R2, R2, R3, R1",
     "12FB2312"),
    ("xxxxxxxx    SMLATT     R2, R2, R3, R1",
     "12FB3312"),

    ("xxxxxxxx    BIC        R1, R1, R3",
     "21EA0301"),
    ("xxxxxxxx    BIC        R4, R0, 0x400",
     "20F48064"),
    ("xxxxxxxx    ADD        R3, R1, R3 LSL 0x1",
     "01EB4303"),
    ("xxxxxxxx    SUB        R3, R0, 0x22",
     "A0F12203"),
    ("xxxxxxxx    UDIV       R3, R3, R1",
     "B3FBF1F3"),
    ("xxxxxxxx    MLA        R2, R6, R3, R2",
     "06FB0322"),

    ("xxxxxxxx    SUB        LR, R3, R2",
     "A3EB020E"),

    ("xxxxxxxx    ADD        R3, R3, 0x908",
     "03F60813"),

    ("xxxxxxxx    ADD        R3, R3, 0x23800",
     "03F50E33"),




    ("xxxxxxxx    B          0x4",
     "00F000B8"),
    #("xxxxxxxx    BEQ        0x4",
    # "00F000A8"),
    ("xxxxxxxx    BEQ        0x1D4",
     "00F0E880"),


    ("xxxxxxxx    UBFX       R1, R1, 0x0, 0x9",
     "C1F30801"),
    ("xxxxxxxx    UXTH       R9, R8",
     "1FFA88F9"),

    ("xxxxxxxx    AND        R2, R0, 0x1F",
     "00F01F02"),
    ("xxxxxxxx    RSB        R3, R3, 0x4",
     "C3F10403"),
    ("xxxxxxxx    RSB        R9, R9, R9 LSL 0x4",
     "C9EB0919"),


    ("xxxxxxxx    ITT        EQ",
     "04BF"),
    ("xxxxxxxx    ITE        EQ",
     "0CBF"),
    ("xxxxxxxx    ITT        HI",
     "84BF"),
    ("xxxxxxxx    ITTT       LT",
     "BEBF"),
    ("xxxxxxxx    ITE        NE",
     "14BF"),

    ("xxxxxxxx    STR        R5, [R0, 0xDC]",
     "C0F8DC50"),
    ("xxxxxxxx    STRB       R1, [R5, 0x4C]",
     "85F84C10"),
    ("xxxxxxxx    STRB       R2, [R3], 0x1",
     "03F8012B"),
    ("xxxxxxxx    STRH       R3, [R0, 0xE0]",
     "A0F8E030"),
    ("xxxxxxxx    STRH       R3, [R0], 0x2",
     "20F8023B"),


    ("xxxxxxxx    LDR        R3, [R0, 0xDC]",
     "D0F8DC30"),
    ("xxxxxxxx    LDR        R4, [SP], 0x4",
     "5DF8044B"),
    ("xxxxxxxx    LDRH       R3, [SP, 0x20]",
     "BDF82030"),

    ("xxxxxxxx    LDRB       R3, [R3, 0xFFFFFFF8]",
     "13F8083C"),
    ("xxxxxxxx    LDRB       R2, [R3, 0x30]",
     "93F83020"),
    ("xxxxxxxx    LDRB       R5, [R8, R6]",
     "18F80650"),
    ("xxxxxxxx    LDR        R3, [R4, R3 LSL 0x2]",
     "54F82330"),
    ("xxxxxxxx    LDRSB      R2, [R4, 0x30]",
     "94F93020"),
    ("xxxxxxxx    LDRH       R3, [R1], 0x2",
     "31F8023B"),
    ("xxxxxxxx    LDRH       R9, [SP, 0x14]",
     "BDF81490"),

    ("xxxxxxxx    STR        R3, [R2, 0xFFFFFFE4]",
     "42F81C3C"),



    ("xxxxxxxx    STR        R1, [R0, R3 LSL 0x2]",
     "40F82310"),

    ("xxxxxxxx    CLZ        R3, R3",
     "B3FA83F3"),

    ("xxxxxxxx    MOV        R0, 0x603",
     "40F20360"),
    ("xxxxxxxx    TBB        [PC, R0]",
     "DFE800F0"),
    ("xxxxxxxx    TBH        [PC, R0 LSL 0x1]",
     "DFE810F0"),


    ("xxxxxxxx    STRD       R5, R5, [R2, 0xFFFFFFF0]",
     "42E90455"),

    ("xxxxxxxx    MOV        R3, R3 ROR 0x19",
     "4FEA7363"),
    ("xxxxxxxx    MOV        R5, R5 LSL 0x3",
     "4FEAC505"),


    ("xxxxxxxx    SUB        R3, R3, 0x6BE",
     "A3F2BE63"),

    ("xxxxxxxx    PLD        [R0]",
     "90F800F0"),

    ("xxxxxxxx    LDRD       R2, R3, [R1]",
     "D1E90023"),

    ("xxxxxxxx    TST        R4, 0x4",
     "14F0040F"),

    ("xxxxxxxx    ORN        R2, R2, R5",
     "62EA0502"),

    ("xxxxxxxx    UADD8      R2, R2, R12",
     "82FA4CF2"),

    ("xxxxxxxx    SEL        R2, R4, R12",
     "A4FA8CF2"),

    ("xxxxxxxx    REV        R2, R2",
     "12BA"),

    ("xxxxxxxx    ADD        R8, SP, 0xC8",
     "0DF1C808"),

    ("xxxxxxxx    CMP        R9, 0x80",
     "B9F1800F"),

    ("xxxxxxxx    MUL        R2, R1, R2",
     "01FB02F2"),

    ("xxxxxxxx    LDRSH      R3, [R4, 0xC]",
     "B4F90C30"),

    ("xxxxxxxx    EOR        R3, R3, R1",
     "83EA0103"),

    ("xxxxxxxx    EOR        R0, R1, 0x42",
     "81F04200"),

    ("xxxxxxxx    DSB        SY",
     "bff34f8f"),

    ("xxxxxxxx    CMP        R5, R0 LSR 0x8",
     "B5EB102F"),


]
print("#" * 40, 'armthumb', '#' * 40)

for s, l in reg_tests_armt:
    print("-" * 80)
    s = s[12:]
    b = h2i((l))
    print(encode_hex(b))
    mn = mn_armt.dis(b, 'l')
    print([str(x) for x in mn.args])
    print(s)
    print(mn)
    assert(str(mn) == s)
    l = mn_armt.fromstring(s, loc_db, 'l')
    assert(str(l) == s)
    print('Asm..', l)
    a = mn_armt.asm(l)
    print([x for x in a])
    print(repr(b))
    assert(b in a)
    print(l.to_html())

print('TEST time', time.time() - ts)

# speed test arm
o = b""
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
    mn = mn_arm.dis(bs, 'l', off)
    instr_num += 1
    off += 4
print('instr per sec:', instr_num // (time.time() - ts))


# speed test thumb
o = b""
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
    mn = mn_armt.dis(bs, 'l', off)
    instr_num += 1
    off += mn.l
print('instr per sec:', instr_num // (time.time() - ts))

import cProfile
cProfile.run(r'mn_arm.dis("\xe1\xa0\xa0\x06", "l")')
