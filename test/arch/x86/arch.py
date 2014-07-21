import os
import time
from miasm2.arch.x86.arch import *

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)
for s in ["[EAX]",
          "[0x10]",
          "[EBX + 0x10]",
          "[EBX + ECX*0x10]",
          "[EBX + ECX*0x10 + 0x1337]"]:
    (e, a, b) = deref_mem_ad.scanString(s).next()
    print 'expr', e[0]

print '---'

mylabel16 = ExprId('mylabel16', 16)
mylabel32 = ExprId('mylabel32', 32)
mylabel64 = ExprId('mylabel64', 64)

reg_and_id = dict(mn_x86.regs.all_regs_ids_byname)
reg_and_id.update({'mylabel16': mylabel16,
                   'mylabel32': mylabel32,
                   'mylabel64': mylabel64,
                   })


def my_ast_id2expr(t):
    r = reg_and_id.get(t, ExprId(t, size=32))
    return r

my_var_parser = parse_ast(my_ast_id2expr, ast_int2expr)
base_expr.setParseAction(my_var_parser)

for s in ['EAX',
          "BYTE PTR [EAX]",
          "WORD PTR [EAX]",
          "DWORD PTR [ECX+0x1337]",
          "QWORD PTR [RAX+4*RCX + 0x1337]",
          "DWORD PTR [EAX+EBX]",
          "QWORD PTR [RAX+RBX+0x55667788]",
          "BYTE PTR CS:[EAX]",
          "QWORD PTR [RAX+RBX+mylabel64]",
          "BYTE PTR [RAX+RBX+mylabel64]",
          "BYTE PTR [AX+BX+mylabel16]",
          "BYTE PTR [mylabel32]",
          ]:
    print '*' * 80
    print s
    (e, a, b) = rmarg.scanString(s).next()
    print 'expr', e[0]
    e[0].visit(print_size)


def h2i(s):
    return int(s.replace(' ', '').decode('hex')[::].encode('hex'), 16)


m16 = 16  # (16, 16)
m32 = 32  # (32, 32)
m64 = 64  # (64, 64)
reg_tests = [


    (m32, "00000000    AAA",
     "37"),
    (m32, "00000000    AAS",
     "3F"),
    (m32, "00000000    AAD        0x11",
     "d511"),
    (m32, "00000000    AAM        0x11",
     "d411"),
    (m32, "00000000    ADC        AL, 0x11",
     "1411"),
    (m32, "00000000    ADC        EAX, 0x11223344",
     "1544332211"),
    (m16, "00000000    ADC        AX, 0x1122",
     "152211"),
    (m64, "00000000    ADC        EAX, 0x11223344",
     "1544332211"),
    (m64, "00000000    ADC        RAX, 0x11223344",
     "481544332211"),
    (m32, "00000000    ADC        EAX, 0xFFFFFFFC",
     "83d0fc"),
    (m64, "00000000    ADC        RAX, 0xFFFFFFFFFFFFFFFC",
     "4883d0fc"),
    (m16, "00000000    ADC        AX, 0xFFFC",
     "83d0fc"),
    (m64, "00000000    ADC        EAX, 0xFFFFFFFC",
     "15fcffffff"),
    (m64, "00000000    ADC        RAX, 0xFFFFFFFFFFFFFFFC",
     "4815fcffffff"),
    (m16, "00000000    ADC        WORD PTR [BX+SI], 0x1122",
     "81102211"),
    (m32, "00000000    ADC        DWORD PTR [EAX], 0x11223344",
     "811044332211"),
    (m32, "00000000    ADC        DWORD PTR [EAX+EBX+0xFFFFFFFE], 0x11223344",
     "815418fe44332211"),
    (m32, "00000000    ADC        DWORD PTR [EAX+EBX+0x55667788], 0x11223344",
     "8194188877665544332211"),
    (m64, "00000000    ADC        DWORD PTR [RAX], 0x11223344",
     "811044332211"),
    (m64, "00000000    ADC        QWORD PTR [RAX], 0x11223344",
     "48811044332211"),
    (m64, "00000000    ADC        QWORD PTR [RAX+RBX], 0x11223344",
     "4881141844332211"),
    (m64, "00000000    ADC        QWORD PTR [RAX+RBX+0x55667788], 0x11223344",
     "488194188877665544332211"),
    (m64, "00000000    ADC        QWORD PTR [RAX+RBX+0xFFFFFFFFFFFFFFFE], 0x11223344",
     "48815403fe44332211"),
    (m64, "00000000    ADC        QWORD PTR [EAX], 0x11223344",
     "6748811044332211"),
    (m32, "00000000    ADC        BYTE PTR [EAX], 0x11",
     "801011"),
    (m16, "00000000    ADC        DX, 0x1122",
     "81d22211"),
    (m32, "00000000    ADC        EDX, 0x11223344",
     "81d244332211"),
    (m64, "00000000    ADC        RDX, 0x11223344",
     "4881d244332211"),
    (m32, "00000000    ADC        DWORD PTR [EAX+EBX], 0x11223344",
     "81141844332211"),
    (m32, "00000000    ADC        DWORD PTR [EAX+EBX], EAX",
     "110418"),
    (m64, "00000000    ADC        QWORD PTR [RAX+RBX], RAX",
     "48110418"),
    (m32, "00000000    ADC        BYTE PTR [EAX+EBX], AL",
     "100418"),
    (m32, "00000000    ADC        AL, BYTE PTR [EAX+EBX]",
     "120418"),
    (m16, "00000000    ADC        WORD PTR [BX+SI], DX",
     "1110"),
    (m32, "00000000    ADC        WORD PTR [BX+SI], DX",
     "66671110"),
    (m16, "00000000    ADC        DWORD PTR [EBX+ESI], EDX",
     "6667111433"),

    # prefix test
    (m32, "00000000    ADC        AX, 0x1122",
     "66152211"),

    (m32, "00000000    ADC        EAX, 0x11223344",
     "1544332211"),

    (m16, "00000000    ADC        WORD PTR [BX+DI], 0x1",
     "831101"),
    (m32, "00000000    ADC        DWORD PTR [EAX+EBX+0xFFFFFFFE], 0x1",
     "835403fe01"),
    (m32, "00000000    ADC        WORD PTR [EAX+EBX+0xFFFFFFFE], 0x1",
     "66835403fe01"),
    (m64, "00000000    ADC        DWORD PTR [RAX+RBX+0xFFFFFFFFFFFFFFFE], 0x1",
     "835403fe01"),
    #
    (m32, "00000000    ADC        DWORD PTR [EAX+EBX*0x4+0xFFFFFFFE], 0x1",
     "835498fe01"),

    (m64, "00000000    ADC        QWORD PTR [RAX+RBX], R8",
     "4c110418"),
    (m64, "00000000    ADC        QWORD PTR [RAX+RBX], R15",
     "4c113c18"),

    (m64, "00000000    ADC        QWORD PTR [R8], RAX",
     "491100"),
    (m64, "00000000    ADC        QWORD PTR [R8+R9], RAX",
     "4b110408"),
    (m64, "00000000    ADC        QWORD PTR [R8+RBP], RAX",
     "49110428"),
    (m64, "00000000    ADC        QWORD PTR [RBP+R8*0x4], RAX",
     "4a11448500"),
    (m64, "00000000    ADC        QWORD PTR [RBP+R12*0x4], RAX",
     "4a1144a500"),
    (m64, "00000000    ADC        QWORD PTR [RSP+R12*0x4], RAX",
     "4a1104a4"),
    (m64, "00000000    ADC        QWORD PTR [R12*0x5], RAX",
     "4b1104a4"),
    (m64, "00000000    ADC        QWORD PTR [R12*0x5+0x11], RAX",
     "4b1144a411"),
    (m64, "00000000    ADC        QWORD PTR [RBP+R12*0x4+0x10], RAX",
     "4a1144a510"),

    (m32, "00000000    ADD        AL, 0x11",
     "0411"),
    (m32, "00000000    ADD        EAX, 0x11223344",
     "0544332211"),


    (m32, "00000000    AND        AL, 0x11",
     "2411"),
    (m32, "00000000    AND        EAX, 0x11223344",
     "2544332211"),
    (m64, "00000000    AND        CX, R14W",
     "664123CE"),
    (m64, "00000000    AND        R12W, R14W",
     "664521f4"),



    (m32, "00000000    BSF        EAX, DWORD PTR [EAX]",
     "0fbc00"),

    (m32, "00000000    BSR        EAX, DWORD PTR [EAX]",
     "0fbd00"),

    (m32, "00000000    BSWAP      EAX",
     "0fc8"),

    (m32, "00000000    BT         DWORD PTR [EAX], EAX",
     "0fa300"),
    (m32, "00000000    BT         DWORD PTR [EAX], 0x11",
     "0fba2011"),
    (m32, "00000000    BT         DWORD PTR [EAX], 0xFF",
     "0fba20ff"),
    (m64, "00000000    BT         R9D, 0x1E",
     "410fbae11e"),

    (m32, "00000000    BTC        DWORD PTR [EAX], EAX",
     "0fbb00"),
    (m32, "00000000    BTC        DWORD PTR [EAX], 0x42",
     "0fba3842"),


    (m32, "00000000    BTR        DWORD PTR [EAX], EAX",
     "0fb300"),
    (m32, "00000000    BTR        DWORD PTR [EAX], 0x42",
     "0fba3042"),


    (m32, "00000000    BTS        DWORD PTR [EAX], EAX",
     "0fab00"),
    (m32, "00000000    BTS        DWORD PTR [EAX], 0x42",
     "0fba2842"),


    (m32, "00000000    CALL       0x112233",
     "e833221100"),
    (m64, "00000000    CALL       0x112233",
     "e833221100"),
    (m32, "00000000    CALL       DWORD PTR [EAX]",
     "ff10"),
    (m64, "00000000    CALL       QWORD PTR [RAX]",
     "ff10"),

    (m32, "00000000    CALL       0x6655:0x44332211",
     "9a112233445566"),
    (m32, "00000000    CALL       0x6655:0xFF332211",
     "9a112233FF5566"),


    (m16, "00000000    CBW",
     "98"),
    (m16, "00000000    CWDE",
     "6698"),
    (m32, "00000000    CWDE",
     "98"),
    (m64, "00000000    CWDE",
     "98"),
    (m64, "00000000    CDQE",
     "4898"),

    (m32, "00000000    CMOVO      EAX, DWORD PTR [EAX]",
     "0f4000"),
    (m32, "00000000    CMOVNO     EAX, DWORD PTR [EAX]",
     "0f4100"),
    (m32, "00000000    CMOVB      EAX, DWORD PTR [EAX]",
     "0f4200"),
    (m32, "00000000    CMOVAE     EAX, DWORD PTR [EAX]",
     "0f4300"),
    (m32, "00000000    CMOVZ      EAX, DWORD PTR [EAX]",
     "0f4400"),
    (m32, "00000000    CMOVNZ     EAX, DWORD PTR [EAX]",
     "0f4500"),
    (m32, "00000000    CMOVBE     EAX, DWORD PTR [EAX]",
     "0f4600"),
    (m32, "00000000    CMOVA      EAX, DWORD PTR [EAX]",
     "0f4700"),
    (m32, "00000000    CMOVS      EAX, DWORD PTR [EAX]",
     "0f4800"),
    (m32, "00000000    CMOVNS     EAX, DWORD PTR [EAX]",
     "0f4900"),
    (m32, "00000000    CMOVPE     EAX, DWORD PTR [EAX]",
     "0f4A00"),
    (m32, "00000000    CMOVNP     EAX, DWORD PTR [EAX]",
     "0f4B00"),
    (m32, "00000000    CMOVL      EAX, DWORD PTR [EAX]",
     "0f4C00"),
    (m32, "00000000    CMOVGE     EAX, DWORD PTR [EAX]",
     "0f4D00"),
    (m32, "00000000    CMOVLE     EAX, DWORD PTR [EAX]",
     "0f4E00"),
    (m32, "00000000    CMOVG      EAX, DWORD PTR [EAX]",
     "0f4F00"),

    (m32, "00000000    CMP        EAX, DWORD PTR [EAX]",
     "3b00"),

    (m32, "00000000    CMPXCHG    BYTE PTR [EAX], AL",
     "0fb000"),
    (m32, "00000000    CMPXCHG    DWORD PTR [EAX], EAX",
     "0fb100"),

    (m32, "00000000    CDQ",
     "99"),
    (m64, "00000000    CQO",
     "4899"),

    (m32, "00000000    DEC        BYTE PTR [EAX]",
     "fe08"),
    (m32, "00000000    DEC        DWORD PTR [EAX]",
     "ff08"),

    (m32, "00000000    DEC        ECX",
     "49"),

    (m32, "00000000    DIV        BL",
     "f6f3"),
    (m32, "00000000    DIV        EBX",
     "f7f3"),

    (m32, "00000000    ENTER      0x12, 0x0",
     "c8120000"),
    (m32, "00000000    ENTER      0x12, 0x66",
     "c8120066"),

    (m32, "00000000    F2XM1",
     "D9f0"),
    (m32, "00000000    FABS",
     "D9e1"),

    (m16, "00000000    FADD       DWORD PTR [BX+SI]",
     "D800"),
    (m32, "00000000    FADD       DWORD PTR [EAX]",
     "D800"),
    (m32, "00000000    FADD       QWORD PTR [EAX]",
     "DC00"),

    (m32, "00000000    FADD       ST, ST(2)",
     "D8C2"),
    (m32, "00000000    FADD       ST(2), ST",
     "DCC2"),

    (m32, "00000000    FADDP      ST(2), ST",
     "DEC2"),

    (m16, "00000000    FIADD      DWORD PTR [BX+SI]",
     "DA00"),
    (m32, "00000000    FIADD      DWORD PTR [EAX]",
     "DA00"),
    (m32, "00000000    FIADD      WORD PTR [EAX]",
     "DE00"),

    (m32, "00000000    FBLD       TBYTE PTR [EAX]",
     "DF20"),
    (m64, "00000000    FBLD       TBYTE PTR [RAX]",
     "DF20"),

    (m32, "00000000    FBLDP      TBYTE PTR [EAX]",
     "DF30"),
    (m64, "00000000    FBLDP      TBYTE PTR [RAX]",
     "DF30"),

    (m16, "00000000    FCHS",
     "d9e0"),
    (m32, "00000000    FCHS",
     "d9e0"),
    (m64, "00000000    FCHS",
     "d9e0"),


    #(m32, "00000000    FCLEX",
    # "9bdbe2"),
    (m32, "00000000    FNCLEX",
     "dbe2"),

    (m32, "00000000    FCMOVB     ST, ST(2)",
     "dac2"),

    (m32, "00000000    FCOM       DWORD PTR [EAX]",
     "d810"),
    (m32, "00000000    FCOM       QWORD PTR [EAX]",
     "dC10"),
    (m32, "00000000    FCOMP      DWORD PTR [EAX]",
     "d818"),
    (m32, "00000000    FCOMP      QWORD PTR [EAX]",
     "dC18"),
    (m32, "00000000    FCOMPP",
     "ded9"),

    (m32, "00000000    FCOMI      ST, ST(2)",
     "dbf2"),
    (m32, "00000000    FCOMIP     ST, ST(2)",
     "dff2"),

    (m32, "00000000    FUCOMI     ST, ST(2)",
     "dbea"),
    (m32, "00000000    FUCOMIP    ST, ST(2)",
     "dfea"),

    (m32, "00000000    FCOS",
     "d9ff"),

    (m32, "00000000    FDECSTP",
     "d9f6"),


    (m16, "00000000    FDIV       DWORD PTR [BX+SI]",
     "D830"),
    (m32, "00000000    FDIV       DWORD PTR [EAX]",
     "D830"),
    (m32, "00000000    FDIV       QWORD PTR [EAX]",
     "DC30"),

    (m32, "00000000    FDIV       ST, ST(2)",
     "D8F2"),
    (m32, "00000000    FDIV       ST(2), ST",
     "DCFA"),

    (m32, "00000000    FDIVP      ST(2), ST",
     "DEFA"),

    (m16, "00000000    FIDIV      DWORD PTR [BX+SI]",
     "DA30"),
    (m32, "00000000    FIDIV      DWORD PTR [EAX]",
     "DA30"),
    (m32, "00000000    FIDIV      WORD PTR [EAX]",
     "DE30"),



    (m16, "00000000    FDIVR      DWORD PTR [BX+SI]",
     "D838"),
    (m32, "00000000    FDIVR      DWORD PTR [EAX]",
     "D838"),
    (m32, "00000000    FDIVR      QWORD PTR [EAX]",
     "DC38"),

    (m32, "00000000    FDIVR      ST, ST(2)",
     "D8Fa"),
    (m32, "00000000    FDIVR      ST(2), ST",
     "DCF2"),

    (m32, "00000000    FDIVRP     ST(2), ST",
     "DEF2"),

    (m16, "00000000    FIDIVR     DWORD PTR [BX+SI]",
     "DA38"),
    (m32, "00000000    FIDIVR     DWORD PTR [EAX]",
     "DA38"),
    (m32, "00000000    FIDIVR     WORD PTR [EAX]",
     "DE38"),

    (m32, "00000000    FFREE      ST(2)",
     "DDC2"),

    (m32, "00000000    FICOM      WORD PTR [EAX]",
     "DE10"),
    (m32, "00000000    FICOM      DWORD PTR [EAX]",
     "DA10"),

    (m32, "00000000    FICOMP     WORD PTR [EAX]",
     "DE18"),
    (m32, "00000000    FICOMP     DWORD PTR [EAX]",
     "DA18"),

    (m32, "00000000    FILD       WORD PTR [EAX]",
     "DF00"),
    (m32, "00000000    FILD       DWORD PTR [EAX]",
     "DB00"),


    (m32, "00000000    FILD       QWORD PTR [EAX]",
     "DF28"),

    (m32, "00000000    FINCSTP",
     "d9f7"),

    #(m32, "00000000    FINIT",
    # "9bdbe3"),
    (m32, "00000000    FNINIT",
     "dbe3"),

    (m32, "00000000    FIST       WORD PTR [EAX]",
     "DF10"),
    (m32, "00000000    FIST       DWORD PTR [EAX]",
     "DB10"),

    (m32, "00000000    FISTP      WORD PTR [EAX]",
     "DF18"),
    (m32, "00000000    FISTP      DWORD PTR [EAX]",
     "DB18"),

    (m32, "00000000    FISTP      QWORD PTR [EAX]",
     "Df38"),

    (m32, "00000000    FISTTP     WORD PTR [EAX]",
     "DF08"),
    (m32, "00000000    FISTTP     DWORD PTR [EAX]",
     "DB08"),

    (m32, "00000000    FISTTP     QWORD PTR [EAX]",
     "Dd08"),

    (m32, "00000000    FLD        DWORD PTR [EAX]",
     "d900"),
    (m32, "00000000    FLD        QWORD PTR [EAX]",
     "dd00"),

    (m32, "00000000    FLD        TBYTE PTR [EAX]",
     "db28"),
    (m32, "00000000    FLD        ST(2)",
     "d9c2"),


    (m32, "00000000    FLD1",
     "d9e8"),
    (m32, "00000000    FLDL2T",
     "d9e9"),
    (m32, "00000000    FLDL2E",
     "d9eA"),
    (m32, "00000000    FLDPI",
     "d9eB"),
    (m32, "00000000    FLDLG2",
     "d9eC"),
    (m32, "00000000    FLDLN2",
     "d9eD"),
    (m32, "00000000    FLDZ",
     "d9eE"),

    (m32, "00000000    FLDCW      WORD PTR [EAX]",
     "d928"),



    (m16, "00000000    FMUL       DWORD PTR [BX+SI]",
     "D808"),
    (m32, "00000000    FMUL       DWORD PTR [EAX]",
     "D808"),
    (m32, "00000000    FMUL       QWORD PTR [EAX]",
     "DC08"),

    (m32, "00000000    FMUL       ST, ST(2)",
     "D8Ca"),
    (m32, "00000000    FMUL       ST(2), ST",
     "DCCa"),

    (m32, "00000000    FMULP      ST(2), ST",
     "DECa"),

    (m16, "00000000    FIMUL      DWORD PTR [BX+SI]",
     "DA08"),
    (m32, "00000000    FIMUL      DWORD PTR [EAX]",
     "DA08"),
    (m32, "00000000    FIMUL      WORD PTR [EAX]",
     "DE08"),

    (m32, "00000000    FNOP",
     "D9d0"),
    (m32, "00000000    FPATAN",
     "D9f3"),
    (m32, "00000000    FPREM",
     "D9f8"),
    (m32, "00000000    FPREM1",
     "D9f5"),
    (m32, "00000000    FPTAN",
     "D9f2"),
    (m32, "00000000    FRNDINT",
     "D9fc"),

    (m32, "00000000    FRSTOR     TBYTE PTR [EAX]",
     "dd20"),

    #(m32, "00000000    FSAVE      TBYTE PTR [EAX]",
    # "9bdd30"),
    (m32, "00000000    FNSAVE     TBYTE PTR [EAX]",
     "dd30"),

    (m32, "00000000    FSCALE",
     "d9fd"),

    (m32, "00000000    FSIN",
     "d9fe"),
    (m32, "00000000    FSINCOS",
     "d9fb"),
    (m32, "00000000    FSQRT",
     "d9fa"),



    (m32, "00000000    FST        DWORD PTR [EAX]",
     "D910"),
    (m32, "00000000    FST        QWORD PTR [EAX]",
     "DD10"),

    (m32, "00000000    FST        ST(2)",
     "ddd2"),

    (m32, "00000000    FSTP       DWORD PTR [EAX]",
     "D918"),
    (m32, "00000000    FSTP       QWORD PTR [EAX]",
     "Dd18"),
    (m32, "00000000    FSTP       TBYTE PTR [EAX]",
     "db38"),

    #(m32, "00000000    FSTCW      WORD PTR [EAX]",
    # "9bd938"),
    (m32, "00000000    FNSTCW     WORD PTR [EAX]",
     "d938"),

    (m32, "00000000    FNSTENV    TBYTE PTR [EAX]",
     "d930"),
    #(m32, "00000000    FSTENV     TBYTE PTR [EAX]",
    # "9bd930"),

    (m32, "00000000    FNSTSW     WORD PTR [EAX]",
     "dd38"),
    #(m32, "00000000    FSTSW      WORD PTR [EAX]",
    # "9bdd38"),

    #(m32, "00000000    FSTSW      AX",
    # "9bdfe0"),
    (m32, "00000000    FNSTSW     AX",
     "dfe0"),

    (m16, "00000000    FSUB       DWORD PTR [BX+SI]",
     "D820"),
    (m32, "00000000    FSUB       DWORD PTR [EAX]",
     "D820"),
    (m32, "00000000    FSUB       QWORD PTR [EAX]",
     "DC20"),

    (m32, "00000000    FSUB       ST, ST(2)",
     "D8E2"),
    (m32, "00000000    FSUB       ST(2), ST",
     "DCEA"),

    (m32, "00000000    FSUBP      ST(2), ST",
     "DEEA"),

    (m16, "00000000    FISUB      DWORD PTR [BX+SI]",
     "DA20"),
    (m32, "00000000    FISUB      DWORD PTR [EAX]",
     "DA20"),
    (m32, "00000000    FISUB      WORD PTR [EAX]",
     "DE20"),



    (m16, "00000000    FSUBR      DWORD PTR [BX+SI]",
     "D828"),
    (m32, "00000000    FSUBR      DWORD PTR [EAX]",
     "D828"),
    (m32, "00000000    FSUBR      QWORD PTR [EAX]",
     "DC28"),

    (m32, "00000000    FSUBR      ST, ST(2)",
     "D8EA"),
    (m32, "00000000    FSUBR      ST(2), ST",
     "DCE2"),

    (m32, "00000000    FSUBRP     ST(2), ST",
     "DEE2"),

    (m16, "00000000    FISUBR     DWORD PTR [BX+SI]",
     "DA28"),
    (m32, "00000000    FISUBR     DWORD PTR [EAX]",
     "DA28"),
    (m32, "00000000    FISUBR     WORD PTR [EAX]",
     "DE28"),

    (m32, "00000000    FTST",
     "d9e4"),

    (m32, "00000000    FUCOM      ST(2)",
     "dde2"),
    (m32, "00000000    FUCOMP     ST(2)",
     "DDEA"),
    (m32, "00000000    FUCOMPP",
     "DAe9"),

    (m32, "00000000    FXAM",
     "d9e5"),

    (m32, "00000000    FXCH       ST(2)",
     "d9ca"),

    (m32, "00000000    FXRSTOR    TBYTE PTR [EAX]",
     "0fae08"),
    (m32, "00000000    FXSAVE     TBYTE PTR [EAX]",
     "0fae00"),

    (m32, "00000000    FXTRACT",
     "d9f4"),
    (m32, "00000000    FYL2X",
     "d9f1"),
    (m32, "00000000    FYL2XP1",
     "d9f9"),

    (m32, "00000000    HLT",
     "f4"),
    (m32, "00000000    ICEBP",
     "f1"),

    (m32, "00000000    IDIV       BYTE PTR [EAX]",
     "f638"),
    (m32, "00000000    IDIV       DWORD PTR [EAX]",
     "f738"),

    (m32, "00000000    IMUL       EAX, DWORD PTR [EAX]",
     "0faf00"),


    (m32, "00000000    IMUL       EAX, EBX, 0x8",
     "6bc308"),
    (m32, "00000000    IMUL       EAX, EBX, 0xFFFFFFFF",
     "6bc3FF"),
    (m32, "00000000    IMUL       EAX, DWORD PTR [EBX], 0x11223344",
     "690344332211"),
    (m64, "00000000    IMUL       RAX, QWORD PTR [RBX], 0x11223344",
     "48690344332211"),
    (m64, "00000000    IMUL       RAX, QWORD PTR [RBX], 0x11223344",
     "48690344332211"),
    (m64, "00000000    IMUL       RAX, QWORD PTR [RBX], 0xFFFFFFFFF1223344",
     "486903443322F1"),
    (m16, "00000000    IMUL       AX, BX, 0x8",
     "6bc308"),
    (m16, "00000000    IMUL       AX, BX, 0xFFF0",
     "6bc3F0"),

    (m32, "00000000    IN         AL, 0x12",
     "e412"),
    (m32, "00000000    IN         EAX, 0x12",
     "e512"),
    (m64, "00000000    IN         RAX, 0x12",
     "48e512"),

    (m32, "00000000    IN         AL, DL",
     "EC"),
    (m32, "00000000    IN         EAX, EDX",
     "ED"),
    (m32, "00000000    IN         AX, DX",
     "66ED"),

    (m32, "00000000    INC        DWORD PTR [EAX]",
     "ff00"),
    (m32, "00000000    INC        ECX",
     "41"),

    (m32, "00000000    INT        0x3",
     "CC"),
    (m32, "00000000    INT        0x21",
     "CD21"),

    (m16, "00000000    IRET",
     "CF"),
    (m32, "00000000    IRETD",
     "CF"),
    (m64, "00000000    IRETQ",
     "48CF"),

    (m32, "00000000    JA         0x12",
     "7712"),
    (m32, "00000000    JA         0xFFFFFFEE",
     "77EE"),
    (m64, "00000000    JA         0xFFFFFFFFFFFFFFEE",
     "77EE"),

    #(m32, "00000000    JA         0xFFEE",
    # "6677EE"),
    #(m64, "00000000    JA         0xFFEE",
    # "6677EE"),


    (m16, "00000000    JCXZ       0xFFEE",
     "E3EE"),
    (m16, "00000000    JECXZ      0xFFEE",
     "67E3EE"),
    (m32, "00000000    JECXZ      0xFFFFFFEE",
     "E3EE"),
    (m32, "00000000    JCXZ       0xFFFFFFEE",
     "67E3EE"),
    (m32, "00000000    JCXZ       0xFFEE",
     "6667E3EE"),
    (m64, "00000000    JRCXZ      0xFFFFFFFFFFFFFFEE",
     "E3EE"),
    (m64, "00000000    JECXZ      0xFFFFFFFFFFFFFFEE",
     "67E3EE"),


    (m32, "00000000    MOV        BYTE PTR [EAX], AL",
     "8800"),
    (m32, "00000000    MOV        AL, BYTE PTR [EAX]",
     "8a00"),
    (m32, "00000000    MOV        EAX, DWORD PTR [EAX]",
     "8b00"),
    (m32, "00000000    MOV        DWORD PTR [EAX], EAX",
     "8900"),
    (m64, "00000000    MOV        ECX, DWORD PTR [RCX]",
     "8b09"),
    (m64, "00000000    MOV        DWORD PTR [RCX], ECX",
     "8909"),
    (m64, "00000000    MOV        QWORD PTR [RAX], RAX",
     "488900"),

    (m32, "00000000    MOV        EAX, EBX",
     "89d8"),
    (m32, "00000000    MOV        EAX, EBX",
     "8bc3"),


    (m16, "00000000    MOV        WORD PTR [BX+SI], ES",
     "8c00"),
    (m32, "00000000    MOV        DWORD PTR [EAX], ES",
     "8c00"),
    (m32, "00000000    MOV        ES, DWORD PTR [EAX]",
     "8e00"),
    (m32, "00000000    MOV        DWORD PTR [EAX], CS",
     "8c08"),
    (m64, "00000000    MOV        DWORD PTR [RCX], ES",
     "8c01"),

    (m16, "00000000    MOV        BH, 0x12",
     "b712"),
    (m16, "00000000    MOV        DI, 0x1122",
     "bf2211"),

    (m32, "00000000    MOV        AL, 0x12",
     "b012"),
    (m32, "00000000    MOV        EAX, 0x11223344",
     "b844332211"),
    (m32, "00000000    MOV        BH, 0x12",
     "b712"),
    (m32, "00000000    MOV        EDI, 0x11223344",
     "bf44332211"),

    (m64, "00000000    MOV        BH, 0x12",
     "b712"),
    (m64, "00000000    MOV        EDI, 0x11223344",
     "bf44332211"),

    (m16, "00000000    MOV        WORD PTR [BX], 0x1122",
     "c7072211"),
    (m32, "00000000    MOV        DWORD PTR [EAX], 0x11223344",
     "c70044332211"),
    (m64, "00000000    MOV        DWORD PTR [RCX], 0x11223344",
     "c70144332211"),

    (m32, "00000000    MOV        CR0, EAX",
     "0f22c0"),
    (m32, "00000000    MOV        EAX, CR0",
     "0f20c0"),

    (m32, "00000000    MOV        EAX, DR0",
     "0f21c0"),
    (m32, "00000000    MOV        DR0, EAX",
     "0f23c0"),

    (m64, "00000000    MOV        DWORD PTR [RSP+0x20], 0x10",
     "C744242010000000"),
    (m64, "00000000    MOV        DWORD PTR [RBX+0x20], 0x30",
     "c744a32030000000"),
    (m64, "00000000    MOV        DWORD PTR [R12+0x20], 0x10",
     "41C744242010000000"),

    (m32, "00000000    MOV        BYTE PTR [EBX+0xFFFFFF98], 0xCC",
     "C64398CC"),

    (m64, "00000000    MOV        BYTE PTR [R11+0xFFFFFFFFFFFFFF98], 0xCC",
     "41C64398CC"),

    (m64, "00000000    MOV        RAX, 0x1122334455667788",
     "48b88877665544332211"),

    (m64, "00000000    MOV        RDX, 0x1122334455667788",
     "48ba8877665544332211"),



    (m64, "00000000    MOV        RAX, RBX",
     "4889d8"),
    (m64, "00000000    MOV        RAX, RBX",
     "4A89d8"),
    (m64, "00000000    MOV        RAX, R11",
     "4C89d8"),
    (m64, "00000000    MOV        R8D, EBX",
     "4189d8"),
    (m64, "00000000    MOV        R8D, EBX",
     "4389d8"),
    (m64, "00000000    MOV        EAX, R11D",
     "4489d8"),
    (m64, "00000000    MOV        R8D, R11D",
     "4589d8"),
    (m64, "00000000    MOV        EAX, R11D",
     "4689d8"),
    (m64, "00000000    MOV        R8D, R11D",
     "4789d8"),

    (m64, "00000000    MOV        BYTE PTR [RBX+0x3], R11B",
     "44885B03"),

    (m32, "00000000    MOV        AL, BYTE PTR [0x11223344]",
     "A044332211"),
    (m32, "00000000    MOV        BYTE PTR [0x11223344], AL",
     "A244332211"),
    (m32, "00000000    MOV        EAX, DWORD PTR [0x11223344]",
     "A144332211"),
    (m32, "00000000    MOV        DWORD PTR [0x11223344], EAX",
     "A344332211"),

    (m32, "00000000    MOV        WORD PTR [0x11223344], AX",
     "66A344332211"),

    (m32, "00000000    MOV        DWORD PTR [0x1122], EAX",
     "67A32211"),



    (m16, "00000000    MOV        AL, BYTE PTR [0x1122]",
     "A02211"),
    (m16, "00000000    MOV        BYTE PTR [0x1122], AL",
     "A22211"),
    (m16, "00000000    MOV        AX, WORD PTR [0x1122]",
     "A12211"),
    (m16, "00000000    MOV        WORD PTR [0x1122], AX",
     "A32211"),

    (m64, "00000000    MOV        AL, BYTE PTR [0x1122334455667788]",
     "A08877665544332211"),
    (m64, "00000000    MOV        BYTE PTR [0x1122334455667788], AL",
     "A28877665544332211"),
    (m64, "00000000    MOV        EAX, DWORD PTR [0x1122334455667788]",
     "A18877665544332211"),
    (m64, "00000000    MOV        DWORD PTR [0x1122334455667788], EAX",
     "A38877665544332211"),



    (m32, "00000000    MOV        EAX, DWORD PTR CS:[EAX]",
     "2e8b00"),
    (m32, "00000000    MOV        EAX, DWORD PTR SS:[EAX]",
     "368b00"),
    (m32, "00000000    MOV        EAX, DWORD PTR DS:[EAX]",
     "3e8b00"),
    (m32, "00000000    MOV        EAX, DWORD PTR ES:[EAX]",
     "268b00"),
    (m32, "00000000    MOV        EAX, DWORD PTR FS:[EAX]",
     "648b00"),
    (m32, "00000000    MOV        EAX, DWORD PTR GS:[EAX]",
     "658b00"),



    (m32, "00000000    MOVSX      EAX, BYTE PTR [EAX]",
     "0fbe00"),
    (m32, "00000000    MOVSX      EAX, WORD PTR [EAX]",
     "0fbf00"),

    (m64, "00000000    MOVSX      RAX, BYTE PTR [RAX]",
     "480fbe00"),
    (m64, "00000000    MOVSX      RAX, WORD PTR [RAX]",
     "480fbf00"),

    (m16, "00000000    MOVZX      AX, BYTE PTR [BX+SI]",
     "0fb600"),
    (m16, "00000000    MOVZX      AX, WORD PTR [BX+SI]",
     "0fb700"),

    (m32, "00000000    MOVZX      EAX, BYTE PTR [EAX]",
     "0fb600"),
    (m32, "00000000    MOVZX      EAX, WORD PTR [EAX]",
     "0fb700"),

    (m64, "00000000    MOVSXD     R8, EAX",
     "4c63c0"),


    (m32, "00000000    MUL        BYTE PTR [EAX]",
     "f620"),
    (m32, "00000000    MUL        EBX",
     "f7e3"),

    (m16, "00000000    CMPSW",
     "a7"),
    (m32, "00000000    CMPSW",
     "66a7"),
    (m32, "00000000    CMPSD",
     "a7"),

    (m64, "00000000    CMPSD",
     "a7"),
    (m64, "00000000    CMPSQ",
     "48a7"),

    (m16, "00000000    LODSB",
     "aC"),
    (m32, "00000000    LODSB",
     "66ac"),
    (m16, "00000000    LODSW",
     "ad"),
    (m32, "00000000    LODSW",
     "66ad"),
    (m32, "00000000    LODSD",
     "ad"),

    (m64, "00000000    LODSD",
     "ad"),
    (m64, "00000000    LODSQ",
     "48ad"),



    (m32, "00000000    NEG        BYTE PTR [EAX]",
     "f618"),
    (m32, "00000000    NEG        EBX",
     "f7db"),

    #(m32, "00000000    NOP",
    # "90"),

    (m32, "00000000    NOP        DWORD PTR [EAX]",
     "0f1f00"),

    (m32, "00000000    NOT        BYTE PTR [EAX]",
     "f610"),
    (m32, "00000000    NOT        EBX",
     "f7d3"),

    (m32, "00000000    OR         AL, 0x11",
     "0c11"),
    (m32, "00000000    OR         EAX, 0x11223344",
     "0d44332211"),
    (m32, "00000000    OR         BYTE PTR [EAX], 0x11",
     "800811"),
    (m32, "00000000    OR         DWORD PTR [EAX], 0x11223344",
     "810844332211"),
    (m32, "00000000    OR         DWORD PTR [EAX], 0x11",
     "830811"),
    (m32, "00000000    OR         BYTE PTR [EAX], AL",
     "0800"),
    (m32, "00000000    OR         DWORD PTR [EAX], EAX",
     "0900"),
    (m32, "00000000    OR         AL, BYTE PTR [EAX]",
     "0A00"),
    (m32, "00000000    OR         EAX, DWORD PTR [EAX]",
     "0B00"),

    (m32, "00000000    OUT        0x12, AL",
     "e612"),
    (m32, "00000000    OUT        0x12, EAX",
     "e712"),
    (m64, "00000000    OUT        0x12, RAX",
     "48e712"),

    (m32, "00000000    OUT        DL, AL",
     "EE"),
    (m32, "00000000    OUT        EDX, EAX",
     "EF"),
    (m32, "00000000    OUT        DX, AX",
     "66EF"),

    (m32, "00000000    OUTSB",
     "6e"),
    (m32, "00000000    OUTSD",
     "6f"),
    (m32, "00000000    OUTSW",
     "666f"),
    (m64, "00000000    OUTSD",
     "6f"),
    (m64, "00000000    OUTSW",
     "666f"),

    #(m32, "00000000    PAUSE",
    # "f390"),


    (m16, "00000000    POP        WORD PTR [BX+SI]",
     "8f00"),
    (m32, "00000000    POP        DWORD PTR [EAX]",
     "8f00"),
    (m64, "00000000    POP        QWORD PTR [RAX]",
     "8f00"),


    (m32, "00000000    POP        EAX",
     "8fC0"),
    (m64, "00000000    POP        RAX",
     "8fC0"),

    (m32, "00000000    POP        EAX",
     "58"),
    (m64, "00000000    POP        RAX",
     "58"),
    (m64, "00000000    POP        R10",
     "415a"),

    (m32, "00000000    POP        DS",
     "1f"),
    (m32, "00000000    POP        ES",
     "07"),
    (m32, "00000000    POP        SS",
     "17"),
    (m32, "00000000    POP        FS",
     "0fa1"),
    (m32, "00000000    POP        GS",
     "0fa9"),

    (m16, "00000000    POPA",
     "61"),
    (m32, "00000000    POPAD",
     "61"),

    (m16, "00000000    POPF",
     "9d"),
    (m32, "00000000    POPFD",
     "9d"),
    (m64, "00000000    POPFD",
     "9d"),
    (m64, "00000000    POPFQ",
     "489d"),

    (m32, "00000000    PREFETCH0  BYTE PTR [EAX]",
     "0f1808"),
    (m32, "00000000    PREFETCH1  BYTE PTR [EAX]",
     "0f1810"),
    (m32, "00000000    PREFETCH2  BYTE PTR [EAX]",
     "0f1818"),
    (m32, "00000000    PREFETCHNTA BYTE PTR [EAX]",
     "0f1800"),


    (m16, "00000000    PUSH       AX",
     "50"),
    (m32, "00000000    PUSH       EAX",
     "50"),
    (m64, "00000000    PUSH       RAX",
     "50"),
    (m64, "00000000    PUSH       R10",
     "4152"),
    (m16, "00000000    PUSH       WORD PTR [BX+SI]",
     "FF30"),
    (m16, "00000000    PUSH       WORD PTR [EAX]",
     "67FF30"),
    (m16, "00000000    PUSH       DWORD PTR [EAX]",
     "6667FF30"),
    (m32, "00000000    PUSH       DWORD PTR [EAX]",
     "FF30"),
    (m64, "00000000    PUSH       QWORD PTR [RAX]",
     "FF30"),

    (m16, "00000000    PUSH       0x11",
     "6a11"),
    (m32, "00000000    PUSH       0x11223344",
     "6844332211"),
    (m32, "00000000    PUSH       0x1122",
     "66682211"),
    (m32, "00000000    PUSH       0x80",
     "6880000000"),

    (m64, "00000000    PUSH       0x11223344",
     "6844332211"),

    (m32, "00000000    PUSH       CS",
     "0e"),
    (m32, "00000000    PUSH       SS",
     "16"),
    (m32, "00000000    PUSH       DS",
     "1E"),
    (m32, "00000000    PUSH       ES",
     "06"),
    (m32, "00000000    PUSH       FS",
     "0fa0"),
    (m32, "00000000    PUSH       GS",
     "0fa8"),

    (m16, "00000000    PUSHA",
     "60"),
    (m32, "00000000    PUSHAD",
     "60"),

    (m16, "00000000    PUSHF",
     "9c"),
    (m32, "00000000    PUSHFD",
     "9c"),
    (m64, "00000000    PUSHFD",
     "9c"),
    (m64, "00000000    PUSHFQ",
     "489c"),

    (m32, "00000000    RCL        BYTE PTR [EAX], 0x1",
     "D010"),
    (m32, "00000000    RCL        BYTE PTR [EAX], CL",
     "d210"),

    (m32, "00000000    RCL        DWORD PTR [EAX], 0x1",
     "D110"),
    (m32, "00000000    RCL        DWORD PTR [EAX], CL",
     "d310"),

    (m32, "00000000    RCL        BYTE PTR [EAX], 0x11",
     "c01011"),
    (m32, "00000000    RCL        DWORD PTR [EAX], 0x11",
     "c11011"),

    (m64, "00000000    RCL        QWORD PTR [RAX], 0x1",
     "48D110"),
    (m64, "00000000    RCL        QWORD PTR [RAX], CL",
     "48d310"),

    (m64, "00000000    RCL        BYTE PTR [RAX], 0x11",
     "c01011"),
    (m64, "00000000    RCL        QWORD PTR [RAX], 0x11",
     "48c11011"),




    (m32, "00000000    RCR        BYTE PTR [EAX], 0x1",
     "D018"),
    (m32, "00000000    RCR        BYTE PTR [EAX], CL",
     "d218"),

    (m32, "00000000    RCR        DWORD PTR [EAX], 0x1",
     "D118"),
    (m32, "00000000    RCR        DWORD PTR [EAX], CL",
     "d318"),

    (m32, "00000000    RCR        BYTE PTR [EAX], 0x11",
     "c01811"),
    (m32, "00000000    RCR        DWORD PTR [EAX], 0x11",
     "c11811"),

    (m64, "00000000    RCR        QWORD PTR [RAX], 0x1",
     "48D118"),
    (m64, "00000000    RCR        QWORD PTR [RAX], CL",
     "48d318"),

    (m64, "00000000    RCR        BYTE PTR [RAX], 0x11",
     "c01811"),
    (m64, "00000000    RCR        QWORD PTR [RAX], 0x11",
     "48c11811"),




    (m32, "00000000    ROL        BYTE PTR [EAX], 0x1",
     "D000"),
    (m32, "00000000    ROL        BYTE PTR [EAX], CL",
     "d200"),

    (m32, "00000000    ROL        DWORD PTR [EAX], 0x1",
     "D100"),
    (m32, "00000000    ROL        DWORD PTR [EAX], CL",
     "d300"),

    (m32, "00000000    ROL        BYTE PTR [EAX], 0x11",
     "c00011"),
    (m32, "00000000    ROL        DWORD PTR [EAX], 0x11",
     "c10011"),

    (m64, "00000000    ROL        QWORD PTR [RAX], 0x1",
     "48D100"),
    (m64, "00000000    ROL        QWORD PTR [RAX], CL",
     "48d300"),

    (m64, "00000000    ROL        BYTE PTR [RAX], 0x11",
     "c00011"),
    (m64, "00000000    ROL        QWORD PTR [RAX], 0x11",
     "48c10011"),



    (m32, "00000000    ROR        BYTE PTR [EAX], 0x1",
     "D008"),
    (m32, "00000000    ROR        BYTE PTR [EAX], CL",
     "d208"),

    (m32, "00000000    ROR        DWORD PTR [EAX], 0x1",
     "D108"),
    (m32, "00000000    ROR        DWORD PTR [EAX], CL",
     "d308"),

    (m32, "00000000    ROR        BYTE PTR [EAX], 0x11",
     "c00811"),
    (m32, "00000000    ROR        DWORD PTR [EAX], 0x11",
     "c10811"),

    (m64, "00000000    ROR        QWORD PTR [RAX], 0x1",
     "48D108"),
    (m64, "00000000    ROR        QWORD PTR [RAX], CL",
     "48d308"),

    (m64, "00000000    ROR        BYTE PTR [RAX], 0x11",
     "c00811"),
    (m64, "00000000    ROR        QWORD PTR [RAX], 0x11",
     "48c10811"),



    (m32, "00000000    RDMSR",
     "0f32"),
    (m32, "00000000    RDPMC",
     "0f33"),
    (m32, "00000000    RDTSC",
     "0f31"),

    (m32, "00000000    INSB",
     "6C"),
    (m16, "00000000    INSW",
     "6D"),
    (m32, "00000000    INSD",
     "6D"),
    (m64, "00000000    INSD",
     "486D"),
    (m64, "00000000    INSD",
     "6D"),


    (m32, "00000000    MOVSB",
     "a4"),
    (m16, "00000000    MOVSW",
     "a5"),
    (m32, "00000000    MOVSD",
     "a5"),
    (m64, "00000000    MOVSQ",
     "48a5"),
    (m64, "00000000    MOVSD",
     "a5"),

    (m32, "00000000    OUTSB",
     "6e"),
    (m16, "00000000    OUTSW",
     "6f"),
    (m32, "00000000    OUTSD",
     "6f"),
    (m64, "00000000    OUTSD",
     "486f"),
    (m64, "00000000    OUTSD",
     "6f"),


    (m32, "00000000    LODSB",
     "ac"),
    (m16, "00000000    LODSW",
     "ad"),
    (m32, "00000000    LODSD",
     "ad"),
    (m64, "00000000    LODSQ",
     "48ad"),
    (m64, "00000000    LODSD",
     "ad"),

    (m32, "00000000    STOSB",
     "aa"),
    (m16, "00000000    STOSW",
     "ab"),
    (m32, "00000000    STOSD",
     "ab"),
    (m64, "00000000    STOSQ",
     "48ab"),
    (m64, "00000000    STOSD",
     "ab"),


    (m32, "00000000    CMPSB",
     "a6"),
    (m16, "00000000    CMPSW",
     "a7"),
    (m32, "00000000    CMPSD",
     "a7"),
    (m64, "00000000    CMPSQ",
     "48a7"),
    (m64, "00000000    CMPSD",
     "a7"),


    (m32, "00000000    SCASB",
     "ae"),
    (m16, "00000000    SCASW",
     "af"),
    (m32, "00000000    SCASD",
     "af"),
    (m64, "00000000    SCASQ",
     "48af"),
    (m64, "00000000    SCASD",
     "af"),

    (m32, "00000000    REPNE SCASB",
     "F2AE"),
    (m32, "00000000    REPE SCASB",
     "F3AE"),
    (m32, "00000000    REPE LODSD",
     "F3ad"),

    (m32, "00000000    RET",
     "c3"),

    (m32, "00000000    RET        0x1122",
     "C22211"),

    (m32, "00000000    RETF       0x1122",
     "CA2211"),

    (m32, "00000000    RSM",
     "0faa"),
    (m32, "00000000    SAHF",
     "9e"),

    (m32, "00000000    SAL        BYTE PTR [EAX], 0x1",
     "D030"),
    (m32, "00000000    SAL        BYTE PTR [EAX], CL",
     "d230"),

    (m32, "00000000    SAR        BYTE PTR [EAX], 0x1",
     "D038"),
    (m32, "00000000    SAR        BYTE PTR [EAX], CL",
     "d238"),

    (m32, "00000000    SHL        BYTE PTR [EAX], 0x1",
     "D020"),
    (m32, "00000000    SHL        BYTE PTR [EAX], CL",
     "d220"),

    (m32, "00000000    SHR        BYTE PTR [EAX], 0x1",
     "D028"),
    (m32, "00000000    SHR        BYTE PTR [EAX], CL",
     "d228"),


    (m32, "00000000    SBB        AL, 0x11",
     "1c11"),
    (m32, "00000000    SBB        EAX, 0x11223344",
     "1D44332211"),
    (m32, "00000000    SBB        BYTE PTR [EAX], 0x11",
     "801811"),
    (m32, "00000000    SBB        DWORD PTR [EAX], 0x11223344",
     "811844332211"),
    (m32, "00000000    SBB        BYTE PTR [EAX], AL",
     "1800"),
    (m32, "00000000    SBB        DWORD PTR [EAX], EAX",
     "1900"),
    (m32, "00000000    SBB        AL, BYTE PTR [EAX]",
     "1A00"),
    (m32, "00000000    SBB        EAX, DWORD PTR [EAX]",
     "1B00"),
    (m64, "00000000    SBB        QWORD PTR [RAX], RAX",
     "481900"),


    (m32, "00000000    SETA       BYTE PTR [EAX]",
     "0f9700"),
    (m32, "00000000    SETO       BYTE PTR [EAX]",
     "0f9000"),
    (m32, "00000000    SETNZ      AL",
     "0f95C0"),

    (m32, "00000000    SGDT       DWORD PTR [EAX]",
     "0f0100"),

    (m32, "00000000    SHLD       DWORD PTR [EAX], EAX, 0x11",
     "0fa40011"),
    (m32, "00000000    SHLD       DWORD PTR [EAX], EAX, CL",
     "0fa500"),

    (m64, "00000000    SHLD       QWORD PTR [RAX], RAX, 0x11",
     "480fa40011"),
    (m64, "00000000    SHLD       QWORD PTR [RAX], RAX, CL",
     "480fa500"),

    (m32, "00000000    SHRD       DWORD PTR [EAX], EAX, 0x11",
     "0fac0011"),
    (m32, "00000000    SHRD       DWORD PTR [EAX], EAX, CL",
     "0fad00"),

    (m64, "00000000    SHRD       QWORD PTR [RAX], RAX, 0x11",
     "480fac0011"),
    (m64, "00000000    SHRD       QWORD PTR [RAX], RAX, CL",
     "480fad00"),

    (m32, "00000000    SIDT       DWORD PTR [EAX]",
     "0f0108"),



    (m32, "00000000    SUB        AL, 0x11",
     "2c11"),
    (m32, "00000000    SUB        EAX, 0x11223344",
     "2D44332211"),
    (m32, "00000000    SUB        BYTE PTR [EAX], 0x11",
     "802811"),
    (m32, "00000000    SUB        DWORD PTR [EAX], 0x11223344",
     "812844332211"),
    (m32, "00000000    SUB        BYTE PTR [EAX], AL",
     "2800"),
    (m32, "00000000    SUB        DWORD PTR [EAX], EAX",
     "2900"),
    (m32, "00000000    SUB        AL, BYTE PTR [EAX]",
     "2A00"),
    (m32, "00000000    SUB        EAX, DWORD PTR [EAX]",
     "2B00"),
    (m32, "00000000    SUB        EBX, DWORD PTR [EBP+0xFFFFF858]",
     "2b9d58f8ffff"),


    (m64, "00000000    SYSCALL",
     "0f05"),
    (m64, "00000000    SYSENTER",
     "0f34"),
    (m64, "00000000    SYSEXIT",
     "0f35"),
    (m64, "00000000    SYSRET",
     "0f07"),



    (m32, "00000000    TEST       AL, 0x11",
     "a811"),
    (m32, "00000000    TEST       EAX, 0x11223344",
     "A944332211"),

    (m32, "00000000    TEST       BYTE PTR [EAX], 0x11",
     "f60011"),
    (m32, "00000000    TEST       DWORD PTR [EAX], 0x11223344",
     "f70044332211"),

    (m32, "00000000    TEST       BYTE PTR [EAX], AL",
     "8400"),
    (m32, "00000000    TEST       DWORD PTR [EAX], EAX",
     "8500"),

    (m32, "00000000    UD2",
     "0f0b"),

    (m32, "00000000    VERR       DWORD PTR [EAX]",
     "0f0020"),

    (m32, "00000000    VERW       DWORD PTR [EAX]",
     "0f0028"),

    (m32, "00000000    WBIND",
     "0f09"),

    (m32, "00000000    WRMSR",
     "0f30"),

    (m32, "00000000    XADD       BYTE PTR [EAX], AL",
     "0fc000"),
    (m32, "00000000    XADD       DWORD PTR [EAX], EAX",
     "0fc100"),

    (m16, "00000000    XCHG       AX, CX",
     "91"),

    (m32, "00000000    XCHG       EAX, ECX",
     "91"),

    (m64, "00000000    XCHG       EAX, ECX",
     "91"),
    (m64, "00000000    XCHG       RAX, RCX",
     "4891"),

    (m32, "00000000    NOP",
     "90"),


    (m32, "00000000    XCHG       BYTE PTR [EAX], AL",
     "8600"),
    (m32, "00000000    XCHG       DWORD PTR [EAX], EAX",
     "8700"),


    (m32, "00000000    XOR        AL, 0x11",
     "3411"),
    (m32, "00000000    XOR        EAX, 0x11223344",
     "3544332211"),
    (m32, "00000000    XOR        BYTE PTR [EAX], 0x11",
     "803011"),
    (m32, "00000000    XOR        DWORD PTR [EAX], 0x11223344",
     "813044332211"),
    (m32, "00000000    XOR        DWORD PTR [EAX], 0xFFFFFFFF",
     "8330FF"),
    (m32, "00000000    XOR        BYTE PTR [EAX], AL",
     "3000"),
    (m32, "00000000    XOR        DWORD PTR [EAX], EAX",
     "3100"),
    (m32, "00000000    XOR        EAX, DWORD PTR [EAX]",
     "3300"),

    (m32, "00000000    XORPS      XMM1, XMM2",
     "0f57ca"),
    (m32, "00000000    XORPS      XMM1, DWORD PTR [EDI+0x42]",
     "0f574f42"),
    (m32, "00000000    XORPD      XMM1, XMM2",
     "660f57ca"),

    (m32, "00000000    MOVAPS     DWORD PTR [EBP+0xFFFFFFB8], XMM0",
     "0f2945b8"),
    (m32, "00000000    MOVAPS     XMM0, DWORD PTR [EBP+0xFFFFFFB8]",
     "0f2845b8"),
    (m32, "00000000    MOVAPD     WORD PTR [EBP+0xFFFFFFB8], XMM0",
     "660f2945b8"),

    (m32, "00000000    MOVUPS     XMM2, DWORD PTR [ECX]",
     "0f1011"),
    (m32, "00000000    MOVSD      XMM2, DWORD PTR [ECX]",
     "f20f1011"),
    (m32, "00000000    MOVSD      DWORD PTR [EBP+0xFFFFFFD8], XMM0",
     "f20f1145d8"),
    (m32, "00000000    MOVSS      XMM2, DWORD PTR [ECX]",
     "f30f1011"),
    (m32, "00000000    MOVUPD     XMM2, DWORD PTR [ECX]",
     "660f1011"),

    (m32, "00000000    MOVSS      DWORD PTR [EBP+0xFFFFFC00], XMM0",
     "f30f118500fcffff"),

    (m64, "00000000    MOVSS      DWORD PTR [RBP+0xFFFFFFFFFFFFFC00], XMM0",
     "f30f118500fcffff"),

    (m32, "00000000    ADDSS      XMM2, DWORD PTR [ECX]",
     "f30f5811"),
    (m32, "00000000    ADDSD      XMM2, DWORD PTR [ECX]",
     "f20f5811"),
    (m32, "00000000    ADDPS      XMM2, DWORD PTR [ECX]",
     "0f5811"),
    (m32, "00000000    ADDPD      XMM2, DWORD PTR [ECX]",
     "660f5811"),

    (m32, "00000000    MULSD      XMM2, DWORD PTR [ECX]",
     "f20f5911"),


    (m32, "00000000    PXOR       XMM0, XMM0",
     "0fefc0"),
    (m32, "00000000    UCOMISD    XMM0, DWORD PTR [EBP+0xFFFFFFD8]",
     "660f2e45d8"),
    (m32, "00000000    ANDPD      XMM0, DWORD PTR [EBX+0x2CBD27]",
     "660f548327bd2c00"),

    (m32, "00000000    SUBSD      XMM1, XMM0",
     "f20f5cc8"),

    (m32, "00000000    MAXSD      XMM0, DWORD PTR [EBX+0x2CBD37]",
     "f20f5f8337bd2c00"),

    (m32, "00000000    CVTSI2SD   XMM0, EBX",
     "f20f2ac3"),

    (m32, "00000000    PMINSW     MM0, MM1",
     "0feac1"),
    (m32, "00000000    PMINSW     XMM0, XMM1",
     "660feac1"),

    (m64, "00000000    MOV        BYTE PTR [RSI], DIL",
     "40883E"),
    (m32, "00000000    MOVZX      EAX, BH",
     "0fb6c7"),
    (m64, "00000000    MOVZX      EAX, BH",
     "0fb6c7"),
    (m64, "00000000    MOVZX      EAX, DIL",
     "400fb6c7"),
    (m64, "00000000    MOV        BYTE PTR [RCX], SIL",
     "408831"),
    (m64, "00000000    CMP        SIL, CL",
     "4038ce"),

    (m64, "00000000    SETZ       DIL",
     "400f94c7"),
    (m64, "00000000    SETNZ      BPL",
     "400f95c5"),
    (m64, "00000000    MOV        CL, BPL",
     "4088e9"),
    (m64, "00000000    AND        DIL, 0x0",
     "4080e700"),
    (m64, "00000000    MOV        DIL, AL",
     "4088c7"),
    (m64, "00000000    MOV        DIL, BYTE PTR [RSI]",
     "408a3e"),
    (m64, "00000000    DEC        DIL",
     "40fecf"),

    (m64, "00000000    TEST       DIL, DIL",
     "4084ff"),
    (m32, "00000000    JMP        EDX",
     "FFE2"),
    (m64, "00000000    JMP        RDX",
     "FFE2"),

    (m32, "00000000    XGETBV",
     "0f01d0"),

    (m32, "00000000    MOVD       MM4, DWORD PTR [EAX+EDX*0x8]",
     "0f6e24d0"),
    (m32, "00000000    MOVD       DWORD PTR [EAX+EDX*0x8], MM4",
     "0f7e24d0"),
    (m64, "00000000    MOVD       DWORD PTR [RAX+RDX*0x8], MM4",
     "0f7e24d0"),
    (m64, "00000000    MOVD       DWORD PTR [RAX+R10*0x8], MM4",
     "420f7e24d0"),

    (m32, "00000000    MOVD       XMM4, DWORD PTR [EAX+EDX*0x8]",
     "660f6e24d0"),
    (m32, "00000000    MOVD       DWORD PTR [EAX+EDX*0x8], XMM4",
     "660f7e24d0"),
    (m64, "00000000    MOVD       DWORD PTR [RAX+RDX*0x8], XMM4",
     "660f7e24d0"),
    (m64, "00000000    MOVD       DWORD PTR [RAX+R10*0x8], XMM4",
     "66420f7e24d0"),

    (m64, "00000000    MOVQ       XMM4, DWORD PTR [RAX+R10*0x8]",
     "f3420f7e24d0"),
    (m64, "00000000    MOVQ       XMM1, DWORD PTR [R12+0xFFFFFFFFFFFFFFE0]",
     "f3410f7e4c24e0"),


    (m32, "00000000    PAND       MM2, MM6",
     "0fdbd6"),
    (m32, "00000000    PAND       XMM2, XMM6",
     "660fdbd6"),


    (m32, "00000000    PAND       MM0, MM4",
     "0fdbc4"),
    (m32, "00000000    PAND       XMM0, XMM4",
     "660fdbc4"),

    (m32, "00000000    POR        XMM0, XMM1",
     "660febc1"),

    (m32, "00000000    MOVDQU     XMM1, DWORD PTR [ESI]",
     "f30f6f0e"),
    (m32, "00000000    MOVDQA     DWORD PTR [ESP], XMM0",
     "660f7f0424"),

    (m32, "00000000    CVTSS2SD   XMM0, XMM0",
     "f30f5ac0"),
    (m32, "00000000    CVTSS2SD   XMM0, DWORD PTR [EBP+0xFFFFFFD0]",
     "f30f5a45d0"),

    (m32, "00000000    CVTSD2SS   XMM0, XMM0",
     "f20f5ac0"),

]


    # mode = 64
    # l = mn_x86.dis('\x4D\x11\x7c\x18\x00', mode)
    # print l
    #"""
    # mode = 64
    # l = mn_x86.fromstring("ADC      DWORD PTR [RAX], 0x11223344", mode)
    # print 'xx'
    # t= time.time()
    # import cProfile
    # def f():
    #    x = l.asm(mode)
    #    print x
    # cProfile.run('f()')
    # l.asm(mode)
    # print time.time()-t
# reg_tests = reg_tests[-1:]

fname64 = ('exe64.bin', 'r+')
if not os.access(fname64[0], os.R_OK):
    fname64 = ('regression_test64_ia32.bin', 'w')

test_file = {16: open('regression_test16_ia32.bin', 'w'),
             32: open('regression_test32_ia32.bin', 'w'),
             # 64:open('regression_test64_ia32.bin', 'w+')}
             # 64:open('testmnemo', 'r+')}
             64: open(*fname64)}
ts = time.time()
# test_file[16].write("\x90"*0x10000)
# test_file[32].write("\x90"*0x10000)
file64off = 0x2524c
test_file[64].seek(0x400)
test_file[64].write('\x90' * 0x30000)
test_file[64].seek(file64off)
for mode, s, l, in reg_tests:
    print "-" * 80
    s = s[12:]
    b = l.decode('hex')
    print mode, repr(b)
    mn = mn_x86.dis(b, mode)
    print "dis args", [(str(x), x.size) for x in mn.args]
    print s
    print mn
    assert(str(mn).strip() == s)
    # print hex(b)
    # print [str(x.get()) for x in mn.args]
    print 'fromstring', repr(s)
    l = mn_x86.fromstring(s, mode)
    # print l
    print 'str args', [(str(x), x.size) for x in l.args]
    assert(str(l).strip(' ') == s)
    a = mn_x86.asm(l)
    print 'asm result', [x for x in a]
    print repr(b)
    # test_file[mode[0]].write(b)

    for x in a:
        print "BYTES", repr(x)
        test_file[mode].write(x)
    test_file[mode].write("\x90" * 2)

    print 'test re dis'
    for x in a:
        print repr(x)
        rl = mn_x86.dis(x, mode)
        assert(str(rl).strip(' ') == s)
    print repr(b), a
    assert(b in a)
    # print mn.args
print 'TEST time', time.time() - ts


# speed test thumb
o = ""
mode_x = m32
for mode, s, l, in reg_tests:
    if mode != mode_x:
        continue
    s = s[12:]
    b = l.decode('hex')
    o += b

while len(o) < 1000:
    o += o
open('x86_speed_reg_test.bin', 'w').write(o)


def profile_dis(o):
    bs = bin_stream_str(o)
    off = 0
    instr_num = 0
    ts = time.time()
    while off < bs.getlen():
        mn = mn_x86.dis(bs, mode_x, off)
        # print instr_num, off, mn.l, str(mn)
        instr_num += 1
        off += mn.l
    print 'instr per sec:', instr_num / (time.time() - ts)

import cProfile
# cProfile.run(r'mn_x86.dis("\x81\x54\x18\xfe\x44\x33\x22\x11", m32)')
cProfile.run('profile_dis(o)')
# profile_dis(o)
