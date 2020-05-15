#-*- coding:utf-8 -*-

from builtins import range
from miasm.expression.expression import ExprId
from miasm.core.cpu import gen_reg, gen_regs


PC, _ = gen_reg('PC')
PC_FETCH, _ = gen_reg('PC_FETCH')

R_LO, _ = gen_reg('R_LO')
R_HI, _ = gen_reg('R_HI')

exception_flags = ExprId('exception_flags', 32)

PC_init = ExprId("PC_init", 32)
PC_FETCH_init = ExprId("PC_FETCH_init", 32)

regs32_str = ["ZERO", 'AT', 'V0', 'V1'] +\
    ['A%d'%i for i in range(4)] +\
    ['T%d'%i for i in range(8)] +\
    ['S%d'%i for i in range(8)] +\
    ['T%d'%i for i in range(8, 10)] +\
    ['K0', 'K1'] +\
    ['GP', 'SP', 'FP', 'RA']

regs32_expr = [ExprId(x, 32) for x in regs32_str]
ZERO = regs32_expr[0]

regs_flt_str = ['F%d'%i for i in range(0x20)]

regs_fcc_str = ['FCC%d'%i for i in range(8)]

R_LO = ExprId('R_LO', 32)
R_HI = ExprId('R_HI', 32)

R_LO_init = ExprId('R_LO_init', 32)
R_HI_init = ExprId('R_HI_init', 32)


cpr0_str = ["CPR0_%d"%x for x in range(0x100)]
cpr0_str[0] = "INDEX"
cpr0_str[8] = "RANDOM"
cpr0_str[16] = "ENTRYLO0"
cpr0_str[24] = "ENTRYLO1"
cpr0_str[32] = "CONTEXT"
cpr0_str[33] = "CONTEXTCONFIG"
cpr0_str[40] = "PAGEMASK"
cpr0_str[41] = "PAGEGRAIN"
cpr0_str[42] = "SEGCTL0"
cpr0_str[43] = "SEGCTL1"
cpr0_str[44] = "SEGCTL2"
cpr0_str[45] = "PWBASE"
cpr0_str[46] = "PWFIELD"
cpr0_str[47] = "PWSIZE"
cpr0_str[48] = "WIRED"
cpr0_str[54] = "PWCTL"
cpr0_str[64] = "BADVADDR"
cpr0_str[65] = "BADINSTR"
cpr0_str[66] = "BADINSTRP"
cpr0_str[72] = "COUNT"
cpr0_str[80] = "ENTRYHI"
cpr0_str[104] = "CAUSE"
cpr0_str[112] = "EPC"
cpr0_str[120] = "PRID"
cpr0_str[121] = "EBASE"
cpr0_str[128] = "CONFIG"
cpr0_str[129] = "CONFIG1"
cpr0_str[130] = "CONFIG2"
cpr0_str[131] = "CONFIG3"
cpr0_str[132] = "CONFIG4"
cpr0_str[133] = "CONFIG5"
cpr0_str[152] = "WATCHHI"
cpr0_str[250] = "KSCRATCH"
cpr0_str[251] = "KSCRATCH1"
cpr0_str[252] = "KSCRATCH2"
cpr0_str[253] = "KSCRATCH3"
cpr0_str[254] = "KSCRATCH4"
cpr0_str[255] = "KSCRATCH5"

regs_cpr0_expr, regs_cpr0_init, regs_cpr0_info = gen_regs(cpr0_str, globals())

gpregs_expr, gpregs_init, gpregs = gen_regs(regs32_str, globals())
regs_flt_expr, regs_flt_init, fltregs = gen_regs(regs_flt_str, globals(), sz=64)
regs_fcc_expr, regs_fcc_init, fccregs = gen_regs(regs_fcc_str, globals())


all_regs_ids = [PC, PC_FETCH, R_LO, R_HI, exception_flags] + gpregs_expr + regs_flt_expr + \
    regs_fcc_expr + regs_cpr0_expr
all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])
all_regs_ids_init = [ExprId("%s_init" % reg.name, reg.size) for reg in all_regs_ids]
all_regs_ids_no_alias = all_regs_ids[:]

attrib_to_regs = {
    'l': all_regs_ids_no_alias,
    'b': all_regs_ids_no_alias,
}

regs_init = {}
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]
