#-*- coding:utf-8 -*-

from builtins import range
from miasm.expression.expression import *


# GP

regs32_str = ["R%d" % i for i in range(13)] + ["SP", "LR", "PC"]
regs32_expr = [ExprId(x, 32) for x in regs32_str]

exception_flags = ExprId('exception_flags', 32)
interrupt_num = ExprId('interrupt_num', 32)
bp_num = ExprId('bp_num', 32)


R0 = regs32_expr[0]
R1 = regs32_expr[1]
R2 = regs32_expr[2]
R3 = regs32_expr[3]
R4 = regs32_expr[4]
R5 = regs32_expr[5]
R6 = regs32_expr[6]
R7 = regs32_expr[7]
R8 = regs32_expr[8]
R9 = regs32_expr[9]
R10 = regs32_expr[10]
R11 = regs32_expr[11]
R12 = regs32_expr[12]
SP = regs32_expr[13]
LR = regs32_expr[14]
PC = regs32_expr[15]

R0_init = ExprId("R0_init", 32)
R1_init = ExprId("R1_init", 32)
R2_init = ExprId("R2_init", 32)
R3_init = ExprId("R3_init", 32)
R4_init = ExprId("R4_init", 32)
R5_init = ExprId("R5_init", 32)
R6_init = ExprId("R6_init", 32)
R7_init = ExprId("R7_init", 32)
R8_init = ExprId("R8_init", 32)
R9_init = ExprId("R9_init", 32)
R10_init = ExprId("R10_init", 32)
R11_init = ExprId("R11_init", 32)
R12_init = ExprId("R12_init", 32)
SP_init = ExprId("SP_init", 32)
LR_init = ExprId("LR_init", 32)
PC_init = ExprId("PC_init", 32)


reg_zf = 'zf'
reg_nf = 'nf'
reg_of = 'of'
reg_cf = 'cf'

zf = ExprId(reg_zf, size=1)
nf = ExprId(reg_nf, size=1)
of = ExprId(reg_of, size=1)
cf = ExprId(reg_cf, size=1)

zf_init = ExprId("zf_init", size=1)
nf_init = ExprId("nf_init", size=1)
of_init = ExprId("of_init", size=1)
cf_init = ExprId("cf_init", size=1)


reg_ge0 = 'ge0'
reg_ge1 = 'ge1'
reg_ge2 = 'ge2'
reg_ge3 = 'ge3'

ge0 = ExprId(reg_ge0, size=1)
ge1 = ExprId(reg_ge1, size=1)
ge2 = ExprId(reg_ge2, size=1)
ge3 = ExprId(reg_ge3, size=1)

ge0_init = ExprId("ge0_init", size=1)
ge1_init = ExprId("ge1_init", size=1)
ge2_init = ExprId("ge2_init", size=1)
ge3_init = ExprId("ge3_init", size=1)

ge_regs = [ge0, ge1, ge2, ge3]

all_regs_ids = [
    R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, SP, LR, PC,
    zf, nf, of, cf,
    ge0, ge1, ge2, ge3,
    exception_flags, interrupt_num, bp_num
]

all_regs_ids_no_alias = all_regs_ids

attrib_to_regs = {
    'l': all_regs_ids_no_alias,
    'b': all_regs_ids_no_alias,
}

all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])

all_regs_ids_init = [R0_init, R1_init, R2_init, R3_init,
                     R4_init, R5_init, R6_init, R7_init,
                     R8_init, R9_init, R10_init, R11_init,
                     R12_init, SP_init, LR_init, PC_init,
                     zf_init, nf_init, of_init, cf_init,
                     ge0_init, ge1_init, ge2_init, ge3_init,
                     ExprInt(0, 32), ExprInt(0, 32), ExprInt(0, 32)
                     ]

regs_init = {}
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]

regs_flt_expr = []
