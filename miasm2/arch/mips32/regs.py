#-*- coding:utf-8 -*-

from miasm2.expression.expression import ExprId
from miasm2.core.cpu import gen_reg, gen_regs


gen_reg('PC', globals())
gen_reg('PC_FETCH', globals())

gen_reg('R_LO', globals())
gen_reg('R_HI', globals())

exception_flags = ExprId('exception_flags', 32)

PC_init = ExprId("PC_init")
PC_FETCH_init = ExprId("PC_FETCH_init")

regs32_str = ["ZERO", 'AT', 'V0', 'V1'] +\
    ['A%d'%i for i in xrange(4)] +\
    ['T%d'%i for i in xrange(8)] +\
    ['S%d'%i for i in xrange(8)] +\
    ['T%d'%i for i in xrange(8, 10)] +\
    ['K0', 'K1'] +\
    ['GP', 'SP', 'FP', 'RA']

regs32_expr = [ExprId(x, 32) for x in regs32_str]

regs_flt_str = ['F%d'%i for i in xrange(0x20)]

regs_fcc_str = ['FCC%d'%i for i in xrange(8)]

R_LO = ExprId('R_LO', 32)
R_HI = ExprId('R_HI', 32)

R_LO_init = ExprId('R_LO_init', 32)
R_HI_init = ExprId('R_HI_init', 32)


cpr0_str = ["CPR0_%d"%x for x in xrange(0x100)]
cpr0_str[0] = "INDEX"
cpr0_str[16] = "ENTRYLO0"
cpr0_str[24] = "ENTRYLO1"
cpr0_str[40] = "PAGEMASK"
cpr0_str[72] = "COUNT"
cpr0_str[80] = "ENTRYHI"
cpr0_str[104] = "CAUSE"
cpr0_str[112] = "EPC"
cpr0_str[128] = "CONFIG"
cpr0_str[152] = "WATCHHI"

regs_cpr0_expr, regs_cpr0_init, regs_cpr0_info = gen_regs(cpr0_str, globals())

gpregs_expr, gpregs_init, gpregs = gen_regs(regs32_str, globals())
regs_flt_expr, regs_flt_init, fltregs = gen_regs(regs_flt_str, globals(), sz=64)
regs_fcc_expr, regs_fcc_init, fccregs = gen_regs(regs_fcc_str, globals())


all_regs_ids = [PC, PC_FETCH, R_LO, R_HI] + gpregs_expr + regs_flt_expr + \
    regs_fcc_expr + regs_cpr0_expr
all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])
all_regs_ids_init = [PC_init, PC_FETCH_init, R_LO_init, R_HI_init] + \
    gpregs_init + regs_flt_init + regs_fcc_init + regs_cpr0_init
all_regs_ids_no_alias = all_regs_ids[:]

attrib_to_regs = {
    'l': all_regs_ids_no_alias,
    'b': all_regs_ids_no_alias,
}

regs_init = {}
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]
