from builtins import range
from miasm.expression.expression import *
from miasm.core.cpu import reg_info


# GP

regs16_str = ["PC", "SP", "SR"] + ["R%d" % i for i in range(3, 16)]
regs16_expr = [ExprId(x, 16) for x in regs16_str]

exception_flags = ExprId('exception_flags', 32)

gpregs = reg_info(regs16_str, regs16_expr)

PC = regs16_expr[0]
SP = regs16_expr[1]
SR = regs16_expr[2]
R3 = regs16_expr[3]
R4 = regs16_expr[4]
R5 = regs16_expr[5]
R6 = regs16_expr[6]
R7 = regs16_expr[7]
R8 = regs16_expr[8]
R9 = regs16_expr[9]
R10 = regs16_expr[10]
R11 = regs16_expr[11]
R12 = regs16_expr[12]
R13 = regs16_expr[13]
R14 = regs16_expr[14]
R15 = regs16_expr[15]

PC_init = ExprId("PC_init", 16)
SP_init = ExprId("SP_init", 16)
SR_init = ExprId("SR_init", 16)
R3_init = ExprId("R3_init", 16)
R4_init = ExprId("R4_init", 16)
R5_init = ExprId("R5_init", 16)
R6_init = ExprId("R6_init", 16)
R7_init = ExprId("R7_init", 16)
R8_init = ExprId("R8_init", 16)
R9_init = ExprId("R9_init", 16)
R10_init = ExprId("R10_init", 16)
R11_init = ExprId("R11_init", 16)
R12_init = ExprId("R12_init", 16)
R13_init = ExprId("R13_init", 16)
R14_init = ExprId("R14_init", 16)
R15_init = ExprId("R15_init", 16)


reg_zf = 'zf'
reg_nf = 'nf'
reg_of = 'of'
reg_cf = 'cf'
reg_cpuoff = 'cpuoff'
reg_gie = 'gie'
reg_osc = 'osc'
reg_scg0 = 'scg0'
reg_scg1 = 'scg1'
reg_res = 'res'

zf = ExprId(reg_zf, size=1)
nf = ExprId(reg_nf, size=1)
of = ExprId(reg_of, size=1)
cf = ExprId(reg_cf, size=1)

cpuoff = ExprId(reg_cpuoff, size=1)
gie = ExprId(reg_gie, size=1)
osc = ExprId(reg_osc, size=1)
scg0 = ExprId(reg_scg0, size=1)
scg1 = ExprId(reg_scg1, size=1)
res = ExprId(reg_res, size=7)


zf_init = ExprId("zf_init", size=1)
nf_init = ExprId("nf_init", size=1)
of_init = ExprId("of_init", size=1)
cf_init = ExprId("cf_init", size=1)


cpuoff_init = ExprId("cpuoff_init", size=1)
gie_init = ExprId("gie_init", size=1)
osc_init = ExprId("osc_init", size=1)
scg0_init = ExprId("scg0_init", size=1)
scg1_init = ExprId("scg1_init", size=1)
res_init = ExprId("res_init", size=7)


all_regs_ids = [
    PC, SP, SR, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
    zf, nf, of, cf,
    cpuoff, gie, osc, scg0, scg1, res,
]

all_regs_ids_no_alias = all_regs_ids

attrib_to_regs = {
    'l': all_regs_ids_no_alias,
    'b': all_regs_ids_no_alias,
}

all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])

all_regs_ids_init = [PC_init, SP_init, SR_init, R3_init,
                     R4_init, R5_init, R6_init, R7_init,
                     R8_init, R9_init, R10_init, R11_init,
                     R12_init, R13_init, R14_init, R15_init,
                     zf_init, nf_init, of_init, cf_init,
                     cpuoff_init, gie_init, osc_init,
                     scg0_init, scg1_init, res_init,
                     ]

regs_init = {}
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]

regs_flt_expr = []
