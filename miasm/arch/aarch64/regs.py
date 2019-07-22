#-*- coding:utf-8 -*-

from builtins import range
from miasm.expression.expression import ExprId
from miasm.core.cpu import gen_reg, gen_regs

exception_flags = ExprId('exception_flags', 32)
interrupt_num = ExprId('interrupt_num', 32)


gpregs32_str = ["W%d" % i for i in range(0x1f)] + ["WSP"]
gpregs32_expr, gpregs32_init, gpregs32_info = gen_regs(
    gpregs32_str, globals(), 32)

gpregs64_str = ["X%d" % i for i in range(0x1E)] + ["LR", "SP"]
gpregs64_expr, gpregs64_init, gpregs64_info = gen_regs(
    gpregs64_str, globals(), 64)


gpregsz32_str = ["W%d" % i for i in range(0x1f)] + ["WZR"]
gpregsz32_expr, gpregsz32_init, gpregsz32_info = gen_regs(
    gpregsz32_str, globals(), 32)

gpregsz64_str = ["X%d" % i for i in range(0x1e)] + ["LR", "XZR"]
gpregsz64_expr, gpregsz64_init, gpregsz64_info = gen_regs(
    gpregsz64_str, globals(), 64)

cr_str = ["c%d" % i for i in range(0xf)]
cr_expr, cr_init, cr_info = gen_regs(cr_str, globals(), 32)


simd08_str = ["B%d" % i for i in range(0x20)]
simd08_expr, simd08_init, simd08_info = gen_regs(simd08_str, globals(), 8)

simd16_str = ["H%d" % i for i in range(0x20)]
simd16_expr, simd16_init, simd16_info = gen_regs(simd16_str, globals(), 16)

simd32_str = ["S%d" % i for i in range(0x20)]
simd32_expr, simd32_init, simd32_info = gen_regs(simd32_str, globals(), 32)

simd64_str = ["D%d" % i for i in range(0x20)]
simd64_expr, simd64_init, simd64_info = gen_regs(simd64_str, globals(), 64)

simd128_str = ["Q%d" % i for i in range(0x20)]
simd128_expr, simd128_init, simd128_info = gen_regs(
    simd128_str, globals(), 128)


PC, _ = gen_reg("PC", 64)
WZR, _ = gen_reg("WZR", 32)
XZR, _ = gen_reg("XZR", 64)

PC_init = ExprId("PC_init", 64)
WZR_init = ExprId("WZR_init", 32)
XZR_init = ExprId("XZR_init", 64)

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


all_regs_ids = [
    B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15, B16,
    B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28, B29, B30, B31,

    H0, H1, H2, H3, H4, H5, H6, H7, H8, H9, H10, H11, H12, H13, H14, H15, H16,
    H17, H18, H19, H20, H21, H22, H23, H24, H25, H26, H27, H28, H29, H30, H31,

    S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12, S13, S14, S15, S16,
    S17, S18, S19, S20, S21, S22, S23, S24, S25, S26, S27, S28, S29, S30, S31,

    D0, D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11, D12, D13, D14, D15, D16,
    D17, D18, D19, D20, D21, D22, D23, D24, D25, D26, D27, D28, D29, D30, D31,

    Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15, Q16,
    Q17, Q18, Q19, Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,

    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15, W16,
    W17, W18, W19, W20, W21, W22, W23, W24, W25, W26, W27, W28, W29, W30, WSP,

    X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16,
    X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, LR, SP,

    exception_flags,
    interrupt_num,
    PC,
    WZR,
    XZR,
    zf, nf, of, cf,

]


all_regs_ids_no_alias = all_regs_ids

attrib_to_regs = {
    'l': all_regs_ids_no_alias,
    'b': all_regs_ids_no_alias,
}

all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])

all_regs_ids_init = [ExprId("%s_init" % x.name, x.size) for x in all_regs_ids]

regs_init = {}
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]

regs_flt_expr = []
