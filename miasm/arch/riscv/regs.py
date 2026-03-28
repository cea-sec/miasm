# -*- coding:utf-8 -*-

from builtins import range
from miasm.expression.expression import ExprId
from miasm.core.cpu import gen_reg, gen_regs, reg_info

exception_flags = ExprId('exception_flags', 32)
interrupt_num = ExprId('interrupt_num', 32)

# riscv64/32 regs are similar, the only difference being their width.
xregs_str = ["X%d" % i for i in range(32)]
xregs_expr, xregs_init, xregs_info = gen_regs(
    xregs_str, globals(), 64)

PC, pc_info = gen_reg("PC", 64)

csr_str = [
    # User-level
    "USTATUS", "UIE", "UTVEC",
    "USCRATCH", "UEPC", "UCAUSE", "UTVAL", "UIP",

    # Supervisor-level
    "SSTATUS", "SIE", "STVEC",
    "SSCRATCH", "SEPC", "SCAUSE", "STVAL", "SIP",
    "SATP",

    # Machine-level
    "MSTATUS", "MISA", "MIE", "MTVEC",
    "MSCRATCH", "MEPC", "MCAUSE", "MTVAL", "MIP",

    # hart info
    "MVENDORID", "MARCHID", "MIMPID", "MHARTID",
]

csr_expr, csr_init, csr_info = gen_regs(csr_str, globals(), 64)

# TODO: add more special regs if needed
'''
    ZERO, RA, SP, GP, TP, T0, T1, T2, S0, S1, A0, A1,
    A2, A3, A4, A5, A6, A7, S2, S3, S4, S5, S6, S7,
    S8, S9, S10, S11, T3, T4, T5, T6,
    PC
'''
all_regs_ids = [
    X0, X1, X2, X3, X4, X5, X6, X7,
    X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23,
    X24, X25, X26, X27, X28, X29, X30, X31,
    PC
] + csr_expr

all_regs_ids_no_alias = all_regs_ids
all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])

all_regs_ids_init = [ExprId("%s_init" % x.name, x.size) for x in all_regs_ids]
regs_init = {}
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]

attrib_to_regs = {
    64: all_regs_ids_no_alias,
}

regs_flt_expr = []