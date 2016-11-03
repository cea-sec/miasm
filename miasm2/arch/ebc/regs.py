#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.core.cpu import reg_info

regs16_str = ['R%d' % i for i in xrange(8)] + ['IP', 'cf', 'sf']

R0 = ExprId('R0', 64)
R1 = ExprId('R1', 64)
R2 = ExprId('R2', 64)
R3 = ExprId('R3', 64)
R4 = ExprId('R4', 64)
R5 = ExprId('R5', 64)
R6 = ExprId('R6', 64)
R7 = ExprId('R7', 64)
IP = ExprId('IP', 64)
cf = ExprId('cf', 64)
sf = ExprId('sf', 64)

regs16_expr = [R0, R1, R2, R3, R4, R5, R6, R7, IP, cf, sf]

R0_init = ExprId('R0_init', 64)
R1_init = ExprId('R1_init', 64)
R2_init = ExprId('R2_init', 64)
R3_init = ExprId('R3_init', 64)
R4_init = ExprId('R4_init', 64)
R5_init = ExprId('R5_init', 64)
R6_init = ExprId('R6_init', 64)
R7_init = ExprId('R7_init', 64)
IP_init = ExprId('IP_init', 64)
cf_init = ExprId('cf_init', 64)
sf_init = ExprId('sf_init', 64)

gpregs = reg_info(regs16_str, regs16_expr)

all_regs_ids_no_alias = all_regs_ids = regs16_expr

regs_flt_expr = []

regs_init = {
    R0: R0_init,
    R1: R1_init,
    R2: R2_init,
    R3: R3_init,
    R4: R4_init,
    R5: R5_init,
    R6: R6_init,
    R7: R7_init,
    IP: IP_init,
    cf: cf_init,
    sf: sf_init,
}

