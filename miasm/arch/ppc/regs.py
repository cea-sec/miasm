
from builtins import range
from miasm.expression.expression import *
from miasm.core.cpu import gen_reg, gen_regs

exception_flags = ExprId('exception_flags', 32)
spr_access = ExprId('spr_access', 32)

reserve = ExprId('reserve', 1)
reserve_address = ExprId('reserve_address', 32)

SPR_ACCESS_IS_WRITE = 0x80000000
SPR_ACCESS_SPR_MASK = 0x000003FF
SPR_ACCESS_SPR_OFF  = 0
SPR_ACCESS_GPR_MASK = 0x0001F000
SPR_ACCESS_GPR_OFF  = 12

gpregs_str = ["R%d" % i for i in range(32)]
gpregs_expr, gpregs_init, gpregs = gen_regs(gpregs_str, globals(), 32)

crfregs_str = ["CR%d" % i for i in range(8)]
crfregs_expr, crfregs_init, crfregs = gen_regs(crfregs_str, globals(), 4)

crfbitregs_str = ["CR%d_%s" % (i, flag) for i in range(8)
                  for flag in ['LT', 'GT', 'EQ', 'SO'] ]
crfbitregs_expr, crfbitregs_init, crfbitregs = gen_regs(crfbitregs_str,
                                                        globals(), 1)

xerbitregs_str = ["XER_%s" % field for field in ['SO', 'OV', 'CA'] ]
xerbitregs_expr, xerbitregs_init, xerbitregs = gen_regs(xerbitregs_str,
                                                        globals(), 1)

xerbcreg_str = ["XER_BC"]
xerbcreg_expr, xerbcreg_init, xerbcreg = gen_regs(xerbcreg_str,
                                                  globals(), 7)


otherregs_str = ["PC", "CTR", "LR", "FPSCR", "VRSAVE", "VSCR" ]
otherregs_expr, otherregs_init, otherregs = gen_regs(otherregs_str,
                                                     globals(), 32)

superregs_str = (["SPRG%d" % i for i in range(4)] +
                 ["SRR%d" % i for i in range(2)] +
                 ["DAR", "DSISR", "MSR", "PIR", "PVR",
                  "DEC", "TBL", "TBU"])
superregs_expr, superregs_init, superregs = gen_regs(superregs_str,
                                                     globals(), 32)

mmuregs_str = (["SR%d" % i for i in range(16)] +
               ["IBAT%dU" % i for i in range(4)] +
               ["IBAT%dL" % i for i in range(4)] +
               ["DBAT%dU" % i for i in range(4)] +
               ["DBAT%dL" % i for i in range(4)] +
               ["SDR1"])
mmuregs_expr, mmuregs_init, mmuregs = gen_regs(mmuregs_str,
                                               globals(), 32)

floatregs_str = (["FPR%d" % i for i in range(32)])
floatregs_expr, floatregs_init, floatregs = gen_regs(floatregs_str,
                                                     globals(), 64)

vexregs_str = (["VR%d" % i for i in range(32)])
vexregs_expr, vexregs_init, vexregs = gen_regs(vexregs_str,
                                              globals(), 128)

regs_flt_expr = []

all_regs_ids = (gpregs_expr + crfbitregs_expr + xerbitregs_expr +
                xerbcreg_expr + otherregs_expr + superregs_expr + mmuregs_expr + floatregs_expr + vexregs_expr +
                [ exception_flags, spr_access, reserve, reserve_address ])
all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])
all_regs_ids_init = [ExprId("%s_init" % x.name, x.size) for x in all_regs_ids]
all_regs_ids_no_alias = all_regs_ids[:]

regs_init = {}
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]
