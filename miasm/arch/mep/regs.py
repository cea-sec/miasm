# Toshiba MeP-c4 - miasm registers definition
# Guillaume Valadon <guillaume@valadon.net>

from builtins import range
from miasm.expression.expression import ExprId
from miasm.core.cpu import reg_info, gen_reg, gen_regs

# Used by internal miasm exceptions
exception_flags = ExprId("exception_flags", 32)
exception_flags_init = ExprId("exception_flags_init", 32)

is_repeat_end = ExprId("is_repeat_end", 32)
is_repeat_end_init = ExprId("is_repeat_end_init", 32)
last_addr = ExprId("last_addr", 32)
last_addr_init = ExprId("last_addr_init", 32)
take_jmp = ExprId("take_jmp", 32)
take_jmp_init = ExprId("take_jmp_init", 32)
in_erepeat = ExprId("in_erepeat", 32)
in_erepeat_init = ExprId("take_jmp_init", 32)


# General-purpose registers (R0 to R15) names
gpr_names = ["R%d" % r for r in range(13)]  # register names
gpr_names += ["TP", "GP", "SP"]  # according to the manual GP does not exist
gpr_exprs, gpr_inits, gpr_infos = gen_regs(gpr_names, globals())  # sz=32 bits (default)

# Notes:
#     - gpr_exprs: register ExprIds on 32 bits.  The size is important for
#       symbolic execution.
#     - gpr_inits: register initial values.
#     - gpr_infos: object that binds names & ExprIds

# Define aliases to general-purpose registers
TP = gpr_exprs[13]  # Tiny data area Pointer
GP = gpr_exprs[14]  # Global Pointer
SP = gpr_exprs[15]  # Stack Pointer


# Control/special registers name
csr_names = ["PC", "LP", "SAR", "S3", "RPB", "RPE", "RPC", "HI", "LO",
             "S9", "S10", "S11", "MB0", "ME0", "MB1", "ME1", "PSW",
             "ID", "TMP", "EPC", "EXC", "CFG", "S22", "NPC", "DBG",
             "DEPC", "OPT", "RCFG", "CCFG", "S29", "S30", "S31", "S32"]
csr_exprs, csr_inits, csr_infos = gen_regs(csr_names, globals())

# Define aliases to control/special registers
PC = csr_exprs[0]  # Program Conter. On MeP, it is the special register R0
LP = csr_exprs[1]  # Link Pointer. On MeP, it is the special register R1
SAR = csr_exprs[2]  # Shift Amount Register. On MeP, it is the special register R2
RPB = csr_exprs[4]  # Repeat Begin. On MeP, it is the special register R4
RPE = csr_exprs[5]  # Repeat End. On MeP, it is the special register R5
RPC = csr_exprs[6]  # Repeat Counter. On MeP, it is the special register R6


# Coprocesssor general-purpose registers (C0 to C15) names
# Note: a processor extension allows up to 32 coprocessor general-purpose registers
copro_gpr_names = ["C%d" % r for r in range(32)]  # register names
copro_gpr_exprs, copro_gpr_inits, copro_gpr_infos = gen_regs(copro_gpr_names, globals())


# Set registers initial values
all_regs_ids = gpr_exprs + csr_exprs + copro_gpr_exprs + [
    exception_flags, take_jmp, last_addr, is_repeat_end,
    in_erepeat
]

all_regs_ids_init = gpr_inits + csr_inits + copro_gpr_inits + [
    exception_flags_init, take_jmp_init, last_addr_init, is_repeat_end_init,
    in_erepeat_init
]

all_regs_ids_no_alias = all_regs_ids[:]  # GV: not understood yet !
all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])


float_st0 = ExprId("float_st0", 64)
float_st1 = ExprId("float_st1", 64)
float_st2 = ExprId("float_st2", 64)
float_st3 = ExprId("float_st3", 64)
float_st4 = ExprId("float_st4", 64)
float_st5 = ExprId("float_st5", 64)
float_st6 = ExprId("float_st6", 64)
float_st7 = ExprId("float_st7", 64)

regs_flt_expr = [float_st0, float_st1, float_st2, float_st3,
                 float_st4, float_st5, float_st6, float_st7]


regs_init = dict()  # mandatory name
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]
