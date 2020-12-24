from builtins import range
from future.utils import viewitems, viewvalues

from miasm.expression.expression import *
from miasm.ir.ir import Lifter, IRBlock, AssignBlock
from miasm.arch.arm.arch import mn_arm, mn_armt
from miasm.arch.arm.regs import *

from miasm.jitter.csts import EXCEPT_DIV_BY_ZERO, EXCEPT_INT_XX

coproc_reg_dict = {
        ("p15", "c0", 0, "c0", 0): MIDR,
        ("p15", "c0", 0, "c0", 1): CTR,
        ("p15", "c0", 0, "c0", 2): TCMTR,
        ("p15", "c0", 0, "c0", 3): TLBTR,
        ("p15", "c0", 0, "c0", 4): MIDR,
        ("p15", "c0", 0, "c0", 5): MPIDR,
        ("p15", "c0", 0, "c0", 6): REVIDR,
        ("p15", "c0", 0, "c0", 7): MIDR,

        ("p15", "c0", 0, "c1", 0): ID_PFR0,
        ("p15", "c0", 0, "c1", 1): ID_PFR1,
        ("p15", "c0", 0, "c1", 2): ID_DFR0,
        ("p15", "c0", 0, "c1", 3): ID_AFR0,
        ("p15", "c0", 0, "c1", 4): ID_MMFR0,
        ("p15", "c0", 0, "c1", 5): ID_MMFR1,
        ("p15", "c0", 0, "c1", 6): ID_MMFR2,
        ("p15", "c0", 0, "c1", 7): ID_MMFR3,

        ("p15", "c0", 0, "c2", 0): ID_ISAR0,
        ("p15", "c0", 0, "c2", 1): ID_ISAR1,
        ("p15", "c0", 0, "c2", 2): ID_ISAR2,
        ("p15", "c0", 0, "c2", 3): ID_ISAR3,
        ("p15", "c0", 0, "c2", 4): ID_ISAR4,
        ("p15", "c0", 0, "c2", 5): ID_ISAR5,

        ("p15", "c0", 1, "c0", 0): CCSIDR,
        ("p15", "c0", 1, "c0", 1): CLIDR,
        ("p15", "c0", 1, "c0", 7): AIDR,

        ("p15", "c0", 2, "c0", 0): CSSELR,

        ("p15", "c0", 4, "c0", 0): VPIDR,
        ("p15", "c0", 4, "c0", 5): VMPIDR,

        ("p15", "c1", 0, "c0", 0): SCTLR,
        ("p15", "c1", 0, "c0", 1): ACTLR,
        ("p15", "c1", 0, "c0", 2): CPACR,

        ("p15", "c1", 0, "c1", 0): SCR,
        ("p15", "c1", 0, "c1", 1): SDER,
        ("p15", "c1", 0, "c1", 2): NSACR,

        ("p15", "c1", 4, "c0", 0): HSCTLR,
        ("p15", "c1", 4, "c0", 1): HACTLR,

        ("p15", "c1", 4, "c1", 0): HCR,
        ("p15", "c1", 4, "c1", 1): HDCR,
        ("p15", "c1", 4, "c1", 2): HCPTR,
        ("p15", "c1", 4, "c1", 3): HSTR,
        ("p15", "c1", 4, "c1", 7): HACR,

        # TODO: TTBRO/TTBR1 64-bit
        ("p15", "c2", 0, "c0", 0): TTBR0,
        ("p15", "c2", 0, "c0", 1): TTBR1,
        ("p15", "c2", 0, "c0", 2): TTBCR,

        ("p15", "c2", 4, "c0", 2): HTCR,

        ("p15", "c2", 4, "c1", 2): VTCR,

        # TODO: HTTBR, VTTBR

        ("p15", "c3", 0, "c0", 0): DACR,

        ("p15", "c5", 0, "c0", 0): DFSR,
        ("p15", "c5", 0, "c0", 1): IFSR,

        ("p15", "c5", 0, "c1", 0): ADFSR,
        ("p15", "c5", 0, "c1", 1): AIFSR,

        ("p15", "c5", 4, "c1", 0): HADFSR,
        ("p15", "c5", 4, "c1", 1): HAIFSR,

        ("p15", "c5", 4, "c2", 0): HSR,

        ("p15", "c6", 0, "c1", 0): DFAR,
        ("p15", "c6", 0, "c1", 2): IFAR,

        ("p15", "c6", 4, "c0", 0): HDFAR,
        ("p15", "c6", 4, "c0", 2): HIFAR,
        ("p15", "c6", 4, "c0", 4): HPFAR,

        ("p15", "c7", 0, "c1", 0): ICIALLUIS,
        ("p15", "c7", 0, "c1", 6): BPIALLIS,

        ("p15", "c7", 0, "c4", 0): PAR,

        # TODO: PAR 64-bit

        ("p15", "c7", 0, "c5", 0): ICIALLU,
        ("p15", "c7", 0, "c5", 1): ICIMVAU,
        ("p15", "c7", 0, "c5", 4): CP15ISB,
        ("p15", "c7", 0, "c5", 6): BPIALL,
        ("p15", "c7", 0, "c5", 7): BPIMVA,

        ("p15", "c7", 0, "c6", 1): DCIMVAC,
        ("p15", "c7", 0, "c6", 2): DCISW,

        ("p15", "c7", 0, "c8", 0): ATS1CPR,
        ("p15", "c7", 0, "c8", 1): ATS1CPW,
        ("p15", "c7", 0, "c8", 2): ATS1CUR,
        ("p15", "c7", 0, "c8", 3): ATS1CUW,
        ("p15", "c7", 0, "c8", 4): ATS12NSOPR,
        ("p15", "c7", 0, "c8", 5): ATS12NSOPW,
        ("p15", "c7", 0, "c8", 6): ATS12NSOUR,
        ("p15", "c7", 0, "c8", 7): ATS12NSOUW,

        ("p15", "c7", 0, "c10", 1): DCCMVAC,
        ("p15", "c7", 0, "c10", 2): DCCSW,
        ("p15", "c7", 0, "c10", 4): CP15DSB,
        ("p15", "c7", 0, "c10", 5): CP15DMB,

        ("p15", "c7", 0, "c11", 1): DCCMVAU,

        ("p15", "c7", 0, "c14", 1): DCCIMVAC,
        ("p15", "c7", 0, "c14", 2): DCCISW,

        ("p15", "c7", 4, "c8", 0): ATS1HR,
        ("p15", "c7", 4, "c8", 1): ATS1HW,

        ("p15", "c8", 0, "c3", 0): TLBIALLIS,
        ("p15", "c8", 0, "c3", 1): TLBIMVAIS,
        ("p15", "c8", 0, "c3", 2): TLBIASIDIS,
        ("p15", "c8", 0, "c3", 3): TLBIMVAAIS,

        ("p15", "c8", 0, "c5", 0): ITLBIALL,
        ("p15", "c8", 0, "c5", 1): ITLBIMVA,
        ("p15", "c8", 0, "c5", 2): ITLBIASID,

        ("p15", "c8", 0, "c6", 0): DTLBIALL,
        ("p15", "c8", 0, "c6", 1): DTLBIMVA,
        ("p15", "c8", 0, "c6", 2): DTLBIASID,

        ("p15", "c8", 0, "c7", 0): TLBIALL,
        ("p15", "c8", 0, "c7", 1): TLBIMVA,
        ("p15", "c8", 0, "c7", 2): TLBIASID,
        ("p15", "c8", 0, "c7", 3): TLBIMVAA,

        ("p15", "c8", 4, "c3", 0): TLBIALLHIS,
        ("p15", "c8", 4, "c3", 1): TLBIMVAHIS,
        ("p15", "c8", 4, "c3", 4): TLBIALLNSNHIS,

        ("p15", "c8", 4, "c7", 0): TLBIALLH,
        ("p15", "c8", 4, "c7", 1): TLBIMVAH,
        ("p15", "c8", 4, "c7", 2): TLBIALLNSNH,

        ("p15", "c9", 0, "c12", 0): PMCR,
        ("p15", "c9", 0, "c12", 1): PMCNTENSET,
        ("p15", "c9", 0, "c12", 2): PMCNTENCLR,
        ("p15", "c9", 0, "c12", 3): PMOVSR,
        ("p15", "c9", 0, "c12", 4): PMSWINC,
        ("p15", "c9", 0, "c12", 5): PMSELR,
        ("p15", "c9", 0, "c12", 6): PMCEID0,
        ("p15", "c9", 0, "c12", 7): PMCEID1,

        ("p15", "c9", 0, "c13", 0): PMCCNTR,
        ("p15", "c9", 0, "c13", 1): PMXEVTYPER,
        ("p15", "c9", 0, "c13", 2): PMXEVCNTR,

        ("p15", "c9", 0, "c14", 0): PMUSERENR,
        ("p15", "c9", 0, "c14", 1): PMINTENSET,
        ("p15", "c9", 0, "c14", 2): PMINTENCLR,
        ("p15", "c9", 0, "c14", 3): PMOVSSET,

        ("p15", "c10", 0, "c2", 0): PRRR,   # ALIAS MAIR0
        ("p15", "c10", 0, "c2", 1): NMRR,   # ALIAS MAIR1

        ("p15", "c10", 0, "c3", 0): AMAIR0,
        ("p15", "c10", 0, "c3", 1): AMAIR1,

        ("p15", "c10", 4, "c2", 0): HMAIR0,
        ("p15", "c10", 4, "c2", 1): HMAIR1,

        ("p15", "c10", 4, "c3", 0): HAMAIR0,
        ("p15", "c10", 4, "c3", 1): HAMAIR1,

        ("p15", "c12", 0, "c0", 0): VBAR,
        ("p15", "c12", 0, "c0", 1): MVBAR,

        ("p15", "c12", 0, "c1", 0): ISR,

        ("p15", "c12", 4, "c0", 0): HVBAR,

        ("p15", "c13", 0, "c0", 0): FCSEIDR,
        ("p15", "c13", 0, "c0", 1): CONTEXTIDR,
        ("p15", "c13", 0, "c0", 2): TPIDRURW,
        ("p15", "c13", 0, "c0", 3): TPIDRURO,
        ("p15", "c13", 0, "c0", 4): TPIDRPRW,

        ("p15", "c13", 4, "c0", 2): HTPIDR,

        ("p15", "c14", 0, "c0", 0): CNTFRQ,
        # TODO: CNTPCT 64-bit

        ("p15", "c14", 0, "c1", 0): CNTKCTL,

        ("p15", "c14", 0, "c2", 0): CNTP_TVAL,
        ("p15", "c14", 0, "c2", 1): CNTP_CTL,

        ("p15", "c14", 0, "c3", 0): CNTV_TVAL,
        ("p15", "c14", 0, "c3", 1): CNTV_CTL,

        # TODO: CNTVCT, CNTP_CVAL, CNTV_CVAL, CNTVOFF 64-bit

        ("p15", "c14", 4, "c1", 0): CNTHCTL,

        ("p15", "c14", 4, "c2", 0): CNTHP_TVAL,
        ("p15", "c14", 4, "c2", 0): CNTHP_CTL

        # TODO: CNTHP_CVAL 64-bit
        }

# liris.cnrs.fr/~mmrissa/lib/exe/fetch.php?media=armv7-a-r-manual.pdf
EXCEPT_SOFT_BP = (1 << 1)

EXCEPT_PRIV_INSN = (1 << 17)

# CPSR: N Z C V


def update_flag_zf(a):
    return [ExprAssign(zf, ExprOp("FLAG_EQ", a))]


def update_flag_zf_eq(a, b):
    return [ExprAssign(zf, ExprOp("FLAG_EQ_CMP", a, b))]


def update_flag_nf(arg):
    return [
        ExprAssign(
            nf,
            ExprOp("FLAG_SIGN_SUB", arg, ExprInt(0, arg.size))
        )
    ]


def update_flag_zn(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    return e



# XXX TODO: set cf if ROT imm in argument


def check_ops_msb(a, b, c):
    if not a or not b or not c or a != b or a != c:
        raise ValueError('bad ops size %s %s %s' % (a, b, c))

def update_flag_add_cf(op1, op2):
    "Compute cf in @op1 + @op2"
    return [ExprAssign(cf, ExprOp("FLAG_ADD_CF", op1, op2))]


def update_flag_add_of(op1, op2):
    "Compute of in @op1 + @op2"
    return [ExprAssign(of, ExprOp("FLAG_ADD_OF", op1, op2))]


def update_flag_sub_cf(op1, op2):
    "Compote CF in @op1 - @op2"
    return [ExprAssign(cf, ExprOp("FLAG_SUB_CF", op1, op2) ^ ExprInt(1, 1))]


def update_flag_sub_of(op1, op2):
    "Compote OF in @op1 - @op2"
    return [ExprAssign(of, ExprOp("FLAG_SUB_OF", op1, op2))]


def update_flag_arith_add_co(arg1, arg2):
    e = []
    e += update_flag_add_cf(arg1, arg2)
    e += update_flag_add_of(arg1, arg2)
    return e


def update_flag_arith_add_zn(arg1, arg2):
    """
    Compute zf and nf flags for (arg1 + arg2)
    """
    e = []
    e += update_flag_zf_eq(arg1, -arg2)
    e += [ExprAssign(nf, ExprOp("FLAG_SIGN_SUB", arg1, -arg2))]
    return e


def update_flag_arith_sub_co(arg1, arg2):
    """
    Compute cf and of flags for (arg1 - arg2)
    """
    e = []
    e += update_flag_sub_cf(arg1, arg2)
    e += update_flag_sub_of(arg1, arg2)
    return e


def update_flag_arith_sub_zn(arg1, arg2):
    """
    Compute zf and nf flags for (arg1 - arg2)
    """
    e = []
    e += update_flag_zf_eq(arg1, arg2)
    e += [ExprAssign(nf, ExprOp("FLAG_SIGN_SUB", arg1, arg2))]
    return e




def update_flag_zfaddwc_eq(arg1, arg2, arg3):
    return [ExprAssign(zf, ExprOp("FLAG_EQ_ADDWC", arg1, arg2, arg3))]

def update_flag_zfsubwc_eq(arg1, arg2, arg3):
    return [ExprAssign(zf, ExprOp("FLAG_EQ_SUBWC", arg1, arg2, arg3))]


def update_flag_arith_addwc_zn(arg1, arg2, arg3):
    """
    Compute znp flags for (arg1 + arg2 + cf)
    """
    e = []
    e += update_flag_zfaddwc_eq(arg1, arg2, arg3)
    e += [ExprAssign(nf, ExprOp("FLAG_SIGN_ADDWC", arg1, arg2, arg3))]
    return e


def update_flag_arith_subwc_zn(arg1, arg2, arg3):
    """
    Compute znp flags for (arg1 - (arg2 + cf))
    """
    e = []
    e += update_flag_zfsubwc_eq(arg1, arg2, arg3)
    e += [ExprAssign(nf, ExprOp("FLAG_SIGN_SUBWC", arg1, arg2, arg3))]
    return e


def update_flag_addwc_cf(op1, op2, op3):
    "Compute cf in @res = @op1 + @op2 + @op3"
    return [ExprAssign(cf, ExprOp("FLAG_ADDWC_CF", op1, op2, op3))]


def update_flag_addwc_of(op1, op2, op3):
    "Compute of in @res = @op1 + @op2 + @op3"
    return [ExprAssign(of, ExprOp("FLAG_ADDWC_OF", op1, op2, op3))]


def update_flag_arith_addwc_co(arg1, arg2, arg3):
    e = []
    e += update_flag_addwc_cf(arg1, arg2, arg3)
    e += update_flag_addwc_of(arg1, arg2, arg3)
    return e



def update_flag_subwc_cf(op1, op2, op3):
    "Compute cf in @res = @op1 + @op2 + @op3"
    return [ExprAssign(cf, ExprOp("FLAG_SUBWC_CF", op1, op2, op3) ^ ExprInt(1, 1))]


def update_flag_subwc_of(op1, op2, op3):
    "Compute of in @res = @op1 + @op2 + @op3"
    return [ExprAssign(of, ExprOp("FLAG_SUBWC_OF", op1, op2, op3))]


def update_flag_arith_subwc_co(arg1, arg2, arg3):
    e = []
    e += update_flag_subwc_cf(arg1, arg2, arg3)
    e += update_flag_subwc_of(arg1, arg2, arg3)
    return e



def get_dst(a):
    if a == PC:
        return PC
    return None

# instruction definition ##############


def adc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    r = b + c + cf.zeroExtend(32)
    if instr.name == 'ADCS' and a != PC:
        e += update_flag_arith_addwc_zn(arg1, arg2, cf)
        e += update_flag_arith_addwc_co(arg1, arg2, cf)
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def add(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    r = b + c
    if instr.name == 'ADDS' and a != PC:
        e += update_flag_arith_add_zn(arg1, arg2)
        e += update_flag_arith_add_co(arg1, arg2)
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def l_and(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & c
    if instr.name == 'ANDS' and a != PC:
        e += [ExprAssign(zf, ExprOp('FLAG_EQ_AND', b, c))]
        e += update_flag_nf(r)

    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def sub(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b - c
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def subs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    r = b - c
    e += update_flag_arith_sub_zn(arg1, arg2)
    e += update_flag_arith_sub_co(arg1, arg2)
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def eor(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b ^ c
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def eors(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    r = arg1 ^ arg2

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_CMP', arg1, arg2))]
    e += update_flag_nf(r)

    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def rsb(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = c, b
    r = arg1 - arg2
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def rsbs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = c, b
    r = arg1 - arg2
    e += update_flag_arith_sub_zn(arg1, arg2)
    e += update_flag_arith_sub_co(arg1, arg2)
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def sbc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    r = arg1 - (arg2 + (~cf).zeroExtend(32))
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def sbcs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    r = arg1 - (arg2 + (~cf).zeroExtend(32))

    e += update_flag_arith_subwc_zn(arg1, arg2, ~cf)
    e += update_flag_arith_subwc_co(arg1, arg2, ~cf)

    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def rsc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = c, b
    r = arg1 - (arg2 + (~cf).zeroExtend(32))
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def rscs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = c, b
    r = arg1 - (arg2 + (~cf).zeroExtend(32))

    e += update_flag_arith_subwc_zn(arg1, arg2, ~cf)
    e += update_flag_arith_subwc_co(arg1, arg2, ~cf)

    e.append(ExprAssign(a, r))

    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def tst(ir, instr, a, b):
    e = []
    arg1, arg2 = a, b
    r = arg1 & arg2

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_AND', arg1, arg2))]
    e += update_flag_nf(r)

    return e, []


def teq(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    r = arg1 ^ arg2

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_CMP', arg1, arg2))]
    e += update_flag_nf(r)

    return e, []


def l_cmp(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    e += update_flag_arith_sub_zn(arg1, arg2)
    e += update_flag_arith_sub_co(arg1, arg2)
    return e, []


def cmn(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    e += update_flag_arith_add_zn(arg1, arg2)
    e += update_flag_arith_add_co(arg1, arg2)
    return e, []


def orr(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b | c
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def orn(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = ~(b | c)
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def orrs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    arg1, arg2 = b, c
    r = arg1 | arg2

    e += [ExprAssign(zf, ExprOp('FLAG_EQ', r))]
    e += update_flag_nf(r)

    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def mov(ir, instr, a, b):
    e = [ExprAssign(a, b)]
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, b))
    return e, []


def movt(ir, instr, a, b):
    r = a | b << ExprInt(16, 32)
    e = [ExprAssign(a, r)]
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def movs(ir, instr, a, b):
    e = []
    e.append(ExprAssign(a, b))
    # XXX TODO check
    e += [ExprAssign(zf, ExprOp('FLAG_EQ', b))]
    e += update_flag_nf(b)

    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, b))
    return e, []


def mvn(ir, instr, a, b):
    r = b ^ ExprInt(-1, 32)
    e = [ExprAssign(a, r)]
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def mvns(ir, instr, a, b):
    e = []
    r = b ^ ExprInt(-1, 32)
    e.append(ExprAssign(a, r))
    # XXX TODO check
    e += [ExprAssign(zf, ExprOp('FLAG_EQ', r))]
    e += update_flag_nf(r)

    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []



def mrs(ir, instr, a, b):
    e = []
    if b.is_id('CPSR_cxsf'):
        out = []
        out.append(ExprInt(0x10, 28))
        out.append(of)
        out.append(cf)
        out.append(zf)
        out.append(nf)
        e.append(ExprAssign(a, ExprCompose(*out)))
    else:
        raise NotImplementedError("MRS not implemented")
    return e, []

def msr(ir, instr, a, b):
    e = []
    if a.is_id('CPSR_cf'):
        e.append(ExprAssign(nf, b[31:32]))
        e.append(ExprAssign(zf, b[30:31]))
        e.append(ExprAssign(cf, b[29:30]))
        e.append(ExprAssign(of, b[28:29]))
    else:
        raise NotImplementedError("MSR not implemented")
    return e, []


def neg(ir, instr, a, b):
    e = []
    r = - b
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []

def negs(ir, instr, a, b):
    return subs(ir, instr, a, ExprInt(0, b.size), b)

def bic(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & (c ^ ExprInt(-1, 32))
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def bics(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    tmp1, tmp2 = b, ~c
    r = tmp1 & tmp2

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_AND', tmp1, tmp2))]
    e += update_flag_nf(r)

    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def sdiv(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b

    loc_div = ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
    loc_except = ExprId(ir.loc_db.add_location(), ir.IRDst.size)
    loc_next = ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

    e.append(ExprAssign(ir.IRDst, ExprCond(c, loc_div, loc_except)))

    do_except = []
    do_except.append(ExprAssign(exception_flags, ExprInt(EXCEPT_DIV_BY_ZERO, exception_flags.size)))
    do_except.append(ExprAssign(ir.IRDst, loc_next))
    blk_except = IRBlock(ir.loc_db, loc_except.loc_key, [AssignBlock(do_except, instr)])



    r = ExprOp("sdiv", b, c)
    do_div = []
    do_div.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        do_div.append(ExprAssign(ir.IRDst, r))

    do_div.append(ExprAssign(ir.IRDst, loc_next))
    blk_div = IRBlock(ir.loc_db, loc_div.loc_key, [AssignBlock(do_div, instr)])

    return e, [blk_div, blk_except]


def udiv(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b



    loc_div = ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
    loc_except = ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
    loc_next = ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

    e.append(ExprAssign(ir.IRDst, ExprCond(c, loc_div, loc_except)))

    do_except = []
    do_except.append(ExprAssign(exception_flags, ExprInt(EXCEPT_DIV_BY_ZERO, exception_flags.size)))
    do_except.append(ExprAssign(ir.IRDst, loc_next))
    blk_except = IRBlock(ir.loc_db, loc_except.loc_key, [AssignBlock(do_except, instr)])


    r = ExprOp("udiv", b, c)
    do_div = []
    do_div.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        do_div.append(ExprAssign(ir.IRDst, r))

    do_div.append(ExprAssign(ir.IRDst, loc_next))
    blk_div = IRBlock(ir.loc_db, loc_div.loc_key, [AssignBlock(do_div, instr)])

    return e, [blk_div, blk_except]


def mla(ir, instr, a, b, c, d):
    e = []
    r = (b * c) + d
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def mlas(ir, instr, a, b, c, d):
    e = []
    r = (b * c) + d
    e += update_flag_zn(r)
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def mls(ir, instr, a, b, c, d):
    e = []
    r = d - (b * c)
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def mul(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b * c
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def muls(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b * c
    e += update_flag_zn(r)
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []

def umull(ir, instr, a, b, c, d):
    e = []
    r = c.zeroExtend(64) * d.zeroExtend(64)
    e.append(ExprAssign(a, r[0:32]))
    e.append(ExprAssign(b, r[32:64]))
    # r15/IRDst not allowed as output
    return e, []

def umlal(ir, instr, a, b, c, d):
    e = []
    r = c.zeroExtend(64) * d.zeroExtend(64) + ExprCompose(a, b)
    e.append(ExprAssign(a, r[0:32]))
    e.append(ExprAssign(b, r[32:64]))
    # r15/IRDst not allowed as output
    return e, []

def smull(ir, instr, a, b, c, d):
    e = []
    r = c.signExtend(64) * d.signExtend(64)
    e.append(ExprAssign(a, r[0:32]))
    e.append(ExprAssign(b, r[32:64]))
    # r15/IRDst not allowed as output
    return e, []

def smlal(ir, instr, a, b, c, d):
    e = []
    r = c.signExtend(64) * d.signExtend(64) + ExprCompose(a, b)
    e.append(ExprAssign(a, r[0:32]))
    e.append(ExprAssign(b, r[32:64]))
    # r15/IRDst not allowed as output
    return e, []

def b(ir, instr, a):
    e = []
    e.append(ExprAssign(PC, a))
    e.append(ExprAssign(ir.IRDst, a))
    return e, []


def bl(ir, instr, a):
    e = []
    l = ExprInt(instr.offset + instr.l, 32)
    e.append(ExprAssign(PC, a))
    e.append(ExprAssign(ir.IRDst, a))
    e.append(ExprAssign(LR, l))
    return e, []


def bx(ir, instr, a):
    e = []
    e.append(ExprAssign(PC, a))
    e.append(ExprAssign(ir.IRDst, a))
    return e, []


def blx(ir, instr, a):
    e = []
    l = ExprInt(instr.offset + instr.l, 32)
    e.append(ExprAssign(PC, a))
    e.append(ExprAssign(ir.IRDst, a))
    e.append(ExprAssign(LR, l))
    return e, []


def st_ld_r(ir, instr, a, a2, b, store=False, size=32, s_ext=False, z_ext=False):
    e = []
    wb = False
    postinc = False
    b = b.ptr
    if isinstance(b, ExprOp):
        if b.op == "wback":
            wb = True
            b = b.args[0]
        if b.op == "postinc":
            postinc = True
    if isinstance(b, ExprOp) and b.op in ["postinc", 'preinc']:
        # XXX TODO CHECK
        base, off = b.args[0],  b.args[1]  # ExprInt(size/8, 32)
    else:
        base, off = b, ExprInt(0, 32)
    if postinc:
        ad = base
    else:
        ad = base + off

    # PC base lookup uses PC 4 byte alignment
    ad = ad.replace_expr({PC: PC & ExprInt(0xFFFFFFFC, 32)})

    dmem = False
    if size in [8, 16]:
        if store:
            a = a[:size]
            m = ExprMem(ad, size=size)
        elif s_ext:
            m = ExprMem(ad, size=size).signExtend(a.size)
        elif z_ext:
            m = ExprMem(ad, size=size).zeroExtend(a.size)
        else:
            raise ValueError('unhandled case')
    elif size == 32:
        m = ExprMem(ad, size=size)
    elif size == 64:
        assert a2 is not None
        m = ExprMem(ad, size=32)
        dmem = True
        size = 32
    else:
        raise ValueError('the size DOES matter')
    dst = None

    if store:
        e.append(ExprAssign(m, a))
        if dmem:
            e.append(ExprAssign(ExprMem(ad + ExprInt(4, 32), size=size), a2))
    else:
        if a == PC:
            dst = PC
            e.append(ExprAssign(ir.IRDst, m))
        e.append(ExprAssign(a, m))
        if dmem:
            e.append(ExprAssign(a2, ExprMem(ad + ExprInt(4, 32), size=size)))

    # XXX TODO check multiple write cause by wb
    if wb or postinc:
        e.append(ExprAssign(base, base + off))
    return e, []


def ldr(ir, instr, a, b):
    return st_ld_r(ir, instr, a, None, b, store=False)


def ldrd(ir, instr, a, b, c=None):
    if c is None:
        a2 = ir.arch.regs.all_regs_ids[ir.arch.regs.all_regs_ids.index(a) + 1]
    else:
        a2 = b
        b = c
    return st_ld_r(ir, instr, a, a2, b, store=False, size=64)


def l_str(ir, instr, a, b):
    return st_ld_r(ir, instr, a, None, b, store=True)


def l_strd(ir, instr, a, b, c=None):
    if c is None:
        a2 = ir.arch.regs.all_regs_ids[ir.arch.regs.all_regs_ids.index(a) + 1]
    else:
        a2 = b
        b = c
    return st_ld_r(ir, instr, a, a2, b, store=True, size=64)

def ldrb(ir, instr, a, b):
    return st_ld_r(ir, instr, a, None, b, store=False, size=8, z_ext=True)

def ldrsb(ir, instr, a, b):
    return st_ld_r(ir, instr, a, None, b, store=False, size=8, s_ext=True, z_ext=False)

def strb(ir, instr, a, b):
    return st_ld_r(ir, instr, a, None, b, store=True, size=8)

def ldrh(ir, instr, a, b):
    return st_ld_r(ir, instr, a, None, b, store=False, size=16, z_ext=True)


def strh(ir, instr, a, b):
    return st_ld_r(ir, instr, a, None, b, store=True, size=16, z_ext=True)


def ldrsh(ir, instr, a, b):
    return st_ld_r(ir, instr, a, None, b, store=False, size=16, s_ext=True, z_ext=False)


def st_ld_m(ir, instr, a, b, store=False, postinc=False, updown=False):
    e = []
    wb = False
    dst = None
    if isinstance(a, ExprOp) and a.op == 'wback':
        wb = True
        a = a.args[0]
    if isinstance(b, ExprOp) and b.op == 'sbit':
        b = b.args[0]
    regs = b.args
    base = a
    if updown:
        step = 4
    else:
        step = -4
        regs = regs[::-1]
    if postinc:
        pass
    else:
        base += ExprInt(step, 32)
    for i, r in enumerate(regs):
        ad = base + ExprInt(i * step, 32)
        if store:
            e.append(ExprAssign(ExprMem(ad, 32), r))
        else:
            e.append(ExprAssign(r, ExprMem(ad, 32)))
            if r == PC:
                e.append(ExprAssign(ir.IRDst, ExprMem(ad, 32)))
    # XXX TODO check multiple write cause by wb
    if wb:
        if postinc:
            e.append(ExprAssign(a, base + ExprInt(len(regs) * step, 32)))
        else:
            e.append(ExprAssign(a, base + ExprInt((len(regs) - 1) * step, 32)))
    if store:
        pass
    else:
        assert(isinstance(b, ExprOp) and b.op == "reglist")

    return e, []


def ldmia(ir, instr, a, b):
    return st_ld_m(ir, instr, a, b, store=False, postinc=True, updown=True)


def ldmib(ir, instr, a, b):
    return st_ld_m(ir, instr, a, b, store=False, postinc=False, updown=True)


def ldmda(ir, instr, a, b):
    return st_ld_m(ir, instr, a, b, store=False, postinc=True, updown=False)


def ldmdb(ir, instr, a, b):
    return st_ld_m(ir, instr, a, b, store=False, postinc=False, updown=False)


def stmia(ir, instr, a, b):
    return st_ld_m(ir, instr, a, b, store=True, postinc=True, updown=True)


def stmib(ir, instr, a, b):
    return st_ld_m(ir, instr, a, b, store=True, postinc=False, updown=True)


def stmda(ir, instr, a, b):
    return st_ld_m(ir, instr, a, b, store=True, postinc=True, updown=False)


def stmdb(ir, instr, a, b):
    return st_ld_m(ir, instr, a, b, store=True, postinc=False, updown=False)


def svc(ir, instr, a):
    e = []
    except_int = EXCEPT_INT_XX
    e.append(ExprAssign(exception_flags, ExprInt(except_int, 32)))
    e.append(ExprAssign(interrupt_num, a))
    return e, []


def und(ir, instr, a, b):
    # XXX TODO implement
    e = []
    return e, []

# TODO XXX implement correct CF for shifters
def lsr(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b >> c
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def lsrs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b >> c
    e.append(ExprAssign(a, r))

    e += [ExprAssign(zf, ExprOp('FLAG_EQ', r))]
    e += update_flag_nf(r)

    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []

def asr(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = ExprOp("a>>", b, c)
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []

def asrs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = ExprOp("a>>", b, c)
    e.append(ExprAssign(a, r))

    e += [ExprAssign(zf, ExprOp('FLAG_EQ', r))]
    e += update_flag_nf(r)

    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []

def lsl(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b << c
    e.append(ExprAssign(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def lsls(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b << c
    e.append(ExprAssign(a, r))

    e += [ExprAssign(zf, ExprOp('FLAG_EQ', r))]
    e += update_flag_nf(r)

    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def rors(ir, instr, a, b):
    e = []
    r = ExprOp(">>>", a, b)
    e.append(ExprAssign(a, r))

    e += [ExprAssign(zf, ExprOp('FLAG_EQ', r))]
    e += update_flag_nf(r)

    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def push(ir, instr, a):
    e = []
    regs = list(a.args)
    for i in range(len(regs)):
        r = SP + ExprInt(-4 * len(regs) + 4 * i, 32)
        e.append(ExprAssign(ExprMem(r, 32), regs[i]))
    r = SP + ExprInt(-4 * len(regs), 32)
    e.append(ExprAssign(SP, r))
    return e, []


def pop(ir, instr, a):
    e = []
    regs = list(a.args)
    dst = None
    for i in range(len(regs)):
        r = SP + ExprInt(4 * i, 32)
        e.append(ExprAssign(regs[i], ExprMem(r, 32)))
        if regs[i] == ir.pc:
            dst = ExprMem(r, 32)
    r = SP + ExprInt(4 * len(regs), 32)
    e.append(ExprAssign(SP, r))
    if dst is not None:
        e.append(ExprAssign(ir.IRDst, dst))
    return e, []


def cbz(ir, instr, a, b):
    e = []
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 32)
    e.append(ExprAssign(ir.IRDst, ExprCond(a, loc_next_expr, b)))
    return e, []


def cbnz(ir, instr, a, b):
    e = []
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 32)
    e.append(ExprAssign(ir.IRDst, ExprCond(a, b, loc_next_expr)))
    return e, []


def uxtb(ir, instr, a, b):
    e = []
    r = b[:8].zeroExtend(32)
    e.append(ExprAssign(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAssign(ir.IRDst, r))
    return e, []

def uxth(ir, instr, a, b):
    e = []
    r = b[:16].zeroExtend(32)
    e.append(ExprAssign(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAssign(ir.IRDst, r))
    return e, []

def sxtb(ir, instr, a, b):
    e = []
    r = b[:8].signExtend(32)
    e.append(ExprAssign(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAssign(ir.IRDst, r))
    return e, []

def sxth(ir, instr, a, b):
    e = []
    r = b[:16].signExtend(32)
    e.append(ExprAssign(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def ubfx(ir, instr, a, b, c, d):
    e = []
    c = int(c)
    d = int(d)
    r = b[c:c+d].zeroExtend(32)
    e.append(ExprAssign(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAssign(ir.IRDst, r))
    return e, []

def bfc(ir, instr, a, b, c):
    e = []
    start = int(b)
    stop = start + int(c)
    out = []
    last = 0
    if start:
        out.append(a[:start])
        last = start
    if stop - start:
        out.append(ExprInt(0, 32)[last:stop])
        last = stop
    if last < 32:
        out.append(a[last:])
    r = ExprCompose(*out)
    e.append(ExprAssign(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAssign(ir.IRDst, r))
    return e, []


def pld(ir, instr, a):
    e = []
    return e, []


def pldw(ir, instr, a):
    e = []
    return e, []


def clz(ir, instr, a, b):
    e = []
    e.append(ExprAssign(a, ExprOp('cntleadzeros', b)))
    return e, []

def uxtab(ir, instr, a, b, c):
    e = []
    e.append(ExprAssign(a, b + (c & ExprInt(0xff, 32))))
    return e, []


def uxtah(ir, instr, a, b, c):
    e = []
    e.append(ExprAssign(a, b + (c & ExprInt(0xffff, 32))))
    return e, []


def bkpt(ir, instr, a):
    e = []
    e.append(ExprAssign(exception_flags, ExprInt(EXCEPT_SOFT_BP, 32)))
    e.append(ExprAssign(bp_num, a))
    return e, []


def _extract_s16(arg, part):
    if part == 'B': # bottom 16 bits
        return arg[0:16]
    elif part == 'T': # top 16 bits
        return arg[16:32]


def smul(ir, instr, a, b, c):
    e = []
    e.append(ExprAssign(a, _extract_s16(b, instr.name[4]).signExtend(32) * _extract_s16(c, instr.name[5]).signExtend(32)))
    return e, []


def smulw(ir, instr, a, b, c):
    e = []
    prod = b.signExtend(48) * _extract_s16(c, instr.name[5]).signExtend(48)
    e.append(ExprAssign(a, prod[16:48]))
    return e, [] # signed most significant 32 bits of the 48-bit result


def tbb(ir, instr, a):
    e = []
    dst = PC + ExprInt(2, 32) * a.zeroExtend(32)
    e.append(ExprAssign(PC, dst))
    e.append(ExprAssign(ir.IRDst, dst))
    return e, []


def tbh(ir, instr, a):
    e = []
    dst = PC + ExprInt(2, 32) * a.zeroExtend(32)
    e.append(ExprAssign(PC, dst))
    e.append(ExprAssign(ir.IRDst, dst))
    return e, []


def smlabb(ir, instr, a, b, c, d):
    e = []
    result = (b[:16].signExtend(32) * c[:16].signExtend(32)) + d
    e.append(ExprAssign(a, result))
    return e, []


def smlabt(ir, instr, a, b, c, d):
    e = []
    result = (b[:16].signExtend(32) * c[16:32].signExtend(32)) + d
    e.append(ExprAssign(a, result))
    return e, []


def smlatb(ir, instr, a, b, c, d):
    e = []
    result = (b[16:32].signExtend(32) * c[:16].signExtend(32)) + d
    e.append(ExprAssign(a, result))
    return e, []


def smlatt(ir, instr, a, b, c, d):
    e = []
    result = (b[16:32].signExtend(32) * c[16:32].signExtend(32)) + d
    e.append(ExprAssign(a, result))
    return e, []


def uadd8(ir, instr, a, b, c):
    e = []
    sums = []
    ges = []
    for i in range(0, 32, 8):
        sums.append(b[i:i+8] + c[i:i+8])
        ges.append((b[i:i+8].zeroExtend(9) + c[i:i+8].zeroExtend(9))[8:9])

    e.append(ExprAssign(a, ExprCompose(*sums)))

    for i, value in enumerate(ges):
        e.append(ExprAssign(ge_regs[i], value))
    return e, []


def sel(ir, instr, a, b, c):
    e = []
    cond = nf ^ of ^ ExprInt(1, 1)
    parts = []
    for i in range(4):
        parts.append(ExprCond(ge_regs[i], b[i*8:(i+1)*8], c[i*8:(i+1)*8]))
    result = ExprCompose(*parts)
    e.append(ExprAssign(a, result))
    return e, []


def rev(ir, instr, a, b):
    e = []
    result = ExprCompose(b[24:32], b[16:24], b[8:16], b[:8])
    e.append(ExprAssign(a, result))
    return e, []


def rev16(ir, instr, a, b):
    e = []
    result = ExprCompose(b[8:16], b[:8], b[24:32], b[16:24])
    e.append(ExprAssign(a, result))
    return e, []


def nop(ir, instr):
    e = []
    return e, []


def dsb(ir, instr, a):
    # XXX TODO
    e = []
    return e, []

def isb(ir, instr, a):
    # XXX TODO
    e = []
    return e, []

def cpsie(ir, instr, a):
    # XXX TODO
    e = []
    return e, []


def cpsid(ir, instr, a):
    # XXX TODO
    e = []
    return e, []


def wfe(ir, instr):
    # XXX TODO
    e = []
    return e, []


def wfi(ir, instr):
    # XXX TODO
    e = []
    return e, []

def adr(ir, instr, arg1, arg2):
    e = []
    e.append(ExprAssign(arg1, (PC & ExprInt(0xfffffffc, 32)) + arg2))
    return e, []


def pkhbt(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprCompose(
                arg2[:16],
                arg3[16:]
            )
        )
    )
    return e, []


def pkhtb(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprCompose(
                arg3[:16],
                arg2[16:]
            )
        )
    )
    return e, []

def mrc(ir, insr, arg1, arg2, arg3, arg4, arg5, arg6):
    e = []
    sreg = (str(arg1), str(arg4), int(arg2), str(arg5), int(arg6))
    if sreg in coproc_reg_dict:
        e.append(ExprAssign(arg3, coproc_reg_dict[sreg]))
    else:
        raise NotImplementedError("Unknown coprocessor register: %s %s %d %s %d" % (str(arg1), str(arg4), int(arg2), str(arg5), int(arg6)))

    return e, []

def mcr(ir, insr, arg1, arg2, arg3, arg4, arg5, arg6):
    e = []
    sreg = (str(arg1), str(arg4), int(arg2), str(arg5), int(arg6))
    if sreg in coproc_reg_dict:
        e.append(ExprAssign(coproc_reg_dict[sreg], arg3))
    else:
        raise NotImplementedError("Unknown coprocessor register: %s %s %d %s %d" % (str(arg1), str(arg4), int(arg2), str(arg5), int(arg6)))

    return e, []

COND_EQ = 0
COND_NE = 1
COND_CS = 2
COND_CC = 3
COND_MI = 4
COND_PL = 5
COND_VS = 6
COND_VC = 7
COND_HI = 8
COND_LS = 9
COND_GE = 10
COND_LT = 11
COND_GT = 12
COND_LE = 13
COND_AL = 14
COND_NV = 15

cond_dct = {
    COND_EQ: "EQ",
    COND_NE: "NE",
    COND_CS: "CS",
    COND_CC: "CC",
    COND_MI: "MI",
    COND_PL: "PL",
    COND_VS: "VS",
    COND_VC: "VC",
    COND_HI: "HI",
    COND_LS: "LS",
    COND_GE: "GE",
    COND_LT: "LT",
    COND_GT: "GT",
    COND_LE: "LE",
    COND_AL: "AL",
    # COND_NV: "NV",
}

cond_dct_inv = dict((name, num) for num, name in viewitems(cond_dct))


"""
Code            Meaning (for cmp or subs)                                  Flags Tested
eq              Equal.                                                     Z==1
ne              Not equal.                                                 Z==0
cs or hs        Unsigned higher or same (or carry set).                    C==1
cc or lo        Unsigned lower (or carry clear).                           C==0
mi              Negative. The mnemonic stands for "minus".                 N==1
pl              Positive or zero. The mnemonic stands for "plus".          N==0
vs              Signed overflow. The mnemonic stands for "V set".          V==1
vc              No signed overflow. The mnemonic stands for "V clear".     V==0
hi              Unsigned higher.                                           (C==1) && (Z==0)
ls              Unsigned lower or same.                                    (C==0) || (Z==1)
ge              Signed greater than or equal.                              N==V
lt              Signed less than.                                          N!=V
gt              Signed greater than.                                       (Z==0) && (N==V)
le              Signed less than or equal.                                 (Z==1) || (N!=V)
al (or omitted) Always executed.        None tested.
"""

tab_cond = {COND_EQ: ExprOp("CC_EQ", zf),
            COND_NE: ExprOp("CC_NE", zf),
            COND_CS: ExprOp("CC_U>=", cf ^ ExprInt(1, 1)), # inv cf
            COND_CC: ExprOp("CC_U<", cf ^ ExprInt(1, 1)), # inv cf
            COND_MI: ExprOp("CC_NEG", nf),
            COND_PL: ExprOp("CC_POS", nf),
            COND_VS: ExprOp("CC_sOVR", of),
            COND_VC: ExprOp("CC_sNOOVR", of),
            COND_HI: ExprOp("CC_U>", cf ^ ExprInt(1, 1), zf), # inv cf
            COND_LS: ExprOp("CC_U<=", cf ^ ExprInt(1, 1), zf), # inv cf
            COND_GE: ExprOp("CC_S>=", nf, of),
            COND_LT: ExprOp("CC_S<", nf, of),
            COND_GT: ExprOp("CC_S>", nf, of, zf),
            COND_LE: ExprOp("CC_S<=", nf, of, zf),
            }





def is_pc_written(ir, instr_ir):
    all_pc = viewvalues(ir.mn.pc)
    for ir in instr_ir:
        if ir.dst in all_pc:
            return True, ir.dst
    return False, None


def add_condition_expr(ir, instr, cond, instr_ir, extra_ir):
    if cond == COND_AL:
        return instr_ir, extra_ir
    if not cond in tab_cond:
        raise ValueError('unknown condition %r' % cond)
    cond = tab_cond[cond]



    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 32)
    loc_do = ir.loc_db.add_location()
    loc_do_expr = ExprLoc(loc_do, 32)

    dst_cond = ExprCond(cond, loc_do_expr, loc_next_expr)
    assert(isinstance(instr_ir, list))

    has_irdst = False
    for e in instr_ir:
        if e.dst == ir.IRDst:
            has_irdst = True
            break
    if not has_irdst:
        instr_ir.append(ExprAssign(ir.IRDst, loc_next_expr))
    e_do = IRBlock(ir.loc_db, loc_do, [AssignBlock(instr_ir, instr)])
    e = [ExprAssign(ir.IRDst, dst_cond)]
    return e, [e_do] + extra_ir

mnemo_func = {}
mnemo_func_cond = {}
mnemo_condm0 = {'add': add,
                'sub': sub,
                'eor': eor,
                'and': l_and,
                'rsb': rsb,
                'adc': adc,
                'sbc': sbc,
                'rsc': rsc,

                'tst': tst,
                'teq': teq,
                'cmp': l_cmp,
                'cmn': cmn,
                'orr': orr,
                'mov': mov,
                'movt': movt,
                'bic': bic,
                'mvn': mvn,
                'neg': neg,

                'sdiv': sdiv,
                'udiv': udiv,

                'mrc': mrc,
                'mcr': mcr,

                'mul': mul,
                'umull': umull,
                'umlal': umlal,
                'smull': smull,
                'smlal': smlal,
                'mla': mla,
                'ldr': ldr,
                'ldrd': ldrd,
                'ldrsb': ldrsb,
                'str': l_str,
                'strd': l_strd,
                'b': b,
                'bl': bl,
                'svc': svc,
                'und': und,
                'bx': bx,
                'ldrh': ldrh,
                'strh': strh,
                'ldrsh': ldrsh,
                'ldsh': ldrsh,
                'uxtb': uxtb,
                'uxth': uxth,
                'sxtb': sxtb,
                'sxth': sxth,
                'ubfx': ubfx,
                'bfc': bfc,
                'rev': rev,
                'rev16': rev16,
                'clz': clz,
                'uxtab': uxtab,
                'uxtah': uxtah,
                'bkpt': bkpt,
                'smulbb': smul,
                'smulbt': smul,
                'smultb': smul,
                'smultt': smul,
                'smulwt': smulw,
                'smulwb': smulw,

                'pkhtb': pkhtb,
                'pkhbt': pkhbt,

                }

mnemo_condm1 = {'adds': add,
                'subs': subs,
                'eors': eors,
                'ands': l_and,
                'rsbs': rsbs,
                'adcs': adc,
                'sbcs': sbcs,
                'rscs': rscs,

                'orrs': orrs,
                'movs': movs,
                'bics': bics,
                'mvns': mvns,

                'mrs': mrs,
                'msr': msr,

                'negs': negs,

                'muls': muls,
                'mls': mls,
                'mlas': mlas,
                'blx': blx,

                'ldrb': ldrb,
                'ldsb': ldrsb,
                'strb': strb,
                }

mnemo_condm2 = {'ldmia': ldmia,
                'ldmib': ldmib,
                'ldmda': ldmda,
                'ldmdb': ldmdb,

                'ldmfa': ldmda,
                'ldmfd': ldmia,
                'ldmea': ldmdb,
                'ldmed': ldmib,  # XXX


                'stmia': stmia,
                'stmib': stmib,
                'stmda': stmda,
                'stmdb': stmdb,

                'stmfa': stmib,
                'stmed': stmda,
                'stmfd': stmdb,
                'stmea': stmia,
                }


mnemo_nocond = {'lsr': lsr,
                'lsrs': lsrs,
                'lsl': lsl,
                'lsls': lsls,
                'rors': rors,
                'push': push,
                'pop': pop,
                'asr': asr,
                'asrs': asrs,
                'cbz': cbz,
                'cbnz': cbnz,
                'pld': pld,
                'pldw': pldw,
                'tbb': tbb,
                'tbh': tbh,
                'nop': nop,
                'dsb': dsb,
                'isb': isb,
                'cpsie': cpsie,
                'cpsid': cpsid,
                'wfe': wfe,
                'wfi': wfi,
                'adr': adr,
                'orn': orn,
                'smlabb': smlabb,
                'smlabt': smlabt,
                'smlatb': smlatb,
                'smlatt': smlatt,
                'uadd8': uadd8,
                'sel': sel,
                }

mn_cond_x = [mnemo_condm0,
             mnemo_condm1,
             mnemo_condm2]

for index, mn_base in enumerate(mn_cond_x):
    for mn, mf in viewitems(mn_base):
        for cond, cn in viewitems(cond_dct):
            if cond == COND_AL:
                cn = ""
            cn = cn.lower()
            if index == 0:
                mn_mod = mn + cn
            else:
                mn_mod = mn[:-index] + cn + mn[-index:]
            # print mn_mod
            mnemo_func_cond[mn_mod] = cond, mf

for name, mf in viewitems(mnemo_nocond):
    mnemo_func_cond[name] = COND_AL, mf


def split_expr_dst(ir, instr_ir):
    out = []
    dst = None
    for i in instr_ir:
        if i.dst == ir.pc:
            out.append(i)
            dst = ir.pc  # i.src
        else:
            out.append(i)
    return out, dst


def get_mnemo_expr(ir, instr, *args):
    if not instr.name.lower() in mnemo_func_cond:
        raise ValueError('unknown mnemo %s' % instr)
    cond, mf = mnemo_func_cond[instr.name.lower()]
    instr_ir, extra_ir = mf(ir, instr, *args)
    instr, extra_ir = add_condition_expr(ir, instr, cond, instr_ir, extra_ir)
    return instr, extra_ir

get_arm_instr_expr = get_mnemo_expr


class arminfo(object):
    mode = "arm"
    # offset


class Lifter_Arml(Lifter):
    def __init__(self, loc_db):
        Lifter.__init__(self, mn_arm, "l", loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 32)
        self.addrsize = 32



    def mod_pc(self, instr, instr_ir, extra_ir):
        # fix PC (+8 for arm)
        pc_fixed = {self.pc: ExprInt(instr.offset + 8, 32)}

        for i, expr in enumerate(instr_ir):
            dst, src = expr.dst, expr.src
            if dst != self.pc:
                dst = dst.replace_expr(pc_fixed)
            src = src.replace_expr(pc_fixed)
            instr_ir[i] = ExprAssign(dst, src)

        for idx, irblock in enumerate(extra_ir):
            extra_ir[idx] = irblock.modify_exprs(lambda expr: expr.replace_expr(pc_fixed) \
                                                 if expr != self.pc else expr,
                                                 lambda expr: expr.replace_expr(pc_fixed))

    def get_ir(self, instr):
        args = instr.args
        # ir = get_mnemo_expr(self, self.name.lower(), *args)
        if len(args) and isinstance(args[-1], ExprOp):
            if args[-1].op == 'rrx':
                args[-1] = ExprCompose(args[-1].args[0][1:], cf)
            elif (args[-1].op in ['<<', '>>', '<<a', 'a>>', '<<<', '>>>'] and
                  isinstance(args[-1].args[-1], ExprId)):
                args[-1] = ExprOp(args[-1].op,
                                  args[-1].args[0],
                                  args[-1].args[-1][:8].zeroExtend(32))
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)

        self.mod_pc(instr, instr_ir, extra_ir)
        return instr_ir, extra_ir

    def parse_itt(self, instr):
        name = instr.name
        assert name.startswith('IT')
        name = name[1:]
        out = []
        for hint in name:
            if hint == 'T':
                out.append(0)
            elif hint == "E":
                out.append(1)
            else:
                raise ValueError("IT name invalid %s" % instr)
        return out, instr.args[0]

    def do_it_block(self, loc, index, block, assignments, gen_pc_updt):
        instr = block.lines[index]
        it_hints, it_cond = self.parse_itt(instr)
        cond_num = cond_dct_inv[it_cond.name]
        cond_eq = tab_cond[cond_num]

        if not index + len(it_hints) <= len(block.lines):
            raise NotImplementedError("Split IT block non supported yet")

        ir_blocks_all = []

        # Gen dummy irblock for IT instr
        loc_next = self.get_next_loc_key(instr)
        dst = ExprAssign(self.IRDst, ExprLoc(loc_next, 32))
        dst_blk = AssignBlock([dst], instr)
        assignments.append(dst_blk)
        irblock = IRBlock(self.loc_db, loc, assignments)
        ir_blocks_all.append([irblock])

        loc = loc_next
        assignments = []
        for hint in it_hints:
            irblocks = []
            index += 1
            instr = block.lines[index]

            # Add conditional jump to current irblock
            loc_do = self.loc_db.add_location()
            loc_next = self.get_next_loc_key(instr)

            if hint:
                local_cond = ~cond_eq
            else:
                local_cond = cond_eq
            dst = ExprAssign(self.IRDst, ExprCond(local_cond, ExprLoc(loc_do, 32), ExprLoc(loc_next, 32)))
            dst_blk = AssignBlock([dst], instr)
            assignments.append(dst_blk)
            irblock = IRBlock(self.loc_db, loc, assignments)

            irblocks.append(irblock)

            it_instr_irblocks = []
            assignments = []
            loc = loc_do

            split = self.add_instr_to_current_state(
                instr, block, assignments,
                it_instr_irblocks, gen_pc_updt
            )
            if split:
                raise NotImplementedError("Unsupported instr in IT block (%s)" % instr)

            if it_instr_irblocks:
                assert len(it_instr_irblocks) == 1
                it_instr_irblocks = it_instr_irblocks.pop()
            # Remove flags assignment if instr != [CMP, CMN, TST]
            if instr.name not in ["CMP", "CMN", "TST"]:
                # Fix assignments
                out = []
                for assignment in assignments:
                    assignment = AssignBlock(
                        {
                            dst: src for (dst, src) in viewitems(assignment)
                            if dst not in [zf, nf, of, cf]
                        },
                        assignment.instr
                    )
                    out.append(assignment)
                assignments = out
                # Fix extra irblocksx
                new_irblocks = []
                for irblock in it_instr_irblocks:
                    out = []
                    for tmp_assignment in irblock:
                        assignment = AssignBlock(
                            {
                                dst: src for (dst, src) in viewitems(assignment)
                                if dst not in [zf, nf, of, cf]
                            },
                            assignment.instr
                        )
                        out.append(assignment)
                    new_irblock = IRBlock(self.loc_db, irblock.loc_key, out)
                    new_irblocks.append(new_irblock)
                it_instr_irblocks = new_irblocks

            irblocks += it_instr_irblocks
            dst = ExprAssign(self.IRDst, ExprLoc(loc_next, 32))
            dst_blk = AssignBlock([dst], instr)
            assignments.append(dst_blk)
            irblock = IRBlock(self.loc_db, loc, assignments)
            irblocks.append(irblock)
            loc = loc_next
            assignments = []
            ir_blocks_all.append(irblocks)
        return index, ir_blocks_all

    def add_asmblock_to_ircfg(self, block, ircfg, gen_pc_updt=False):
        """
        Add a native block to the current IR
        @block: native assembly block
        @gen_pc_updt: insert PC update effects between instructions
        """

        it_hints = None
        it_cond = None
        label = block.loc_key
        assignments = []
        ir_blocks_all = []
        index = -1
        while index + 1 < len(block.lines):
            index += 1
            instr = block.lines[index]
            if label is None:
                assignments = []
                label = self.get_loc_key_for_instr(instr)
            if instr.name.startswith("IT"):
                index, irblocks_it = self.do_it_block(label, index, block, assignments, gen_pc_updt)
                for irblocks in irblocks_it:
                    ir_blocks_all += irblocks
                label = None
                continue

            split = self.add_instr_to_current_state(
                instr, block, assignments,
                ir_blocks_all, gen_pc_updt
            )
            if split:
                ir_blocks_all.append(IRBlock(self.loc_db, label, assignments))
                label = None
                assignments = []
        if label is not None:
            ir_blocks_all.append(IRBlock(self.loc_db, label, assignments))

        new_ir_blocks_all = self.post_add_asmblock_to_ircfg(block, ircfg, ir_blocks_all)
        for irblock in new_ir_blocks_all:
            ircfg.add_irblock(irblock)
        return new_ir_blocks_all



class Lifter_Armb(Lifter_Arml):
    def __init__(self, loc_db):
        Lifter.__init__(self, mn_arm, "b", loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 32)
        self.addrsize = 32


class Lifter_Armtl(Lifter_Arml):
    def __init__(self, loc_db):
        Lifter.__init__(self, mn_armt, "l", loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 32)
        self.addrsize = 32


    def mod_pc(self, instr, instr_ir, extra_ir):
        # fix PC (+4 for thumb)
        pc_fixed = {self.pc: ExprInt(instr.offset + 4, 32)}

        for i, expr in enumerate(instr_ir):
            dst, src = expr.dst, expr.src
            if dst != self.pc:
                dst = dst.replace_expr(pc_fixed)
            src = src.replace_expr(pc_fixed)
            instr_ir[i] = ExprAssign(dst, src)

        for idx, irblock in enumerate(extra_ir):
            extra_ir[idx] = irblock.modify_exprs(lambda expr: expr.replace_expr(pc_fixed) \
                                                 if expr != self.pc else expr,
                                                 lambda expr: expr.replace_expr(pc_fixed))


class Lifter_Armtb(Lifter_Armtl):
    def __init__(self, loc_db):
        Lifter.__init__(self, mn_armt, "b", loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 32)
        self.addrsize = 32

