from builtins import range
from future.utils import viewitems

from miasm2.expression.expression import ExprId, ExprInt, ExprLoc, ExprMem, \
    ExprCond, ExprCompose, ExprOp, ExprAssign
from miasm2.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock
from miasm2.arch.aarch64.arch import mn_aarch64, conds_expr, replace_regs
from miasm2.arch.aarch64.regs import *
from miasm2.core.sembuilder import SemBuilder
from miasm2.jitter.csts import EXCEPT_DIV_BY_ZERO, EXCEPT_INT_XX


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


cond2expr = {'EQ': ExprOp("CC_EQ", zf),
             'NE': ExprOp("CC_NE", zf),
             'CS': ExprOp("CC_U>=", cf ^ ExprInt(1, 1)), # inv cf
             'CC': ExprOp("CC_U<", cf ^ ExprInt(1, 1)), # inv cf
             'MI': ExprOp("CC_NEG", nf),
             'PL': ExprOp("CC_POS", nf),
             'VS': ExprOp("CC_sOVR", of),
             'VC': ExprOp("CC_sNOOVR", of),
             'HI': ExprOp("CC_U>", cf ^ ExprInt(1, 1), zf), # inv cf
             'LS': ExprOp("CC_U<=", cf ^ ExprInt(1, 1), zf), # inv cf
             'GE': ExprOp("CC_S>=", nf, of),
             'LT': ExprOp("CC_S<", nf, of),
             'GT': ExprOp("CC_S>", nf, of, zf),
             'LE': ExprOp("CC_S<=", nf, of, zf),
             'AL': ExprInt(1, 1),
             'NV': ExprInt(0, 1)
             }


def extend_arg(dst, arg):
    if not isinstance(arg, ExprOp):
        return arg

    op, (reg, shift) = arg.op, arg.args
    if op == "SXTB":
        base = reg[:8].signExtend(dst.size)
        op = "<<"
    elif op == "SXTH":
        base = reg[:16].signExtend(dst.size)
        op = "<<"
    elif op == 'SXTW':
        base = reg[:32].signExtend(dst.size)
        op = "<<"
    elif op == "SXTX":
        base = reg.signExtend(dst.size)
        op = "<<"

    elif op == "UXTB":
        base = reg[:8].zeroExtend(dst.size)
        op = "<<"
    elif op == "UXTH":
        base = reg[:16].zeroExtend(dst.size)
        op = "<<"
    elif op == 'UXTW':
        base = reg[:32].zeroExtend(dst.size)
        op = "<<"
    elif op == "UXTX":
        base = reg.zeroExtend(dst.size)
        op = "<<"

    elif op in ['<<', '>>', '<<a', 'a>>', '<<<', '>>>']:
        base = reg.zeroExtend(dst.size)
    else:
        raise NotImplementedError('Unknown shifter operator')

    out = ExprOp(op, base, (shift.zeroExtend(dst.size)
                            & ExprInt(dst.size - 1, dst.size)))
    return out


# SemBuilder context
ctx = {"PC": PC,
       "LR": LR,
       "nf": nf,
       "zf": zf,
       "cf": cf,
       "of": of,
       "cond2expr": cond2expr,
       "extend_arg": extend_arg,
       "ExprId":ExprId,
       "exception_flags": exception_flags,
       "interrupt_num": interrupt_num,
       "EXCEPT_DIV_BY_ZERO": EXCEPT_DIV_BY_ZERO,
       "EXCEPT_INT_XX": EXCEPT_INT_XX,
       }

sbuild = SemBuilder(ctx)


# instruction definition ##############

@sbuild.parse
def add(arg1, arg2, arg3):
    arg1 = arg2 + extend_arg(arg2, arg3)


@sbuild.parse
def sub(arg1, arg2, arg3):
    arg1 = arg2 - extend_arg(arg2, arg3)


@sbuild.parse
def neg(arg1, arg2):
    arg1 = - arg2


@sbuild.parse
def and_l(arg1, arg2, arg3):
    arg1 = arg2 & extend_arg(arg2, arg3)


@sbuild.parse
def eor(arg1, arg2, arg3):
    arg1 = arg2 ^ extend_arg(arg2, arg3)


@sbuild.parse
def eon(arg1, arg2, arg3):
    arg1 = arg2 ^ (~extend_arg(arg2, arg3))


@sbuild.parse
def orr(arg1, arg2, arg3):
    arg1 = arg2 | extend_arg(arg2, arg3)


@sbuild.parse
def orn(arg1, arg2, arg3):
    arg1 = arg2 | (~extend_arg(arg2, arg3))


@sbuild.parse
def bic(arg1, arg2, arg3):
    arg1 = arg2 & (~extend_arg(arg2, arg3))


def bics(ir, instr, arg1, arg2, arg3):
    e = []
    tmp1, tmp2 = arg2, (~extend_arg(arg2, arg3))
    res = tmp1 & tmp2

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_AND', tmp1, tmp2))]
    e += update_flag_nf(res)

    e.append(ExprAssign(arg1, res))
    return e, []


@sbuild.parse
def mvn(arg1, arg2):
    arg1 = (~extend_arg(arg1, arg2))


def adds(ir, instr, arg1, arg2, arg3):
    e = []
    arg3 = extend_arg(arg2, arg3)
    res = arg2 + arg3

    e += update_flag_arith_add_zn(arg2, arg3)
    e += update_flag_arith_add_co(arg2, arg3)

    e.append(ExprAssign(arg1, res))

    return e, []


def subs(ir, instr, arg1, arg2, arg3):
    e = []
    arg3 = extend_arg(arg2, arg3)
    res = arg2 - arg3


    e += update_flag_arith_sub_zn(arg2, arg3)
    e += update_flag_arith_sub_co(arg2, arg3)

    e.append(ExprAssign(arg1, res))
    return e, []


def cmp(ir, instr, arg1, arg2):
    e = []
    arg2 = extend_arg(arg1, arg2)

    e += update_flag_arith_sub_zn(arg1, arg2)
    e += update_flag_arith_sub_co(arg1, arg2)

    return e, []


def cmn(ir, instr, arg1, arg2):
    e = []
    arg2 = extend_arg(arg1, arg2)

    e += update_flag_arith_add_zn(arg1, arg2)
    e += update_flag_arith_add_co(arg1, arg2)

    return e, []


def ands(ir, instr, arg1, arg2, arg3):
    e = []
    arg3 = extend_arg(arg2, arg3)
    res = arg2 & arg3

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_AND', arg2, arg3))]
    e += update_flag_nf(res)

    e.append(ExprAssign(arg1, res))
    return e, []

def tst(ir, instr, arg1, arg2):
    e = []
    arg2 = extend_arg(arg1, arg2)
    res = arg1 & arg2

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_AND', arg1, arg2))]
    e += update_flag_nf(res)

    return e, []


@sbuild.parse
def lsl(arg1, arg2, arg3):
    arg1 = arg2 << (arg3 & ExprInt(arg3.size - 1, arg3.size))


@sbuild.parse
def lsr(arg1, arg2, arg3):
    arg1 = arg2 >> (arg3 & ExprInt(arg3.size - 1, arg3.size))


@sbuild.parse
def asr(arg1, arg2, arg3):
    arg1 = ExprOp(
        'a>>', arg2, (arg3 & ExprInt(arg3.size - 1, arg3.size)))


@sbuild.parse
def mov(arg1, arg2):
    arg1 = arg2


def movk(ir, instr, arg1, arg2):
    e = []
    if isinstance(arg2, ExprOp):
        assert(arg2.op == 'slice_at' and
               isinstance(arg2.args[0], ExprInt) and
               isinstance(arg2.args[1], ExprInt))
        value, shift = int(arg2.args[0].arg), int(arg2.args[1])
        e.append(
            ExprAssign(arg1[shift:shift + 16], ExprInt(value, 16)))
    else:
        e.append(ExprAssign(arg1[:16], ExprInt(int(arg2), 16)))

    return e, []


@sbuild.parse
def movz(arg1, arg2):
    arg1 = arg2


@sbuild.parse
def movn(arg1, arg2):
    arg1 = ~arg2


@sbuild.parse
def bl(arg1):
    PC = arg1
    ir.IRDst = arg1
    LR = ExprInt(instr.offset + instr.l, 64)

@sbuild.parse
def csel(arg1, arg2, arg3, arg4):
    cond_expr = cond2expr[arg4.name]
    arg1 = arg2 if cond_expr else arg3

def ccmp(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    if(arg2.is_int()):
        arg2=ExprInt(arg2.arg.arg,arg1.size)
    default_nf = arg3[0:1]
    default_zf = arg3[1:2]
    default_cf = arg3[2:3]
    default_of = arg3[3:4]
    cond_expr = cond2expr[arg4.name]
    res = arg1 - arg2
    new_nf = nf
    new_zf = update_flag_zf(res)[0].src
    new_cf = update_flag_sub_cf(arg1, arg2)[0].src
    new_of = update_flag_sub_of(arg1, arg2)[0].src

    e.append(ExprAssign(nf, ExprCond(cond_expr,
                                                    new_nf,
                                                    default_nf)))
    e.append(ExprAssign(zf, ExprCond(cond_expr,
                                                    new_zf,
                                                    default_zf)))
    e.append(ExprAssign(cf, ExprCond(cond_expr,
                                                    new_cf,
                                                    default_cf)))
    e.append(ExprAssign(of, ExprCond(cond_expr,
                                                    new_of,
                                                    default_of)))
    return e, []


def csinc(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    cond_expr = cond2expr[arg4.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                arg2,
                arg3 + ExprInt(1, arg3.size)
            )
        )
    )
    return e, []


def csinv(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    cond_expr = cond2expr[arg4.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                arg2,
                ~arg3)
        )
    )
    return e, []


def csneg(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    cond_expr = cond2expr[arg4.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                arg2,
                -arg3)
        )
    )
    return e, []


def cset(ir, instr, arg1, arg2):
    e = []
    cond_expr = cond2expr[arg2.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                ExprInt(1, arg1.size),
                ExprInt(0, arg1.size)
            )
        )
    )
    return e, []


def csetm(ir, instr, arg1, arg2):
    e = []
    cond_expr = cond2expr[arg2.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                ExprInt(-1, arg1.size),
                ExprInt(0, arg1.size)
            )
        )
    )
    return e, []


def get_mem_access(mem):
    updt = None
    if isinstance(mem, ExprOp):
        if mem.op == 'preinc':
            addr = mem.args[0] + mem.args[1]
        elif mem.op == 'segm':
            base = mem.args[0]
            op, (reg, shift) = mem.args[1].op, mem.args[1].args
            if op == 'SXTW':
                off = reg.signExtend(base.size) << shift.zeroExtend(base.size)
                addr = base + off
            elif op == 'UXTW':
                off = reg.zeroExtend(base.size) << shift.zeroExtend(base.size)
                addr = base + off
            elif op == 'LSL':
                if isinstance(shift, ExprInt) and int(shift) == 0:
                    addr = base + reg.zeroExtend(base.size)
                else:
                    addr = base + \
                        (reg.zeroExtend(base.size)
                         << shift.zeroExtend(base.size))
            else:
                raise NotImplementedError('bad op')
        elif mem.op == "postinc":
            addr, off = mem.args
            updt = ExprAssign(addr, addr + off)
        elif mem.op == "preinc_wb":
            base, off = mem.args
            addr = base + off
            updt = ExprAssign(base, base + off)
        else:
            raise NotImplementedError('bad op')
    else:
        raise NotImplementedError('bad op')
    return addr, updt



def ldr(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(ExprAssign(arg1, ExprMem(addr, arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def ldr_size(ir, instr, arg1, arg2, size):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(
        ExprAssign(arg1, ExprMem(addr, size).zeroExtend(arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def ldrb(ir, instr, arg1, arg2):
    return ldr_size(ir, instr, arg1, arg2, 8)


def ldrh(ir, instr, arg1, arg2):
    return ldr_size(ir, instr, arg1, arg2, 16)


def ldrs_size(ir, instr, arg1, arg2, size):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(
        ExprAssign(arg1, ExprMem(addr, size).signExtend(arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def ldrsb(ir, instr, arg1, arg2):
    return ldrs_size(ir, instr, arg1, arg2, 8)


def ldrsh(ir, instr, arg1, arg2):
    return ldrs_size(ir, instr, arg1, arg2, 16)


def ldrsw(ir, instr, arg1, arg2):
    return ldrs_size(ir, instr, arg1, arg2, 32)

def ldaxrb(ir, instr, arg1, arg2):
    # TODO XXX no memory lock implemented
    assert arg2.is_op('preinc')
    assert len(arg2.args) == 1
    ptr = arg2.args[0]
    e = []
    e.append(ExprAssign(arg1, ExprMem(ptr, 8).zeroExtend(arg1.size)))
    return e, []


def stlxrb(ir, instr, arg1, arg2, arg3):
    assert arg3.is_op('preinc')
    assert len(arg3.args) == 1
    ptr = arg3.args[0]
    e = []
    e.append(ExprAssign(ExprMem(ptr, 8), arg2[:8]))
    # TODO XXX here, force update success
    e.append(ExprAssign(arg1, ExprInt(0, arg1.size)))
    return e, []


def l_str(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(ExprAssign(ExprMem(addr, arg1.size), arg1))
    if updt:
        e.append(updt)
    return e, []


def strb(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(ExprAssign(ExprMem(addr, 8), arg1[:8]))
    if updt:
        e.append(updt)
    return e, []


def strh(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(ExprAssign(ExprMem(addr, 16), arg1[:16]))
    if updt:
        e.append(updt)
    return e, []


def stp(ir, instr, arg1, arg2, arg3):
    e = []
    addr, updt = get_mem_access(arg3)
    e.append(ExprAssign(ExprMem(addr, arg1.size), arg1))
    e.append(
        ExprAssign(ExprMem(addr + ExprInt(arg1.size // 8, addr.size), arg2.size), arg2))
    if updt:
        e.append(updt)
    return e, []


def ldp(ir, instr, arg1, arg2, arg3):
    e = []
    addr, updt = get_mem_access(arg3)
    e.append(ExprAssign(arg1, ExprMem(addr, arg1.size)))
    e.append(
        ExprAssign(arg2, ExprMem(addr + ExprInt(arg1.size // 8, addr.size), arg2.size)))
    if updt:
        e.append(updt)
    return e, []


def sbfm(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    rim, sim = int(arg3.arg), int(arg4) + 1
    if sim > rim:
        res = arg2[rim:sim].signExtend(arg1.size)
    else:
        shift = ExprInt(arg2.size - rim, arg2.size)
        res = (arg2[:sim].signExtend(arg1.size) << shift)
    e.append(ExprAssign(arg1, res))
    return e, []


def ubfm(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    rim, sim = int(arg3.arg), int(arg4) + 1
    if sim != arg1.size - 1 and rim == sim:
        # Simple case: lsl
        value = int(rim)
        assert value < arg1.size
        e.append(ExprAssign(arg1, arg2 << (ExprInt(arg1.size - value, arg2.size))))
        return e, []
    if sim == arg1.size:
        # Simple case: lsr
        value = int(rim)
        assert value < arg1.size
        e.append(ExprAssign(arg1, arg2 >> (ExprInt(value, arg2.size))))
        return e, []

    if sim > rim:
        res = arg2[rim:sim].zeroExtend(arg1.size)
    else:
        shift = ExprInt(arg2.size - rim, arg2.size)
        res = (arg2[:sim].zeroExtend(arg1.size) << shift)
    e.append(ExprAssign(arg1, res))
    return e, []

def bfm(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    rim, sim = int(arg3.arg), int(arg4) + 1
    if sim > rim:
        res = arg2[rim:sim]
        e.append(ExprAssign(arg1[:sim-rim], res))
    else:
        shift_i = arg2.size - rim
        shift = ExprInt(shift_i, arg2.size)
        res = arg2[:sim]
        e.append(ExprAssign(arg1[shift_i:shift_i+sim], res))
    return e, []



def mrs(ir, insr, arg1, arg2, arg3, arg4, arg5):
    e = []
    if arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(0):
        out = []
        out.append(ExprInt(0x0, 28))
        out.append(of)
        out.append(cf)
        out.append(zf)
        out.append(nf)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))
    else:
        raise NotImplementedError("MRS not implemented")
    return e, []

def msr(ir, instr, arg1, arg2, arg3, arg4, arg5):

    e = []
    if arg1.is_int(3) and arg2.is_id("c4") and arg3.is_id("c2") and arg4.is_int(0):
        e.append(ExprAssign(nf, arg5[31:32]))
        e.append(ExprAssign(zf, arg5[30:31]))
        e.append(ExprAssign(cf, arg5[29:30]))
        e.append(ExprAssign(of, arg5[28:29]))
    else:
        raise NotImplementedError("MSR not implemented")
    return e, []



def adc(ir, instr, arg1, arg2, arg3):
    arg3 = extend_arg(arg2, arg3)
    e = []
    r = arg2 + arg3 + cf.zeroExtend(arg3.size)
    e.append(ExprAssign(arg1, r))
    return e, []


def adcs(ir, instr, arg1, arg2, arg3):
    arg3 = extend_arg(arg2, arg3)
    e = []
    r = arg2 + arg3 + cf.zeroExtend(arg3.size)
    e.append(ExprAssign(arg1, r))
    e += update_flag_arith_addwc_zn(arg2, arg3, cf)
    e += update_flag_arith_addwc_co(arg2, arg3, cf)
    return e, []


def sbc(ir, instr, arg1, arg2, arg3):
    arg3 = extend_arg(arg2, arg3)
    e = []
    r = arg2 - (arg3 + (~cf).zeroExtend(arg3.size))
    e.append(ExprAssign(arg1, r))
    return e, []


def sbcs(ir, instr, arg1, arg2, arg3):
    arg3 = extend_arg(arg2, arg3)
    e = []
    r = arg2 - (arg3 + (~cf).zeroExtend(arg3.size))
    e.append(ExprAssign(arg1, r))
    e += update_flag_arith_subwc_zn(arg2, arg3, ~cf)
    e += update_flag_arith_subwc_co(arg2, arg3, ~cf)
    return e, []


@sbuild.parse
def madd(arg1, arg2, arg3, arg4):
    arg1 = arg2 * arg3 + arg4


@sbuild.parse
def msub(arg1, arg2, arg3, arg4):
    arg1 = arg4 - (arg2 * arg3)


@sbuild.parse
def udiv(arg1, arg2, arg3):
    if arg3:
        arg1 = ExprOp('udiv', arg2, arg3)
    else:
        exception_flags = ExprInt(EXCEPT_DIV_BY_ZERO,
                                          exception_flags.size)

@sbuild.parse
def sdiv(arg1, arg2, arg3):
    if arg3:
        arg1 = ExprOp('sdiv', arg2, arg3)
    else:
        exception_flags = ExprInt(EXCEPT_DIV_BY_ZERO,
                                          exception_flags.size)



@sbuild.parse
def smaddl(arg1, arg2, arg3, arg4):
    arg1 = arg2.signExtend(arg1.size) * arg3.signExtend(arg1.size) + arg4


@sbuild.parse
def cbz(arg1, arg2):
    dst = ExprLoc(ir.get_next_loc_key(instr), 64) if arg1 else arg2
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def cbnz(arg1, arg2):
    dst = arg2 if arg1 else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def tbz(arg1, arg2, arg3):
    bitmask = ExprInt(1, arg1.size) << arg2
    dst = ExprLoc(
        ir.get_next_loc_key(instr),
        64
    ) if arg1 & bitmask else arg3
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def tbnz(arg1, arg2, arg3):
    bitmask = ExprInt(1, arg1.size) << arg2
    dst = arg3 if arg1 & bitmask else ExprLoc(
        ir.get_next_loc_key(instr),
        64
    )
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_ne(arg1):
    cond = cond2expr['NE']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_eq(arg1):
    cond = cond2expr['EQ']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_ge(arg1):
    cond = cond2expr['GE']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_mi(arg1):
    cond = cond2expr['MI']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_pl(arg1):
    cond = cond2expr['PL']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_gt(arg1):
    cond = cond2expr['GT']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_cc(arg1):
    cond = cond2expr['CC']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_cs(arg1):
    cond = cond2expr['CS']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_hi(arg1):
    cond = cond2expr['HI']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_le(arg1):
    cond = cond2expr['LE']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_ls(arg1):
    cond = cond2expr['LS']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_lt(arg1):
    cond = cond2expr['LT']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def ret(arg1):
    PC = arg1
    ir.IRDst = arg1


@sbuild.parse
def adrp(arg1, arg2):
    arg1 = (PC & ExprInt(0xfffffffffffff000, 64)) + arg2


@sbuild.parse
def adr(arg1, arg2):
    arg1 = PC + arg2


@sbuild.parse
def b(arg1):
    PC = arg1
    ir.IRDst = arg1


@sbuild.parse
def br(arg1):
    PC = arg1
    ir.IRDst = arg1

@sbuild.parse
def blr(arg1):
    PC = arg1
    ir.IRDst = arg1
    LR = ExprLoc(ir.get_next_loc_key(instr), 64)

@sbuild.parse
def nop():
    """Do nothing"""


def rev(ir, instr, arg1, arg2):
    out = []
    for i in range(0, arg2.size, 8):
        out.append(arg2[i:i+8])
    out.reverse()
    e = []
    result = ExprCompose(*out)
    e.append(ExprAssign(arg1, result))
    return e, []


def rev16(ir, instr, arg1, arg2):
    out = []
    for i in range(0, arg2.size // 8):
        index = (i & ~1) + (1 - (i & 1))
        out.append(arg2[index * 8:(index + 1) * 8])
    e = []
    result = ExprCompose(*out)
    e.append(ExprAssign(arg1, result))
    return e, []


@sbuild.parse
def extr(arg1, arg2, arg3, arg4):
    compose = ExprCompose(arg2, arg3)
    arg1 = compose[int(arg4.arg):int(arg4)+arg1.size]


@sbuild.parse
def svc(arg1):
    exception_flags = ExprInt(EXCEPT_INT_XX, exception_flags.size)
    interrupt_num = ExprInt(int(arg1), interrupt_num.size)


def fmov(ir, instr, arg1, arg2):
    if arg2.is_int():
        # Transform int to signed floating-point constant with 3-bit exponent
        # and normalized 4 bits of precision
        # VFPExpandImm() of ARM Architecture Reference Manual
        imm8 = int(arg2)
        N = arg1.size
        assert N in [32, 64]
        E = 8 if N == 32 else 11
        F = N - E - 1;
        # sign = imm8<7>;
        sign = (imm8 >> 7) & 1;
        # exp = NOT(imm8<6>):Replicate(imm8<6>,E-3):imm8<5:4>;
        exp = (((imm8 >> 6) & 1) ^ 1) << (E - 3 + 2)
        if (imm8 >> 6) & 1:
            tmp = (1 << (E - 3)) - 1
        else:
            tmp = 0
        exp |= tmp << 2
        exp |= (imm8 >> 4) & 3
        # frac = imm8<3:0>:Zeros(F-4);
        frac = (imm8 & 0xf) << (F - 4)
        value = frac
        value |= exp << (4 + F - 4)
        value |= sign << (4 + F - 4  + 1 + E - 3 + 2)
        arg2 = ExprInt(value, N)
    e = [ExprAssign(arg1, arg2)]
    return e, []


def fadd(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fadd', arg2, arg3)))
    return e, []


def fsub(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fsub', arg2, arg3)))
    return e, []


def fmul(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fmul', arg2, arg3)))
    return e, []


def fdiv(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fdiv', arg2, arg3)))
    return e, []


def fabs(ir, instr, arg1, arg2):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fabs', arg2)))
    return e, []


def fmadd(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprOp(
                'fadd',
                arg4,
                ExprOp('fmul', arg2, arg3)
            )
        )
    )
    return e, []


def fmsub(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprOp(
                'fsub',
                arg4,
                ExprOp('fmul', arg2, arg3)
            )
        )
    )
    return e, []


def fcvt(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    src = ExprOp('fpconvert_fp%d' % arg1.size, arg2)
    e.append(ExprAssign(arg1, src))
    return e, []


def scvtf(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    src = ExprOp('sint_to_fp', arg2)
    if arg1.size != src.size:
        src = ExprOp('fpconvert_fp%d' % arg1.size, src)
    e.append(ExprAssign(arg1, src))
    return e, []


def ucvtf(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    src = ExprOp('uint_to_fp', arg2)
    if arg1.size != src.size:
        src = ExprOp('fpconvert_fp%d' % arg1.size, src)
    e.append(ExprAssign(arg1, src))
    return e, []


def fcvtzs(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprOp('fp_to_sint%d' % arg1.size,
                   ExprOp('fpround_towardszero', arg2)
            )
        )
    )
    return e, []


def fcvtzu(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprOp('fp_to_uint%d' % arg1.size,
                   ExprOp('fpround_towardszero', arg2)
            )
        )
    )
    return e, []


def fcmpe(ir, instr, arg1, arg2):
    e = []
    e.append(
        ExprAssign(
            nf,
            ExprOp('fcom_c0', arg1, arg2)
        )
    )
    e.append(
        ExprAssign(
            cf,
            ~ExprOp('fcom_c0', arg1, arg2)
        )
    )
    e.append(
        ExprAssign(
            zf,
            ExprOp('fcom_c3', arg1, arg2)
        )
    )
    e.append(ExprAssign(of, ExprInt(0, 1)))
    return e, []


def clz(ir, instr, arg1, arg2):
    e = []
    e.append(ExprAssign(arg1, ExprOp('cntleadzeros', arg2)))
    return e, []

def casp(ir, instr, arg1, arg2, arg3):
    # XXX TODO: memory barrier
    e = []
    if arg1.size == 32:
        regs = gpregs32_expr
    else:
        regs = gpregs64_expr
    index1 = regs.index(arg1)
    index2 = regs.index(arg2)

    # TODO endianness
    comp_value = ExprCompose(regs[index1], regs[index1 + 1])
    new_value = ExprCompose(regs[index2], regs[index2 + 1])
    assert arg3.is_op('preinc')
    ptr = arg3.args[0]
    data = ExprMem(ptr, comp_value.size)

    loc_store = ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
    loc_do = ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
    loc_next = ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

    e.append(ExprAssign(ir.IRDst, ExprCond(ExprOp("FLAG_EQ_CMP", data, comp_value), loc_do, loc_store)))

    e_store = []
    e_store.append(ExprAssign(data, new_value))
    e_store.append(ExprAssign(ir.IRDst, loc_do))
    blk_store = IRBlock(loc_store.loc_key, [AssignBlock(e_store, instr)])

    e_do = []
    e_do.append(ExprAssign(regs[index1], data[:data.size // 2]))
    e_do.append(ExprAssign(regs[index1 + 1], data[data.size // 2:]))
    e_do.append(ExprAssign(ir.IRDst, loc_next))
    blk_do = IRBlock(loc_do.loc_key, [AssignBlock(e_do, instr)])

    return e, [blk_store, blk_do]


@sbuild.parse
def umaddl(arg1, arg2, arg3, arg4):
    arg1 = arg2.zeroExtend(arg1.size) * arg3.zeroExtend(arg1.size) + arg4


@sbuild.parse
def umsubbl(arg1, arg2, arg3, arg4):
    arg1 = arg2.zeroExtend(arg1.size) * arg3.zeroExtend(arg1.size) + arg4


@sbuild.parse
def umull(arg1, arg2, arg3):
    arg1 = (arg2.zeroExtend(64) * arg3.zeroExtend(64))


@sbuild.parse
def umulh(arg1, arg2, arg3):
    arg1 = (arg2.zeroExtend(128) * arg3.zeroExtend(128))[64:]


@sbuild.parse
def smulh(arg1, arg2, arg3):
    arg1 = (arg2.signExtend(128) * arg3.signExtend(128))[64:]


@sbuild.parse
def smull(arg1, arg2, arg3):
    arg1 = (arg2.signExtend(64) * arg3.signExtend(64))[64:]



mnemo_func = sbuild.functions
mnemo_func.update({
    'and': and_l,
    'adds': adds,
    'ands': ands,
    'tst': tst,
    'subs': subs,
    'cmp': cmp,
    'cmn': cmn,
    'movk': movk,
    'ccmp': ccmp,
    'csinc': csinc,
    'csinv': csinv,
    'csneg': csneg,
    'cset': cset,
    'csetm': csetm,

    'b.ne': b_ne,
    'b.eq': b_eq,
    'b.ge': b_ge,
    'b.mi': b_mi,
    'b.pl': b_pl,
    'b.gt': b_gt,
    'b.cc': b_cc,
    'b.cs': b_cs,
    'b.hi': b_hi,
    'b.le': b_le,
    'b.ls': b_ls,
    'b.lt': b_lt,

    'bics': bics,

    'ret': ret,
    'stp': stp,
    'ldp': ldp,

    'ldr': ldr,
    'ldrb': ldrb,
    'ldrh': ldrh,

    'ldur': ldr,
    'ldurb': ldrb,
    'ldursb': ldrsb,
    'ldurh': ldrh,
    'ldursh': ldrsh,
    'ldursw': ldrsw,

    'ldrsb': ldrsb,
    'ldrsh': ldrsh,
    'ldrsw': ldrsw,

    'ldaxrb': ldaxrb,
    'stlxrb': stlxrb,

    'str': l_str,
    'strb': strb,
    'strh': strh,

    'stur': l_str,
    'sturb': strb,
    'sturh': strh,


    'bfm': bfm,
    'sbfm': sbfm,
    'ubfm': ubfm,

    'extr': extr,
    'rev': rev,
    'rev16': rev16,

    'msr': msr,
    'mrs': mrs,

    'adc': adc,
    'adcs': adcs,
    'sbc': sbc,
    'sbcs': sbcs,

    'fmov': fmov,
    'fadd': fadd,
    'fsub': fsub,
    'fmul': fmul,
    'fdiv': fdiv,
    'fabs': fabs,
    'fmadd': fmadd,
    'fmsub': fmsub,
    'fcvt': fcvt,
    'scvtf': scvtf,
    'ucvtf': ucvtf,
    'fcvtzs': fcvtzs,
    'fcvtzu': fcvtzu,
    'fcmpe': fcmpe,
    'clz': clz,

    # XXX TODO: memory barrier
    'casp':casp,
    'caspl':casp,
    'caspa':casp,
    'caspal':casp,


})


def get_mnemo_expr(ir, instr, *args):
    if not instr.name.lower() in mnemo_func:
        raise NotImplementedError('unknown mnemo %s' % instr)
    instr, extra_ir = mnemo_func[instr.name.lower()](ir, instr, *args)
    return instr, extra_ir


class aarch64info(object):
    mode = "aarch64"
    # offset


class ir_aarch64l(IntermediateRepresentation):

    def __init__(self, loc_db=None):
        IntermediateRepresentation.__init__(self, mn_aarch64, "l", loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 64)
        self.addrsize = 64

    def get_ir(self, instr):
        args = instr.args
        if len(args) and isinstance(args[-1], ExprOp):
            if (args[-1].op in ['<<', '>>', '<<a', 'a>>', '<<<', '>>>'] and
               isinstance(args[-1].args[-1], ExprId)):
                args[-1] = ExprOp(args[-1].op,
                                          args[-1].args[0],
                                          args[-1].args[-1][:8].zeroExtend(32))
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)
        self.mod_pc(instr, instr_ir, extra_ir)
        instr_ir, extra_ir = self.del_dst_zr(instr, instr_ir, extra_ir)
        return instr_ir, extra_ir

    def expr_fix_regs_for_mode(self, e):
        return e.replace_expr(replace_regs)

    def expraff_fix_regs_for_mode(self, e):
        dst = self.expr_fix_regs_for_mode(e.dst)
        src = self.expr_fix_regs_for_mode(e.src)
        return ExprAssign(dst, src)

    def irbloc_fix_regs_for_mode(self, irblock, mode=64):
        irs = []
        for assignblk in irblock:
            new_assignblk = dict(assignblk)
            for dst, src in viewitems(assignblk):
                del(new_assignblk[dst])
                # Special case for 64 bits:
                # If destination is a 32 bit reg, zero extend the 64 bit reg
                if (isinstance(dst, ExprId) and
                    dst.size == 32 and
                    dst in replace_regs):
                    src = src.zeroExtend(64)
                    dst = replace_regs[dst].arg

                dst = self.expr_fix_regs_for_mode(dst)
                src = self.expr_fix_regs_for_mode(src)
                new_assignblk[dst] = src
            irs.append(AssignBlock(new_assignblk, assignblk.instr))
        return IRBlock(irblock.loc_key, irs)

    def mod_pc(self, instr, instr_ir, extra_ir):
        "Replace PC by the instruction's offset"
        cur_offset = ExprInt(instr.offset, 64)
        pc_fixed = {self.pc: cur_offset}
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


    def del_dst_zr(self, instr, instr_ir, extra_ir):
        "Writes to zero register are discarded"
        regs_to_fix = [WZR, XZR]
        instr_ir = [expr for expr in instr_ir if expr.dst not in regs_to_fix]

        new_irblocks = []
        for irblock in extra_ir:
            irs = []
            for assignblk in irblock:
                new_dsts = {
                    dst:src for dst, src in viewitems(assignblk)
                    if dst not in regs_to_fix
                }
                irs.append(AssignBlock(new_dsts, assignblk.instr))
            new_irblocks.append(IRBlock(irblock.loc_key, irs))

        return instr_ir, new_irblocks


class ir_aarch64b(ir_aarch64l):

    def __init__(self, loc_db=None):
        IntermediateRepresentation.__init__(self, mn_aarch64, "b", loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 64)
