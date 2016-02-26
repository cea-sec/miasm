from miasm2.expression import expression as m2_expr
from miasm2.ir.ir import ir, irbloc, AssignBlock
from miasm2.arch.aarch64.arch import mn_aarch64, conds_expr, replace_regs
from miasm2.arch.aarch64.regs import *
from miasm2.core.sembuilder import SemBuilder

EXCEPT_PRIV_INSN = (1 << 17)

# CPSR: N Z C V


def update_flag_zf(a):
    return [m2_expr.ExprAff(zf, m2_expr.ExprCond(a, m2_expr.ExprInt1(0), m2_expr.ExprInt1(1)))]


def update_flag_nf(a):
    return [m2_expr.ExprAff(nf, a.msb())]


def update_flag_zn(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    return e


def update_flag_logic(a):
    e = []
    e += update_flag_zn(a)
    # XXX TODO: set cf if ROT imm in argument
    # e.append(m2_expr.ExprAff(cf, m2_expr.ExprInt1(0)))
    return e


def update_flag_arith(a):
    e = []
    e += update_flag_zn(a)
    return e


def check_ops_msb(a, b, c):
    if not a or not b or not c or a != b or a != c:
        raise ValueError('bad ops size %s %s %s' % (a, b, c))


def arith_flag(a, b, c):
    a_s, b_s, c_s = a.size, b.size, c.size
    check_ops_msb(a_s, b_s, c_s)
    a_s, b_s, c_s = a.msb(), b.msb(), c.msb()
    return a_s, b_s, c_s

# checked: ok for adc add because b & c before +cf


def update_flag_add_cf(op1, op2, res):
    "Compute cf in @res = @op1 + @op2"
    return m2_expr.ExprAff(cf, (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (~(op1 ^ op2)))).msb())


def update_flag_add_of(op1, op2, res):
    "Compute of in @res = @op1 + @op2"
    return m2_expr.ExprAff(of, (((op1 ^ res) & (~(op1 ^ op2)))).msb())


# checked: ok for sbb add because b & c before +cf
def update_flag_sub_cf(op1, op2, res):
    "Compote CF in @res = @op1 - @op2"
    return m2_expr.ExprAff(cf,
                           ((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))).msb()) ^ m2_expr.ExprInt1(1))


def update_flag_sub_of(op1, op2, res):
    "Compote OF in @res = @op1 - @op2"
    return m2_expr.ExprAff(of, (((op1 ^ res) & (op1 ^ op2))).msb())

# z = x+y (+cf?)


def update_flag_add(x, y, z):
    e = []
    e.append(update_flag_add_cf(x, y, z))
    e.append(update_flag_add_of(x, y, z))
    return e

# z = x-y (+cf?)


def update_flag_sub(x, y, z):
    e = []
    e.append(update_flag_sub_cf(x, y, z))
    e.append(update_flag_sub_of(x, y, z))
    return e


cond2expr = {'EQ': zf,
             'NE': zf ^ m2_expr.ExprInt1(1),
             'CS': cf,
             'CC': cf ^ m2_expr.ExprInt1(1),
             'MI': nf,
             'PL': nf ^ m2_expr.ExprInt1(1),
             'VS': of,
             'VC': of ^ m2_expr.ExprInt1(1),
             'HI': cf & (zf ^ m2_expr.ExprInt1(1)),
             'LS': (cf ^ m2_expr.ExprInt1(1)) | zf,
             'GE': nf ^ of ^ m2_expr.ExprInt1(1),
             'LT': nf ^ of,
             'GT': ((zf ^ m2_expr.ExprInt1(1)) &
                    (nf ^ of ^ m2_expr.ExprInt1(1))),
             'LE': zf | (nf ^ of),
             'AL': m2_expr.ExprInt1(1),
             'NV': m2_expr.ExprInt1(0)
             }


def extend_arg(dst, arg):
    if not isinstance(arg, m2_expr.ExprOp):
        return arg

    op, (reg, shift) = arg.op, arg.args
    if op == 'SXTW':
        base = reg.signExtend(dst.size)
    else:
        base = reg.zeroExtend(dst.size)

    out = base << (shift.zeroExtend(dst.size)
                   & m2_expr.ExprInt_from(dst, dst.size - 1))
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
       "m2_expr":m2_expr
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


@sbuild.parse
def mvn(arg1, arg2):
    arg1 = (~extend_arg(arg1, arg2))


def adds(ir, instr, arg1, arg2, arg3):
    e = []
    arg3 = extend_arg(arg2, arg3)
    res = arg2 + arg3
    e += update_flag_arith(res)
    e += update_flag_add(arg2, arg3, res)
    e.append(m2_expr.ExprAff(arg1, res))
    return e, []


def subs(ir, instr, arg1, arg2, arg3):
    e = []
    arg3 = extend_arg(arg2, arg3)
    res = arg2 - arg3
    e += update_flag_arith(res)
    e += update_flag_sub(arg2, arg3, res)
    e.append(m2_expr.ExprAff(arg1, res))
    return e, []


def cmp(ir, instr, arg1, arg2):
    e = []
    arg2 = extend_arg(arg1, arg2)
    res = arg1 - arg2
    e += update_flag_arith(res)
    e += update_flag_sub(arg1, arg2, res)
    return e, []


def cmn(ir, instr, arg1, arg2):
    e = []
    arg2 = extend_arg(arg1, arg2)
    res = arg1 + arg2
    e += update_flag_arith(res)
    e += update_flag_add(arg1, arg2, res)
    return e, []


def ands(ir, instr, arg1, arg2, arg3):
    e = []
    arg3 = extend_arg(arg2, arg3)
    res = arg2 & arg3
    e += update_flag_logic(res)
    e.append(m2_expr.ExprAff(arg1, res))
    return e, []

def tst(ir, instr, arg1, arg2):
    e = []
    arg2 = extend_arg(arg1, arg2)
    res = arg1 & arg2
    e += update_flag_logic(res)
    return e, []


@sbuild.parse
def lsl(arg1, arg2, arg3):
    arg1 = arg2 << (arg3 & m2_expr.ExprInt_from(arg3, arg3.size - 1))


@sbuild.parse
def lsr(arg1, arg2, arg3):
    arg1 = arg2 >> (arg3 & m2_expr.ExprInt_from(arg3, arg3.size - 1))


@sbuild.parse
def asr(arg1, arg2, arg3):
    arg1 = m2_expr.ExprOp(
        'a>>', arg2, (arg3 & m2_expr.ExprInt_from(arg3, arg3.size - 1)))


@sbuild.parse
def mov(arg1, arg2):
    arg1 = arg2


def movk(ir, instr, arg1, arg2):
    e = []
    if isinstance(arg2, m2_expr.ExprOp):
        assert(arg2.op == 'slice_at' and
               isinstance(arg2.args[0], m2_expr.ExprInt) and
               isinstance(arg2.args[1], m2_expr.ExprInt))
        value, shift = int(arg2.args[0].arg), int(arg2.args[1].arg)
        e.append(
            m2_expr.ExprAff(arg1[shift:shift + 16], m2_expr.ExprInt16(value)))
    else:
        e.append(m2_expr.ExprAff(arg1[:16], m2_expr.ExprInt16(int(arg2.arg))))

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
    LR = m2_expr.ExprInt64(instr.offset + instr.l)

@sbuild.parse
def csel(arg1, arg2, arg3, arg4):
    cond_expr = cond2expr[arg4.name]
    arg1 = arg2 if cond_expr else arg3


def csinc(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    cond_expr = cond2expr[arg4.name]
    e.append(m2_expr.ExprAff(arg1, m2_expr.ExprCond(cond_expr,
                                                    arg2,
                                                    arg3 + m2_expr.ExprInt_from(arg3, 1))))
    return e, []


def csinv(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    cond_expr = cond2expr[arg4.name]
    e.append(m2_expr.ExprAff(arg1, m2_expr.ExprCond(cond_expr,
                                                    arg2,
                                                    ~arg3)))
    return e, []


def csneg(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    cond_expr = cond2expr[arg4.name]
    e.append(m2_expr.ExprAff(arg1, m2_expr.ExprCond(cond_expr,
                                                    arg2,
                                                    -arg3)))
    return e, []


def cset(ir, instr, arg1, arg2):
    e = []
    cond_expr = cond2expr[arg2.name]
    e.append(m2_expr.ExprAff(arg1, m2_expr.ExprCond(cond_expr,
                                                    m2_expr.ExprInt_from(
                                                        arg1, 1),
                                                    m2_expr.ExprInt_from(arg1, 0))))
    return e, []


def csetm(ir, instr, arg1, arg2):
    e = []
    cond_expr = cond2expr[arg2.name]
    e.append(m2_expr.ExprAff(arg1, m2_expr.ExprCond(cond_expr,
                                                    m2_expr.ExprInt_from(
                                                        arg1, -1),
                                                    m2_expr.ExprInt_from(arg1, 0))))
    return e, []


def get_mem_access(mem):
    updt = None
    if isinstance(mem, m2_expr.ExprOp):
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
                if isinstance(shift, m2_expr.ExprInt) and int(shift.arg) == 0:
                    addr = base + reg.zeroExtend(base.size)
                else:
                    addr = base + \
                        (reg.zeroExtend(base.size)
                         << shift.zeroExtend(base.size))
            else:
                raise NotImplementedError('bad op')
        elif mem.op == "postinc":
            addr, off = mem.args
            updt = m2_expr.ExprAff(addr, addr + off)
        elif mem.op == "preinc_wb":
            base, off = mem.args
            addr = base + off
            updt = m2_expr.ExprAff(base, base + off)
        else:
            raise NotImplementedError('bad op')
    else:
        raise NotImplementedError('bad op')
    return addr, updt



def ldr(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(m2_expr.ExprAff(arg1, m2_expr.ExprMem(addr, arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def ldrb(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(
        m2_expr.ExprAff(arg1, m2_expr.ExprMem(addr, 8).zeroExtend(arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def ldrh(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(
        m2_expr.ExprAff(arg1, m2_expr.ExprMem(addr, 16).zeroExtend(arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def l_str(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(addr, arg1.size), arg1))
    if updt:
        e.append(updt)
    return e, []


def strb(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(addr, 8), arg1[:8]))
    if updt:
        e.append(updt)
    return e, []


def strh(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(addr, 16), arg1[:16]))
    if updt:
        e.append(updt)
    return e, []


def stp(ir, instr, arg1, arg2, arg3):
    e = []
    addr, updt = get_mem_access(arg3)
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(addr, arg1.size), arg1))
    e.append(
        m2_expr.ExprAff(m2_expr.ExprMem(addr + m2_expr.ExprInt_from(addr, arg1.size / 8), arg2.size), arg2))
    if updt:
        e.append(updt)
    return e, []


def ldp(ir, instr, arg1, arg2, arg3):
    e = []
    addr, updt = get_mem_access(arg3)
    e.append(m2_expr.ExprAff(arg1, m2_expr.ExprMem(addr, arg1.size)))
    e.append(
        m2_expr.ExprAff(arg2, m2_expr.ExprMem(addr + m2_expr.ExprInt_from(addr, arg1.size / 8), arg2.size)))
    if updt:
        e.append(updt)
    return e, []


def ldrsw(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(
        m2_expr.ExprAff(arg1, m2_expr.ExprMem(addr, 32).signExtend(arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def sbfm(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    rim, sim = int(arg3.arg), int(arg4.arg) + 1
    if sim > rim:
        res = arg2[rim:sim].signExtend(arg1.size)
    else:
        shift = m2_expr.ExprInt_from(arg2, arg2.size - rim)
        res = (arg2[:sim].signExtend(arg1.size) << shift)
    e.append(m2_expr.ExprAff(arg1, res))
    return e, []


def ubfm(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    rim, sim = int(arg3.arg), int(arg4.arg) + 1
    if sim > rim:
        res = arg2[rim:sim].zeroExtend(arg1.size)
    else:
        shift = m2_expr.ExprInt_from(arg2, arg2.size - rim)
        res = (arg2[:sim].zeroExtend(arg1.size) << shift)
    e.append(m2_expr.ExprAff(arg1, res))
    return e, []

def bfm(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    rim, sim = int(arg3.arg), int(arg4.arg) + 1
    if sim > rim:
        res = arg2[rim:sim]
        e.append(m2_expr.ExprAff(arg1[:sim-rim], res))
    else:
        shift_i = arg2.size - rim
        shift = m2_expr.ExprInt_from(arg2, shift_i)
        res = arg2[:sim]
        e.append(m2_expr.ExprAff(arg1[shift_i:shift_i+sim], res))
    return e, []


@sbuild.parse
def madd(arg1, arg2, arg3, arg4):
    arg1 = arg2 * arg3 + arg4


@sbuild.parse
def msub(arg1, arg2, arg3, arg4):
    arg1 = arg4 - (arg2 * arg3)


@sbuild.parse
def udiv(arg1, arg2, arg3):
    arg1 = m2_expr.ExprOp('udiv', arg2, arg3)


@sbuild.parse
def cbz(arg1, arg2):
    dst = m2_expr.ExprId(ir.get_next_label(instr), 64) if arg1 else arg2
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def cbnz(arg1, arg2):
    dst = arg2 if arg1 else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def tbz(arg1, arg2, arg3):
    bitmask = m2_expr.ExprInt_from(arg1, 1) << arg2
    dst = m2_expr.ExprId(
        ir.get_next_label(instr), 64) if arg1 & bitmask else arg3
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def tbnz(arg1, arg2, arg3):
    bitmask = m2_expr.ExprInt_from(arg1, 1) << arg2
    dst = arg3 if arg1 & bitmask else m2_expr.ExprId(
        ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_ne(arg1):
    dst = m2_expr.ExprId(ir.get_next_label(instr), 64) if zf else arg1
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_eq(arg1):
    dst = arg1 if zf else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_ge(arg1):
    cond = cond2expr['GE']
    dst = arg1 if cond else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_gt(arg1):
    cond = cond2expr['GT']
    dst = arg1 if cond else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_cc(arg1):
    cond = cond2expr['CC']
    dst = arg1 if cond else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_cs(arg1):
    cond = cond2expr['CS']
    dst = arg1 if cond else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_hi(arg1):
    cond = cond2expr['HI']
    dst = arg1 if cond else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_le(arg1):
    cond = cond2expr['LE']
    dst = arg1 if cond else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_ls(arg1):
    cond = cond2expr['LS']
    dst = arg1 if cond else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_lt(arg1):
    cond = cond2expr['LT']
    dst = arg1 if cond else m2_expr.ExprId(ir.get_next_label(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def ret(arg1):
    PC = arg1
    ir.IRDst = arg1


@sbuild.parse
def adrp(arg1, arg2):
    arg1 = (PC & m2_expr.ExprInt64(0xfffffffffffff000)) + arg2


@sbuild.parse
def b(arg1):
    PC = arg1
    ir.IRDst = arg1


@sbuild.parse
def br(arg1):
    PC = arg1
    ir.IRDst = arg1


@sbuild.parse
def nop():
    """Do nothing"""



@sbuild.parse
def extr(arg1, arg2, arg3, arg4):
    compose = m2_expr.ExprCompose([(arg2, 0, arg2.size),
                                   (arg3, arg2.size, arg2.size+arg3.size)])
    arg1 = compose[int(arg4.arg):int(arg4.arg)+arg1.size]

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
    'csinc': csinc,
    'csinv': csinv,
    'csneg': csneg,
    'cset': cset,
    'csetm': csetm,

    'b.ne': b_ne,
    'b.eq': b_eq,
    'b.ge': b_ge,
    'b.gt': b_gt,
    'b.cc': b_cc,
    'b.cs': b_cs,
    'b.hi': b_hi,
    'b.le': b_le,
    'b.ls': b_ls,
    'b.lt': b_lt,

    'ret': ret,
    'stp': stp,
    'ldp': ldp,

    'ldr': ldr,
    'ldrb': ldrb,
    'ldrh': ldrh,

    'ldur': ldr,
    'ldurb': ldrb,
    'ldurh': ldrh,

    'str': l_str,
    'strb': strb,
    'strh': strh,

    'stur': l_str,
    'sturb': strb,
    'sturh': strh,

    'ldrsw': ldrsw,


    'bfm': bfm,
    'sbfm': sbfm,
    'ubfm': ubfm,

    'extr': extr,

})


def get_mnemo_expr(ir, instr, *args):
    if not instr.name.lower() in mnemo_func:
        raise NotImplementedError('unknown mnemo %s' % instr)
    instr, extra_ir = mnemo_func[instr.name.lower()](ir, instr, *args)
    return instr, extra_ir


class aarch64info:
    mode = "aarch64"
    # offset


class ir_aarch64l(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_aarch64, "l", symbol_pool)
        self.pc = PC
        self.sp = SP
        self.IRDst = m2_expr.ExprId('IRDst', 64)

    def get_ir(self, instr):
        args = instr.args
        if len(args) and isinstance(args[-1], m2_expr.ExprOp):
            if (args[-1].op in ['<<', '>>', '<<a', 'a>>', '<<<', '>>>'] and
               isinstance(args[-1].args[-1], m2_expr.ExprId)):
                args[-1] = m2_expr.ExprOp(args[-1].op,
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
        return m2_expr.ExprAff(dst, src)

    def irbloc_fix_regs_for_mode(self, irbloc, mode=64):
        for assignblk in irbloc.irs:
            for dst, src in assignblk.items():
                del(assignblk[dst])
                # Special case for 64 bits:
                # If destination is a 32 bit reg, zero extend the 64 bit reg

                if (isinstance(dst, m2_expr.ExprId) and
                    dst.size == 32 and
                    dst in replace_regs):
                    src = src.zeroExtend(64)
                    dst = replace_regs[dst].arg

                dst = self.expr_fix_regs_for_mode(dst)
                src = self.expr_fix_regs_for_mode(src)
                assignblk[dst] = src
        irbloc.dst = self.expr_fix_regs_for_mode(irbloc.dst)

    def mod_pc(self, instr, instr_ir, extra_ir):
        "Replace PC by the instruction's offset"
        cur_offset = m2_expr.ExprInt64(instr.offset)
        for i, expr in enumerate(instr_ir):
            dst, src = expr.dst, expr.src
            if dst != self.pc:
                dst = dst.replace_expr({self.pc: cur_offset})
            src = src.replace_expr({self.pc: cur_offset})
            instr_ir[i] = m2_expr.ExprAff(dst, src)
        for b in extra_ir:
            for irs in b.irs:
                for i, expr in enumerate(irs):
                    dst, src = expr.dst, expr.src
                    if dst != self.pc:
                        dst = dst.replace_expr({self.pc: cur_offset})
                    src = src.replace_expr({self.pc: cur_offset})
                    irs[i] = m2_expr.ExprAff(dst, src)


    def del_dst_zr(self, instr, instr_ir, extra_ir):
        "Writes to zero register are discarded"
        regs_to_fix = [WZR, XZR]
        instr_ir = [expr for expr in instr_ir if expr.dst not in regs_to_fix]

        for b in extra_ir:
            for i, irs in enumerate(b.irs):
                b.irs[i] = [expr for expr in irs if expr.dst not in regs_to_fix]

        return instr_ir, extra_ir


class ir_aarch64b(ir_aarch64l):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_aarch64, "b", symbol_pool)
        self.pc = PC
        self.sp = SP
        self.IRDst = m2_expr.ExprId('IRDst', 64)
