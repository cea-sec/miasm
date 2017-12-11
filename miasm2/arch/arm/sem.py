from miasm2.expression.expression import *
from miasm2.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock
from miasm2.arch.arm.arch import mn_arm, mn_armt
from miasm2.arch.arm.regs import *

from miasm2.jitter.csts import EXCEPT_DIV_BY_ZERO

# liris.cnrs.fr/~mmrissa/lib/exe/fetch.php?media=armv7-a-r-manual.pdf
EXCEPT_SOFT_BP = (1 << 1)

EXCEPT_PRIV_INSN = (1 << 17)

# CPSR: N Z C V


def update_flag_zf(a):
    return [ExprAff(zf, ExprCond(a, ExprInt(0, 1), ExprInt(1, 1)))]


def update_flag_nf(a):
    return [ExprAff(nf, a.msb())]


def update_flag_zn(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    return e


def update_flag_logic(a):
    e = []
    e += update_flag_zn(a)
    # XXX TODO: set cf if ROT imm in argument
    #e.append(ExprAff(cf, ExprInt(0, 1)))
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
    return ExprAff(cf, (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (~(op1 ^ op2)))).msb())


def update_flag_add_of(op1, op2, res):
    "Compute of in @res = @op1 + @op2"
    return ExprAff(of, (((op1 ^ res) & (~(op1 ^ op2)))).msb())


# checked: ok for sbb add because b & c before +cf
def update_flag_sub_cf(op1, op2, res):
    "Compote CF in @res = @op1 - @op2"
    return ExprAff(cf,
        ((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))).msb()) ^ ExprInt(1, 1))


def update_flag_sub_of(op1, op2, res):
    "Compote OF in @res = @op1 - @op2"
    return ExprAff(of, (((op1 ^ res) & (op1 ^ op2))).msb())

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


def get_dst(a):
    if a == PC:
        return PC
    return None

# instruction definition ##############


def adc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b + c + cf.zeroExtend(32)
    if instr.name == 'ADCS' and a != PC:
        e += update_flag_arith(r)
        e += update_flag_add(b, c, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def add(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b + c
    if instr.name == 'ADDS' and a != PC:
        e += update_flag_arith(r)
        e += update_flag_add(b, c, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def l_and(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & c
    if instr.name == 'ANDS' and a != PC:
        e += update_flag_logic(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def sub(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b - c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def subs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b - c
    e += update_flag_arith(r)
    e += update_flag_sub(b, c, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def eor(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b ^ c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def eors(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b ^ c
    e += update_flag_logic(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def rsb(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = c - b
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def rsbs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = c - b
    e += update_flag_arith(r)
    e += update_flag_sub(c, b, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def sbc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (b + cf.zeroExtend(32)) - (c + ExprInt(1, 32))
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def sbcs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (b + cf.zeroExtend(32)) - (c + ExprInt(1, 32))
    e += update_flag_arith(r)
    e += update_flag_sub(b, c, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def rsc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (c + cf.zeroExtend(32)) - (b + ExprInt(1, 32))
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def rscs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (c + cf.zeroExtend(32)) - (b + ExprInt(1, 32))
    e.append(ExprAff(a, r))
    e += update_flag_arith(r)
    e += update_flag_sub(c, b, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def tst(ir, instr, a, b):
    e = []
    r = a & b
    e += update_flag_logic(r)
    return e, []


def teq(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b ^ c
    e += update_flag_logic(r)
    return e, []


def l_cmp(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b - c
    e += update_flag_arith(r)
    e += update_flag_sub(b, c, r)
    return e, []


def cmn(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b + c
    e += update_flag_arith(r)
    e += update_flag_add(b, c, r)
    return e, []


def orr(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b | c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def orn(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = ~(b | c)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def orrs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b | c
    e += update_flag_logic(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def mov(ir, instr, a, b):
    e = [ExprAff(a, b)]
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, b))
    return e, []


def movt(ir, instr, a, b):
    r = a | b << ExprInt(16, 32)
    e = [ExprAff(a, r)]
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def movs(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    # XXX TODO check
    e += update_flag_logic(b)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, b))
    return e, []


def mvn(ir, instr, a, b):
    r = b ^ ExprInt(-1, 32)
    e = [ExprAff(a, r)]
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def mvns(ir, instr, a, b):
    e = []
    r = b ^ ExprInt(-1, 32)
    e.append(ExprAff(a, r))
    # XXX TODO check
    e += update_flag_logic(r)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def neg(ir, instr, a, b):
    e = []
    r = - b
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []

def negs(ir, instr, a, b):
    return subs(ir, instr, a, ExprInt(0, b.size), b)

def bic(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & (c ^ ExprInt(-1, 32))
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def bics(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & (c ^ ExprInt(-1, 32))
    e += update_flag_logic(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def sdiv(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b

    lbl_div = ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_except = ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_next = ExprId(ir.get_next_label(instr), ir.IRDst.size)

    e.append(ExprAff(ir.IRDst, ExprCond(c, lbl_div, lbl_except)))

    do_except = []
    do_except.append(ExprAff(exception_flags, ExprInt(EXCEPT_DIV_BY_ZERO, exception_flags.size)))
    do_except.append(ExprAff(ir.IRDst, lbl_next))
    blk_except = IRBlock(lbl_except.name.loc_key, [AssignBlock(do_except, instr)])



    r = ExprOp("idiv", b, c)
    do_div = []
    do_div.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        do_div.append(ExprAff(ir.IRDst, r))

    do_div.append(ExprAff(ir.IRDst, lbl_next))
    blk_div = IRBlock(lbl_div.name.loc_key, [AssignBlock(do_div, instr)])

    return e, [blk_div, blk_except]


def udiv(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b



    lbl_div = ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_except = ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_next = ExprId(ir.get_next_label(instr), ir.IRDst.size)

    e.append(ExprAff(ir.IRDst, ExprCond(c, lbl_div, lbl_except)))

    do_except = []
    do_except.append(ExprAff(exception_flags, ExprInt(EXCEPT_DIV_BY_ZERO, exception_flags.size)))
    do_except.append(ExprAff(ir.IRDst, lbl_next))
    blk_except = IRBlock(lbl_except.name.loc_key, [AssignBlock(do_except, instr)])


    r = ExprOp("udiv", b, c)
    do_div = []
    do_div.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        do_div.append(ExprAff(ir.IRDst, r))

    do_div.append(ExprAff(ir.IRDst, lbl_next))
    blk_div = IRBlock(lbl_div.name.loc_key, [AssignBlock(do_div, instr)])

    return e, [blk_div, blk_except]


def mla(ir, instr, a, b, c, d):
    e = []
    r = (b * c) + d
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def mlas(ir, instr, a, b, c, d):
    e = []
    r = (b * c) + d
    e += update_flag_zn(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def mls(ir, instr, a, b, c, d):
    e = []
    r = d - (b * c)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def mul(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b * c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def muls(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b * c
    e += update_flag_zn(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []

def umull(ir, instr, a, b, c, d):
    e = []
    r = c.zeroExtend(64) * d.zeroExtend(64)
    e.append(ExprAff(a, r[0:32]))
    e.append(ExprAff(b, r[32:64]))
    # r15/IRDst not allowed as output
    return e, []

def umlal(ir, instr, a, b, c, d):
    e = []
    r = c.zeroExtend(64) * d.zeroExtend(64) + ExprCompose(a, b)
    e.append(ExprAff(a, r[0:32]))
    e.append(ExprAff(b, r[32:64]))
    # r15/IRDst not allowed as output
    return e, []

def smull(ir, instr, a, b, c, d):
    e = []
    r = c.signExtend(64) * d.signExtend(64)
    e.append(ExprAff(a, r[0:32]))
    e.append(ExprAff(b, r[32:64]))
    # r15/IRDst not allowed as output
    return e, []

def smlal(ir, instr, a, b, c, d):
    e = []
    r = c.signExtend(64) * d.signExtend(64) + ExprCompose(a, b)
    e.append(ExprAff(a, r[0:32]))
    e.append(ExprAff(b, r[32:64]))
    # r15/IRDst not allowed as output
    return e, []

def b(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []


def bl(ir, instr, a):
    e = []
    l = ExprInt(instr.offset + instr.l, 32)
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    e.append(ExprAff(LR, l))
    return e, []


def bx(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []


def blx(ir, instr, a):
    e = []
    l = ExprInt(instr.offset + instr.l, 32)
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    e.append(ExprAff(LR, l))
    return e, []


def st_ld_r(ir, instr, a, a2, b, store=False, size=32, s_ext=False, z_ext=False):
    e = []
    wb = False
    b = b.copy()
    postinc = False
    b = b.arg
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
    # print a, wb, base, off, postinc
    if postinc:
        ad = base
    else:
        ad = base + off

    # PC base lookup uses PC 4 byte alignemnt
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
        pass
    elif size == 64:
        assert a2 is not None
        m = ExprMem(ad, size=32)
        dmem = True
        size = 32
    else:
        raise ValueError('the size DOES matter')
    dst = None

    if store:
        e.append(ExprAff(m, a))
        if dmem:
            e.append(ExprAff(ExprMem(ad + ExprInt(4, 32), size=size), a2))
    else:
        if a == PC:
            dst = PC
            e.append(ExprAff(ir.IRDst, m))
        e.append(ExprAff(a, m))
        if dmem:
            e.append(ExprAff(a2, ExprMem(ad + ExprInt(4, 32), size=size)))

    # XXX TODO check multiple write cause by wb
    if wb or postinc:
        e.append(ExprAff(base, base + off))
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
    # sb = False
    dst = None
    if isinstance(a, ExprOp) and a.op == 'wback':
        wb = True
        a = a.args[0]
    if isinstance(b, ExprOp) and b.op == 'sbit':
        # sb = True
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
            e.append(ExprAff(ExprMem(ad, 32), r))
        else:
            e.append(ExprAff(r, ExprMem(ad, 32)))
            if r == PC:
                e.append(ExprAff(ir.IRDst, ExprMem(ad, 32)))
    # XXX TODO check multiple write cause by wb
    if wb:
        if postinc:
            e.append(ExprAff(a, base + ExprInt(len(regs) * step, 32)))
        else:
            e.append(ExprAff(a, base + ExprInt((len(regs) - 1) * step, 32)))
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
    # XXX TODO implement
    e = [
        ExprAff(exception_flags, ExprInt(EXCEPT_PRIV_INSN, 32))]
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
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def lsrs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b >> c
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []

def asr(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = ExprOp("a>>", b, c)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []

def asrs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = ExprOp("a>>", b, c)
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []

def lsl(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b << c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def lsls(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b << c
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def rors(ir, instr, a, b):
    e = []
    r = ExprOp(">>>", a, b)
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def push(ir, instr, a):
    e = []
    regs = list(a.args)
    for i in xrange(len(regs)):
        r = SP + ExprInt(-4 * len(regs) + 4 * i, 32)
        e.append(ExprAff(ExprMem(r, 32), regs[i]))
    r = SP + ExprInt(-4 * len(regs), 32)
    e.append(ExprAff(SP, r))
    return e, []


def pop(ir, instr, a):
    e = []
    regs = list(a.args)
    dst = None
    for i in xrange(len(regs)):
        r = SP + ExprInt(4 * i, 32)
        e.append(ExprAff(regs[i], ExprMem(r, 32)))
        if regs[i] == ir.pc:
            dst = ExprMem(r, 32)
    r = SP + ExprInt(4 * len(regs), 32)
    e.append(ExprAff(SP, r))
    if dst is not None:
        e.append(ExprAff(ir.IRDst, dst))
    return e, []


def cbz(ir, instr, a, b):
    e = []
    lbl_next = ir.get_next_label(instr)
    lbl_next_expr = ExprLoc(lbl_next.loc_key, 32)
    e.append(ExprAff(ir.IRDst, ExprCond(a, lbl_next_expr, b)))
    return e, []


def cbnz(ir, instr, a, b):
    e = []
    lbl_next = ir.get_next_label(instr)
    lbl_next_expr = ExprLoc(lbl_next.loc_key, 32)
    e.append(ir.IRDst, ExprCond(a, b, lbl_next_expr))
    return e, []


def uxtb(ir, instr, a, b):
    e = []
    r = b[:8].zeroExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e, []

def uxth(ir, instr, a, b):
    e = []
    r = b[:16].zeroExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e, []

def sxtb(ir, instr, a, b):
    e = []
    r = b[:8].signExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e, []

def sxth(ir, instr, a, b):
    e = []
    r = b[:16].signExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e, []


def ubfx(ir, instr, a, b, c, d):
    e = []
    c = int(c)
    d = int(d)
    r = b[c:c+d].zeroExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
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
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e, []

def rev(ir, instr, a, b):
    e = []
    c = ExprCompose(b[24:32], b[16:24], b[8:16], b[:8])
    e.append(ExprAff(a, c))
    return e, []

def pld(ir, instr, a):
    e = []
    return e, []


def pldw(ir, instr, a):
    e = []
    return e, []


def clz(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprOp('cntleadzeros', b)))
    return e, []

def uxtab(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b + (c & ExprInt(0xff, 32))))
    return e, []


def bkpt(ir, instr, a):
    e = []
    e.append(ExprAff(exception_flags, ExprInt(EXCEPT_SOFT_BP, 32)))
    e.append(ExprAff(bp_num, a))
    return e, []


def _extract_s16(arg, part):
    if part == 'B': # bottom 16 bits
        return arg[0:16]
    elif part == 'T': # top 16 bits
        return arg[16:32]


def smul(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, _extract_s16(b, instr.name[4]).signExtend(32) * _extract_s16(c, instr.name[5]).signExtend(32)))
    return e, []


def smulw(ir, instr, a, b, c):
    e = []
    prod = b.signExtend(48) * _extract_s16(c, instr.name[5]).signExtend(48)
    e.append(ExprAff(a, prod[16:48]))
    return e, [] # signed most significant 32 bits of the 48-bit result


def tbb(ir, instr, a):
    e = []
    dst = PC + ExprInt(2, 32) * a.zeroExtend(32)
    e.append(ExprAff(PC, dst))
    e.append(ExprAff(ir.IRDst, dst))
    return e, []


def tbh(ir, instr, a):
    e = []
    dst = PC + ExprInt(2, 32) * a.zeroExtend(32)
    e.append(ExprAff(PC, dst))
    e.append(ExprAff(ir.IRDst, dst))
    return e, []


def smlabb(ir, instr, a, b, c, d):
    e = []
    result = (b[:16].signExtend(32) * c[:16].signExtend(32)) + d
    e.append(ExprAff(a, result))
    return e, []


def smlabt(ir, instr, a, b, c, d):
    e = []
    result = (b[:16].signExtend(32) * c[16:32].signExtend(32)) + d
    e.append(ExprAff(a, result))
    return e, []


def smlatb(ir, instr, a, b, c, d):
    e = []
    result = (b[16:32].signExtend(32) * c[:16].signExtend(32)) + d
    e.append(ExprAff(a, result))
    return e, []


def smlatt(ir, instr, a, b, c, d):
    e = []
    result = (b[16:32].signExtend(32) * c[16:32].signExtend(32)) + d
    e.append(ExprAff(a, result))
    return e, []


def uadd8(ir, instr, a, b, c):
    e = []
    sums = []
    ges = []
    for i in xrange(0, 32, 8):
        sums.append(b[i:i+8] + c[i:i+8])
        ges.append((b[i:i+8].zeroExtend(9) + c[i:i+8].zeroExtend(9))[8:9])

    e.append(ExprAff(a, ExprCompose(*sums)))

    for i, value in enumerate(ges):
        e.append(ExprAff(ge_regs[i], value))
    return e, []


def sel(ir, instr, a, b, c):
    e = []
    cond = nf ^ of ^ ExprInt(1, 1)
    parts = []
    for i in xrange(4):
        parts.append(ExprCond(ge_regs[i], b[i*8:(i+1)*8], c[i*8:(i+1)*8]))
    result = ExprCompose(*parts)
    e.append(ExprAff(a, result))
    return e, []


def rev(ir, instr, a, b):
    e = []
    result = ExprCompose(b[24:32], b[16:24], b[8:16], b[:8])
    e.append(ExprAff(a, result))
    return e, []


def nop(ir, instr):
    e = []
    return e, []


def dsb(ir, instr, a):
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

cond_dct_inv = dict((name, num) for num, name in cond_dct.iteritems())

tab_cond = {COND_EQ: zf,
            COND_NE: ExprCond(zf, ExprInt(0, 1), ExprInt(1, 1)),
            COND_CS: cf,
            COND_CC: ExprCond(cf, ExprInt(0, 1), ExprInt(1, 1)),
            COND_MI: nf,
            COND_PL: ExprCond(nf, ExprInt(0, 1), ExprInt(1, 1)),
            COND_VS: of,
            COND_VC: ExprCond(of, ExprInt(0, 1), ExprInt(1, 1)),
            COND_HI: cf & ExprCond(zf, ExprInt(0, 1), ExprInt(1, 1)),
            # COND_HI: cf,
            # COND_HI: ExprOp('==',
            #                ExprOp('|', cf, zf),
            #                ExprInt(0, 1)),
            COND_LS: ExprCond(cf, ExprInt(0, 1), ExprInt(1, 1)) | zf,
            COND_GE: ExprCond(nf - of, ExprInt(0, 1), ExprInt(1, 1)),
            COND_LT: nf ^ of,
            # COND_GT: ExprOp('|',
            #                ExprOp('==', zf, ExprInt(0, 1)) & (nf | of),
            # ExprOp('==', nf, ExprInt(0, 1)) & ExprOp('==', of, ExprInt(0, 1))),
            COND_GT: (ExprCond(zf, ExprInt(0, 1), ExprInt(1, 1)) &
                      ExprCond(nf - of, ExprInt(0, 1), ExprInt(1, 1))),
            COND_LE: zf | (nf ^ of),
            }


def is_pc_written(ir, instr_ir):
    all_pc = ir.mn.pc.values()
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



    lbl_next = ir.get_next_label(instr)
    lbl_next_expr = ExprLoc(lbl_next.loc_key, 32)
    lbl_do = ir.gen_label()
    lbl_do_expr = ExprLoc(lbl_do.loc_key, 32)

    dst_cond = ExprCond(cond, lbl_do_expr, lbl_next_expr)
    assert(isinstance(instr_ir, list))

    has_irdst = False
    for e in instr_ir:
        if e.dst == ir.IRDst:
            has_irdst = True
            break
    if not has_irdst:
        instr_ir.append(ExprAff(ir.IRDst, lbl_next_expr))
    e_do = IRBlock(lbl_do.loc_key, [AssignBlock(instr_ir, instr)])
    e = [ExprAff(ir.IRDst, dst_cond)]
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

                'mul': mul,
                'umull': umull,
                'umlal': umlal,
                'smull': smull,
                'smlal': smlal,
                'mla': mla,
                'ldr': ldr,
                'ldrd': ldrd,
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
                'clz': clz,
                'uxtab': uxtab,
                'bkpt': bkpt,
                'smulbb': smul,
                'smulbt': smul,
                'smultb': smul,
                'smultt': smul,
                'smulwt': smulw,
                'smulwb': smulw,
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
                'negs': negs,

                'muls': muls,
                'mls': mls,
                'mlas': mlas,
                'blx': blx,

                'ldrb': ldrb,
                'ldrsb': ldrsb,
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
                'cpsie': cpsie,
                'cpsid': cpsid,
                'wfe': wfe,
                'wfi': wfi,
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
    for mn, mf in mn_base.items():
        for cond, cn in cond_dct.items():
            if cond == COND_AL:
                cn = ""
            cn = cn.lower()
            if index == 0:
                mn_mod = mn + cn
            else:
                mn_mod = mn[:-index] + cn + mn[-index:]
            # print mn_mod
            mnemo_func_cond[mn_mod] = cond, mf

for name, mf in mnemo_nocond.items():
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


class arminfo:
    mode = "arm"
    # offset


class ir_arml(IntermediateRepresentation):
    def __init__(self, symbol_pool=None):
        IntermediateRepresentation.__init__(self, mn_arm, "l", symbol_pool)
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
            instr_ir[i] = ExprAff(dst, src)

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

    def do_it_block(self, label, index, block, assignments, gen_pc_updt):
        instr = block.lines[index]
        it_hints, it_cond = self.parse_itt(instr)
        cond_num = cond_dct_inv[it_cond.name]
        cond_eq = tab_cond[cond_num]

        if not index + len(it_hints) <= len(block.lines):
            raise NotImplementedError("Splitted IT block non supported yet")

        ir_blocks_all = []

        # Gen dummy irblock for IT instr
        label_next = self.get_next_label(instr)
        dst = ExprAff(self.IRDst, ExprId(label_next, 32))
        dst_blk = AssignBlock([dst], instr)
        assignments.append(dst_blk)
        irblock = IRBlock(label.loc_key, assignments)
        ir_blocks_all.append([irblock])

        label = label_next
        assignments = []
        for hint in it_hints:
            irblocks = []
            index += 1
            instr = block.lines[index]

            # Add conditionnal jump to current irblock
            label_do = self.symbol_pool.gen_label()
            label_next = self.get_next_label(instr)

            if hint:
                local_cond = ~cond_eq
            else:
                local_cond = cond_eq
            dst = ExprAff(self.IRDst, ExprCond(local_cond, ExprId(label_do, 32), ExprId(label_next, 32)))
            dst_blk = AssignBlock([dst], instr)
            assignments.append(dst_blk)
            irblock = IRBlock(label.loc_key, assignments)

            irblocks.append(irblock)

            assignments = []
            label = label_do
            split = self.add_instr_to_irblock(block, instr, assignments,
                                              irblocks, gen_pc_updt)
            if split:
                raise NotImplementedError("Unsupported instr in IT block (%s)" % instr)

            dst = ExprAff(self.IRDst, ExprId(label_next, 32))
            dst_blk = AssignBlock([dst], instr)
            assignments.append(dst_blk)
            irblock = IRBlock(label.loc_key, assignments)
            irblocks.append(irblock)
            label = label_next
            assignments = []
            ir_blocks_all.append(irblocks)
        return index, ir_blocks_all

    def add_block(self, block, gen_pc_updt=False):
        """
        Add a native block to the current IR
        @block: native assembly block
        @gen_pc_updt: insert PC update effects between instructions
        """

        it_hints = None
        it_cond = None
        label = block.label
        assignments = []
        ir_blocks_all = []
        index = -1
        while index + 1 < len(block.lines):
            index += 1
            instr = block.lines[index]
            if label is None:
                assignments = []
                label = self.get_instr_label(instr)
            if instr.name.startswith("IT"):
                index, irblocks_it = self.do_it_block(label, index, block, assignments, gen_pc_updt)
                for irblocks in irblocks_it:
                    ir_blocks_all += irblocks
                label = None
                continue

            split = self.add_instr_to_irblock(block, instr, assignments,
                                              ir_blocks_all, gen_pc_updt)
            if split:
                ir_blocks_all.append(IRBlock(label.loc_key, assignments))
                label = None
                assignments = []
        if label is not None:
            ir_blocks_all.append(IRBlock(label.loc_key, assignments))

        new_ir_blocks_all = self.post_add_block(block, ir_blocks_all)
        for irblock in new_ir_blocks_all:
            self.blocks[irblock.label] = irblock
        return new_ir_blocks_all



class ir_armb(ir_arml):
    def __init__(self, symbol_pool=None):
        IntermediateRepresentation.__init__(self, mn_arm, "b", symbol_pool)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 32)
        self.addrsize = 32


class ir_armtl(ir_arml):
    def __init__(self, symbol_pool=None):
        IntermediateRepresentation.__init__(self, mn_armt, "l", symbol_pool)
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
            instr_ir[i] = ExprAff(dst, src)

        for idx, irblock in enumerate(extra_ir):
            extra_ir[idx] = irblock.modify_exprs(lambda expr: expr.replace_expr(pc_fixed) \
                                                 if expr != self.pc else expr,
                                                 lambda expr: expr.replace_expr(pc_fixed))


class ir_armtb(ir_armtl):
    def __init__(self, symbol_pool=None):
        IntermediateRepresentation.__init__(self, mn_armt, "b", symbol_pool)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 32)
        self.addrsize = 32

