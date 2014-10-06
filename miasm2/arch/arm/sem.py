from miasm2.expression.expression import *
from miasm2.ir.ir import ir, irbloc
from miasm2.arch.arm.arch import mn_arm, mn_armt
from miasm2.arch.arm.regs import *


# liris.cnrs.fr/~mmrissa/lib/exe/fetch.php?media=armv7-a-r-manual.pdf

EXCEPT_PRIV_INSN = (1 << 17)

# CPSR: N Z C V


def update_flag_zf(a):
    return [ExprAff(zf, ExprCond(a, ExprInt1(0), ExprInt1(1)))]


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
    e.append(ExprAff(cf, ExprInt1(0)))
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
def update_flag_sub_cf(a, b, c):
    return ExprAff(cf,
        ((((a ^ b) ^ c) ^ ((a ^ c) & (a ^ b))).msb()) ^ ExprInt1(1))


def update_flag_sub_of(a, b, c):
    return ExprAff(of, (((a ^ c) & (a ^ b))).msb())

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
    return e


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
    return e


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
    return e


def sub(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b - c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


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
    return e


def eor(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b ^ c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


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
    return e


def rsb(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = c - b
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def rsbs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = c - b
    e += update_flag_arith(r)
    e += update_flag_sub(b, c, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def sbc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (b + cf.zeroExtend(32)) - (c + ExprInt32(1))
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def sbcs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (b + cf.zeroExtend(32)) - (c + ExprInt32(1))
    e += update_flag_arith(r)
    e += update_flag_sub(b, c, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def rsc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (c + cf.zeroExtend(32)) - (b + ExprInt32(1))
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def rscs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (c + cf.zeroExtend(32)) - (b + ExprInt32(1))
    e.append(ExprAff(a, r))
    e += update_flag_arith(r)
    e += update_flag_sub(c, b, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def tst(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & c
    e += update_flag_logic(r)
    return e


def teq(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b ^ c
    e += update_flag_logic(r)
    return e


def l_cmp(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b - c
    e += update_flag_arith(r)
    e += update_flag_sub(c, b, r)
    return e


def cmn(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b + c
    e += update_flag_arith(r)
    e += update_flag_add(b, c, r)
    return e


def orr(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b | c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


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
    return e


def mov(ir, instr, a, b):
    e = [ExprAff(a, b)]
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, b))
    return e


def movt(ir, instr, a, b):
    r = a | b << ExprInt32(16)
    e = [ExprAff(a, r)]
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def movs(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    # XXX TODO check
    e += update_flag_logic(b)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, b))
    return e


def mvn(ir, instr, a, b):
    r = b ^ ExprInt32(-1)
    e = [ExprAff(a, r)]
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def mvns(ir, instr, a, b):
    e = []
    r = b ^ ExprInt32(-1)
    e.append(ExprAff(a, r))
    # XXX TODO check
    e += update_flag_logic(r)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def neg(ir, instr, a, b):
    e = []
    r = - b
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e

def negs(ir, instr, a, b):
    e = subs(ir, instr, a, ExprInt_from(b, 0), b)
    return e

def bic(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & (c ^ ExprInt(uint32(-1)))
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def bics(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & (c ^ ExprInt(uint32(-1)))
    e += update_flag_logic(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def mla(ir, instr, a, b, c, d):
    e = []
    r = (b * c) + d
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def mlas(ir, instr, a, b, c, d):
    e = []
    r = (b * c) + d
    e += update_flag_zn(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def mul(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b * c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def muls(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b * c
    e += update_flag_zn(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def b(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    return e


def bl(ir, instr, a):
    e = []
    l = ExprInt32(instr.offset + instr.l)
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    e.append(ExprAff(LR, l))
    return e


def bx(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    return e


def blx(ir, instr, a):
    e = []
    l = ExprInt32(instr.offset + instr.l)
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    e.append(ExprAff(LR, l))
    return e


def st_ld_r(ir, instr, a, b, store=False, size=32, s_ext=False, z_ext=False):
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
        base, off = b.args[0],  b.args[1]  # ExprInt32(size/8)
    else:
        base, off = b, ExprInt32(0)
    # print a, wb, base, off, postinc
    if postinc:
        ad = base
    else:
        ad = base + off

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
        m = ExprMem(ad, size=32)
        dmem = True
        a2 = ir.arch.regs.all_regs_ids[ir.arch.regs.all_regs_ids.index(a) + 1]
        size = 32
    else:
        raise ValueError('the size DOES matter')
    dst = None

    if store:
        e.append(ExprAff(m, a))
        if dmem:
            e.append(ExprAff(ExprMem(ad + ExprInt32(4), size=size), a2))
    else:
        if a == PC:
            dst = PC
            e.append(ExprAff(ir.IRDst, m))
        e.append(ExprAff(a, m))
        if dmem:
            e.append(ExprAff(a2, ExprMem(ad + ExprInt32(4), size=size)))

    # XXX TODO check multiple write cause by wb
    if wb or postinc:
        e.append(ExprAff(base, base + off))
    return e


def ldr(ir, instr, a, b):
    return st_ld_r(ir, instr, a, b, store=False)


def ldrd(ir, instr, a, b):
    e = st_ld_r(ir, instr, a, b, store=False, size=64)
    return e


def l_str(ir, instr, a, b):
    return st_ld_r(ir, instr, a, b, store=True)


def l_strd(ir, instr, a, b):
    e = st_ld_r(ir, instr, a, b, store=True, size=64)
    return e


def ldrb(ir, instr, a, b):
    e = st_ld_r(ir, instr, a, b, store=False, size=8, z_ext=True)
    return e

def ldrsb(ir, instr, a, b):
    e = st_ld_r(
        ir, instr, a, b, store=False, size=8, s_ext=True, z_ext=False)
    return e

def strb(ir, instr, a, b):
    e = st_ld_r(ir, instr, a, b, store=True, size=8)
    return e


def ldrh(ir, instr, a, b):
    e = st_ld_r(ir, instr, a, b, store=False, size=16, z_ext=True)
    return e


def strh(ir, instr, a, b):
    e = st_ld_r(ir, instr, a, b, store=True, size=16, z_ext=True)
    return e


def ldrsh(ir, instr, a, b):
    e = st_ld_r(
        ir, instr, a, b, store=False, size=16, s_ext=True, z_ext=False)
    return e


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
        base += ExprInt32(step)
    for i, r in enumerate(regs):
        ad = base + ExprInt32(i * step)
        if store:
            e.append(ExprAff(ExprMem(ad), r))
        else:
            e.append(ExprAff(r, ExprMem(ad)))
            if r == PC:
                e.append(ExprAff(ir.IRDst, ExprMem(ad)))
    # XXX TODO check multiple write cause by wb
    if wb:
        if postinc:
            e.append(ExprAff(a, base + ExprInt32(len(regs) * step)))
        else:
            e.append(ExprAff(a, base + ExprInt32((len(regs) - 1) * step)))
    if store:
        pass
    else:
        assert(isinstance(b, ExprOp) and b.op == "reglist")

    return e


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
        ExprAff(exception_flags, ExprInt32(EXCEPT_PRIV_INSN))]
    return e


def und(ir, instr, a, b):
    # XXX TODO implement
    e = []
    return e

# TODO XXX implement correct CF for shifters
def lsr(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b >> c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def lsrs(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b >> c
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e

def asr(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = ExprOp("a>>", b, c)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e

def asrs(ir, instr, a, b, c):
    e = []
    if c is None:
        b, c = a, b
    r = ExprOp("a>>", b, c)
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e

def lsl(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b << c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def lsls(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b << c
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    if dst is not None:
        e.append(ExprAff(ir.IRDst, r))
    return e


def push(ir, instr, a):
    e = []
    regs = list(a.args)
    for i in xrange(len(regs)):
        r = SP + ExprInt32(-4 * (i + 1))
        e.append(ExprAff(regs[i], ExprMem(r)))
    r = SP + ExprInt32(-4 * len(regs))
    e.append(ExprAff(SP, r))
    return e


def pop(ir, instr, a):
    e = []
    regs = list(a.args)
    dst = None
    for i in xrange(len(regs)):
        r = SP + ExprInt32(4 * i)
        e.append(ExprAff(regs[i], ExprMem(r)))
        if regs[i] == ir.pc:
            dst = ExprMem(r)
    r = SP + ExprInt32(4 * len(regs))
    e.append(ExprAff(SP, r))
    if dst is not None:
        e.append(ExprAff(ir.IRDst, dst))
    return e


def cbz(ir, instr, a, b):
    e = []
    lbl_next = ExprId(ir.get_next_label(instr), 32)
    e.append(ExprAff(ir.IRDst, ExprCond(a, lbl_next, b)))
    return e


def cbnz(ir, instr, a, b):
    e = []
    lbl_next = ExprId(ir.get_next_label(instr), 32)
    e.append(ir.IRDst, ExprCond(a, b, lbl_next))
    return e



def uxtb(ir, instr, a, b):
    e = []
    r = b[:8].zeroExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e

def uxth(ir, instr, a, b):
    e = []
    r = b[:16].zeroExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e

def sxtb(ir, instr, a, b):
    e = []
    r = b[:8].signExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e

def sxth(ir, instr, a, b):
    e = []
    r = b[:16].signExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e


def ubfx(ir, instr, a, b, c, d):
    e = []
    c = int(c.arg)
    d = int(d.arg)
    r = b[c:c+d].zeroExtend(32)
    e.append(ExprAff(a, r))
    dst = None
    if PC in a.get_r():
        dst = PC
        e.append(ExprAff(ir.IRDst, r))
    return e



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


tab_cond = {COND_EQ: zf,
            COND_NE: ExprCond(zf, ExprInt1(0), ExprInt1(1)),
            COND_CS: cf,
            COND_CC: ExprCond(cf, ExprInt1(0), ExprInt1(1)),
            COND_MI: nf,
            COND_PL: ExprCond(nf, ExprInt1(0), ExprInt1(1)),
            COND_VS: of,
            COND_VC: ExprCond(of, ExprInt1(0), ExprInt1(1)),
            COND_HI: cf & ExprCond(zf, ExprInt1(0), ExprInt1(1)),
            # COND_HI: cf,
            # COND_HI: ExprOp('==',
            #                ExprOp('|', cf, zf),
            #                ExprInt1(0)),
            COND_LS: ExprCond(cf, ExprInt1(0), ExprInt1(1)) | zf,
            COND_GE: ExprCond(nf - of, ExprInt1(0), ExprInt1(1)),
            COND_LT: nf ^ of,
            # COND_GT: ExprOp('|',
            #                ExprOp('==', zf, ExprInt1(0)) & (nf | of),
            # ExprOp('==', nf, ExprInt1(0)) & ExprOp('==', of, ExprInt1(0))),
            COND_GT: (ExprCond(zf, ExprInt1(0), ExprInt1(1)) &
                      ExprCond(nf - of, ExprInt1(0), ExprInt1(1))),
            COND_LE: zf | (nf ^ of),
            }


def is_pc_written(ir, instr_ir):
    all_pc = ir.mn.pc.values()
    for ir in instr_ir:
        if ir.dst in all_pc:
            return True, ir.dst
    return False, None


def add_condition_expr(ir, instr, cond, instr_ir):
    if cond == COND_AL:
        return instr_ir, []
    if not cond in tab_cond:
        raise ValueError('unknown condition %r' % cond)
    cond = tab_cond[cond]

    lbl_next = ExprId(ir.get_next_label(instr), 32)
    lbl_do = ExprId(ir.gen_label(), 32)

    dst_cond = ExprCond(cond, lbl_do, lbl_next)
    assert(isinstance(instr_ir, list))

    has_irdst = False
    for e in instr_ir:
        if e.dst == ir.IRDst:
            has_irdst = True
            break
    if not has_irdst:
        instr_ir.append(ExprAff(ir.IRDst, lbl_next))
    e_do = irbloc(lbl_do.name, [instr_ir])
    e = [ExprAff(ir.IRDst, dst_cond)]
    return e, [e_do]

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

                'mul': mul,
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
                'push': push,
                'pop': pop,
                'asr': asr,
                'asrs': asrs,
                'cbz': cbz,
                'cbnz': cbnz,
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
    instr_ir = mf(ir, instr, *args)
    instr, extra_ir = add_condition_expr(ir, instr, cond, instr_ir)
    return instr, extra_ir

get_arm_instr_expr = get_mnemo_expr


class arminfo:
    mode = "arm"
    # offset


class ir_arm(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_arm, "arm", symbol_pool)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 32)

    def get_ir(self, instr):
        args = instr.args
        # ir = get_mnemo_expr(self, self.name.lower(), *args)
        if len(args) and isinstance(args[-1], ExprOp):
            if args[-1].op == 'rrx':
                args[-1] = ExprCompose(
                    [(args[-1].args[0][1:], 0, 31), (cf, 31, 32)])
            elif (args[-1].op in ['<<', '>>', '<<a', 'a>>', '<<<', '>>>'] and
                  isinstance(args[-1].args[-1], ExprId)):
                args[-1].args = args[-1].args[:-1] + (
                    args[-1].args[-1][:8].zeroExtend(32),)
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)
        # if self.name.startswith('B'):
        #    return instr_ir, extra_ir
        for i, x in enumerate(instr_ir):
            x = ExprAff(x.dst, x.src.replace_expr(
                {self.pc: ExprInt32(instr.offset + 8)}))
            instr_ir[i] = x
        for b in extra_ir:
            for irs in b.irs:
                for i, x in enumerate(irs):
                    x = ExprAff(x.dst, x.src.replace_expr(
                        {self.pc: ExprInt32(instr.offset + 8)}))
                    irs[i] = x
        # return out_ir, extra_ir
        return instr_ir, extra_ir


class ir_armt(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_armt, "armt", symbol_pool)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 32)

    def get_ir(self, instr):
        return get_mnemo_expr(self, instr, *instr.args)

