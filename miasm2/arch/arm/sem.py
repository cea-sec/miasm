from miasm2.expression.expression import *
from miasm2.ir.ir import ir, irbloc
from miasm2.arch.arm.arch import mn_arm, mn_armt

# liris.cnrs.fr/~mmrissa/lib/exe/fetch.php?media=armv7-a-r-manual.pdf

EXCEPT_PRIV_INSN = (1 << 17)

# CPSR: N Z C V

reg_r0 = 'R0'
reg_r1 = 'R1'
reg_r2 = 'R2'
reg_r3 = 'R3'
reg_r4 = 'R4'
reg_r5 = 'R5'
reg_r6 = 'R6'
reg_r7 = 'R7'
reg_r8 = 'R8'
reg_r9 = 'R9'
reg_r10 = 'R10'
reg_r11 = 'R11'
reg_r12 = 'R12'
reg_sp = 'SP'
reg_lr = 'LR'
reg_pc = 'PC'

reg_zf = 'zf'
reg_nf = 'nf'
reg_of = 'of'
reg_cf = 'cf'

zf = ExprId(reg_zf, size=1)
nf = ExprId(reg_nf, size=1)
of = ExprId(reg_of, size=1)
cf = ExprId(reg_cf, size=1)

R0 = ExprId(reg_r0)
R1 = ExprId(reg_r1)
R2 = ExprId(reg_r2)
R3 = ExprId(reg_r3)
R4 = ExprId(reg_r4)
R5 = ExprId(reg_r5)
R6 = ExprId(reg_r6)
R7 = ExprId(reg_r7)
R8 = ExprId(reg_r8)
R9 = ExprId(reg_r9)
R10 = ExprId(reg_r10)
R11 = ExprId(reg_r11)
R12 = ExprId(reg_r12)
SP = ExprId(reg_sp)
LR = ExprId(reg_lr)
PC = ExprId(reg_pc)


all_registers = [
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    SP,
    LR,
    PC,
]


def update_flag_zf(a):
    return [ExprAff(zf, ExprCond(a, ExprInt_from(zf, 0), ExprInt_from(zf, 1)))]


def update_flag_nf(a):
    return [ExprAff(nf, a.msb())]


def update_flag_pf(a):
    return [ExprAff(pf, ExprOp('parity', a))]


def update_flag_af(a):
    return [ExprAff(af, ExprCond(a & ExprInt_from(a, 0x10),
                                 ExprInt_from(af, 1), ExprInt_from(af, 0)))]


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


def update_flag_add_cf(a, b, c):
    return ExprAff(cf,
        ((((a ^ b) ^ c) ^ ((a ^ c) & (~(a ^ b)))).msb()) ^ ExprInt1(1))


def update_flag_add_of(a, b, c):
    return ExprAff(of, (((a ^ c) & (~(a ^ b)))).msb())


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
    return dst, e


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
    return dst, e


def l_and(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & c
    if instr.name == 'ANDS' and a != PC:
        e += update_flag_logic(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def sub(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b - c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def subs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b - c
    e += update_flag_arith(r)
    e += update_flag_sub(b, c, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def eor(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b ^ c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def eors(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b ^ c
    e += update_flag_logic(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def rsb(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = c - b
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def rsbs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = c - b
    e += update_flag_arith(r)
    e += update_flag_sub(b, c, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def sbc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (b + cf.zeroExtend(32)) - (c + ExprInt32(1))
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def sbcs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (b + cf.zeroExtend(32)) - (c + ExprInt32(1))
    e += update_flag_arith(r)
    e += update_flag_sub(b, c, r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def rsc(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = (c + cf.zeroExtend(32)) - (b + ExprInt32(1))
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


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
    return dst, e


def tst(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & c
    e += update_flag_logic(r)
    return None, e


def teq(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b ^ c
    e += update_flag_logic(r)
    return None, e


def l_cmp(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b - c
    e += update_flag_arith(r)
    e += update_flag_sub(c, b, r)
    return None, e


def cmn(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b + c
    e += update_flag_arith(r)
    e += update_flag_add(b, c, r)
    return None, e


def orr(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b | c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def orrs(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b | c
    e += update_flag_logic(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def mov(ir, instr, a, b):
    e = [ExprAff(a, b)]
    dst = get_dst(a)
    return dst, e


def movt(ir, instr, a, b):
    e = [ExprAff(a, a | b << ExprInt32(16))]
    dst = get_dst(a)
    return dst, e


def movs(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    # XXX TODO check
    e += update_flag_logic(b)
    dst = get_dst(a)
    return dst, e


def mvn(ir, instr, a, b):
    e = [ExprAff(a, b ^ ExprInt32(-1))]
    dst = get_dst(a)
    return dst, e


def mvns(ir, instr, a, b):
    e = []
    r = b ^ ExprInt32(-1)
    e.append(ExprAff(a, r))
    # XXX TODO check
    e += update_flag_logic(r)
    dst = get_dst(a)
    return dst, e


def neg(ir, instr, a, b):
    e = []
    r = - b
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e

def negs(ir, instr, a, b):
    dst, e = subs(ir, instr, a, ExprInt_from(b, 0), b)
    return dst, e

def bic(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & (c ^ ExprInt(uint32(-1)))
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def bics(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = b & (c ^ ExprInt(uint32(-1)))
    e += update_flag_logic(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def mla(ir, instr, a, b, c, d):
    e = []
    r = (b * c) + d
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def mlas(ir, instr, a, b, c, d):
    e = []
    r = (b * c) + d
    e += update_flag_zn(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def mul(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b * c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def muls(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b * c
    e += update_flag_zn(r)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def b(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    return a, e


def bl(ir, instr, a):
    e = []
    l = ExprInt32(instr.offset + instr.l)
    e.append(ExprAff(PC, a))
    e.append(ExprAff(LR, l))
    return a, e


def bx(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    return a, e


def blx(ir, instr, a):
    e = []
    l = ExprInt32(instr.offset + instr.l)
    e.append(ExprAff(PC, a))
    e.append(ExprAff(LR, l))
    return a, e


def st_ld_r(ir, instr, a, b, store=False, size=32, s_ext=False, z_ext=False):
    e = []
    wb = False
    b = b.copy()
    postinc = False
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
        e.append(ExprAff(a, m))
        if dmem:
            e.append(ExprAff(a2, ExprMem(ad + ExprInt32(4), size=size)))

    # XXX TODO check multiple write cause by wb
    if wb or postinc:
        e.append(ExprAff(base, base + off))
    return dst, e


def ldr(ir, instr, a, b):
    return st_ld_r(ir, instr, a, b, store=False)


def ldrd(ir, instr, a, b):
    dst, e = st_ld_r(ir, instr, a, b, store=False, size=64)
    return dst, e


def l_str(ir, instr, a, b):
    return st_ld_r(ir, instr, a, b, store=True)


def l_strd(ir, instr, a, b):
    dst, e = st_ld_r(ir, instr, a, b, store=True, size=64)
    return dst, e


def ldrb(ir, instr, a, b):
    dst, e = st_ld_r(ir, instr, a, b, store=False, size=8, z_ext=True)
    return dst, e

def ldrsb(ir, instr, a, b):
    dst, e = st_ld_r(
        ir, instr, a, b, store=False, size=8, s_ext=True, z_ext=False)
    return dst, e

def strb(ir, instr, a, b):
    dst, e = st_ld_r(ir, instr, a, b, store=True, size=8)
    return dst, e


def ldrh(ir, instr, a, b):
    dst, e = st_ld_r(ir, instr, a, b, store=False, size=16, z_ext=True)
    return dst, e


def strh(ir, instr, a, b):
    dst, e = st_ld_r(ir, instr, a, b, store=True, size=16, z_ext=True)
    return dst, e


def ldrsh(ir, instr, a, b):
    dst, e = st_ld_r(
        ir, instr, a, b, store=False, size=16, s_ext=True, z_ext=False)
    return dst, e


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
        if PC in b.args:
            dst = PC

    return dst, e


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
        ExprAff(ExprId('vmmngr.exception_flags'), ExprInt32(EXCEPT_PRIV_INSN))]
    return None, e


def und(ir, instr, a, b):
    # XXX TODO implement
    e = []
    return None, e

# TODO XXX implement correct CF for shifters
def lsr(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b >> c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def lsrs(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b >> c
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    return dst, e

def asr(ir, instr, a, b, c=None):
    e = []
    if c is None:
        b, c = a, b
    r = ExprOp("a>>", b, c)
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e

def asrs(ir, instr, a, b, c):
    e = []
    if c is None:
        b, c = a, b
    r = ExprOp("a>>", b, c)
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    return dst, e

def lsl(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b << c
    e.append(ExprAff(a, r))
    dst = get_dst(a)
    return dst, e


def lsls(ir, instr, a, b, c = None):
    e = []
    if c is None:
        b, c = a, b
    r = b << c
    e.append(ExprAff(a, r))
    e += update_flag_logic(r)
    dst = get_dst(a)
    return dst, e


def push(ir, instr, a):
    e = []
    regs = list(a.args)
    for i in xrange(len(regs)):
        r = SP + ExprInt32(-4 * (i + 1))
        e.append(ExprAff(regs[i], ExprMem(r)))
    r = SP + ExprInt32(-4 * len(regs))
    e.append(ExprAff(SP, r))
    return None, e


def pop(ir, instr, a):
    e = []
    regs = list(a.args)
    for i in xrange(len(regs)):
        r = SP + ExprInt32(4 * i)
        e.append(ExprAff(regs[i], ExprMem(r)))
    r = SP + ExprInt32(4 * len(regs))
    e.append(ExprAff(SP, r))
    dst = None
    if PC in a.get_r():
        dst = PC
    return dst, e


def cbz(ir, instr, a, b):
    e = []
    lbl_next = ExprId(ir.get_next_label(instr), 32)
    dst = ExprCond(a, lbl_next, b)
    return dst, e


def cbnz(ir, instr, a, b):
    e = []
    lbl_next = ExprId(ir.get_next_label(instr), 32)
    dst = ExprCond(a, b, lbl_next)
    return dst, e



def uxtb(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b[:8].zeroExtend(32)))
    dst = None
    if PC in a.get_r():
        dst = PC
    return dst, e

def uxth(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b[:16].zeroExtend(32)))
    dst = None
    if PC in a.get_r():
        dst = PC
    return dst, e

def ubfx(ir, instr, a, b, c, d):
    e = []
    c = int(c.arg)
    d = int(d.arg)
    e.append(ExprAff(a, b[c:c+d].zeroExtend(32)))
    dst = None
    if PC in a.get_r():
        dst = PC
    return dst, e



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


def add_condition_expr(ir, instr, cond, instr_ir, dst):
    # print "XXX", hex(instr.offset), instr
    if cond == COND_AL:
        return dst, instr_ir, []
    if not cond in tab_cond:
        raise ValueError('unknown condition %r' % cond)
    cond = tab_cond[cond]

    lbl_next = ExprId(ir.get_next_label(instr), 32)
    lbl_do = ExprId(ir.gen_label(), 32)

    dst_cond = ExprCond(cond, lbl_do, lbl_next)
    assert(isinstance(instr_ir, list))

    if dst is None:
        dst = lbl_next
    e_do = irbloc(lbl_do.name, dst, [instr_ir])
    return dst_cond, [], [e_do]

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
    dst, instr_ir = mf(ir, instr, *args)
    dst, instr, extra_ir = add_condition_expr(ir, instr, cond, instr_ir, dst)
    return dst, instr, extra_ir

get_arm_instr_expr = get_mnemo_expr


class arminfo:
    mode = "arm"
    # offset


class ir_arm(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_arm, "arm", symbol_pool)
        self.pc = PC
        self.sp = SP

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
        dst, instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)
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
        return dst, instr_ir, extra_ir


class ir_armt(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_armt, "armt", symbol_pool)
        self.pc = PC
        self.sp = SP

    def get_ir(self, instr):
        return get_mnemo_expr(self, instr, *instr.args)

