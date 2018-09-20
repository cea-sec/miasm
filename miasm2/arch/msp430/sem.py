#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.arch.msp430.regs import *
from miasm2.arch.msp430.arch import mn_msp430
from miasm2.ir.ir import IntermediateRepresentation


# Utils
def hex2bcd(val):
    "Return val as BCD"
    try:
        return int("%x" % val, 10)
    except ValueError:
        raise NotImplementedError("Not defined behaviour")


def bcd2hex(val):
    "Return the hex value of a BCD"
    try:
        return int("0x%d" % val, 16)
    except ValueError:
        raise NotImplementedError("Not defined behaviour")


def reset_sr_res():
    return [ExprAssign(res, ExprInt(0, 7))]


def update_flag_zf(a):
    return [ExprAssign(zf, ExprCond(a, ExprInt(0, zf.size), ExprInt(1, zf.size)))]


def update_flag_nf(a):
    return [ExprAssign(nf, a.msb())]


def update_flag_pf(a):
    return [ExprAssign(pf, ExprOp('parity', a & ExprInt(0xFF, a.size)))]


def update_flag_cf_inv_zf(a):
    return [ExprAssign(cf, ExprCond(a, ExprInt(1, cf.size), ExprInt(0, cf.size)))]


def update_flag_zn_r(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    e += reset_sr_res()
    return e


def update_flag_sub_cf(a, b, c):
    return [ExprAssign(cf,
        ((((a ^ b) ^ c) ^ ((a ^ c) & (a ^ b))).msb()) ^ ExprInt(1, 1))]


def update_flag_add_cf(a, b, c):
    return [ExprAssign(cf, (((a ^ b) ^ c) ^ ((a ^ c) & (~(a ^ b)))).msb())]


def update_flag_add_of(a, b, c):
    return [ExprAssign(of, (((a ^ c) & (~(a ^ b)))).msb())]


def update_flag_sub_of(a, b, c):
    return [ExprAssign(of, (((a ^ c) & (a ^ b))).msb())]


def mng_autoinc(a, b, size):
    e = []
    if not (isinstance(a, ExprOp) and a.op == "autoinc"):
        return e, a, b

    a_r = a.args[0]
    e.append(ExprAssign(a_r, a_r + ExprInt(size / 8, a_r.size)))
    a = ExprMem(a_r, size)
    if isinstance(b, ExprMem) and a_r in b.arg:
        b = ExprMem(b.arg + ExprInt(size / 8, 16), b.size)
    return e, a, b

# Mnemonics


def mov_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    if isinstance(b, ExprMem):
        b = ExprMem(b.arg, 8)
        a = a[:8]
    else:
        a = a[:8].zeroExtend(16)
    e.append(ExprAssign(b, a))
    return e, []


def mov_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    e.append(ExprAssign(b, a))
    if b == ir.pc:
        e.append(ExprAssign(ir.IRDst, a))
    return e, []


def and_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    c = a[:8] & b[:8]
    e.append(ExprAssign(b, c.zeroExtend(16)))
    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e += [ExprAssign(of, ExprInt(0, 1))]
    return e, []


def and_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = a & b
    e.append(ExprAssign(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e += [ExprAssign(of, ExprInt(0, 1))]
    return e, []


def bic_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    c = (a[:8] ^ ExprInt(0xff, 8)) & b[:8]
    c = c.zeroExtend(b.size)
    e.append(ExprAssign(b, c))
    return e, []


def bic_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = (a ^ ExprInt(0xffff, 16)) & b
    e.append(ExprAssign(b, c))
    return e, []


def bis_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = a | b
    e.append(ExprAssign(b, c))
    return e, []


def bit_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = a & b
    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e.append(ExprAssign(of, ExprInt(0, 1)))
    return e, []

"""
def sub_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    c = b - a
    e.append(ExprAssign(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_sub_cf(b, a, c)
    return None, e, []
"""


def sub_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = b - a
    e.append(ExprAssign(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_sub_cf(b, a, c)
    # micrcorruption
    # e += update_flag_sub_of(a, b, c)
    # e += update_flag_sub_of(b, a, c)
    return e, []


def add_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    if isinstance(b, ExprMem):
        b = ExprMem(b.arg, 8)
    else:
        b = b[:8]
    a = a[:8]
    c = b + a
    e.append(ExprAssign(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_add_cf(a, b, c)
    e += update_flag_add_of(a, b, c)
    return e, []


def add_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = b + a
    e.append(ExprAssign(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_add_cf(a, b, c)
    e += update_flag_add_of(a, b, c)
    return e, []


def dadd_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    # TODO: microcorruption no carryflag
    c = ExprOp("bcdadd", b, a)  # +zeroExtend(cf, 16))

    e.append(ExprAssign(b, c))
    # e += update_flag_zn_r(c)

    # micrcorruption
    e += update_flag_zf(a)
    # e += update_flag_nf(a)
    e += reset_sr_res()

    e.append(ExprAssign(cf, ExprOp("bcdadd_cf", b, a)))  # +zeroExtend(cf, 16))))

    # of : undefined
    return e, []


def xor_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = b ^ a
    e.append(ExprAssign(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e.append(ExprAssign(of, b.msb() & a.msb()))
    return e, []


def push_w(ir, instr, a):
    e = []
    e.append(ExprAssign(ExprMem(SP - ExprInt(2, 16), 16), a))
    e.append(ExprAssign(SP, SP - ExprInt(2, 16)))
    return e, []


def call(ir, instr, a):
    e, a, dummy = mng_autoinc(a, None, 16)

    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 16)

    e.append(ExprAssign(ExprMem(SP - ExprInt(2, 16), 16), loc_next_expr))
    e.append(ExprAssign(SP, SP - ExprInt(2, 16)))
    e.append(ExprAssign(PC, a))
    e.append(ExprAssign(ir.IRDst, a))
    return e, []


def swpb(ir, instr, a):
    e = []
    x, y = a[:8], a[8:16]
    e.append(ExprAssign(a, ExprCompose(y, x)))
    return e, []


def cmp_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = b - a
    e += update_flag_zn_r(c)
    e += update_flag_sub_cf(b, a, c)
    e += update_flag_sub_of(b, a, c)
    return e, []


def cmp_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    c = b[:8] - a[:8]
    e += update_flag_zn_r(c)
    e += update_flag_sub_cf(b[:8], a[:8], c)
    e += update_flag_sub_of(b[:8], a[:8], c)
    return e, []


def jz(ir, instr, a):
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 16)
    e = []
    e.append(ExprAssign(PC, ExprCond(zf, a, loc_next_expr)))
    e.append(ExprAssign(ir.IRDst, ExprCond(zf, a, loc_next_expr)))
    return e, []


def jnz(ir, instr, a):
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 16)
    e = []
    e.append(ExprAssign(PC, ExprCond(zf, loc_next_expr, a)))
    e.append(ExprAssign(ir.IRDst, ExprCond(zf, loc_next_expr, a)))
    return e, []


def jl(ir, instr, a):
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 16)
    e = []
    e.append(ExprAssign(PC, ExprCond(nf ^ of, a, loc_next_expr)))
    e.append(ExprAssign(ir.IRDst, ExprCond(nf ^ of, a, loc_next_expr)))
    return e, []


def jc(ir, instr, a):
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 16)
    e = []
    e.append(ExprAssign(PC, ExprCond(cf, a, loc_next_expr)))
    e.append(ExprAssign(ir.IRDst, ExprCond(cf, a, loc_next_expr)))
    return e, []


def jnc(ir, instr, a):
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 16)
    e = []
    e.append(ExprAssign(PC, ExprCond(cf, loc_next_expr, a)))
    e.append(ExprAssign(ir.IRDst, ExprCond(cf, loc_next_expr, a)))
    return e, []


def jge(ir, instr, a):
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = ExprLoc(loc_next, 16)
    e = []
    e.append(ExprAssign(PC, ExprCond(nf ^ of, loc_next_expr, a)))
    e.append(ExprAssign(ir.IRDst, ExprCond(nf ^ of, loc_next_expr, a)))
    return e, []


def jmp(ir, instr, a):
    e = []
    e.append(ExprAssign(PC, a))
    e.append(ExprAssign(ir.IRDst, a))
    return e, []


def rrc_w(ir, instr, a):
    e = []
    c = ExprCompose(a[1:16], cf)
    e.append(ExprAssign(a, c))
    e.append(ExprAssign(cf, a[:1]))
    # e += update_flag_zn_r(c)

    # micrcorruption
    e += update_flag_zf(a)
    # e += update_flag_nf(a)
    e += reset_sr_res()

    e.append(ExprAssign(of, ExprInt(0, 1)))
    return e, []


def rra_w(ir, instr, a):
    e = []
    c = ExprCompose(a[1:16], a[15:16])
    e.append(ExprAssign(a, c))
    # TODO: error in disasm microcorruption?
    # e.append(ExprAssign(cf, a[:1]))
    # e += update_flag_zn_r(c)

    # micrcorruption
    e += update_flag_zf(a)
    # e += update_flag_nf(a)
    e += reset_sr_res()

    e.append(ExprAssign(of, ExprInt(0, 1)))
    return e, []


def sxt(ir, instr, a):
    e = []
    c = a[:8].signExtend(16)
    e.append(ExprAssign(a, c))

    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e.append(ExprAssign(of, ExprInt(0, 1)))

    return e, []

mnemo_func = {
    "mov.b": mov_b,
    "mov.w": mov_w,
    "and.b": and_b,
    "and.w": and_w,
    "bic.b": bic_b,
    "bic.w": bic_w,
    "bis.w": bis_w,
    "bit.w": bit_w,
    "sub.w": sub_w,
    "add.b": add_b,
    "add.w": add_w,
    "push.w": push_w,
    "dadd.w": dadd_w,
    "xor.w": xor_w,
    "call": call,
    "swpb": swpb,
    "cmp.w": cmp_w,
    "cmp.b": cmp_b,
    "jz": jz,
    "jnz": jnz,
    "jl": jl,
    "jc": jc,
    "jnc": jnc,
    "jmp": jmp,
    "jge": jge,
    "rrc.w": rrc_w,
    "rra.w": rra_w,
    "sxt": sxt,
}


composed_sr = ExprCompose(cf, zf, nf, gie, cpuoff, osc, scg0, scg1, of, res)


def ComposeExprAssign(dst, src):
    e = []
    for start, arg in dst.iter_args():
        e.append(ExprAssign(arg, src[start:start+arg.size]))
    return e


class ir_msp430(IntermediateRepresentation):

    def __init__(self, loc_db=None):
        IntermediateRepresentation.__init__(self, mn_msp430, None, loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 16)
        self.addrsize = 16

    def mod_pc(self, instr, instr_ir, extra_ir):
        pass

    def get_ir(self, instr):
        args = instr.args
        instr_ir, extra_ir = mnemo_func[instr.name](self, instr, *args)
        self.mod_sr(instr, instr_ir, extra_ir)

        return instr_ir, extra_ir

    def mod_sr(self, instr, instr_ir, extra_ir):
        for i, x in enumerate(instr_ir):
            x = ExprAssign(x.dst, x.src.replace_expr({SR: composed_sr}))
            instr_ir[i] = x
            if x.dst != SR:
                continue
            xx = ComposeExprAssign(composed_sr, x.src)
            instr_ir[i:i+1] = xx
        for i, x in enumerate(instr_ir):
            x = ExprAssign(x.dst, x.src.replace_expr(
                {self.pc: ExprInt(instr.offset + instr.l, 16)}))
            instr_ir[i] = x

        if extra_ir:
            raise NotImplementedError('not fully functional')
