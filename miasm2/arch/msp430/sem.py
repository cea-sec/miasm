#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.arch.msp430.regs import *
from miasm2.arch.msp430.arch import mn_msp430
from miasm2.ir.ir import ir
from regs import *


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
    return [ExprAff(res, ExprInt_fromsize(7, 0))]


def update_flag_zf(a):
    return [ExprAff(zf, ExprCond(a, ExprInt_from(zf, 0), ExprInt_from(zf, 1)))]


def update_flag_nf(a):
    return [ExprAff(nf, a.msb())]


def update_flag_pf(a):
    return [ExprAff(pf, ExprOp('parity', a & ExprInt_from(a, 0xFF)))]


def update_flag_cf_inv_zf(a):
    return [ExprAff(cf, ExprCond(a, ExprInt_from(cf, 1), ExprInt_from(cf, 0)))]


def update_flag_zn_r(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    e += reset_sr_res()
    return e


def update_flag_sub_cf(a, b, c):
    return [ExprAff(cf,
        ((((a ^ b) ^ c) ^ ((a ^ c) & (a ^ b))).msb()) ^ ExprInt1(1))]


def update_flag_add_cf(a, b, c):
    return [ExprAff(cf, (((a ^ b) ^ c) ^ ((a ^ c) & (~(a ^ b)))).msb())]


def update_flag_add_of(a, b, c):
    return [ExprAff(of, (((a ^ c) & (~(a ^ b)))).msb())]


def update_flag_sub_of(a, b, c):
    return [ExprAff(of, (((a ^ c) & (a ^ b))).msb())]


def mng_autoinc(a, b, size):
    e = []
    if not (isinstance(a, ExprOp) and a.op == "autoinc"):
        return e, a, b

    a_r = a.args[0]
    e.append(ExprAff(a_r, a_r + ExprInt_from(a_r, size / 8)))
    a = ExprMem(a_r, size)
    if isinstance(b, ExprMem) and a_r in b.arg:
        b = ExprMem(b.arg + ExprInt16(size / 8), b.size)
    return e, a, b

# Mnemonics


def mov_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    if isinstance(b, ExprMem):
        b = ExprMem(b.arg, 8)
        a = a[:8]
    else:
        a = a[:8].zeroExtend(16)
    e.append(ExprAff(b, a))
    return e, []


def mov_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    e.append(ExprAff(b, a))
    if b == ir.pc:
        e.append(ExprAff(ir.IRDst, a))
    return e, []


def and_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    c = a[:8] & b[:8]
    e.append(ExprAff(b, c.zeroExtend(16)))
    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e += [ExprAff(of, ExprInt1(0))]
    return e, []


def and_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = a & b
    e.append(ExprAff(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e += [ExprAff(of, ExprInt1(0))]
    return e, []


def bic_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    c = (a[:8] ^ ExprInt8(0xff)) & b[:8]
    c = c.zeroExtend(b.size)
    e.append(ExprAff(b, c))
    return e, []


def bic_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = (a ^ ExprInt16(0xffff)) & b
    e.append(ExprAff(b, c))
    return e, []


def bis_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = a | b
    e.append(ExprAff(b, c))
    return e, []


def bit_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = a & b
    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e.append(ExprAff(of, ExprInt1(0)))
    return e, []

"""
def sub_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    c = b - a
    e.append(ExprAff(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_sub_cf(b, a, c)
    return None, e, []
"""


def sub_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = b - a
    e.append(ExprAff(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_sub_cf(b, a, c)
    # micrcorruption
    # e += update_flag_sub_of(a, b, c)
    # e += update_flag_sub_of(b, a, c)
    return e, []


def add_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = b + a
    e.append(ExprAff(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_add_cf(a, b, c)
    e += update_flag_add_of(a, b, c)
    return e, []


def dadd_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    # TODO: microcorruption no carryflag
    c = ExprOp("bcdadd", b, a)  # +zeroExtend(cf, 16))

    e.append(ExprAff(b, c))
    # e += update_flag_zn_r(c)

    # micrcorruption
    e += update_flag_zf(a)
    # e += update_flag_nf(a)
    e += reset_sr_res()

    e.append(ExprAff(cf, ExprOp("bcdadd_cf", b, a)))  # +zeroExtend(cf, 16))))

    # of : undefined
    return e, []


def xor_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = b ^ a
    e.append(ExprAff(b, c))
    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e.append(ExprAff(of, b.msb() & a.msb()))
    return e, []


def push_w(ir, instr, a):
    e = []
    e.append(ExprAff(ExprMem(SP - ExprInt16(2), 16), a))
    e.append(ExprAff(SP, SP - ExprInt16(2)))
    return e, []


def call(ir, instr, a):
    e, a, dummy = mng_autoinc(a, None, 16)
    n = ExprId(ir.get_next_label(instr), 16)
    e.append(ExprAff(ExprMem(SP - ExprInt16(2), 16), n))
    e.append(ExprAff(SP, SP - ExprInt16(2)))
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []


def swpb(ir, instr, a):
    e = []
    x, y = a[:8], a[8:16]
    e.append(ExprAff(a, ExprCompose([(y, 0, 8),
                                     (x, 8, 16)])))
    return e, []


def cmp_w(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 16)
    c = b - a
    e += update_flag_zn_r(c)
    e += update_flag_sub_cf(a, b, c)
    e += update_flag_sub_of(a, b, c)
    return e, []


def cmp_b(ir, instr, a, b):
    e, a, b = mng_autoinc(a, b, 8)
    c = b[:8] - a[:8]
    e += update_flag_zn_r(c)
    e += update_flag_sub_cf(a[:8], b[:8], c)
    e += update_flag_sub_of(a[:8], b[:8], c)
    return e, []


def jz(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 16)
    e = []
    e.append(ExprAff(PC, ExprCond(zf, a, n)))
    e.append(ExprAff(ir.IRDst, ExprCond(zf, a, n)))
    return e, []


def jnz(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 16)
    e = []
    e.append(ExprAff(PC, ExprCond(zf, n, a)))
    e.append(ExprAff(ir.IRDst, ExprCond(zf, n, a)))
    return e, []


def jl(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 16)
    e = []
    e.append(ExprAff(PC, ExprCond(nf ^ of, a, n)))
    e.append(ExprAff(ir.IRDst, ExprCond(nf ^ of, a, n)))
    return e, []


def jc(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 16)
    e = []
    e.append(ExprAff(PC, ExprCond(cf, a, n)))
    e.append(ExprAff(ir.IRDst, ExprCond(cf, a, n)))
    return e, []


def jnc(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 16)
    e = []
    e.append(ExprAff(PC, ExprCond(cf, n, a)))
    e.append(ExprAff(ir.IRDst, ExprCond(cf, n, a)))
    return e, []


def jge(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 16)
    e = []
    e.append(ExprAff(PC, ExprCond(nf ^ of, n, a)))
    e.append(ExprAff(ir.IRDst, ExprCond(nf ^ of, n, a)))
    return e, []


def jmp(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []


def rrc_w(ir, instr, a):
    e = []
    c = ExprCompose([(a[1:16], 0, 15),
                   (cf, 15, 16)])
    e.append(ExprAff(a, c))
    e.append(ExprAff(cf, a[:1]))
    # e += update_flag_zn_r(c)

    # micrcorruption
    e += update_flag_zf(a)
    # e += update_flag_nf(a)
    e += reset_sr_res()

    e.append(ExprAff(of, ExprInt1(0)))
    return e, []


def rra_w(ir, instr, a):
    e = []
    c = ExprCompose([(a[1:16], 0, 15),
                   (a[15:16], 15, 16)])
    e.append(ExprAff(a, c))
    # TODO: error in disasm microcorruption?
    # e.append(ExprAff(cf, a[:1]))
    # e += update_flag_zn_r(c)

    # micrcorruption
    e += update_flag_zf(a)
    # e += update_flag_nf(a)
    e += reset_sr_res()

    e.append(ExprAff(of, ExprInt1(0)))
    return e, []


def sxt(ir, instr, a):
    e = []
    c = a[:8].signExtend(16)
    e.append(ExprAff(a, c))

    e += update_flag_zn_r(c)
    e += update_flag_cf_inv_zf(c)
    e.append(ExprAff(of, ExprInt1(0)))

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


composed_sr = ExprCompose([
    (cf,   0,  1),
    (zf,   1,  2),
    (nf,   2,  3),
    (gie,  3,  4),
    (cpuoff,  4,  5),
    (osc,  5,  6),
    (scg0, 6,  7),
    (scg1, 7,  8),
    (of, 8,  9),
    (res, 9, 16),
])


def ComposeExprAff(dst, src):
    e = []
    for x, start, stop in dst.args:
        e.append(ExprAff(x, src[start:stop]))
    return e


class ir_msp430(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_msp430, None, symbol_pool)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 16)

    def mod_pc(self, instr, instr_ir, extra_ir):
        pass

    def get_ir(self, instr):
        # print instr#, args
        args = instr.args
        instr_ir, extra_ir = mnemo_func[instr.name](self, instr, *args)
        self.mod_sr(instr, instr_ir, extra_ir)

        return instr_ir, extra_ir

    def mod_sr(self, instr, instr_ir, extra_ir):
        for i, x in enumerate(instr_ir):
            x.src = x.src.replace_expr({SR: composed_sr})
            if x.dst != SR:
                continue
            xx = ComposeExprAff(composed_sr, x.src)
            instr_ir[i:i + 1] = xx
        for i, x in enumerate(instr_ir):
            x = ExprAff(x.dst, x.src.replace_expr(
                {self.pc: ExprInt16(instr.offset + instr.l)}))
            instr_ir[i] = x

        if extra_ir:
            raise NotImplementedError('not fully functional')
