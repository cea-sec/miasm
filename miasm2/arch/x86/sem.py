#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import miasm2.expression.expression as m2_expr
from miasm2.expression.simplifications import expr_simp
from miasm2.arch.x86.regs import *
from miasm2.arch.x86.arch import mn_x86, repeat_mn, replace_regs
from miasm2.expression.expression_helper import expr_cmps, expr_cmpu
from miasm2.ir.ir import ir, irbloc
import math
import struct

# interrupt with eip update after instr
EXCEPT_SOFT_BP = (1 << 1)
EXCEPT_INT_XX = (1 << 2)

EXCEPT_BREAKPOINT_INTERN = (1 << 10)

EXCEPT_NUM_UPDT_EIP = (1 << 11)
# interrupt with eip at instr
EXCEPT_UNK_MEM_AD = (1 << 12)
EXCEPT_THROW_SEH = (1 << 13)
EXCEPT_UNK_EIP = (1 << 14)
EXCEPT_ACCESS_VIOL = (1 << 14)
EXCEPT_INT_DIV_BY_ZERO = (1 << 16)
EXCEPT_PRIV_INSN = (1 << 17)
EXCEPT_ILLEGAL_INSN = (1 << 18)
EXCEPT_UNK_MNEMO = (1 << 19)


"""
http://www.emulators.com/docs/nx11_flags.htm

CF(A+B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND NOT (A XOR B)) < 0)
CF(A-B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND (A XOR B)) < 0)

OF(A+B) = ((A XOR D) AND NOT (A XOR B)) < 0
OF(A-B) = ((A XOR D) AND (A XOR B)) < 0
"""



# XXX TODO make default check against 0 or not 0 (same eq as in C)


def update_flag_zf(a):
    return [m2_expr.ExprAff(zf, m2_expr.ExprCond(a, m2_expr.ExprInt_from(zf, 0),
                                                 m2_expr.ExprInt_from(zf, 1)))]


def update_flag_nf(a):
    return [m2_expr.ExprAff(nf, a.msb())]


def update_flag_pf(a):
    return [m2_expr.ExprAff(pf,
                            m2_expr.ExprOp('parity',
                                           a & m2_expr.ExprInt_from(a, 0xFF)))]


def update_flag_af(a):
    return [m2_expr.ExprAff(af,
                            m2_expr.ExprCond((a & m2_expr.ExprInt_from(a,0x10)),
                                             m2_expr.ExprInt_from(af, 1),
                                             m2_expr.ExprInt_from(af, 0)))]


def update_flag_znp(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    e += update_flag_pf(a)
    return e


def update_flag_logic(a):
    e = []
    e += update_flag_znp(a)
    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt_from(of, 0)))
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprInt_from(cf, 0)))
    return e


def update_flag_arith(a):
    e = []
    e += update_flag_znp(a)
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
    ret = (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (~(op1 ^ op2)))).msb()
    return m2_expr.ExprAff(cf, ret)


def update_flag_add_of(op1, op2, res):
    "Compute of in @res = @op1 + @op2"
    return m2_expr.ExprAff(of, (((op1 ^ res) & (~(op1 ^ op2)))).msb())


# checked: ok for sbb add because b & c before +cf
def update_flag_sub_cf(op1, op2, res):
    "Compote CF in @res = @op1 - @op2"
    ret = (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))).msb()
    return m2_expr.ExprAff(cf, ret)


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


def set_float_cs_eip(instr):
    e = []
    # XXX TODO check float updt
    e.append(m2_expr.ExprAff(float_eip,
                             m2_expr.ExprInt_from(float_eip, instr.offset)))
    e.append(m2_expr.ExprAff(float_cs, CS))
    return e

def mem2double(arg):
    """
    Add float convertion if argument is an ExprMem
    @arg: argument to tranform
    """
    if isinstance(arg, m2_expr.ExprMem):
        if arg.size > 64:
            raise NotImplementedError('float to long')
        return m2_expr.ExprOp('mem_%.2d_to_double' % arg.size, arg)
    else:
        return arg

def float_implicit_st0(arg1, arg2):
    """
    Generate full float operators if one argument is implicit (float_st0)
    """
    if arg2 is None:
        arg2 = arg1
        arg1 = float_st0
    return arg1, arg2


def gen_jcc(ir, instr, cond, dst, jmp_if):
    """
    Macro to generate jcc semantic
    @ir: ir instance
    @instr: instruction
    @cond: condtion of the jcc
    @dst: the dstination if jcc is taken
    @jmp_if: jump if/notif cond
    """

    e = []
    meip = mRIP[instr.mode]
    next_lbl = m2_expr.ExprId(ir.get_next_label(instr), dst.size)
    if jmp_if:
        dstA, dstB = dst, next_lbl
    else:
        dstA, dstB = next_lbl, dst
    mn_dst = m2_expr.ExprCond(cond,
                              dstA.zeroExtend(instr.mode),
                              dstB.zeroExtend(instr.mode))
    e.append(m2_expr.ExprAff(meip, mn_dst))
    e.append(m2_expr.ExprAff(ir.IRDst, mn_dst))
    return e, []


def gen_fcmov(ir, instr, cond, arg1, arg2, mov_if):
    """Generate fcmov
    @ir: ir instance
    @instr: instruction instance
    @cond: condition
    @mov_if: invert condition if False"""

    lbl_do = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)
    if mov_if:
        dstA, dstB = lbl_do, lbl_skip
    else:
        dstA, dstB = lbl_skip, lbl_do
    e = []
    e_do, extra_irs = [m2_expr.ExprAff(arg1, arg2)], []
    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
    e.append(m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(cond, dstA, dstB)))
    return e, [irbloc(lbl_do.name, [e_do])]


def gen_cmov(ir, instr, cond, arg1, arg2, mov_if):
    """Generate cmov
    @ir: ir instance
    @instr: instruction instance
    @cond: condition
    @mov_if: invert condition if False"""

    lbl_do = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)
    if mov_if:
        dstA, dstB = lbl_do, lbl_skip
    else:
        dstA, dstB = lbl_skip, lbl_do
    e = []
    e_do, extra_irs = mov(ir, instr, arg1, arg2)
    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
    e.append(m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(cond, dstA, dstB)))
    return e, [irbloc(lbl_do.name, [e_do])]


def mov(ir, instr, a, b):
    if a in [ES, CS, SS, DS, FS, GS]:
        b = b[:a.size]
    if b in [ES, CS, SS, DS, FS, GS]:
        b = b.zeroExtend(a.size)
    e = [m2_expr.ExprAff(a, b)]
    return e, []


def xchg(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, b))
    e.append(m2_expr.ExprAff(b, a))
    return e, []


def movzx(ir, instr, a, b):
    e = [m2_expr.ExprAff(a, b.zeroExtend(a.size))]
    return e, []

def movsx(ir, instr, a, b):
    e = [m2_expr.ExprAff(a, b.signExtend(a.size))]
    return e, []


def lea(ir, instr, a, b):
    src = b.arg
    if src.size > a.size:
        src = src[:a.size]
    e = [m2_expr.ExprAff(a, src.zeroExtend(a.size))]
    return e, []


def add(ir, instr, a, b):
    e = []
    c = a + b
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_add(a, b, c)
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def xadd(ir, instr, a, b):
    e = []
    c = a + b
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_add(b, a, c)
    e.append(m2_expr.ExprAff(b, a))
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def adc(ir, instr, a, b):
    e = []
    c = a + (b + m2_expr.ExprCompose([(m2_expr.ExprInt(0, a.size - 1),
                                       1, a.size),
                              (cf, 0, 1)]))
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_add(a, b, c)
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def sub(ir, instr, a, b):
    e = []
    c = a - b
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_sub(a, b, c)
    e.append(m2_expr.ExprAff(a, c))
    return e, []

# a-(b+cf)


def sbb(ir, instr, a, b):
    e = []
    c = a - (b + m2_expr.ExprCompose([(m2_expr.ExprInt(0, a.size - 1),
                                       1, a.size),
                              (cf, 0, 1)]))
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_sub(a, b, c)
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def neg(ir, instr, b):
    e = []
    a = m2_expr.ExprInt_from(b, 0)

    c = a - b
    e += update_flag_arith(c)
    e += update_flag_sub(a, b, c)
    e += update_flag_af(c)
    e.append(m2_expr.ExprAff(b, c))
    return e, []


def l_not(ir, instr, b):
    e = []
    c = ~b
    e.append(m2_expr.ExprAff(b, c))
    return e, []


def l_cmp(ir, instr, a, b):
    e = []
    c = a - b
    e += update_flag_arith(c)
    e += update_flag_sub(a, b, c)
    e += update_flag_af(c)
    return e, []


def xor(ir, instr, a, b):
    e = []
    c = a ^ b
    e += update_flag_logic(c)
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def pxor(ir, instr, a, b):
    e = []
    c = a ^ b
    e.append(m2_expr.ExprAff(a, c))
    return e, []

def l_or(ir, instr, a, b):
    e = []
    c = a | b
    e += update_flag_logic(c)
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def l_and(ir, instr, a, b):
    e = []
    c = a & b
    e += update_flag_logic(c)
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def l_test(ir, instr, a, b):
    e = []
    c = a & b
    e += update_flag_logic(c)
    return e, []



def get_shift(a, b):
    # b.size must match a
    b = b.zeroExtend(a.size)
    if a.size == 64:
        shift = b & m2_expr.ExprInt_from(b, 0x3f)
    else:
        shift = b & m2_expr.ExprInt_from(b, 0x1f)
    shift = expr_simp(shift)
    return shift


def l_rol(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = m2_expr.ExprOp('<<<', a, shifter)

    new_cf = c[:1]
    e.append(m2_expr.ExprAff(cf, new_cf))
    # hack (only valid if b=1)
    e.append(m2_expr.ExprAff(of, c.msb() ^ new_cf))
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def l_ror(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = m2_expr.ExprOp('>>>', a, shifter)

    e.append(m2_expr.ExprAff(cf, c.msb()))
    # hack (only valid if b=1): when count == 1: a = msb-1(dest)
    e.append(m2_expr.ExprAff(of, (c ^ a).msb()))
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def rcl(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = m2_expr.ExprOp('<<<c_rez', a, shifter, cf.zeroExtend(a.size))
    new_cf = m2_expr.ExprOp('<<<c_cf', a, shifter, cf.zeroExtend(a.size))[:1]

    e.append(m2_expr.ExprAff(cf, new_cf))
    # hack (only valid if b=1)
    e.append(m2_expr.ExprAff(of, c.msb() ^ new_cf))
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def rcr(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = m2_expr.ExprOp('>>>c_rez', a, shifter, cf.zeroExtend(a.size))
    new_cf = m2_expr.ExprOp('>>>c_cf', a, shifter, cf.zeroExtend(a.size))[:1]

    e.append(m2_expr.ExprAff(cf, new_cf))
    # hack (only valid if b=1)
    e.append(m2_expr.ExprAff(of, (a ^ c).msb()))
    e.append(m2_expr.ExprAff(a, c))

    return e, []


def sar(ir, instr, a, b):

    shifter = get_shift(a, b)
    c = m2_expr.ExprOp('a>>', a, shifter)

    lbl_do = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)

    new_cf = m2_expr.ExprOp('a>>', a,(shifter - m2_expr.ExprInt_from(a, 1)))[:1]

    e_do = [
        m2_expr.ExprAff(cf, new_cf),
        m2_expr.ExprAff(of, m2_expr.ExprInt_from(of, 0)),
        m2_expr.ExprAff(a, c),
    ]

    e_do += update_flag_znp(c)

    # dont generate conditional shifter on constant
    if isinstance(shifter, m2_expr.ExprInt):
        if int(shifter.arg) != 0:
            return e_do, []
        else:
            return [], []

    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))

    e = []
    e.append(m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(shifter, lbl_do,
                                                        lbl_skip)))
    return e, [irbloc(lbl_do.name, [e_do])]


def shr(ir, instr, a, b):

    shifter = get_shift(a, b)
    c = m2_expr.ExprOp('>>', a, shifter)

    lbl_do = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)

    new_cf = m2_expr.ExprOp('>>', a, (shifter - m2_expr.ExprInt_from(a, 1)))[:1]

    e_do = [
        m2_expr.ExprAff(cf, new_cf),
        m2_expr.ExprAff(of, m2_expr.ExprInt_from(of, 0)),
        m2_expr.ExprAff(a, c),
    ]

    e_do += update_flag_znp(c)

    # dont generate conditional shifter on constant
    if isinstance(shifter, m2_expr.ExprInt):
        if int(shifter.arg) != 0:
            return e_do, []
        else:
            return [], []

    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))

    e = []
    e.append(m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(shifter, lbl_do,
                                                        lbl_skip)))
    return e, [irbloc(lbl_do.name, [e_do])]


def shrd_cl(ir, instr, a, b):
    e = []
    opmode, admode = s, instr.v_admode()
    shifter = mRCX[instr.mode][:8].zeroExtend(a.size)
    shifter &= m2_expr.ExprInt_from(a, 0x1f)
    c = (a >> shifter) | (b << (m2_expr.ExprInt_from(a, a.size) - shifter))
    new_cf = (a >> (shifter - m2_expr.ExprInt_from(a, 1)))[:1]
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e.append(m2_expr.ExprAff(of, a.msb()))
    e += update_flag_znp(c)
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def shrd(ir, instr, a, b, c):
    e = []
    shifter = get_shift(a, c)

    d = (a >> shifter) | (b << (m2_expr.ExprInt_from(a, a.size) - shifter))
    new_cf = (a >> (shifter - m2_expr.ExprInt_from(a, 1)))[:1]
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e.append(m2_expr.ExprAff(of, a.msb()))
    e += update_flag_znp(d)
    e.append(m2_expr.ExprAff(a, d))
    return e, []


def sal(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = m2_expr.ExprOp('a<<', a, shifter)
    new_cf = (a >> (m2_expr.ExprInt_from(a, a.size) - shifter))[:1]
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e += update_flag_znp(c)
    e.append(m2_expr.ExprAff(of, c.msb() ^ new_cf))
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def shl(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = a << shifter
    new_cf = (a >> (m2_expr.ExprInt_from(a, a.size) - shifter))[:1]
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e += update_flag_znp(c)
    e.append(m2_expr.ExprAff(of, c.msb() ^ new_cf))
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def shld_cl(ir, instr, a, b):
    return shld(ir, instr, a, b, ecx)


def shld(ir, instr, a, b, c):
    e = []
    shifter = c.zeroExtend(a.size) & m2_expr.ExprInt_from(a, 0x1f)
    c = m2_expr.ExprOp('|',
               a << shifter,
               b >> (m2_expr.ExprInt_from(a, a.size) - shifter)
               )

    new_cf = (a >> (m2_expr.ExprInt_from(a, a.size) - shifter))[:1]
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    # XXX todo: don't update flag if shifter is 0
    e += update_flag_znp(c)
    e.append(m2_expr.ExprAff(of, c.msb() ^ new_cf))
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(shifter,
                                 c,
                                 a)))
    return e, []


# XXX todo ###
def cmc(ir, instr):
    e = [m2_expr.ExprAff(cf, m2_expr.ExprCond(cf, m2_expr.ExprInt_from(cf, 0),
                                              m2_expr.ExprInt_from(cf, 1)))]
    return e, []


def clc(ir, instr):
    e = [m2_expr.ExprAff(cf, m2_expr.ExprInt_from(cf, 0))]
    return e, []


def stc(ir, instr):
    e = [m2_expr.ExprAff(cf, m2_expr.ExprInt_from(cf, 1))]
    return e, []


def cld(ir, instr):
    e = [m2_expr.ExprAff(df, m2_expr.ExprInt_from(df, 0))]
    return e, []


def std(ir, instr):
    e = [m2_expr.ExprAff(df, m2_expr.ExprInt_from(df, 1))]
    return e, []


def cli(ir, instr):
    e = [m2_expr.ExprAff(i_f, m2_expr.ExprInt_from(i_f, 0))]
    return e, []


def sti(ir, instr):
    e = [m2_expr.ExprAff(exception_flags, m2_expr.ExprInt32(EXCEPT_PRIV_INSN))]
    e = []  # XXX TODO HACK
    return e, []


def inc(ir, instr, a):
    e = []
    b = m2_expr.ExprInt_from(a, 1)
    c = a + b
    e += update_flag_arith(c)
    e += update_flag_af(c)

    e.append(update_flag_add_of(a, b, c))
    e.append(m2_expr.ExprAff(a, c))
    return e, []

def dec(ir, instr, a):
    e = []
    b = m2_expr.ExprInt_from(a, -1)
    c = a + b
    e += update_flag_arith(c)
    e += update_flag_af(c)

    e.append(update_flag_add_of(a, b, c))
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def push_gen(ir, instr, a, size):
    e = []
    if not size in [16, 32, 64]:
        raise ValueError('bad size stacker!')
    if a.size < size:
        a = a.zeroExtend(size)
    elif a.size == size:
        pass
    else:
        raise ValueError('strange arg size')

    sp = mRSP[instr.mode]
    new_sp = sp - m2_expr.ExprInt_from(sp, size / 8)
    e.append(m2_expr.ExprAff(sp, new_sp))
    if ir.do_stk_segm:
        new_sp = m2_expr.ExprOp('segm', SS, new_sp)
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(new_sp, size), a))
    return e, []

def push(ir, instr, a):
    return push_gen(ir, instr, a, instr.mode)

def pushw(ir, instr, a):
    return push_gen(ir, instr, a, 16)


def pop_gen(ir, instr, a, size):
    e = []
    if not size in [16, 32, 64]:
        raise ValueError('bad size stacker!')

    sp = mRSP[instr.mode]
    new_sp = sp + m2_expr.ExprInt_from(sp, size / 8)
    # don't generate ESP incrementation on POP ESP
    if a != ir.sp:
        e.append(m2_expr.ExprAff(sp, new_sp))
    # XXX FIX XXX for pop [esp]
    if isinstance(a, m2_expr.ExprMem):
        a = a.replace_expr({sp: new_sp})
    c = sp
    if ir.do_stk_segm:
        c = m2_expr.ExprOp('segm', SS, c)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprMem(c, a.size)))
    return e, []

def pop(ir, instr, a):
    return pop_gen(ir, instr, a, instr.mode)

def popw(ir, instr, a):
    return pop_gen(ir, instr, a, 16)


def sete(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(zf, m2_expr.ExprInt_from(a, 1),
                                                 m2_expr.ExprInt_from(a, 0))))
    return e, []


def setnz(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(zf, m2_expr.ExprInt_from(a, 0),
                                                 m2_expr.ExprInt_from(a, 1))))
    return e, []


def setl(ir, instr, a):
    e = []
    e.append(
        m2_expr.ExprAff(a, m2_expr.ExprCond(nf - of, m2_expr.ExprInt_from(a, 1),
                                            m2_expr.ExprInt_from(a, 0))))
    return e, []


def setg(ir, instr, a):
    e = []
    a0 = m2_expr.ExprInt_from(a, 0)
    a1 = m2_expr.ExprInt_from(a, 1)
    ret = m2_expr.ExprCond(zf, a0, a1) & m2_expr.ExprCond(nf - of, a0, a1)
    e.append(m2_expr.ExprAff(a, ret))
    return e, []


def setge(ir, instr, a):
    e = []
    e.append(
        m2_expr.ExprAff(a, m2_expr.ExprCond(nf - of, m2_expr.ExprInt_from(a, 0),
                                            m2_expr.ExprInt_from(a, 1))))
    return e, []


def seta(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(cf | zf,
                                 m2_expr.ExprInt_from(a, 0),
                                 m2_expr.ExprInt_from(a, 1))))

    return e, []


def setae(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(cf, m2_expr.ExprInt_from(a, 0),
                                                 m2_expr.ExprInt_from(a, 1))))
    return e, []


def setb(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(cf, m2_expr.ExprInt_from(a, 1),
                                                 m2_expr.ExprInt_from(a, 0))))
    return e, []


def setbe(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(cf | zf,
                                 m2_expr.ExprInt_from(a, 1),
                                 m2_expr.ExprInt_from(a, 0)))
             )
    return e, []


def setns(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(nf, m2_expr.ExprInt_from(a, 0),
                                                 m2_expr.ExprInt_from(a, 1))))
    return e, []


def sets(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(nf, m2_expr.ExprInt_from(a, 1),
                                                 m2_expr.ExprInt_from(a, 0))))
    return e, []


def seto(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(of, m2_expr.ExprInt_from(a, 1),
                                                 m2_expr.ExprInt_from(a, 0))))
    return e, []


def setp(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(pf, m2_expr.ExprInt_from(a, 1),
                                                 m2_expr.ExprInt_from(a, 0))))
    return e, []


def setnp(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(pf, m2_expr.ExprInt_from(a, 0),
                                                 m2_expr.ExprInt_from(a, 1))))
    return e, []


def setle(ir, instr, a):
    e = []
    a0 = m2_expr.ExprInt_from(a, 0)
    a1 = m2_expr.ExprInt_from(a, 1)
    ret = m2_expr.ExprCond(zf, a1, a0) | m2_expr.ExprCond(nf ^ of, a1, a0)
    e.append(m2_expr.ExprAff(a, ret))
    return e, []


def setna(ir, instr, a):
    e = []
    a0 = m2_expr.ExprInt_from(a, 0)
    a1 = m2_expr.ExprInt_from(a, 1)
    ret = m2_expr.ExprCond(cf, a1, a0) & m2_expr.ExprCond(zf, a1, a0)
    e.append(m2_expr.ExprAff(a, ret))
    return e, []


def setnbe(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(cf | zf,
                                 m2_expr.ExprInt_from(a, 0),
                                 m2_expr.ExprInt_from(a, 1)))
             )
    return e, []


def setno(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(of, m2_expr.ExprInt_from(a, 0),
                                                 m2_expr.ExprInt_from(a, 1))))
    return e, []


def setnb(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(cf, m2_expr.ExprInt_from(a, 0),
                                                 m2_expr.ExprInt_from(a, 1))))
    return e, []


def setalc(ir, instr):
    a = mRAX[instr.mode][0:8]
    e = []
    e.append(
        m2_expr.ExprAff(a, m2_expr.ExprCond(cf, m2_expr.ExprInt_from(a, 0xff),
                                            m2_expr.ExprInt_from(a, 0))))
    return e, []


def bswap(ir, instr, a):
    e = []
    if a.size == 16:
        c = m2_expr.ExprCompose([(a[:8],        8, 16),
                         (a[8:16],      0,  8),
                         ])
    elif a.size == 32:
        c = m2_expr.ExprCompose([(a[:8],      24, 32),
                         (a[8:16],    16, 24),
                         (a[16:24],   8, 16),
                         (a[24:32],   0, 8),
                         ])
    elif a.size == 64:
        c = m2_expr.ExprCompose([(a[:8],      56, 64),
                         (a[8:16],    48, 56),
                         (a[16:24],   40, 48),
                         (a[24:32],   32, 40),
                         (a[32:40],   24, 32),
                         (a[40:48],   16, 24),
                         (a[48:56],    8, 16),
                         (a[56:64],    0, 8),
                         ])
    else:
        raise ValueError('the size DOES matter')
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def cmps(ir, instr, size):
    lbl_cmp = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)

    s = instr.v_admode()
    a = m2_expr.ExprMem(mRDI[instr.mode][:s], size)
    b = m2_expr.ExprMem(mRSI[instr.mode][:s], size)

    e, extra = l_cmp(ir, instr, a, b)

    e0 = []
    e0.append(m2_expr.ExprAff(a.arg,
                              a.arg + m2_expr.ExprInt_from(a.arg, size / 8)))
    e0.append(m2_expr.ExprAff(b.arg,
                              b.arg + m2_expr.ExprInt_from(b.arg, size / 8)))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = irbloc(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(a.arg,
                              a.arg - m2_expr.ExprInt_from(a.arg, size / 8)))
    e1.append(m2_expr.ExprAff(b.arg,
                              b.arg - m2_expr.ExprInt_from(b.arg, size / 8)))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = irbloc(lbl_df_1.name, [e1])

    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))
    return e, [e0, e1]


def scas(ir, instr, size):
    lbl_cmp = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)

    s = instr.v_admode()
    a = m2_expr.ExprMem(mRDI[instr.mode][:s], size)

    e, extra = l_cmp(ir, instr, mRAX[instr.mode][:size], a)

    e0 = []
    e0.append(m2_expr.ExprAff(a.arg,
                              a.arg + m2_expr.ExprInt_from(a.arg, size / 8)))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = irbloc(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(a.arg,
                              a.arg - m2_expr.ExprInt_from(a.arg, size / 8)))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = irbloc(lbl_df_1.name, [e1])

    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))

    return e, [e0, e1]


def compose_eflag(s=32):
    args = []

    regs = [cf, m2_expr.ExprInt1(1), pf, m2_expr.ExprInt1(
        0), af, m2_expr.ExprInt1(0), zf, nf, tf, i_f, df, of]
    for i in xrange(len(regs)):
        args.append((regs[i], i, i + 1))

    args.append((iopl, 12, 14))

    if s == 32:
        regs = [nt, m2_expr.ExprInt1(0), rf, vm, ac, vif, vip, i_d]
    elif s == 16:
        regs = [nt, m2_expr.ExprInt1(0)]
    else:
        raise ValueError('unk size')
    for i in xrange(len(regs)):
        args.append((regs[i], i + 14, i + 15))
    if s == 32:
        args.append((m2_expr.ExprInt(0, 10), 22, 32))
    return m2_expr.ExprCompose(args)


def pushfd(ir, instr):
    return push(ir, instr, compose_eflag())

def pushfq(ir, instr):
    return push(ir, instr, compose_eflag().zeroExtend(64))

def pushfw(ir, instr):
    return pushw(ir, instr, compose_eflag(16))


def popfd(ir, instr):
    tmp = m2_expr.ExprMem(mRSP[instr.mode])
    e = []
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprSlice(tmp, 0, 1)))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprSlice(tmp, 2, 3)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprSlice(tmp, 4, 5)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprSlice(tmp, 6, 7)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprSlice(tmp, 7, 8)))
    e.append(m2_expr.ExprAff(tf, m2_expr.ExprSlice(tmp, 8, 9)))
    e.append(m2_expr.ExprAff(i_f, m2_expr.ExprSlice(tmp, 9, 10)))
    e.append(m2_expr.ExprAff(df, m2_expr.ExprSlice(tmp, 10, 11)))
    e.append(m2_expr.ExprAff(of, m2_expr.ExprSlice(tmp, 11, 12)))
    e.append(m2_expr.ExprAff(iopl, m2_expr.ExprSlice(tmp, 12, 14)))
    e.append(m2_expr.ExprAff(nt, m2_expr.ExprSlice(tmp, 14, 15)))
    e.append(m2_expr.ExprAff(rf, m2_expr.ExprSlice(tmp, 16, 17)))
    e.append(m2_expr.ExprAff(vm, m2_expr.ExprSlice(tmp, 17, 18)))
    e.append(m2_expr.ExprAff(ac, m2_expr.ExprSlice(tmp, 18, 19)))
    e.append(m2_expr.ExprAff(vif, m2_expr.ExprSlice(tmp, 19, 20)))
    e.append(m2_expr.ExprAff(vip, m2_expr.ExprSlice(tmp, 20, 21)))
    e.append(m2_expr.ExprAff(i_d, m2_expr.ExprSlice(tmp, 21, 22)))
    e.append(m2_expr.ExprAff(mRSP[instr.mode],
                             mRSP[instr.mode] + m2_expr.ExprInt_from(mRSP[instr.mode], instr.mode/8)))
    e.append(m2_expr.ExprAff(exception_flags,
                     m2_expr.ExprCond(m2_expr.ExprSlice(tmp, 8, 9),
                              m2_expr.ExprInt32(EXCEPT_SOFT_BP),
                              exception_flags
                              )
                     )
             )
    return e, []


def popfw(ir, instr):
    tmp = m2_expr.ExprMem(mRSP[instr.mode])
    e = []
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprSlice(tmp, 0, 1)))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprSlice(tmp, 2, 3)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprSlice(tmp, 4, 5)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprSlice(tmp, 6, 7)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprSlice(tmp, 7, 8)))
    e.append(m2_expr.ExprAff(tf, m2_expr.ExprSlice(tmp, 8, 9)))
    e.append(m2_expr.ExprAff(i_f, m2_expr.ExprSlice(tmp, 9, 10)))
    e.append(m2_expr.ExprAff(df, m2_expr.ExprSlice(tmp, 10, 11)))
    e.append(m2_expr.ExprAff(of, m2_expr.ExprSlice(tmp, 11, 12)))
    e.append(m2_expr.ExprAff(iopl, m2_expr.ExprSlice(tmp, 12, 14)))
    e.append(m2_expr.ExprAff(nt, m2_expr.ExprSlice(tmp, 14, 15)))
    e.append(m2_expr.ExprAff(mRSP[instr.mode], mRSP[instr.mode] + m2_expr.ExprInt(2, mRSP[instr.mode].size)))
    return e, []


def pushad(ir, instr):
    e = []
    s = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    if not s in [16, 32, 64]:
        raise ValueError('bad size stacker!')

    regs = [
        mRAX[instr.mode][:s], mRCX[instr.mode][
            :s], mRDX[instr.mode][:s], mRBX[instr.mode][:s],
        mRSP[instr.mode][:s], mRBP[instr.mode][:s],
        mRSI[instr.mode][:s], mRDI[instr.mode][:s]]

    for i in xrange(len(regs)):
        c = mRSP[instr.mode][:s] + m2_expr.ExprInt(-(s / 8) * (i + 1), s)
        e.append(m2_expr.ExprAff(m2_expr.ExprMem(c, s), regs[i]))
    e.append(m2_expr.ExprAff(mRSP[instr.mode][:s], c))
    return e, []


def popad(ir, instr):
    e = []
    s = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    if not s in [16, 32, 64]:
        raise ValueError('bad size stacker!')
    regs = [
        mRAX[instr.mode][:s], mRCX[instr.mode][
            :s], mRDX[instr.mode][:s], mRBX[instr.mode][:s],
        mRSP[instr.mode][:s], mRBP[instr.mode][:s],
        mRSI[instr.mode][:s], mRDI[instr.mode][:s]]
    myesp = mRSP[instr.mode][:s]
    regs.reverse()
    for i in xrange(len(regs)):
        if regs[i] == myesp:
            continue
        c = myesp + m2_expr.ExprInt_from(myesp, ((s / 8) * i))
        e.append(m2_expr.ExprAff(regs[i], m2_expr.ExprMem(c, s)))

    c = myesp + m2_expr.ExprInt_from(myesp, ((s / 8) * (i + 1)))
    e.append(m2_expr.ExprAff(myesp, c))

    return e, []


def call(ir, instr, dst):
    e = []
    # opmode, admode = instr.opmode, instr.admode
    s = dst.size
    meip = mRIP[instr.mode]
    opmode, admode = s, instr.v_admode()
    myesp = mRSP[instr.mode][:opmode]
    n = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)


    if (isinstance(dst, m2_expr.ExprOp) and dst.op == "segm"):
        # call far
        if instr.mode != 16:
            raise NotImplementedError('add 32 bit support!')
        segm = dst.args[0]
        base = dst.args[1]
        m1 = segm.zeroExtend(CS.size)
        m2 = base.zeroExtend(meip.size)
        e.append(m2_expr.ExprAff(CS, m1))
        e.append(m2_expr.ExprAff(meip, m2))

        e.append(m2_expr.ExprAff(ir.IRDst, m2))

        c = myesp + m2_expr.ExprInt(-s/8, s)
        e.append(m2_expr.ExprAff(m2_expr.ExprMem(c, size=s).zeroExtend(s),
                                 CS.zeroExtend(s)))

        c = myesp + m2_expr.ExprInt(-2*s/8, s)
        e.append(m2_expr.ExprAff(m2_expr.ExprMem(c, size=s).zeroExtend(s),
                                 meip.zeroExtend(s)))

        c = myesp + m2_expr.ExprInt((-2*s) / 8, s)
        e.append(m2_expr.ExprAff(myesp, c))
        return e, []


    c = myesp + m2_expr.ExprInt((-s / 8), s)
    e.append(m2_expr.ExprAff(myesp, c))
    if ir.do_stk_segm:
        c = m2_expr.ExprOp('segm', SS, c)
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(c, size=s), n))
    e.append(m2_expr.ExprAff(meip, dst.zeroExtend(instr.mode)))
    e.append(m2_expr.ExprAff(ir.IRDst, dst.zeroExtend(instr.mode)))
    #if not expr_is_int_or_label(dst):
    #    dst = meip
    return e, []


def ret(ir, instr, a=None):
    e = []
    s = instr.mode
    meip = mRIP[instr.mode]
    opmode, admode = instr.v_opmode(), instr.v_admode()
    s = opmode
    myesp = mRSP[instr.mode][:s]

    if a is None:
        a = m2_expr.ExprInt(0, s)
        value =  (myesp + (m2_expr.ExprInt((s / 8), s)))
    else:
        a = a.zeroExtend(s)
        value =  (myesp + (m2_expr.ExprInt((s / 8), s) + a))

    e.append(m2_expr.ExprAff(myesp, value))
    c = myesp
    if ir.do_stk_segm:
        c = m2_expr.ExprOp('segm', SS, c)
    e.append(m2_expr.ExprAff(meip, m2_expr.ExprMem(c, size=s).zeroExtend(s)))
    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprMem(c, size=s).zeroExtend(s)))
    return e, []


def retf(ir, instr, a=None):
    e = []
    s = instr.mode
    meip = mRIP[instr.mode]
    opmode, admode = instr.v_opmode(), instr.v_admode()
    if a is None:
        a = m2_expr.ExprInt(0, s)
    s = opmode
    myesp = mRSP[instr.mode][:s]

    a = a.zeroExtend(s)

    c = myesp
    if ir.do_stk_segm:
        c = m2_expr.ExprOp('segm', SS, c)
    e.append(m2_expr.ExprAff(meip, m2_expr.ExprMem(c, size=s).zeroExtend(s)))
    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprMem(c, size=s).zeroExtend(s)))
    # e.append(m2_expr.ExprAff(meip, m2_expr.ExprMem(c, size = s)))
    c = myesp + m2_expr.ExprInt(s / 8, s)
    if ir.do_stk_segm:
        c = m2_expr.ExprOp('segm', SS, c)
    e.append(m2_expr.ExprAff(CS, m2_expr.ExprMem(c, size=16)))

    value =  myesp + (m2_expr.ExprInt((2*s) / 8, s) + a)
    e.append(m2_expr.ExprAff(myesp, value))
    return e, []


def leave(ir, instr):
    opmode, admode = instr.v_opmode(), instr.v_admode()
    size = instr.mode
    myesp = mRSP[size]
    e = []
    e.append(m2_expr.ExprAff(mRBP[size],
                             m2_expr.ExprMem(mRBP[size], size=size)))
    e.append(m2_expr.ExprAff(myesp,
                             m2_expr.ExprInt(size / 8, size) + mRBP[size]))
    return e, []


def enter(ir, instr, a, b):
    opmode, admode = instr.v_opmode(), instr.v_admode()
    s = opmode
    myesp = mRSP[instr.mode][:s]
    myebp = mRBP[instr.mode][:s]

    a = a.zeroExtend(s)

    e = []
    esp_tmp = myesp - m2_expr.ExprInt(s / 8, s)
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(esp_tmp,
                             size=s),
                     myebp))
    e.append(m2_expr.ExprAff(myebp, esp_tmp))
    e.append(m2_expr.ExprAff(myesp,
                             myesp - (a + m2_expr.ExprInt(s / 8, s))))
    return e, []


def jmp(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    e.append(m2_expr.ExprAff(meip, dst))  # dst.zeroExtend(instr.mode)))
    e.append(m2_expr.ExprAff(ir.IRDst, dst))  # dst.zeroExtend(instr.mode)))

    if isinstance(dst, m2_expr.ExprMem):
        dst = meip
    return e, []


def jmpf(ir, instr, a):
    e = []
    meip = mRIP[instr.mode]
    s = instr.mode
    if (isinstance(a, m2_expr.ExprOp) and a.op == "segm"):
        segm = a.args[0]
        base = a.args[1]
        m1 = segm.zeroExtend(CS.size)#m2_expr.ExprMem(m2_expr.ExprOp('segm', segm, base), 16)
        m2 = base.zeroExtend(meip.size)#m2_expr.ExprMem(m2_expr.ExprOp('segm', segm, base + m2_expr.ExprInt_from(base, 2)), s)
    else:
        m1 = m2_expr.ExprMem(a, 16)
        m2 = m2_expr.ExprMem(a + m2_expr.ExprInt_from(a, 2), meip.size)

    e.append(m2_expr.ExprAff(CS, m1))
    e.append(m2_expr.ExprAff(meip, m2))
    e.append(m2_expr.ExprAff(ir.IRDst, m2))
    return e, []


def jz(ir, instr, dst):
    return gen_jcc(ir, instr, zf, dst, True)


def jcxz(ir, instr, dst):
    return gen_jcc(ir, instr, mRCX[instr.mode][:16], dst, False)


def jecxz(ir, instr, dst):
    return gen_jcc(ir, instr, mRCX[instr.mode][:32], dst, False)


def jrcxz(ir, instr, dst):
    return gen_jcc(ir, instr, mRCX[instr.mode], dst, False)


def jnz(ir, instr, dst):
    return gen_jcc(ir, instr, zf, dst, False)


def jp(ir, instr, dst):
    return gen_jcc(ir, instr, pf, dst, True)


def jnp(ir, instr, dst):
    return gen_jcc(ir, instr, pf, dst, False)


def ja(ir, instr, dst):
    return gen_jcc(ir, instr, cf|zf, dst, False)


def jae(ir, instr, dst):
    return gen_jcc(ir, instr, cf, dst, False)


def jb(ir, instr, dst):
    return gen_jcc(ir, instr, cf, dst, True)


def jbe(ir, instr, dst):
    return gen_jcc(ir, instr, cf|zf, dst, True)


def jge(ir, instr, dst):
    return gen_jcc(ir, instr, nf-of, dst, False)


def jg(ir, instr, dst):
    return gen_jcc(ir, instr, zf|(nf-of), dst, False)


def jl(ir, instr, dst):
    return gen_jcc(ir, instr, nf-of, dst, True)


def jle(ir, instr, dst):
    return gen_jcc(ir, instr, zf|(nf-of), dst, True)


def js(ir, instr, dst):
    return gen_jcc(ir, instr, nf, dst, True)


def jns(ir, instr, dst):
    return gen_jcc(ir, instr, nf, dst, False)


def jo(ir, instr, dst):
    return gen_jcc(ir, instr, of, dst, True)


def jno(ir, instr, dst):
    return gen_jcc(ir, instr, of, dst, False)


def loop(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    s = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)
    c = myecx - m2_expr.ExprInt_from(myecx, 1)
    dst_o = m2_expr.ExprCond(c,
                             dst.zeroExtend(instr.mode),
                             n.zeroExtend(instr.mode))
    e.append(m2_expr.ExprAff(myecx, c))
    e.append(m2_expr.ExprAff(meip, dst_o))
    e.append(m2_expr.ExprAff(ir.IRDst, dst_o))
    return e, []


def loopne(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    s = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)

    c = m2_expr.ExprCond(mRCX[instr.mode][:s] - m2_expr.ExprInt(1, s),
                 m2_expr.ExprInt1(1),
                 m2_expr.ExprInt1(0))
    c &= zf ^ m2_expr.ExprInt1(1)

    e.append(m2_expr.ExprAff(myecx, myecx - m2_expr.ExprInt_from(myecx, 1)))
    dst_o = m2_expr.ExprCond(c,
                             dst.zeroExtend(instr.mode),
                             n.zeroExtend(instr.mode))
    e.append(m2_expr.ExprAff(meip, dst_o))
    e.append(m2_expr.ExprAff(ir.IRDst, dst_o))
    return e, []


def loope(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    s = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)
    c = m2_expr.ExprCond(mRCX[instr.mode][:s] - m2_expr.ExprInt(1, s),
                 m2_expr.ExprInt1(1),
                 m2_expr.ExprInt1(0))
    c &= zf
    e.append(m2_expr.ExprAff(myecx, myecx - m2_expr.ExprInt_from(myecx, 1)))
    dst_o = m2_expr.ExprCond(c,
                             dst.zeroExtend(instr.mode),
                             n.zeroExtend(instr.mode))
    e.append(m2_expr.ExprAff(meip, dst_o))
    e.append(m2_expr.ExprAff(ir.IRDst, dst_o))
    return e, []


# XXX size to do; eflag
def div(ir, instr, a):
    e = []
    size = a.size
    if size == 8:
        b = mRAX[instr.mode][:16]
    elif size in [16, 32, 64]:
        s1, s2 = mRDX[size], mRAX[size]
        b = m2_expr.ExprCompose([(s2, 0, size),
                         (s1, size, size*2)])
    else:
        raise ValueError('div arg not impl', a)

    c_d = m2_expr.ExprOp('udiv', b, a.zeroExtend(b.size))
    c_r = m2_expr.ExprOp('umod', b, a.zeroExtend(b.size))

    # if 8 bit div, only ax is affected
    if size == 8:
        e.append(m2_expr.ExprAff(b, m2_expr.ExprCompose([(c_d[:8], 0, 8),
                                         (c_r[:8], 8, 16)])))
    else:
        e.append(m2_expr.ExprAff(s1, c_r[:size]))
        e.append(m2_expr.ExprAff(s2, c_d[:size]))
    return e, []

# XXX size to do; eflag


def idiv(ir, instr, a):
    e = []
    size = a.size

    if size == 8:
        b = mRAX[instr.mode][:16]
    elif size in [16, 32]:
        s1, s2 = mRDX[size], mRAX[size]
        b = m2_expr.ExprCompose([(s2, 0, size),
                         (s1, size, size*2)])
    else:
        raise ValueError('div arg not impl', a)

    c_d = m2_expr.ExprOp('idiv', b, a.signExtend(b.size))
    c_r = m2_expr.ExprOp('imod', b, a.signExtend(b.size))

    # if 8 bit div, only ax is affected
    if size == 8:
        e.append(m2_expr.ExprAff(b, m2_expr.ExprCompose([(c_d[:8], 0, 8),
                                         (c_r[:8], 8, 16)])))
    else:
        e.append(m2_expr.ExprAff(s1, c_r[:size]))
        e.append(m2_expr.ExprAff(s2, c_d[:size]))
    return e, []

# XXX size to do; eflag


def mul(ir, instr, a):
    e = []
    size = a.size
    if a.size in [16, 32, 64]:
        result = m2_expr.ExprOp('*',
                        mRAX[size].zeroExtend(size * 2),
                        a.zeroExtend(size * 2))
        e.append(m2_expr.ExprAff(mRAX[size], result[:size]))
        e.append(m2_expr.ExprAff(mRDX[size], result[size:size * 2]))

    elif a.size == 8:
        result = m2_expr.ExprOp('*',
                        mRAX[instr.mode][:8].zeroExtend(16),
                        a.zeroExtend(16))
        e.append(m2_expr.ExprAff(mRAX[instr.mode][:16], result))
    else:
        raise ValueError('unknow size')

    e.append(m2_expr.ExprAff(of, m2_expr.ExprCond(result[size:size * 2],
                                  m2_expr.ExprInt1(1),
                                  m2_expr.ExprInt1(0))))
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprCond(result[size:size * 2],
                                  m2_expr.ExprInt1(1),
                                  m2_expr.ExprInt1(0))))

    return e, []


def imul(ir, instr, a, b=None, c=None):
    e = []
    size = a.size
    if b is None:
        if size in [16, 32, 64]:
            result = m2_expr.ExprOp('*',
                            mRAX[size].signExtend(size * 2),
                            a.signExtend(size * 2))
            e.append(m2_expr.ExprAff(mRAX[size], result[:size]))
            e.append(m2_expr.ExprAff(mRDX[size], result[size:size * 2]))
        elif size == 8:
            dst = mRAX[instr.mode][:16]
            result = m2_expr.ExprOp('*',
                            mRAX[instr.mode][:8].signExtend(16),
                            a.signExtend(16))

            e.append(m2_expr.ExprAff(dst, result))
        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt1(1),
                                 m2_expr.ExprInt1(0))
        e.append(m2_expr.ExprAff(cf, value))
        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt1(1),
                                 m2_expr.ExprInt1(0))
        e.append(m2_expr.ExprAff(of, value))

    else:
        if c is None:
            c = b
            b = a
        result = m2_expr.ExprOp('*',
                        b.signExtend(size * 2),
                        c.signExtend(size * 2))
        e.append(m2_expr.ExprAff(a, result[:size]))

        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt1(1),
                                 m2_expr.ExprInt1(0))
        e.append(m2_expr.ExprAff(cf, value))
        value =  m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                  m2_expr.ExprInt1(1),
                                  m2_expr.ExprInt1(0))
        e.append(m2_expr.ExprAff(of, value))
    return e, []


def cbw(ir, instr):
    e = []
    tempAL = mRAX[instr.mode][:8]
    tempAX = mRAX[instr.mode][:16]
    e.append(m2_expr.ExprAff(tempAX, tempAL.signExtend(16)))
    return e, []


def cwde(ir, instr):
    e = []
    tempAX = mRAX[instr.mode][:16]
    tempEAX = mRAX[instr.mode][:32]
    e.append(m2_expr.ExprAff(tempEAX, tempAX.signExtend(32)))
    return e, []


def cdqe(ir, instr):
    e = []
    tempEAX = mRAX[instr.mode][:32]
    tempRAX = mRAX[instr.mode][:64]
    e.append(m2_expr.ExprAff(tempRAX, tempEAX.signExtend(64)))
    return e, []


def cwd(ir, instr):
    e = []
    tempAX = mRAX[instr.mode][:16]
    tempDX = mRDX[instr.mode][:16]
    c = tempAX.signExtend(32)
    e.append(m2_expr.ExprAff(tempAX, c[:16]))
    e.append(m2_expr.ExprAff(tempDX, c[16:32]))
    return e, []


def cdq(ir, instr):
    e = []
    tempEAX = mRAX[instr.mode][:32]
    tempEDX = mRDX[instr.mode][:32]
    c = tempEAX.signExtend(64)
    e.append(m2_expr.ExprAff(tempEAX, c[:32]))
    e.append(m2_expr.ExprAff(tempEDX, c[32:64]))
    return e, []


def cqo(ir, instr):
    e = []
    tempRAX = mRAX[instr.mode][:64]
    tempRDX = mRDX[instr.mode][:64]
    c = tempRAX.signExtend(128)
    e.append(m2_expr.ExprAff(tempRAX, c[:64]))
    e.append(m2_expr.ExprAff(tempRDX, c[64:128]))
    return e, []


def stos(ir, instr, size):
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)

    s = instr.v_admode()

    addr_o = mRDI[instr.mode][:s]
    addr = addr_o
    addr_p = addr + m2_expr.ExprInt_from(addr, size / 8)
    addr_m = addr - m2_expr.ExprInt_from(addr, size / 8)
    if ir.do_str_segm:
        mss = ES
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        addr = m2_expr.ExprOp('segm', mss, addr)

    b = mRAX[instr.mode][:size]

    e0 = []
    e0.append(m2_expr.ExprAff(addr_o, addr_p))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = irbloc(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(addr_o, addr_m))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = irbloc(lbl_df_1.name, [e1])

    e = []
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(addr, size), b))
    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))
    return e, [e0, e1]


def lods(ir, instr, size):
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)
    e = []
    s = instr.v_admode()

    addr_o = mRSI[instr.mode][:s]
    addr = addr_o
    addr_p = addr + m2_expr.ExprInt_from(addr, size / 8)
    addr_m = addr - m2_expr.ExprInt_from(addr, size / 8)
    if ir.do_str_segm:
        mss = DS
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        addr = m2_expr.ExprOp('segm', mss, addr)

    b = mRAX[instr.mode][:size]

    e0 = []
    e0.append(m2_expr.ExprAff(addr_o, addr_p))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = irbloc(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(addr_o, addr_m))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = irbloc(lbl_df_1.name, [e1])

    e = []
    e.append(m2_expr.ExprAff(b, m2_expr.ExprMem(addr, size)))

    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))
    return e, [e0, e1]


def movs(ir, instr, size):
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)

    s = instr.v_admode()
    # a = m2_expr.ExprMem(mRDI[instr.mode][:s], size)
    # b = m2_expr.ExprMem(mRSI[instr.mode][:s], size)

    a = mRDI[instr.mode][:s]
    b = mRSI[instr.mode][:s]

    e = []
    src = b
    dst = a
    if ir.do_str_segm:
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        src = m2_expr.ExprOp('segm', DS, src)
        dst = m2_expr.ExprOp('segm', ES, dst)
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(dst, size),
                             m2_expr.ExprMem(src, size)))

    e0 = []
    e0.append(m2_expr.ExprAff(a, a + m2_expr.ExprInt_from(a, size / 8)))
    e0.append(m2_expr.ExprAff(b, b + m2_expr.ExprInt_from(b, size / 8)))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = irbloc(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(a, a - m2_expr.ExprInt_from(a, size / 8)))
    e1.append(m2_expr.ExprAff(b, b - m2_expr.ExprInt_from(b, size / 8)))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = irbloc(lbl_df_1.name, [e1])

    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))
    return e, [e0, e1]

def movsd(ir, instr, a, b):
    e = []
    if isinstance(a, m2_expr.ExprId) and isinstance(b, m2_expr.ExprMem):
        b = m2_expr.ExprMem(b.arg, a.size)
    elif isinstance(a, m2_expr.ExprMem) and isinstance(b, m2_expr.ExprId):
        a = m2_expr.ExprMem(a.arg, b.size)

    e.append(m2_expr.ExprAff(a, b))
    return e, []

def movsd_dispatch(ir, instr, a = None, b = None):
    if a is None and b is None:
        return movs(ir, instr, 32)
    else:
        return movsd(ir, instr, a, b)


def float_prev(flt, popcount=1):
    if not flt in float_list:
        return None
    i = float_list.index(flt)
    if i < popcount:
        raise ValueError('broken index')
    flt = float_list[i - popcount]
    return flt


def float_pop(avoid_flt=None, popcount=1):
    """
    Generate floatpop semantic (@popcount times), avoiding the avoid_flt@ float
    @avoid_flt: float avoided in the generated semantic
    @popcount: pop count
    """
    avoid_flt = float_prev(avoid_flt, popcount)
    e = []
    for i in xrange(8-popcount):
        if avoid_flt != float_list[i]:
            e.append(m2_expr.ExprAff(float_list[i],
                                     float_list[i+popcount]))
    for i in xrange(8-popcount, 8):
        e.append(m2_expr.ExprAff(float_list[i],
                                 m2_expr.ExprInt_from(float_list[i], 0)))
    e.append(
        m2_expr.ExprAff(float_stack_ptr,
                        float_stack_ptr - m2_expr.ExprInt(popcount, 3)))
    return e

# XXX TODO


def fcom(ir, instr, a=None, b=None):

    if a is None and b is None:
        a, b = float_st0, float_st1
    elif b is None:
        b = a
        a = float_st0

    e = []
    b = mem2double(b)

    e.append(m2_expr.ExprAff(float_c0, m2_expr.ExprOp('fcom_c0', a, b)))
    e.append(m2_expr.ExprAff(float_c1, m2_expr.ExprOp('fcom_c1', a, b)))
    e.append(m2_expr.ExprAff(float_c2, m2_expr.ExprOp('fcom_c2', a, b)))
    e.append(m2_expr.ExprAff(float_c3, m2_expr.ExprOp('fcom_c3', a, b)))

    e += set_float_cs_eip(instr)
    return e, []


def ftst(ir, instr):
    a = float_st0

    e = []
    b = m2_expr.ExprOp('int_32_to_double', m2_expr.ExprInt32(0))
    e.append(m2_expr.ExprAff(float_c0, m2_expr.ExprOp('fcom_c0', a, b)))
    e.append(m2_expr.ExprAff(float_c1, m2_expr.ExprOp('fcom_c1', a, b)))
    e.append(m2_expr.ExprAff(float_c2, m2_expr.ExprOp('fcom_c2', a, b)))
    e.append(m2_expr.ExprAff(float_c3, m2_expr.ExprOp('fcom_c3', a, b)))

    e += set_float_cs_eip(instr)
    return e, []


def fxam(ir, instr):
    a = float_st0

    e = []
    e.append(m2_expr.ExprAff(float_c0, m2_expr.ExprOp('fxam_c0', a)))
    e.append(m2_expr.ExprAff(float_c2, m2_expr.ExprOp('fxam_c2', a)))
    e.append(m2_expr.ExprAff(float_c3, m2_expr.ExprOp('fxam_c3', a)))

    e += set_float_cs_eip(instr)
    return e, []


def ficom(ir, instr, a, b = None):

    a, b = float_implicit_st0(a, b)

    e = []

    e.append(m2_expr.ExprAff(float_c0,
                             m2_expr.ExprOp('fcom_c0', a,
                                            b.zeroExtend(a.size))))
    e.append(m2_expr.ExprAff(float_c1,
                             m2_expr.ExprOp('fcom_c1', a,
                                            b.zeroExtend(a.size))))
    e.append(m2_expr.ExprAff(float_c2,
                             m2_expr.ExprOp('fcom_c2', a,
                                            b.zeroExtend(a.size))))
    e.append(m2_expr.ExprAff(float_c3,
                             m2_expr.ExprOp('fcom_c3', a,
                                            b.zeroExtend(a.size))))

    e += set_float_cs_eip(instr)
    return e, []



def fcomi(ir, instr, a=None, b=None):
    # TODO unordered float
    if a is None and b is None:
        a, b = float_st0, float_st1
    elif b is None:
        b = a
        a = float_st0

    e = []

    e.append(m2_expr.ExprAff(cf, m2_expr.ExprOp('fcom_c0', a, b)))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprOp('fcom_c2', a, b)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('fcom_c3', a, b)))

    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt1(0)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprInt1(0)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt1(0)))

    e += set_float_cs_eip(instr)
    return e, []


def fcomip(ir, instr, a=None, b=None):
    e, extra = fcomi(ir, instr, a, b)
    e += float_pop()
    e += set_float_cs_eip(instr)
    return e, extra


def fucomi(ir, instr, a=None, b=None):
    # TODO unordered float
    return fcomi(ir, instr, a, b)

def fucomip(ir, instr, a=None, b=None):
    # TODO unordered float
    return fcomip(ir, instr, a, b)


def fcomp(ir, instr, a=None, b=None):
    e, extra = fcom(ir, instr, a, b)
    e += float_pop()
    e += set_float_cs_eip(instr)
    return e, extra


def fcompp(ir, instr, a=None, b=None):
    e, extra = fcom(ir, instr, a, b)
    e += float_pop(popcount=2)
    e += set_float_cs_eip(instr)
    return e, extra


def ficomp(ir, instr, a, b = None):
    e, extra = ficom(ir, instr, a, b)
    e += float_pop()
    e += set_float_cs_eip(instr)
    return e, extra


def fucom(ir, instr, a=None, b=None):
    # TODO unordered float
    return fcom(ir, instr, a, b)


def fucomp(ir, instr, a=None, b=None):
    # TODO unordered float
    return fcomp(ir, instr, a, b)


def fucompp(ir, instr, a=None, b=None):
    # TODO unordered float
    return fcompp(ir, instr, a, b)


def comiss(ir, instr, a, b):
    # TODO unordered float

    e = []

    a = m2_expr.ExprOp('int_32_to_float', a[:32])
    b = m2_expr.ExprOp('int_32_to_float', b[:32])

    e.append(m2_expr.ExprAff(cf, m2_expr.ExprOp('fcom_c0', a, b)))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprOp('fcom_c2', a, b)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('fcom_c3', a, b)))

    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt1(0)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprInt1(0)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt1(0)))

    e += set_float_cs_eip(instr)
    return e, []


def comisd(ir, instr, a, b):
    # TODO unordered float

    e = []

    a = m2_expr.ExprOp('int_64_to_double', a[:64])
    b = m2_expr.ExprOp('int_64_to_double', b[:64])

    e.append(m2_expr.ExprAff(cf, m2_expr.ExprOp('fcom_c0', a, b)))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprOp('fcom_c2', a, b)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('fcom_c3', a, b)))

    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt1(0)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprInt1(0)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt1(0)))

    e += set_float_cs_eip(instr)
    return e, []


def fld(ir, instr, a):
    src = mem2double(a)

    e = []
    e.append(m2_expr.ExprAff(float_st7, float_st6))
    e.append(m2_expr.ExprAff(float_st6, float_st5))
    e.append(m2_expr.ExprAff(float_st5, float_st4))
    e.append(m2_expr.ExprAff(float_st4, float_st3))
    e.append(m2_expr.ExprAff(float_st3, float_st2))
    e.append(m2_expr.ExprAff(float_st2, float_st1))
    e.append(m2_expr.ExprAff(float_st1, float_st0))
    e.append(m2_expr.ExprAff(float_st0, src))
    e.append(
        m2_expr.ExprAff(float_stack_ptr,
                        float_stack_ptr + m2_expr.ExprInt(1, 3)))

    e += set_float_cs_eip(instr)
    return e, []


def fst(ir, instr, a):
    e = []

    if isinstance(a, m2_expr.ExprMem):
        if a.size > 64:
            raise NotImplementedError('float to long')
        src = m2_expr.ExprOp('double_to_mem_%.2d' % a.size, a)
    else:
        src = a

    e.append(m2_expr.ExprAff(a, src))
    e += set_float_cs_eip(instr)
    return e, []


def fstp(ir, instr, a):
    e, extra = fst(ir, instr, a)
    e += float_pop(a)
    return e, extra


def fist(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('double_to_int_%d' % a.size,
                                               float_st0)))

    e += set_float_cs_eip(instr)
    return e, []

def fistp(ir, instr, a):
    e, extra = fist(ir, instr, a)
    e += float_pop(a)
    return e, extra

def fist(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('double_to_int_%d' % a.size,
                                               float_st0)))

    e += set_float_cs_eip(instr)
    return e, []

def fisttp(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a,
                             m2_expr.ExprOp('double_trunc_to_int_%d' % a.size,
                                            float_st0)))

    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fild(ir, instr, a):
    # XXXXX
    src = m2_expr.ExprOp('int_%.2d_to_double' % a.size, a)
    e = []
    e += set_float_cs_eip(instr)
    e_fld, extra = fld(ir, instr, src)
    e += e_fld
    return e, extra


def fldz(ir, instr):
    return fld(ir, instr, m2_expr.ExprOp('int_32_to_double',
                                         m2_expr.ExprInt32(0)))


def fld1(ir, instr):
    return fld(ir, instr, m2_expr.ExprOp('int_32_to_double',
                                         m2_expr.ExprInt32(1)))


def fldl2t(ir, instr):
    value_f = math.log(10)/math.log(2)
    value = struct.unpack('I', struct.pack('f', value_f))[0]
    return fld(ir, instr, m2_expr.ExprOp('int_32_to_double',
                                         m2_expr.ExprInt32(value)))


def fldpi(ir, instr):
    value_f = math.pi
    value = struct.unpack('I', struct.pack('f', value_f))[0]
    return fld(ir, instr, m2_expr.ExprOp('int_32_to_double',
                                         m2_expr.ExprInt32(value)))


def fldln2(ir, instr):
    value_f = math.log(2)
    value = struct.unpack('I', struct.pack('f', value_f))[0]
    return fld(ir, instr, m2_expr.ExprOp('int_32_to_double',
                                         m2_expr.ExprInt32(value)))


def fldl2e(ir, instr):
    x = struct.pack('d', 1 / math.log(2))
    x = struct.unpack('Q', x)[0]
    return fld(ir, instr, m2_expr.ExprOp('mem_64_to_double',
                                         m2_expr.ExprInt64(x)))


def fldlg2(ir, instr):
    x = struct.pack('d', math.log10(2))
    x = struct.unpack('Q', x)[0]
    return fld(ir, instr, m2_expr.ExprOp('mem_64_to_double',
                                         m2_expr.ExprInt64(x)))


def fadd(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fadd', a, src)))

    e += set_float_cs_eip(instr)
    return e, []

def fiadd(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fiadd', a, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fisub(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fisub', a, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fisubr(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fisub', src, a)))
    e += set_float_cs_eip(instr)
    return e, []


def fpatan(ir, instr):
    e = []
    a = float_st1
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fpatan', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fprem(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fprem', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    return e, []


def fprem1(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fprem1', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    return e, []


def faddp(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(float_prev(a), m2_expr.ExprOp('fadd', a, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fninit(ir, instr):
    e = []
    e += set_float_cs_eip(instr)
    return e, []


def fyl2x(ir, instr):
    e = []
    a = float_st1
    e.append(m2_expr.ExprAff(float_prev(a), m2_expr.ExprOp('fyl2x', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fnstenv(ir, instr, a):
    e = []
    # XXX TODO tag word, ...
    status_word = m2_expr.ExprCompose([(m2_expr.ExprInt8(0), 0, 8),
                               (float_c0,           8, 9),
                               (float_c1,           9, 10),
                               (float_c2,           10, 11),
                               (float_stack_ptr,    11, 14),
                               (float_c3,           14, 15),
                               (m2_expr.ExprInt1(0), 15, 16),
                               ])

    s = instr.mode
    # The behaviour in 64bit is identical to 64 bit
    # This will truncate addresses
    s = min(32, s)
    ad = m2_expr.ExprMem(a.arg, size=16)
    e.append(m2_expr.ExprAff(ad, float_control))
    ad = m2_expr.ExprMem(a.arg + m2_expr.ExprInt_from(a.arg, s / 8 * 1),
                         size=16)
    e.append(m2_expr.ExprAff(ad, status_word))
    ad = m2_expr.ExprMem(a.arg + m2_expr.ExprInt_from(a.arg, s / 8 * 3),
                         size=s)
    e.append(m2_expr.ExprAff(ad, float_eip[:s]))
    ad = m2_expr.ExprMem(a.arg + m2_expr.ExprInt_from(a.arg, s / 8 * 4),
                         size=16)
    e.append(m2_expr.ExprAff(ad, float_cs))
    ad = m2_expr.ExprMem(a.arg + m2_expr.ExprInt_from(a.arg, s / 8 * 5),
                         size=s)
    e.append(m2_expr.ExprAff(ad, float_address[:s]))
    ad = m2_expr.ExprMem(a.arg + m2_expr.ExprInt_from(a.arg, s / 8 * 6),
                         size=16)
    e.append(m2_expr.ExprAff(ad, float_ds))
    return e, []


def fsub(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fsub', a, src)))
    e += set_float_cs_eip(instr)
    return e, []

def fsubp(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(float_prev(a), m2_expr.ExprOp('fsub', a, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fsubr(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fsub', src, a)))
    e += set_float_cs_eip(instr)
    return e, []


def fsubrp(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(float_prev(a), m2_expr.ExprOp('fsub', src, a)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fmul(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fmul', a, src)))
    e += set_float_cs_eip(instr)
    return e, []

def fimul(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fimul', a, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fdiv(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fdiv', a, src)))
    e += set_float_cs_eip(instr)
    return e, []

def fdivr(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fdiv', src, a)))
    e += set_float_cs_eip(instr)
    return e, []


def fdivrp(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(float_prev(a), m2_expr.ExprOp('fdiv', src, a)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fidiv(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fidiv', a, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fidivr(ir, instr, a, b=None):
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fidiv', src, a)))
    e += set_float_cs_eip(instr)
    return e, []


def fdivp(ir, instr, a, b=None):
    # Invalid emulation
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(float_prev(a), m2_expr.ExprOp('fdiv', a, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fmulp(ir, instr, a, b=None):
    # Invalid emulation
    a, b = float_implicit_st0(a, b)
    e = []
    src = mem2double(b)
    e.append(m2_expr.ExprAff(float_prev(a), m2_expr.ExprOp('fmul', a, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def ftan(ir, instr, a):
    e = []
    src = mem2double(a)
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('ftan', src)))
    e += set_float_cs_eip(instr)
    return e, []


def fxch(ir, instr, a):
    e = []
    src = mem2double(a)
    e.append(m2_expr.ExprAff(float_st0, src))
    e.append(m2_expr.ExprAff(src, float_st0))
    e += set_float_cs_eip(instr)
    return e, []


def fptan(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st7, float_st6))
    e.append(m2_expr.ExprAff(float_st6, float_st5))
    e.append(m2_expr.ExprAff(float_st5, float_st4))
    e.append(m2_expr.ExprAff(float_st4, float_st3))
    e.append(m2_expr.ExprAff(float_st3, float_st2))
    e.append(m2_expr.ExprAff(float_st2, float_st1))
    e.append(m2_expr.ExprAff(float_st1, m2_expr.ExprOp('ftan', float_st0)))
    e.append(m2_expr.ExprAff(float_st0,
                             m2_expr.ExprOp('int_32_to_double',
                                            m2_expr.ExprInt32(1))))
    e.append(
        m2_expr.ExprAff(float_stack_ptr,
                        float_stack_ptr + m2_expr.ExprInt(1, 3)))
    return e, []


def frndint(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('frndint', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fsin(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fsin', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fcos(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fcos', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fsincos(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st7, float_st6))
    e.append(m2_expr.ExprAff(float_st6, float_st5))
    e.append(m2_expr.ExprAff(float_st5, float_st4))
    e.append(m2_expr.ExprAff(float_st4, float_st3))
    e.append(m2_expr.ExprAff(float_st3, float_st2))
    e.append(m2_expr.ExprAff(float_st2, float_st1))
    e.append(m2_expr.ExprAff(float_st1, m2_expr.ExprOp('fsin', float_st0)))
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fcos', float_st0)))
    e.append(
        m2_expr.ExprAff(float_stack_ptr,
                        float_stack_ptr + m2_expr.ExprInt(1, 3)))
    return e, []


def fscale(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fscale', float_st0,
                                                       float_st1)))
    e += set_float_cs_eip(instr)
    return e, []


def f2xm1(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('f2xm1', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []

def fchs(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fchs', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fsqrt(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fsqrt', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fabs(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fabs', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fnstsw(ir, instr, dst):
    args = [(m2_expr.ExprInt8(0),        0, 8),
            (float_c0,           8, 9),
            (float_c1,           9, 10),
            (float_c2,           10, 11),
            (float_stack_ptr,    11, 14),
            (float_c3,           14, 15),
            (m2_expr.ExprInt1(0), 15, 16)]
    e = [m2_expr.ExprAff(dst, m2_expr.ExprCompose(args))]
    return e, []


def fnstcw(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, float_control))
    return e, []


def fldcw(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(float_control, a))
    return e, []


def fwait(ir, instr):
    return [], None


def fcmovb(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, cf, arg1, arg2, True)


def fcmove(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, zf, arg1, arg2, True)


def fcmovbe(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, cf|zf, arg1, arg2, True)


def fcmovu(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, pf, arg1, arg2, True)


def fcmovnb(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, cf, arg1, arg2, False)


def fcmovne(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, zf, arg1, arg2, False)


def fcmovnbe(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, cf|zf, arg1, arg2, False)


def fcmovnu(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, pf, arg1, arg2, False)


def nop(ir, instr, a=None):
    return [], []


def hlt(ir, instr):
    e = []
    except_int = EXCEPT_PRIV_INSN
    e.append(m2_expr.ExprAff(exception_flags, m2_expr.ExprInt32(except_int)))
    return e, []


def rdtsc(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(tsc1, tsc1 + m2_expr.ExprInt32(1)))
    e.append(m2_expr.ExprAff(mRAX[32], tsc1))
    e.append(m2_expr.ExprAff(mRDX[32], tsc2))
    return e, []


def daa(ir, instr):
    e = []
    r_al = mRAX[instr.mode][:8]

    cond1 = expr_cmpu(r_al[:4], m2_expr.ExprInt(0x9, 4)) | af
    e.append(m2_expr.ExprAff(af, cond1))


    cond2 = expr_cmpu(m2_expr.ExprInt8(6), r_al)
    cond3 = expr_cmpu(r_al, m2_expr.ExprInt8(0x99)) | cf


    cf_c1 = m2_expr.ExprCond(cond1,
                             cf | (cond2),
                             m2_expr.ExprInt1(0))
    new_cf = m2_expr.ExprCond(cond3,
                              m2_expr.ExprInt1(1),
                              m2_expr.ExprInt1(0))
    e.append(m2_expr.ExprAff(cf, new_cf))

    al_c1 = m2_expr.ExprCond(cond1,
                             r_al + m2_expr.ExprInt8(6),
                             r_al)

    new_al = m2_expr.ExprCond(cond3,
                              al_c1 + m2_expr.ExprInt8(0x60),
                              al_c1)
    e.append(m2_expr.ExprAff(r_al, new_al))
    return e, []

def das(ir, instr):
    e = []
    r_al = mRAX[instr.mode][:8]

    cond1 = expr_cmpu(r_al[:4], m2_expr.ExprInt(0x9, 4)) | af
    e.append(m2_expr.ExprAff(af, cond1))


    cond2 = expr_cmpu(m2_expr.ExprInt8(6), r_al)
    cond3 = expr_cmpu(r_al, m2_expr.ExprInt8(0x99)) | cf


    cf_c1 = m2_expr.ExprCond(cond1,
                             cf | (cond2),
                             m2_expr.ExprInt1(0))
    new_cf = m2_expr.ExprCond(cond3,
                              m2_expr.ExprInt1(1),
                              cf_c1)
    e.append(m2_expr.ExprAff(cf, new_cf))

    al_c1 = m2_expr.ExprCond(cond1,
                             r_al - m2_expr.ExprInt8(6),
                             r_al)

    new_al = m2_expr.ExprCond(cond3,
                              al_c1 - m2_expr.ExprInt8(0x60),
                              al_c1)
    e.append(m2_expr.ExprAff(r_al, new_al))
    return e, []


def aam(ir, instr, a):
    e = []
    tempAL = mRAX[instr.mode][0:8]
    newEAX = m2_expr.ExprCompose([
                         (tempAL % a,           0,  8),
                        (tempAL / a,           8,  16),
                        (mRAX[instr.mode][16:], 16, mRAX[instr.mode].size),
                         ])
    e += [m2_expr.ExprAff(mRAX[instr.mode], newEAX)]
    e += update_flag_arith(newEAX)
    return e, []


def aad(ir, instr, a):
    e = []
    tempAL = mRAX[instr.mode][0:8]
    tempAH = mRAX[instr.mode][8:16]
    newEAX = m2_expr.ExprCompose([
            ((tempAL + (tempAH * a)) & m2_expr.ExprInt8(0xFF), 0,  8),
            (m2_expr.ExprInt8(0),                              8,  16),
            (mRAX[instr.mode][16:],
             16, mRAX[instr.mode].size),
            ])
    e += [m2_expr.ExprAff(mRAX[instr.mode], newEAX)]
    e += update_flag_arith(newEAX)
    return e, []


def aaa(ir, instr, ):
    e = []
    c = (mRAX[instr.mode][:8] & m2_expr.ExprInt8(0xf)) - m2_expr.ExprInt8(9)

    c = m2_expr.ExprCond(c.msb(),
                 m2_expr.ExprInt1(0),
                 m2_expr.ExprInt1(1)) & \
        m2_expr.ExprCond(c,
                 m2_expr.ExprInt1(1),
                 m2_expr.ExprInt1(0))

    c |= af & m2_expr.ExprInt1(1)
    # set AL
    m_al = m2_expr.ExprCond(c,
                            (mRAX[instr.mode][:8] + m2_expr.ExprInt8(6)) & \
                                m2_expr.ExprInt8(0xF),
                            mRAX[instr.mode][:8] & m2_expr.ExprInt8(0xF))
    m_ah = m2_expr.ExprCond(c,
                            mRAX[instr.mode][8:16] + m2_expr.ExprInt8(1),
                            mRAX[instr.mode][8:16])

    e.append(m2_expr.ExprAff(mRAX[instr.mode], m2_expr.ExprCompose([
        (m_al, 0, 8), (m_ah, 8, 16),
        (mRAX[instr.mode][16:], 16, mRAX[instr.mode].size)])))
    e.append(m2_expr.ExprAff(af, c))
    e.append(m2_expr.ExprAff(cf, c))
    return e, []


def aas(ir, instr, ):
    e = []
    c = (mRAX[instr.mode][:8] & m2_expr.ExprInt8(0xf)) - m2_expr.ExprInt8(9)

    c = m2_expr.ExprCond(c.msb(),
                 m2_expr.ExprInt1(0),
                 m2_expr.ExprInt1(1)) & \
        m2_expr.ExprCond(c,
                 m2_expr.ExprInt1(1),
                 m2_expr.ExprInt1(0))

    c |= af & m2_expr.ExprInt1(1)
    # set AL
    m_al = m2_expr.ExprCond(c,
                   (mRAX[instr.mode][:8] - m2_expr.ExprInt8(6)) & \
                                m2_expr.ExprInt8(0xF),
                    mRAX[instr.mode][:8] & m2_expr.ExprInt8(0xF))
    m_ah = m2_expr.ExprCond(c,
                    mRAX[instr.mode][8:16] - m2_expr.ExprInt8(1),
                    mRAX[instr.mode][8:16])

    e.append(m2_expr.ExprAff(mRAX[instr.mode], m2_expr.ExprCompose([
        (m_al, 0, 8), (m_ah, 8, 16),
        (mRAX[instr.mode][16:], 16, mRAX[instr.mode].size)])))
    e.append(m2_expr.ExprAff(af, c))
    e.append(m2_expr.ExprAff(cf, c))
    return e, []


def bsr_bsf(ir, instr, a, b, op_name):
    """
    IF SRC == 0
        ZF = 1
        DEST is left unchanged
    ELSE
        ZF = 0
        DEST = @op_name(SRC)
    """
    lbl_src_null = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_src_not_null = m2_expr.ExprId(ir.gen_label(), instr.mode)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), instr.mode)

    aff_dst = m2_expr.ExprAff(ir.IRDst, lbl_next)
    e = [m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(b,
                                                    lbl_src_not_null,
                                                    lbl_src_null))]
    e_src_null = []
    e_src_null.append(m2_expr.ExprAff(zf, m2_expr.ExprInt_from(zf, 1)))
    # XXX destination is undefined
    e_src_null.append(aff_dst)

    e_src_not_null = []
    e_src_not_null.append(m2_expr.ExprAff(zf, m2_expr.ExprInt_from(zf, 0)))
    e_src_not_null.append(m2_expr.ExprAff(a, m2_expr.ExprOp(op_name, b)))
    e_src_not_null.append(aff_dst)

    return e, [irbloc(lbl_src_null.name, [e_src_null]),
               irbloc(lbl_src_not_null.name, [e_src_not_null])]

def bsf(ir, instr, a, b):
    return bsr_bsf(ir, instr, a, b, "bsf")

def bsr(ir, instr, a, b):
    return bsr_bsf(ir, instr, a, b, "bsr")


def arpl(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(exception_flags, m2_expr.ExprInt32(1 << 7)))
    return e, []


def ins(ir, instr, size):
    e = []
    e.append(m2_expr.ExprAff(exception_flags, m2_expr.ExprInt32(1 << 7)))
    return e, []


def sidt(ir, instr, a):
    e = []
    if not isinstance(a, m2_expr.ExprMem) or a.size != 32:
        raise ValueError('not exprmem 32bit instance!!')
    b = a.arg
    print "DEFAULT SIDT ADDRESS %s!!" % str(a)
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(b, 32),
                             m2_expr.ExprInt32(0xe40007ff)))
    e.append(
        m2_expr.ExprAff(m2_expr.ExprMem(m2_expr.ExprOp("+", b,
        m2_expr.ExprInt_from(b, 4)), 16), m2_expr.ExprInt16(0x8245)))
    return e, []


def sldt(ir, instr, a):
    # XXX TOOD
    e = [m2_expr.ExprAff(exception_flags, m2_expr.ExprInt32(EXCEPT_PRIV_INSN))]
    return e, []


def cmovz(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, zf, arg1, arg2, True)

def cmovnz(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, zf, arg1, arg2, False)


def cmovpe(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, pf, arg1, arg2, True)


def cmovnp(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, pf, arg1, arg2, False)


def cmovge(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, nf^of, arg1, arg2, False)


def cmovg(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, zf|(nf^of), arg1, arg2, False)


def cmovl(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, nf^of, arg1, arg2, True)


def cmovle(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, zf|(nf^of), arg1, arg2, True)


def cmova(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, cf|zf, arg1, arg2, False)


def cmovae(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, cf, arg1, arg2, False)


def cmovbe(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, cf|zf, arg1, arg2, True)


def cmovb(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, cf, arg1, arg2, True)


def cmovo(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, of, arg1, arg2, True)


def cmovno(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, of, arg1, arg2, False)


def cmovs(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, nf, arg1, arg2, True)


def cmovns(ir, instr, arg1, arg2):
    return gen_cmov(ir, instr, nf, arg1, arg2, False)


def icebp(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                     m2_expr.ExprInt32(EXCEPT_PRIV_INSN)))
    return e, []
# XXX


def l_int(ir, instr, a):
    e = []
    # XXX
    if a.arg in [1, 3]:
        except_int = EXCEPT_SOFT_BP
    else:
        except_int = EXCEPT_INT_XX
    e.append(m2_expr.ExprAff(exception_flags,
                     m2_expr.ExprInt32(except_int)))
    return e, []


def l_sysenter(ir, instr):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                     m2_expr.ExprInt32(EXCEPT_PRIV_INSN)))
    return e, []

# XXX


def l_out(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                     m2_expr.ExprInt32(EXCEPT_PRIV_INSN)))
    return e, []

# XXX


def l_outs(ir, instr, size):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                     m2_expr.ExprInt32(EXCEPT_PRIV_INSN)))
    return e, []

# XXX actually, xlat performs al = (ds:[e]bx + ZeroExtend(al))


def xlat(ir, instr):
    e = []
    a = m2_expr.ExprCompose([(m2_expr.ExprInt(0, 24), 8, 32),
                     (mRAX[instr.mode][0:8], 0, 8)])
    b = m2_expr.ExprMem(m2_expr.ExprOp('+', mRBX[instr.mode], a), 8)
    e.append(m2_expr.ExprAff(mRAX[instr.mode][0:8], b))
    return e, []


def cpuid(ir, instr):
    e = []
    e.append(
        m2_expr.ExprAff(mRAX[instr.mode],
        m2_expr.ExprOp('cpuid', mRAX[instr.mode], m2_expr.ExprInt(0, instr.mode))))
    e.append(
        m2_expr.ExprAff(mRBX[instr.mode],
        m2_expr.ExprOp('cpuid', mRAX[instr.mode], m2_expr.ExprInt(1, instr.mode))))
    e.append(
        m2_expr.ExprAff(mRCX[instr.mode],
        m2_expr.ExprOp('cpuid', mRAX[instr.mode], m2_expr.ExprInt(2, instr.mode))))
    e.append(
        m2_expr.ExprAff(mRDX[instr.mode],
        m2_expr.ExprOp('cpuid', mRAX[instr.mode], m2_expr.ExprInt(3, instr.mode))))
    return e, []


def bittest_get(a, b):
    b = b.zeroExtend(a.size)
    if isinstance(a, m2_expr.ExprMem):
        b_mask = {16:4, 32:5, 64:6}
        b_decal = {16:1, 32:3, 64:7}
        ptr = a.arg
        off_bit = b.zeroExtend(a.size) & m2_expr.ExprInt((1<<b_mask[a.size])-1,
                                                         a.size)
        off_byte = ((b.zeroExtend(ptr.size) >> m2_expr.ExprInt_from(ptr, 3)) &
                    m2_expr.ExprInt_from(ptr,
                                         ((1<<a.size)-1) ^ b_decal[a.size]))

        d = m2_expr.ExprMem(ptr + off_byte, a.size)
    else:
        off_bit = m2_expr.ExprOp('&', b, m2_expr.ExprInt_from(a, a.size - 1))
        d = a
    return d, off_bit


def bt(ir, instr, a, b):
    e = []
    b = b.zeroExtend(a.size)
    d, off_bit = bittest_get(a, b)
    d = d >> off_bit
    e.append(m2_expr.ExprAff(cf, d[:1]))
    return e, []


def btc(ir, instr, a, b):
    e = []
    d, off_bit = bittest_get(a, b)
    e.append(m2_expr.ExprAff(cf, (d >> off_bit)[:1]))

    m = m2_expr.ExprInt_from(a, 1) << off_bit
    e.append(m2_expr.ExprAff(d, d ^ m))

    return e, []


def bts(ir, instr, a, b):
    e = []
    d, off_bit = bittest_get(a, b)
    e.append(m2_expr.ExprAff(cf, (d >> off_bit)[:1]))
    m = m2_expr.ExprInt_from(a, 1) << off_bit
    e.append(m2_expr.ExprAff(d, d | m))

    return e, []


def btr(ir, instr, a, b):
    e = []
    d, off_bit = bittest_get(a, b)
    e.append(m2_expr.ExprAff(cf, (d >> off_bit)[:1]))
    m = ~(m2_expr.ExprInt_from(a, 1) << off_bit)
    e.append(m2_expr.ExprAff(d, d & m))

    return e, []


def into(ir, instr):
    return [], None


def l_in(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                     m2_expr.ExprInt32(EXCEPT_PRIV_INSN)))
    return e, []


def cmpxchg(ir, instr, a, b):
    e = []

    c = mRAX[instr.mode][:a.size]
    cond = c - a
    e.append(
        m2_expr.ExprAff(zf,
                        m2_expr.ExprCond(cond,
                                         m2_expr.ExprInt_from(zf, 0),
                                         m2_expr.ExprInt_from(zf, 1))))
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond(cond,
                                 b,
                                 a)
                     ))
    e.append(m2_expr.ExprAff(c, m2_expr.ExprCond(cond,
                                 a,
                                 c)
                     ))
    return e, []


def lds(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprMem(b.arg, size=a.size)))
    DS_value = m2_expr.ExprMem(b.arg + m2_expr.ExprInt_from(b.arg, a.size/8),
                               size=16)
    e.append(m2_expr.ExprAff(DS, DS_value))
    return e, []


def les(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprMem(b.arg, size=a.size)))
    ES_value = m2_expr.ExprMem(b.arg + m2_expr.ExprInt_from(b.arg, a.size/8),
                               size=16)
    e.append(m2_expr.ExprAff(ES, ES_value))
    return e, []


def lss(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprMem(b.arg, size=a.size)))
    SS_value = m2_expr.ExprMem(b.arg + m2_expr.ExprInt_from(b.arg, a.size/8),
                               size=16)
    e.append(m2_expr.ExprAff(SS, SS_value))
    return e, []

def lfs(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprMem(b.arg, size=a.size)))
    FS_value = m2_expr.ExprMem(b.arg + m2_expr.ExprInt_from(b.arg, a.size/8),
                               size=16)
    e.append(m2_expr.ExprAff(FS, FS_value))
    return e, []

def lgs(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprMem(b.arg, size=a.size)))
    GS_value = m2_expr.ExprMem(b.arg + m2_expr.ExprInt_from(b.arg, a.size/8),
                               size=16)
    e.append(m2_expr.ExprAff(GS, GS_value))
    return e, []


def lahf(ir, instr):
    e = []
    args = []
    regs = [cf, m2_expr.ExprInt1(1), pf, m2_expr.ExprInt1(0), af,
            m2_expr.ExprInt1(0), zf, nf]
    for i in xrange(len(regs)):
        args.append((regs[i], i, i + 1))
    e.append(m2_expr.ExprAff(mRAX[instr.mode][8:16], m2_expr.ExprCompose(args)))
    return e, []


def sahf(ir, instr):
    tmp = mRAX[instr.mode][8:16]
    e = []
    e.append(m2_expr.ExprAff(cf, tmp[0:1]))
    e.append(m2_expr.ExprAff(pf, tmp[2:3]))
    e.append(m2_expr.ExprAff(af, tmp[4:5]))
    e.append(m2_expr.ExprAff(zf, tmp[6:7]))
    e.append(m2_expr.ExprAff(nf, tmp[7:8]))
    return e, []


def lar(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('access_segment', b)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('access_segment_ok', b)))
    return e, []


def lsl(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('load_segment_limit', b)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('load_segment_limit_ok', b)))
    return e, []


def fclex(ir, instr):
    # XXX TODO
    return [], None


def fnclex(ir, instr):
    # XXX TODO
    return [], None


def l_str(ir, instr, a):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('load_tr_segment_selector',
                                               m2_expr.ExprInt32(0))))
    return e, []


def movd(ir, instr, a, b):
    e = []
    if a in regs_mm_expr:
        e.append(m2_expr.ExprAff(a, m2_expr.ExprCompose([(b, 0, 32),
                                                         (m2_expr.ExprInt32(0), 32, 64)])))
    elif a in regs_xmm_expr:
        e.append(m2_expr.ExprAff(a, m2_expr.ExprCompose([(b, 0, 32),
                                                         (m2_expr.ExprInt(0, 96), 32, 128)])))
    else:
        e.append(m2_expr.ExprAff(a, b[:32]))
    return e, []

def movdqu(ir, instr, a, b):
    # XXX TODO alignement check
    return [m2_expr.ExprAff(a, b)], []


def movapd(ir, instr, a, b):
    # XXX TODO alignement check
    return [m2_expr.ExprAff(a, b)], []


def andps(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('&', a, b)))
    return e, []


def orps(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('|', a, b)))
    return e, []


def xorps(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('^', a, b)))
    return e, []


def rdmsr(ir, instr):
    msr_addr = m2_expr.ExprId('MSR') + m2_expr.ExprInt32(8) * mRCX[instr.mode][:32]
    e = []
    e.append(m2_expr.ExprAff(mRAX[instr.mode][:32], m2_expr.ExprMem(msr_addr, 32)))
    e.append(m2_expr.ExprAff(mRDX[instr.mode][:32], m2_expr.ExprMem(msr_addr + m2_expr.ExprInt_from(msr_addr, 4), 32)))
    return e, []

def wrmsr(ir, instr):
    msr_addr = m2_expr.ExprId('MSR') + m2_expr.ExprInt32(8) * mRCX[instr.mode][:32]
    e = []
    src = m2_expr.ExprCompose([(mRAX[instr.mode][:32], 0, 32),
                               (mRDX[instr.mode][:32], 32, 64)])
    e.append(m2_expr.ExprAff(m2_expr.ExprMem(msr_addr, 64), src))
    return e, []

### MMX/SSE/AVX operations
###

def vec_op_clip(op, size):
    """
    Generate simd operations
    @op: the operator
    @size: size of an element
    """
    def vec_op_clip_instr(ir, instr, a, b):
        if op == '-':
            return [m2_expr.ExprAff(a[:size], a[:size] - b[:size])], []
        else:
            return [m2_expr.ExprAff(a[:size], m2_expr.ExprOp(op, a[:size], b[:size]))], []
    return vec_op_clip_instr

# Generic vertical operation
def vec_vertical_sem(op, elt_size, reg_size, a, b):
    assert(reg_size % elt_size == 0)
    n = reg_size/elt_size
    if op == '-':
        ops = [((a[i*elt_size:(i+1)*elt_size] - b[i*elt_size:(i+1)*elt_size]),
               i*elt_size, (i+1)*elt_size) for i in xrange(0, n)]
    else:
        ops = [(m2_expr.ExprOp(op, a[i*elt_size:(i+1)*elt_size],
                               b[i*elt_size:(i+1)*elt_size]),
                i*elt_size,
                (i+1)*elt_size) for i in xrange(0, n)]

    return m2_expr.ExprCompose(ops)

def float_vec_vertical_sem(op, elt_size, reg_size, a, b):
    assert(reg_size % elt_size == 0)
    n = reg_size/elt_size

    x_to_int, int_to_x = {32: ('float_to_int_%d', 'int_%d_to_float'),
                          64: ('double_to_int_%d', 'int_%d_to_double')}[elt_size]
    if op == '-':
        ops = [(m2_expr.ExprOp(x_to_int % elt_size,
                               m2_expr.ExprOp(int_to_x % elt_size, a[i*elt_size:(i+1)*elt_size]) -
                               m2_expr.ExprOp(int_to_x % elt_size, b[i*elt_size:(i+1)*elt_size])),
                i*elt_size, (i+1)*elt_size) for i in xrange(0, n)]
    else:
        ops = [(m2_expr.ExprOp(x_to_int % elt_size,
                               m2_expr.ExprOp(op,
                                              m2_expr.ExprOp(int_to_x % elt_size, a[i*elt_size:(i+1)*elt_size]),
                                              m2_expr.ExprOp(int_to_x % elt_size, b[i*elt_size:(i+1)*elt_size]))),
                i*elt_size, (i+1)*elt_size) for i in xrange(0, n)]

    return m2_expr.ExprCompose(ops)

def __vec_vertical_instr_gen(op, elt_size, sem):
    def vec_instr(ir, instr, a, b):
        e = []
        if isinstance(b, m2_expr.ExprMem):
            b = m2_expr.ExprMem(b.arg, a.size)
        reg_size = a.size
        e.append(m2_expr.ExprAff(a, sem(op, elt_size, reg_size, a, b)))
        return e, []
    return vec_instr

def vec_vertical_instr(op, elt_size):
    return __vec_vertical_instr_gen(op, elt_size, vec_vertical_sem)

def float_vec_vertical_instr(op, elt_size):
    return __vec_vertical_instr_gen(op, elt_size, float_vec_vertical_sem)

### Integer arithmetic
###

## Additions
##

# SSE
paddb = vec_vertical_instr('+', 8)
paddw = vec_vertical_instr('+', 16)
paddd = vec_vertical_instr('+', 32)
paddq = vec_vertical_instr('+', 64)

## Substractions
##

# SSE
psubb = vec_vertical_instr('-', 8)
psubw = vec_vertical_instr('-', 16)
psubd = vec_vertical_instr('-', 32)
psubq = vec_vertical_instr('-', 64)

### Floating-point arithmetic
###

# SSE
addss = vec_op_clip('+', 32)
addsd = vec_op_clip('+', 64)
addps = float_vec_vertical_instr('+', 32)
addpd = float_vec_vertical_instr('+', 64)
subss = vec_op_clip('-', 32)
subsd = vec_op_clip('-', 64)
subps = float_vec_vertical_instr('-', 32)
subpd = float_vec_vertical_instr('-', 64)
mulss = vec_op_clip('*', 32)
mulsd = vec_op_clip('*', 64)
mulps = float_vec_vertical_instr('*', 32)
mulpd = float_vec_vertical_instr('*', 64)
divss = vec_op_clip('/', 32)
divsd = vec_op_clip('/', 64)
divps = float_vec_vertical_instr('/', 32)
divpd = float_vec_vertical_instr('/', 64)

### Logical (floating-point)
###

# MMX/SSE/AVX
def pand(ir, instr, a, b):
    e = []
    c = a & b
    # No flag affected
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def por(ir, instr, a, b):
    e = []
    c = a | b
    e.append(m2_expr.ExprAff(a, c))
    return e, []


def pminsw(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprCond((a - b).msb(), a, b)))
    return e, []

def cvtdq2pd(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:64], m2_expr.ExprOp('int_32_to_double', b[:32])))
    e.append(m2_expr.ExprAff(a[64:128], m2_expr.ExprOp('int_32_to_double', b[32:64])))
    return e, []

def cvtdq2ps(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('int_32_to_float', b[:32])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('int_32_to_float', b[32:64])))
    e.append(m2_expr.ExprAff(a[64:96], m2_expr.ExprOp('int_32_to_float', b[64:96])))
    e.append(m2_expr.ExprAff(a[96:128], m2_expr.ExprOp('int_32_to_float', b[96:128])))
    return e, []

def cvtpd2dq(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('double_to_int_32', b[:64])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('double_to_int_32', b[64:128])))
    e.append(m2_expr.ExprAff(a[64:128], m2_expr.ExprInt64(0)))
    return e, []

def cvtpd2pi(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('double_to_int_32', b[:64])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('double_to_int_32', b[64:128])))
    return e, []

def cvtpd2ps(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('double_to_float', b[:64])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('double_to_float', b[64:128])))
    e.append(m2_expr.ExprAff(a[64:128], m2_expr.ExprInt64(0)))
    return e, []

def cvtpi2pd(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:64], m2_expr.ExprOp('int_32_to_double', b[:32])))
    e.append(m2_expr.ExprAff(a[64:128], m2_expr.ExprOp('int_32_to_double', b[32:64])))
    return e, []

def cvtpi2ps(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('int_32_to_float', b[:32])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('int_32_to_float', b[32:64])))
    return e, []

def cvtps2dq(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('float_to_int_32', b[:32])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('float_to_int_32', b[32:64])))
    e.append(m2_expr.ExprAff(a[64:96], m2_expr.ExprOp('float_to_int_32', b[64:96])))
    e.append(m2_expr.ExprAff(a[96:128], m2_expr.ExprOp('float_to_int_32', b[96:128])))
    return e, []

def cvtps2pd(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:64], m2_expr.ExprOp('float_to_double', b[:32])))
    e.append(m2_expr.ExprAff(a[64:128], m2_expr.ExprOp('float_to_double', b[32:64])))
    return e, []

def cvtps2pi(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('float_to_int_32', b[:32])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('float_to_int_32', b[32:64])))
    return e, []

def cvtsd2si(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('double_to_int_32', b[:64])))
    return e, []

def cvtsd2ss(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('double_to_float', b[:64])))
    return e, []

def cvtsi2sd(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:64], m2_expr.ExprOp('int_32_to_double', b[:32])))
    return e, []

def cvtsi2ss(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('int_32_to_float', b[:32])))
    return e, []

def cvtss2sd(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:64], m2_expr.ExprOp('float_to_double', b[:32])))
    return e, []

def cvtss2si(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('float_to_int_32', b[:32])))
    return e, []

def cvttpd2pi(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('double_trunc_to_int_32', b[:64])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('double_trunc_to_int_32', b[64:128])))
    return e, []

def cvttpd2dq(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('double_trunc_to_int_32', b[:64])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('double_trunc_to_int_32', b[64:128])))
    e.append(m2_expr.ExprAff(a[64:128], m2_expr.ExprInt64(0)))
    return e, []

def cvttps2dq(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('float_trunc_to_int_32', b[:32])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('float_trunc_to_int_32', b[32:64])))
    e.append(m2_expr.ExprAff(a[64:96], m2_expr.ExprOp('float_trunc_to_int_32', b[64:96])))
    e.append(m2_expr.ExprAff(a[96:128], m2_expr.ExprOp('float_trunc_to_int_32', b[96:128])))
    return e, []

def cvttps2pi(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('float_trunc_to_int_32', b[:32])))
    e.append(m2_expr.ExprAff(a[32:64], m2_expr.ExprOp('float_trunc_to_int_32', b[32:64])))
    return e, []

def cvttsd2si(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('double_trunc_to_int_32', b[:64])))
    return e, []

def cvttss2si(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a[:32], m2_expr.ExprOp('float_trunc_to_int_32', b[:32])))
    return e, []

def movss(ir, instr, a, b):
    e = []
    if not isinstance(a, m2_expr.ExprMem) and not isinstance(b, m2_expr.ExprMem):
        # Source and Destination xmm
        e.append(m2_expr.ExprAff(a[:32], b[:32]))
    elif not isinstance(b, m2_expr.ExprMem) and isinstance(a, m2_expr.ExprMem):
        # Source XMM Destination Mem
        e.append(m2_expr.ExprAff(a, b[:32]))
    else:
        # Source Mem Destination XMM
        e.append(m2_expr.ExprAff(a, m2_expr.ExprCompose([(b, 0, 32),
                                                         (m2_expr.ExprInt(0, 96), 32, 128)])))
    return e, []


def ucomiss(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('ucomiss_zf', a[:32], b[:32])))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprOp('ucomiss_pf', a[:32], b[:32])))
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprOp('ucomiss_cf', a[:32], b[:32])))

    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt1(0)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt1(0)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprInt1(0)))

    return e, []

mnemo_func = {'mov': mov,
              'xchg': xchg,
              'movzx': movzx,
              'movsx': movsx,
              'movsxd': movsx,
              'lea': lea,
              'add': add,
              'xadd': xadd,
              'adc': adc,
              'sub': sub,
              'sbb': sbb,
              'neg': neg,
              'not': l_not,
              'cmp': l_cmp,
              'xor': xor,
              'pxor': pxor,
              'or': l_or,
              'and': l_and,
              'test': l_test,
              'rol': l_rol,
              'ror': l_ror,
              'rcl': rcl,
              'rcr': rcr,
              'sar': sar,
              'shr': shr,
              'shrd_cl': shrd_cl,
              'sal': sal,
              'shl': shl,
              'shld_cl': shld_cl,
              'shld': shld,
              'cmc': cmc,
              'clc': clc,
              'stc': stc,
              'cld': cld,
              'std': std,
              'cli': cli,
              'sti': sti,
              'bsf': bsf,
              'bsr': bsr,
              'inc': inc,
              'dec': dec,
              'push': push,
              'pushw': pushw,
              'pop': pop,
              'popw': popw,
              'sete': sete,
              'setnz': setnz,
              'setl': setl,
              'setg': setg,
              'setge': setge,
              'seta': seta,
              'setae': setae,
              'setb': setb,
              'setbe': setbe,
              'setns': setns,
              'sets': sets,
              'seto': seto,
              'setp': setp,
              'setpe': setp,
              'setnp': setnp,
              'setpo': setnp,
              'setle': setle,
              'setng': setle,
              'setna': setna,
              'setnbe': setnbe,
              'setno': setno,
              'setnc': setnb,
              'setz': sete,
              'setne': setnz,
              'setnb': setae,
              'setnae': setb,
              'setc': setb,
              'setnge': setl,
              'setnl': setge,
              'setnle': setg,
              'setalc': setalc,
              'bswap': bswap,
              'cmpsb': lambda ir, instr: cmps(ir, instr, 8),
              'cmpsw': lambda ir, instr: cmps(ir, instr, 16),
              'cmpsd': lambda ir, instr: cmps(ir, instr, 32),
              'scasb': lambda ir, instr: scas(ir, instr, 8),
              'scasw': lambda ir, instr: scas(ir, instr, 16),
              'scasd': lambda ir, instr: scas(ir, instr, 32),
              'pushfd': pushfd,
              'pushfq': pushfq,
              'pushfw': pushfw,
              'popfd': popfd,
              'popfq': popfd,
              'popfw': popfw,
              'pushad': pushad,
              'pusha': pushad,
              'popad': popad,
              'popa': popad,
              'call': call,
              'ret': ret,
              'retf': retf,
              'leave': leave,
              'enter': enter,
              'jmp': jmp,
              'jmpf': jmpf,
              'jz': jz,
              'je': jz,
              'jcxz': jcxz,
              'jecxz': jecxz,
              'jrcxz': jrcxz,
              'jnz': jnz,
              'jp': jp,
              'jpe': jp,
              'jnp': jnp,
              'ja': ja,
              'jae': jae,
              'jb': jb,
              'jbe': jbe,
              'jg': jg,
              'jge': jge,
              'jl': jl,
              'jle': jle,
              'js': js,
              'jns': jns,
              'jo': jo,
              'jno': jno,
              'jecxz': jecxz,
              'loop': loop,
              'loopne': loopne,
              'loope': loope,
              'div': div,
              'mul': mul,
              'imul': imul,
              'idiv': idiv,

              'cbw': cbw,
              'cwde': cwde,
              'cdqe': cdqe,

              'cwd': cwd,
              'cdq': cdq,
              'cqo': cqo,

              'daa': daa,
              'das': das,
              'aam': aam,
              'aad': aad,
              'aaa': aaa,
              'aas': aas,
              'shrd': shrd,
              'stosb': lambda ir, instr: stos(ir, instr, 8),
              'stosw': lambda ir, instr: stos(ir, instr, 16),
              'stosd': lambda ir, instr: stos(ir, instr, 32),
              'stosq': lambda ir, instr: stos(ir, instr, 64),

              'lodsb': lambda ir, instr: lods(ir, instr, 8),
              'lodsw': lambda ir, instr: lods(ir, instr, 16),
              'lodsd': lambda ir, instr: lods(ir, instr, 32),
              'lodsq': lambda ir, instr: lods(ir, instr, 64),

              'movsb': lambda ir, instr: movs(ir, instr, 8),
              'movsw': lambda ir, instr: movs(ir, instr, 16),
              'movsd': movsd_dispatch,
              'movsq': lambda ir, instr: movs(ir, instr, 64),
              'fcomp': fcomp,
              'fcompp': fcompp,
              'ficomp': ficomp,
              'fucom': fucom,
              'fucomp': fucomp,
              'fucompp': fucompp,
              'comiss': comiss,
              'comisd': comisd,
              'fcomi': fcomi,
              'fcomip': fcomip,
              'nop': nop,
              'fnop': nop,  # XXX
              'hlt': hlt,
              'rdtsc': rdtsc,
              'fst': fst,
              'fstp': fstp,
              'fist': fist,
              'fistp': fistp,
              'fisttp': fisttp,
              'fld': fld,
              'fldz': fldz,
              'fld1': fld1,
              'fldl2t': fldl2t,
              'fldpi': fldpi,
              'fldln2': fldln2,
              'fldl2e': fldl2e,
              'fldlg2': fldlg2,
              'fild': fild,
              'fadd': fadd,
              'fiadd': fiadd,
              'fisub': fisub,
              'fisubr': fisubr,
              'fpatan': fpatan,
              'fprem': fprem,
              'fprem1': fprem1,
              'fninit': fninit,
              'fyl2x': fyl2x,
              'faddp': faddp,
              'fsub': fsub,
              'fsubp': fsubp,
              'fsubr': fsubr,
              'fsubrp': fsubrp,
              'fmul': fmul,
              'fimul': fimul,
              'fmulp': fmulp,
              'fdiv': fdiv,
              'fdivr': fdivr,
              'fdivrp': fdivrp,
              'fidiv': fidiv,
              'fidivr': fidivr,
              'fdivp': fdivp,
              'fxch': fxch,
              'fptan': fptan,
              'frndint': frndint,
              'fsin': fsin,
              'fcos': fcos,
              'fsincos': fsincos,
              'fscale': fscale,
              'f2xm1': f2xm1,
              'fchs': fchs,
              'fsqrt': fsqrt,
              'fabs': fabs,
              'fnstsw': fnstsw,
              'fnstcw': fnstcw,
              'fldcw': fldcw,
              'fwait': fwait,
              'fcmovb':   fcmovb,
              'fcmove':   fcmove,
              'fcmovbe':  fcmovbe,
              'fcmovu':   fcmovu,
              'fcmovnb':  fcmovnb,
              'fcmovne':  fcmovne,
              'fcmovnbe': fcmovnbe,
              'fcmovnu':  fcmovnu,
              'fnstenv': fnstenv,
              'sidt': sidt,
              'sldt': sldt,
              'arpl': arpl,
              'cmovz': cmovz,
              'cmove': cmovz,
              'cmovnz': cmovnz,
              'cmovpe':cmovpe,
              'cmovnp':cmovnp,
              'cmovge': cmovge,
              'cmovnl': cmovge,
              'cmovg': cmovg,
              'cmovl': cmovl,
              'cmova': cmova,
              'cmovae': cmovae,
              'cmovbe': cmovbe,
              'cmovb': cmovb,
              'cmovnge': cmovl,
              'cmovle': cmovle,
              'cmovng': cmovle,
              'cmovo': cmovo,
              'cmovno': cmovno,
              'cmovs': cmovs,
              'cmovns': cmovns,
              'icebp': icebp,
              'int': l_int,
              'xlat': xlat,
              'bt': bt,
              'cpuid': cpuid,
              'jo': jo,
              'fcom': fcom,
              'ftst': ftst,
              'fxam': fxam,
              'ficom': ficom,
              'fcomi': fcomi,
              'fcomip': fcomip,
              'fucomi': fucomi,
              'fucomip': fucomip,
              'insb': lambda ir, instr: ins(ir, instr, 8),
              'insw': lambda ir, instr: ins(ir, instr, 16),
              'insd': lambda ir, instr: ins(ir, instr, 32),
              'btc': btc,
              'bts': bts,
              'btr': btr,
              'into': into,
              'in': l_in,
              'outsb': lambda ir, instr: l_outs(ir, instr, 8),
              'outsw': lambda ir, instr: l_outs(ir, instr, 16),
              'outsd': lambda ir, instr: l_outs(ir, instr, 32),

              'out': l_out,
              "sysenter": l_sysenter,
              "cmpxchg": cmpxchg,
              "lds": lds,
              "les": les,
              "lss": lss,
              "lfs": lfs,
              "lgs": lgs,
              "lahf": lahf,
              "sahf": sahf,
              "lar": lar,
              "lsl": lsl,
              "fclex": fclex,
              "fnclex": fnclex,
              "str": l_str,
              "movd": movd,
              "movdqu":movdqu,
              "movdqa":movdqu,
              "movapd": movapd, # XXX TODO alignement check
              "movupd": movapd, # XXX TODO alignement check
              "movaps": movapd, # XXX TODO alignement check
              "movups": movapd, # XXX TODO alignement check
              "andps": andps,
              "andpd": andps,
              "orps": orps,
              "orpd": orps,
              "xorps": xorps,
              "xorpd": xorps,

              "pminsw": pminsw,
              "cvtdq2pd": cvtdq2pd,
              "cvtdq2ps": cvtdq2ps,
              "cvtpd2dq": cvtpd2dq,
              "cvtpd2pi": cvtpd2pi,
              "cvtpd2ps": cvtpd2ps,
              "cvtpi2pd": cvtpi2pd,
              "cvtpi2ps": cvtpi2ps,
              "cvtps2dq": cvtps2dq,
              "cvtps2pd": cvtps2pd,
              "cvtps2pi": cvtps2pi,
              "cvtsd2si": cvtsd2si,
              "cvtsd2ss": cvtsd2ss,
              "cvtsi2sd": cvtsi2sd,
              "cvtsi2ss": cvtsi2ss,
              "cvtss2sd": cvtss2sd,
              "cvtss2si": cvtss2si,
              "cvttpd2pi": cvttpd2pi,
              "cvttpd2dq": cvttpd2dq,
              "cvttps2dq": cvttps2dq,
              "cvttps2pi": cvttps2pi,
              "cvttsd2si": cvttsd2si,
              "cvttss2si": cvttss2si,









              "movss": movss,

              "ucomiss": ucomiss,

              ####
              #### MMX/AVX/SSE operations

              ### Arithmetic (integers)
              ###

              ## Additions
              # SSE
              "paddb": paddb,
              "paddw": paddw,
              "paddd": paddd,
              "paddq": paddq,

              # Substractions
              # SSE
              "psubb": psubb,
              "psubw": psubw,
              "psubd": psubd,
              "psubq": psubq,

              ### Arithmetic (floating-point)
              ###

              ## Additions
              # SSE
              "addss": addss,
              "addsd": addsd,
              "addps": addps,
              "addpd": addpd,

              ## Substractions
              # SSE
              "subss": subss,
              "subsd": subsd,
              "subps": subps,
              "subpd": subpd,

              ## Multiplications
              # SSE
              "mulss": mulss,
              "mulsd": mulsd,
              "mulps": mulps,
              "mulpd": mulpd,

              ## Divisions
              # SSE
              "divss": divss,
              "divsd": divsd,
              "divps": divps,
              "divpd": divpd,

              ### Logical (floating-point)
              ###

              "pand": pand,
              "por": por,

              "rdmsr": rdmsr,
              "wrmsr": wrmsr,

              }


class ir_x86_16(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_x86, 16, symbol_pool)
        self.do_stk_segm = False
        self.do_ds_segm = False
        self.do_str_segm = False
        self.do_all_segm = False
        self.pc = IP
        self.sp = SP
        self.IRDst = m2_expr.ExprId('IRDst', 16)

    def mod_pc(self, instr, instr_ir, extra_ir):
        pass

    def get_ir(self, instr):
        args = instr.args[:]
        args = [arg.replace_expr(float_replace) for arg in args]
        my_ss = None
        if self.do_ds_segm:
            my_ss = DS
        if self.do_all_segm and instr.additional_info.g2.value:
            my_ss = {1: CS, 2: SS, 3: DS, 4: ES, 5: FS, 6: GS}[
                instr.additional_info.g2.value]
        if my_ss is not None:
            for i, a in enumerate(args):
                if isinstance(a, m2_expr.ExprMem) and not a.is_op_segm():
                    args[i] = m2_expr.ExprMem(m2_expr.ExprOp('segm', my_ss,
                                                             a.arg), a.size)

        if not instr.name.lower() in mnemo_func:
            raise NotImplementedError("Mnemonic %s not implemented" % instr.name)

        instr_ir, extra_ir = mnemo_func[
            instr.name.lower()](self, instr, *args)
        self.mod_pc(instr, instr_ir, extra_ir)

        self.mod_pc(instr, instr_ir, extra_ir)
        instr.additional_info.except_on_instr = False
        if instr.additional_info.g1.value & 6 == 0 or \
                not instr.name in repeat_mn:
            return instr_ir, extra_ir
        if instr.name == "MOVSD" and len(instr.args) == 2:
            return instr_ir, extra_ir

        instr.additional_info.except_on_instr = True
        # get instruction size
        s = {"B": 8, "W": 16, "D": 32, 'Q': 64}[instr.name[-1]]
        size = instr.v_opmode()
        c_reg = mRCX[instr.mode][:size]
        out_ir = []
        zf_val = None
        # set if zf is tested (cmps, scas)
        for e in instr_ir:  # +[updt_c]:
            if e.dst == zf:
                zf_val = e.src

        cond_dec = m2_expr.ExprCond(c_reg - m2_expr.ExprInt_from(c_reg, 1),
                                    m2_expr.ExprInt1(0), m2_expr.ExprInt1(1))
        # end condition
        if zf_val is None:
            c_cond = cond_dec
        elif instr.additional_info.g1.value & 2:  # REPNE
            c_cond = cond_dec | zf
        elif instr.additional_info.g1.value & 4:  # REP
            c_cond = cond_dec | (zf ^ m2_expr.ExprInt1(1))

        # gen while
        lbl_do = m2_expr.ExprId(self.gen_label(), instr.mode)
        lbl_end = m2_expr.ExprId(self.gen_label(), instr.mode)
        lbl_skip = m2_expr.ExprId(self.get_next_label(instr), instr.mode)
        lbl_next = m2_expr.ExprId(self.get_next_label(instr), instr.mode)

        for b in extra_ir:
            for ir in b.irs:
                for i, e in enumerate(ir):
                    src = e.src.replace_expr({lbl_next: lbl_end})
                    ir[i] = m2_expr.ExprAff(e.dst, src)
        cond_bloc = []
        cond_bloc.append(m2_expr.ExprAff(c_reg,
                                         c_reg - m2_expr.ExprInt_from(c_reg,
                                                                      1)))
        cond_bloc.append(m2_expr.ExprAff(self.IRDst, m2_expr.ExprCond(c_cond,
                                                                      lbl_skip,
                                                                      lbl_do)))
        cond_bloc = irbloc(lbl_end.name, [cond_bloc])
        e_do = instr_ir

        c = irbloc(lbl_do.name, [e_do])
        c.except_automod = False
        e_n = [m2_expr.ExprAff(self.IRDst, m2_expr.ExprCond(c_reg, lbl_do,
                                                            lbl_skip))]
        return e_n, [cond_bloc, c] + extra_ir

    def expr_fix_regs_for_mode(self, e, mode=64):
        return e.replace_expr(replace_regs[mode])

    def expraff_fix_regs_for_mode(self, e, mode=64):
        dst = self.expr_fix_regs_for_mode(e.dst, mode)
        src = self.expr_fix_regs_for_mode(e.src, mode)
        return m2_expr.ExprAff(dst, src)

    def irbloc_fix_regs_for_mode(self, irbloc, mode=64):
        for irs in irbloc.irs:
            for i, e in enumerate(irs):
                """
                special case for 64 bits:
                if destination is a 32 bit reg, zero extend the 64 bit reg
                """
                if mode == 64:
                    if (isinstance(e.dst, m2_expr.ExprId) and \
                            e.dst.size == 32 and \
                            e.dst in replace_regs[64]):
                        src = self.expr_fix_regs_for_mode(e.src, mode)
                        dst = replace_regs[64][e.dst].arg
                        e = m2_expr.ExprAff(dst, src.zeroExtend(64))
                irs[i] = self.expr_fix_regs_for_mode(e, mode)
        irbloc.dst = self.expr_fix_regs_for_mode(irbloc.dst, mode)


class ir_x86_32(ir_x86_16):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_x86, 32, symbol_pool)
        self.do_stk_segm = False
        self.do_ds_segm = False
        self.do_str_segm = False
        self.do_all_segm = False
        self.pc = EIP
        self.sp = ESP
        self.IRDst = m2_expr.ExprId('IRDst', 32)


class ir_x86_64(ir_x86_16):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_x86, 64, symbol_pool)
        self.do_stk_segm = False
        self.do_ds_segm = False
        self.do_str_segm = False
        self.do_all_segm = False
        self.pc = RIP
        self.sp = RSP
        self.IRDst = m2_expr.ExprId('IRDst', 64)

    def mod_pc(self, instr, instr_ir, extra_ir):
        # fix RIP for 64 bit
        for i, expr in enumerate(instr_ir):
            dst, src = expr.dst, expr.src
            if dst != self.pc:
                dst = dst.replace_expr(
                    {self.pc: m2_expr.ExprInt64(instr.offset + instr.l)})
            src = src.replace_expr(
                {self.pc: m2_expr.ExprInt64(instr.offset + instr.l)})
            instr_ir[i] = m2_expr.ExprAff(dst, src)
        for b in extra_ir:
            for irs in b.irs:
                for i, expr in enumerate(irs):
                    dst, src = expr.dst, expr.src
                    if dst != self.pc:
                        new_pc = m2_expr.ExprInt64(instr.offset + instr.l)
                        dst = dst.replace_expr({self.pc: new_pc})
                    src = src.replace_expr(
                        {self.pc: m2_expr.ExprInt64(instr.offset + instr.l)})
                    irs[i] = m2_expr.ExprAff(dst, src)
