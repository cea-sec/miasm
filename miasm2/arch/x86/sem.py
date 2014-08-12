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

from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp
from miasm2.arch.x86.regs import *
from miasm2.arch.x86.arch import mn_x86, repeat_mn, replace_regs
from miasm2.core.asmbloc import expr_is_int_or_label
from miasm2.ir.ir import ir, irbloc
import math
import struct
from regs import *

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


float_list = [
    float_st0,
    float_st1,
    float_st2,
    float_st3,
    float_st4,
    float_st5,
    float_st6,
    float_st7,
]


# XXX TODO make default check against 0 or not 0 (same eq as in C)


def update_flag_zf(a):
    return [ExprAff(zf, ExprCond(a, ExprInt_from(zf, 0), ExprInt_from(zf, 1)))]


def update_flag_nf(a):
    return [ExprAff(nf, a.msb())]


def update_flag_pf(a):
    return [ExprAff(pf, ExprOp('parity', a & ExprInt_from(a, 0xFF)))]


def update_flag_af(a):
    return [ExprAff(af, ExprCond((a & ExprInt_from(a, 0x10)),
                                 ExprInt_from(af, 1), ExprInt_from(af, 0)))]


def update_flag_znp(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    e += update_flag_pf(a)
    return e


def update_flag_logic(a):
    e = []
    e += update_flag_znp(a)
    e.append(ExprAff(of, ExprInt_from(of, 0)))
    e.append(ExprAff(cf, ExprInt_from(cf, 0)))
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


def update_flag_add_cf(a, b, c):
    return ExprAff(cf, (((a ^ b) ^ c) ^ ((a ^ c) & (~(a ^ b)))).msb())


def update_flag_add_of(a, b, c):
    return ExprAff(of, (((a ^ c) & (~(a ^ b)))).msb())


# checked: ok for sbb add because b & c before +cf
def update_flag_sub_cf(a, b, c):
    return ExprAff(cf, (((a ^ b) ^ c) ^ ((a ^ c) & (a ^ b))).msb())


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


def set_float_cs_eip(instr):
    e = []
    # XXX TODO check float updt
    e.append(ExprAff(float_eip, ExprInt_from(float_eip, instr.offset)))
    e.append(ExprAff(float_cs, CS))
    return e


def mov(ir, instr, a, b):
    if a in [ES, CS, SS, DS, FS, GS]:
        b = b[:a.size]
    if b in [ES, CS, SS, DS, FS, GS]:
        b = b.zeroExtend(a.size)
    e = [ExprAff(a, b)]
    return None, e, []


def xchg(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    e.append(ExprAff(b, a))
    return None, e, []


def movzx(ir, instr, a, b):
    e = [ExprAff(a, b.zeroExtend(a.size))]
    return None, e, []


def movsx(ir, instr, a, b):
    e = [ExprAff(a, b.signExtend(a.size))]
    return None, e, []


def lea(ir, instr, a, b):
    src = b.arg
    if src.size > a.size:
        src = src[:a.size]
    e = [ExprAff(a, src.zeroExtend(a.size))]
    return None, e, []


def add(ir, instr, a, b):
    e = []
    c = a + b
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_add(a, b, c)
    e.append(ExprAff(a, c))
    return None, e, []


def xadd(ir, instr, a, b):
    e = []
    c = a + b
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_add(b, a, c)
    e.append(ExprAff(b, a))
    e.append(ExprAff(a, c))
    return None, e, []


def adc(ir, instr, a, b):
    e = []
    c = a + (b + ExprCompose([(ExprInt_fromsize(a.size - 1, 0), 1, a.size),
                              (cf, 0, 1)]))
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_add(a, b, c)
    e.append(ExprAff(a, c))
    return None, e, []


def sub(ir, instr, a, b):
    e = []
    c = a - b
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_sub(a, b, c)
    e.append(ExprAff(a, c))
    return None, e, []

# a-(b+cf)


def sbb(ir, instr, a, b):
    e = []
    c = a - (b + ExprCompose([(ExprInt_fromsize(a.size - 1, 0), 1, a.size),
                              (cf, 0, 1)]))
    e += update_flag_arith(c)
    e += update_flag_af(c)
    e += update_flag_sub(a, b, c)
    e.append(ExprAff(a, c))
    return None, e, []


def neg(ir, instr, b):
    e = []
    a = ExprInt_from(b, 0)

    c = a - b
    e += update_flag_arith(c)
    e += update_flag_sub(a, b, c)
    e += update_flag_af(c)
    e.append(ExprAff(b, c))
    return None, e, []


def l_not(ir, instr, b):
    e = []
    c = ~b
    e.append(ExprAff(b, c))
    return None, e, []


def l_cmp(ir, instr, a, b):
    e = []
    c = a - b
    e += update_flag_arith(c)
    e += update_flag_sub(a, b, c)
    e += update_flag_af(c)
    return None, e, []


def xor(ir, instr, a, b):
    e = []
    c = a ^ b
    e += update_flag_logic(c)
    e.append(ExprAff(a, c))
    return None, e, []


def l_or(ir, instr, a, b):
    e = []
    c = a | b
    e += update_flag_logic(c)
    e.append(ExprAff(a, c))
    return None, e, []


def l_and(ir, instr, a, b):
    e = []
    c = a & b
    e += update_flag_logic(c)
    e.append(ExprAff(a, c))
    return None, e, []


def l_test(ir, instr, a, b):
    e = []
    c = a & b
    e += update_flag_logic(c)
    return None, e, []



def get_shift(a, b):
    # b.size must match a
    b = b.zeroExtend(a.size)
    if a.size == 64:
        shift = b & ExprInt_from(b, 0x3f)
    else:
        shift = b & ExprInt_from(b, 0x1f)
    shift = expr_simp(shift)
    return shift


def l_rol(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = ExprOp('<<<', a, shifter)

    new_cf = c[:1]
    e.append(ExprAff(cf, new_cf))
    # hack (only valid if b=1)
    e.append(ExprAff(of, c.msb() ^ new_cf))
    e.append(ExprAff(a, c))
    return None, e, []


def l_ror(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = ExprOp('>>>', a, shifter)

    e.append(ExprAff(cf, c.msb()))
    # hack (only valid if b=1): when count == 1: a = msb-1(dest)
    e.append(ExprAff(of, (c ^ a).msb()))
    e.append(ExprAff(a, c))
    return None, e, []


def rcl(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = ExprOp('<<<c_rez', a, shifter, cf.zeroExtend(a.size))
    new_cf = ExprOp('<<<c_cf', a, shifter, cf.zeroExtend(a.size))[:1]

    e.append(ExprAff(cf, new_cf))
    # hack (only valid if b=1)
    e.append(ExprAff(of, c.msb() ^ new_cf))
    e.append(ExprAff(a, c))
    return None, e, []


def rcr(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = ExprOp('>>>c_rez', a, shifter, cf.zeroExtend(a.size))
    new_cf = ExprOp('>>>c_cf', a, shifter, cf.zeroExtend(a.size))[:1]

    e.append(ExprAff(cf, new_cf))
    # hack (only valid if b=1)
    e.append(ExprAff(of, (a ^ c).msb()))
    e.append(ExprAff(a, c))

    return None, e, []


def sar(ir, instr, a, b):

    shifter = get_shift(a, b)
    c = ExprOp('a>>', a, shifter)

    lbl_do = ExprId(ir.gen_label(), instr.mode)
    lbl_skip = ExprId(ir.get_next_label(instr), instr.mode)

    new_cf = ExprOp('a>>', a, (shifter - ExprInt_from(a, 1)))[:1]

    e_do = [
        ExprAff(cf, new_cf),
        ExprAff(of, ExprInt_from(of, 0)),
        ExprAff(a, c)
    ]

    e_do += update_flag_znp(c)

    # dont generate conditional shifter on constant
    if isinstance(shifter, ExprInt):
        if int(shifter.arg) != 0:
            return None, e_do, []
        else:
            return None, [], []

    return ExprCond(shifter, lbl_do, lbl_skip), [], [irbloc(lbl_do.name, lbl_skip, [e_do])]


def shr(ir, instr, a, b):
    e = []
    # TODO FIX AS SAR!
    shifter = get_shift(a, b)
    c = ExprOp('>>', a, shifter)

    new_cf = ExprOp('>>', a, (shifter - ExprInt_from(a, 1)))[:1]
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e.append(ExprAff(of, a.msb()))
    e += update_flag_znp(c)
    e.append(ExprAff(a, c))
    return None, e, []


def shrd_cl(ir, instr, a, b):
    e = []
    opmode, admode = s, instr.v_admode()
    shifter = mRCX[instr.mode][:8].zeroExtend(a.size) & ExprInt_from(a, 0x1f)
    c = (a >> shifter) | (b << (ExprInt_from(a, a.size) - shifter))
    new_cf = (a >> (shifter - ExprInt_from(a, 1)))[:1]
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e.append(ExprAff(of, a.msb()))
    e += update_flag_znp(c)
    e.append(ExprAff(a, c))
    return None, e, []


def shrd(ir, instr, a, b, c):
    e = []
    shifter = get_shift(a, c)

    d = (a >> shifter) | (b << (ExprInt_from(a, a.size) - shifter))
    new_cf = (a >> (shifter - ExprInt_from(a, 1)))[:1]
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e.append(ExprAff(of, a.msb()))
    e += update_flag_znp(d)
    e.append(ExprAff(a, d))
    return None, e, []


def sal(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = ExprOp('a<<', a, shifter)
    new_cf = (a >> (ExprInt_from(a, a.size) - shifter))[:1]
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e += update_flag_znp(c)
    e.append(ExprAff(of, c.msb() ^ new_cf))
    e.append(ExprAff(a, c))
    return None, e, []


def shl(ir, instr, a, b):
    e = []
    shifter = get_shift(a, b)
    c = a << shifter
    new_cf = (a >> (ExprInt_from(a, a.size) - shifter))[:1]
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e += update_flag_znp(c)
    e.append(ExprAff(of, c.msb() ^ new_cf))
    e.append(ExprAff(a, c))
    return None, e, []


def shld_cl(ir, instr, a, b):
    return shld(ir, instr, a, b, ecx)


def shld(ir, instr, a, b, c):
    e = []
    shifter = c.zeroExtend(a.size) & ExprInt_from(a, 0x1f)
    c = ExprOp('|',
               a << shifter,
               b >> (ExprInt_from(a, a.size) - shifter)
               )

    new_cf = (a >> (ExprInt_from(a, a.size) - shifter))[:1]
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    # XXX todo: don't update flag if shifter is 0
    e += update_flag_znp(c)
    e.append(ExprAff(of, c.msb() ^ new_cf))
    e.append(ExprAff(a, ExprCond(shifter,
                                 c,
                                 a)))
    return None, e, []


# XXX todo ###
def cmc(ir, instr):
    e = [ExprAff(cf, ExprCond(cf, ExprInt_from(cf, 0), ExprInt_from(cf, 1)))]
    return None, e, []


def clc(ir, instr):
    e = [ExprAff(cf, ExprInt_from(cf, 0))]
    return None, e, []


def stc(ir, instr):
    e = [ExprAff(cf, ExprInt_from(cf, 1))]
    return None, e, []


def cld(ir, instr):
    e = [ExprAff(df, ExprInt_from(df, 0))]
    return None, e, []


def std(ir, instr):
    e = [ExprAff(df, ExprInt_from(df, 1))]
    return None, e, []


def cli(ir, instr):
    e = [ExprAff(i_f, ExprInt_from(i_f, 0))]
    return None, e, []


def sti(ir, instr):
    e = [ExprAff(exception_flags, ExprInt32(EXCEPT_PRIV_INSN))]
    e = []  # XXX TODO HACK
    return None, e, []


def inc(ir, instr, a):
    e = []
    b = ExprInt_from(a, 1)
    c = a + b
    e += update_flag_arith(c)
    e += update_flag_af(c)

    e.append(update_flag_add_of(a, b, c))
    e.append(ExprAff(a, c))
    return None, e, []

def dec(ir, instr, a):
    e = []
    b = ExprInt_from(a, -1)
    c = a + b
    e += update_flag_arith(c)
    e += update_flag_af(c)

    e.append(update_flag_add_of(a, b, c))
    e.append(ExprAff(a, c))
    return None, e, []


def push(ir, instr, a):
    e = []
    s = instr.mode
    size = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    # special case segment regs
    if a in [ES, CS, SS, DS, FS, GS]:
        pass
    if not s in [16, 32, 64]:
        raise ValueError('bad size stacker!')
    if isinstance(a, ExprInt):
        a = ExprInt_fromsize(s, a.arg)

    c = mRSP[instr.mode][:s] - ExprInt_fromsize(s, s / 8)
    e.append(ExprAff(mRSP[instr.mode][:s], c))
    # we sub vopmode to stack, but mem access is arg size wide
    if ir.do_stk_segm:
        c = ExprOp('segm', SS, c)
    e.append(ExprAff(ExprMem(c, a.size), a))
    return None, e, []


def pop(ir, instr, a):
    e = []
    s = instr.mode
    size = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    # special case segment regs
    if a in [ES, CS, SS, DS, FS, GS]:
        s = admode
    if not s in [16, 32, 64]:
        raise ValueError('bad size stacker!')
    new_esp = mRSP[instr.mode][:s] + ExprInt_fromsize(s, s / 8)
    e.append(ExprAff(mRSP[instr.mode][:s], new_esp))
    # XXX FIX XXX for pop [esp]
    if isinstance(a, ExprMem):
        a = a.replace_expr({mRSP[instr.mode]: new_esp})
    c = mRSP[instr.mode][:s]
    if ir.do_stk_segm:
        c = ExprOp('segm', SS, c)
    e.append(ExprAff(a, ExprMem(c, a.size)))
    return None, e, []


def sete(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(zf, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return None, e, []


def setnz(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(zf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return None, e, []


def setl(ir, instr, a):
    e = []
    e.append(
        ExprAff(a, ExprCond(nf - of, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return None, e, []


def setg(ir, instr, a):
    e = []
    a0 = ExprInt_from(a, 0)
    a1 = ExprInt_from(a, 1)
    e.append(ExprAff(a, ExprCond(zf, a0, a1) & ExprCond(nf - of, a0, a1)))
    return None, e, []


def setge(ir, instr, a):
    e = []
    e.append(
        ExprAff(a, ExprCond(nf - of, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return None, e, []


def seta(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(cf | zf,
                                 ExprInt_from(a, 0),
                                 ExprInt_from(a, 1))))

    return None, e, []


def setae(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(cf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return None, e, []


def setb(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(cf, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return None, e, []


def setbe(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(cf | zf,
                                 ExprInt_from(a, 1),
                                 ExprInt_from(a, 0)))
             )
    return None, e, []


def setns(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(nf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return None, e, []


def sets(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(nf, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return None, e, []


def seto(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(of, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return None, e, []


def setp(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(pf, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return None, e, []


def setnp(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(pf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return None, e, []


def setle(ir, instr, a):
    e = []
    a0 = ExprInt_from(a, 0)
    a1 = ExprInt_from(a, 1)
    e.append(ExprAff(a, ExprCond(zf, a1, a0) | ExprCond(nf ^ of, a1, a0)))
    return None, e, []


def setna(ir, instr, a):
    e = []
    a0 = ExprInt_from(a, 0)
    a1 = ExprInt_from(a, 1)
    e.append(ExprAff(a, ExprCond(cf, a1, a0) & ExprCond(zf, a1, a0)))
    return None, e, []


def setnbe(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(cf | zf,
                                 ExprInt_from(a, 0),
                                 ExprInt_from(a, 1)))
             )
    return None, e, []


def setno(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(of, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return None, e, []


def setnb(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprCond(cf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return None, e, []


def setalc(ir, instr):
    a = mRAX[instr.mode][0:8]
    e = []
    e.append(
        ExprAff(a, ExprCond(cf, ExprInt_from(a, 0xff), ExprInt_from(a, 0))))
    return None, e, []


def bswap(ir, instr, a):
    e = []
    if a.size == 16:
        c = ExprCompose([(a[:8],        8, 16),
                         (a[8:16],      0,  8),
                         ])
    elif a.size == 32:
        c = ExprCompose([(a[:8],      24, 32),
                         (a[8:16],    16, 24),
                         (a[16:24],   8, 16),
                         (a[24:32],   0, 8),
                         ])
    elif a.size == 64:
        c = ExprCompose([(a[:8],      56, 64),
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
    e.append(ExprAff(a, c))
    return None, e, []


def cmps(ir, instr, size):
    lbl_cmp = ExprId(ir.gen_label(), instr.mode)
    lbl_df_0 = ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = ExprId(ir.gen_label(), instr.mode)
    lbl_next = ExprId(ir.get_next_label(instr), instr.mode)

    s = instr.v_admode()
    a = ExprMem(mRDI[instr.mode][:s], size)
    b = ExprMem(mRSI[instr.mode][:s], size)

    dummy, e, extra = l_cmp(ir, instr, a, b)

    e0 = []
    e0.append(ExprAff(a.arg, a.arg + ExprInt_from(a.arg, size / 8)))
    e0.append(ExprAff(b.arg, b.arg + ExprInt_from(b.arg, size / 8)))
    e0 = irbloc(lbl_df_0.name, lbl_next, [e0])

    e1 = []
    e1.append(ExprAff(a.arg, a.arg - ExprInt_from(a.arg, size / 8)))
    e1.append(ExprAff(b.arg, b.arg - ExprInt_from(b.arg, size / 8)))
    e1 = irbloc(lbl_df_1.name, lbl_next, [e1])

    return ExprCond(df, lbl_df_1, lbl_df_0), e, [e0, e1]


def scas(ir, instr, size):
    lbl_cmp = ExprId(ir.gen_label(), instr.mode)
    lbl_df_0 = ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = ExprId(ir.gen_label(), instr.mode)
    lbl_next = ExprId(ir.get_next_label(instr), instr.mode)

    s = instr.v_admode()
    a = ExprMem(mRDI[instr.mode][:s], size)

    dummy, e, extra = l_cmp(ir, instr, mRAX[instr.mode][:size], a)

    e0 = []
    e0.append(ExprAff(a.arg, a.arg + ExprInt_from(a.arg, size / 8)))
    e0 = irbloc(lbl_df_0.name, lbl_next, [e0])

    e1 = []
    e1.append(ExprAff(a.arg, a.arg - ExprInt_from(a.arg, size / 8)))
    e1 = irbloc(lbl_df_1.name, lbl_next, [e1])

    return ExprCond(df, lbl_df_1, lbl_df_0), e, [e0, e1]


def compose_eflag(s=32):
    args = []

    regs = [cf, ExprInt1(1), pf, ExprInt1(
        0), af, ExprInt1(0), zf, nf, tf, i_f, df, of]
    for i in xrange(len(regs)):
        args.append((regs[i], i, i + 1))

    args.append((iopl, 12, 14))

    if s == 32:
        regs = [nt, ExprInt1(0), rf, vm, ac, vif, vip, i_d]
    elif s == 16:
        regs = [nt, ExprInt1(0)]
    else:
        raise ValueError('unk size')
    for i in xrange(len(regs)):
        args.append((regs[i], i + 14, i + 15))
    if s == 32:
        args.append((ExprInt_fromsize(10, 0), 22, 32))
    return ExprCompose(args)


def pushfd(ir, instr):
    return push(ir, instr, compose_eflag())


def pushfw(ir, instr):
    return push(ir, instr, compose_eflag(16))


def popfd(ir, instr):
    tmp = ExprMem(mRSP[instr.mode])
    e = []
    e.append(ExprAff(cf, ExprSlice(tmp, 0, 1)))
    e.append(ExprAff(pf, ExprSlice(tmp, 2, 3)))
    e.append(ExprAff(af, ExprSlice(tmp, 4, 5)))
    e.append(ExprAff(zf, ExprSlice(tmp, 6, 7)))
    e.append(ExprAff(nf, ExprSlice(tmp, 7, 8)))
    e.append(ExprAff(tf, ExprSlice(tmp, 8, 9)))
    e.append(ExprAff(i_f, ExprSlice(tmp, 9, 10)))
    e.append(ExprAff(df, ExprSlice(tmp, 10, 11)))
    e.append(ExprAff(of, ExprSlice(tmp, 11, 12)))
    e.append(ExprAff(iopl, ExprSlice(tmp, 12, 14)))
    e.append(ExprAff(nt, ExprSlice(tmp, 14, 15)))
    e.append(ExprAff(rf, ExprSlice(tmp, 16, 17)))
    e.append(ExprAff(vm, ExprSlice(tmp, 17, 18)))
    e.append(ExprAff(ac, ExprSlice(tmp, 18, 19)))
    e.append(ExprAff(vif, ExprSlice(tmp, 19, 20)))
    e.append(ExprAff(vip, ExprSlice(tmp, 20, 21)))
    e.append(ExprAff(i_d, ExprSlice(tmp, 21, 22)))
    e.append(ExprAff(mRSP[instr.mode], mRSP[instr.mode] + ExprInt32(4)))
    e.append(ExprAff(exception_flags,
                     ExprCond(ExprSlice(tmp, 8, 9),
                              ExprInt32(EXCEPT_SOFT_BP),
                              exception_flags
                              )
                     )
             )
    return None, e, []


def popfw(ir, instr):
    tmp = ExprMem(esp)
    e = []
    e.append(ExprAff(cf, ExprSlice(tmp, 0, 1)))
    e.append(ExprAff(pf, ExprSlice(tmp, 2, 3)))
    e.append(ExprAff(af, ExprSlice(tmp, 4, 5)))
    e.append(ExprAff(zf, ExprSlice(tmp, 6, 7)))
    e.append(ExprAff(nf, ExprSlice(tmp, 7, 8)))
    e.append(ExprAff(tf, ExprSlice(tmp, 8, 9)))
    e.append(ExprAff(i_f, ExprSlice(tmp, 9, 10)))
    e.append(ExprAff(df, ExprSlice(tmp, 10, 11)))
    e.append(ExprAff(of, ExprSlice(tmp, 11, 12)))
    e.append(ExprAff(iopl, ExprSlice(tmp, 12, 14)))
    e.append(ExprAff(nt, ExprSlice(tmp, 14, 15)))
    e.append(ExprAff(esp, esp + ExprInt32(2)))
    return None, e, []


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
        c = mRSP[instr.mode][:s] + ExprInt_fromsize(s, -(s / 8) * (i + 1))
        e.append(ExprAff(ExprMem(c, s), regs[i]))
    e.append(ExprAff(mRSP[instr.mode][:s], c))
    return None, e, []


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
        c = myesp + ExprInt_from(myesp, ((s / 8) * i))
        e.append(ExprAff(regs[i], ExprMem(c, s)))

    c = myesp + ExprInt_from(myesp, ((s / 8) * (i + 1)))
    e.append(ExprAff(myesp, c))

    return None, e, []


def call(ir, instr, dst):
    e = []
    # opmode, admode = instr.opmode, instr.admode
    s = dst.size
    meip = mRIP[instr.mode]
    opmode, admode = s, instr.v_admode()
    myesp = mRSP[instr.mode][:opmode]
    n = ExprId(ir.get_next_label(instr), instr.mode)


    if (isinstance(dst, ExprOp) and dst.op == "segm"):
        # call far
        if instr.mode != 16:
            raise NotImplementedError('add 32 bit support!')
        segm = dst.args[0]
        base = dst.args[1]
        m1 = segm.zeroExtend(CS.size)
        m2 = base.zeroExtend(meip.size)
        e.append(ExprAff(CS, m1))
        e.append(ExprAff(meip, m2))

        c = myesp + ExprInt_fromsize(s, -s/8)
        e.append(ExprAff(ExprMem(c, size=s).zeroExtend(s), CS.zeroExtend(s)))

        c = myesp + ExprInt_fromsize(s, -2*s/8)
        e.append(ExprAff(ExprMem(c, size=s).zeroExtend(s), meip.zeroExtend(s)))

        c = myesp + ExprInt_fromsize(s, (-2*s) / 8)
        e.append(ExprAff(myesp, c))
        return meip, e, []


    c = myesp + ExprInt_fromsize(s, (-s / 8))
    e.append(ExprAff(myesp, c))
    if ir.do_stk_segm:
        c = ExprOp('segm', SS, c)
    e.append(ExprAff(ExprMem(c, size=s), n))
    e.append(ExprAff(meip, dst.zeroExtend(instr.mode)))
    if not expr_is_int_or_label(dst):
        dst = meip
    return dst, e, []


def ret(ir, instr, a=None):
    e = []
    s = instr.mode
    meip = mRIP[instr.mode]
    opmode, admode = instr.v_opmode(), instr.v_admode()
    s = opmode
    myesp = mRSP[instr.mode][:s]

    if a is None:
        a = ExprInt_fromsize(s, 0)
        e.append(ExprAff(myesp, (myesp + (ExprInt_fromsize(s, (s / 8))))))
    else:
        a = a.zeroExtend(s)
        e.append(ExprAff(myesp, (myesp + (ExprInt_fromsize(s, (s / 8)) + a))))
    c = myesp
    if ir.do_stk_segm:
        c = ExprOp('segm', SS, c)
    e.append(ExprAff(meip, ExprMem(c, size=s).zeroExtend(s)))
    return meip, e, []


def retf(ir, instr, a=None):
    e = []
    s = instr.mode
    meip = mRIP[instr.mode]
    opmode, admode = instr.v_opmode(), instr.v_admode()
    if a is None:
        a = ExprInt_fromsize(s, 0)
    s = opmode
    myesp = mRSP[instr.mode][:s]

    a = a.zeroExtend(s)

    e.append(ExprAff(myesp, (myesp + (ExprInt_fromsize(s, (s / 8)) + a))))

    c = myesp
    if ir.do_stk_segm:
        c = ExprOp('segm', SS, c)
    e.append(ExprAff(meip, ExprMem(c, size=s).zeroExtend(s)))
    # e.append(ExprAff(meip, ExprMem(c, size = s)))
    c = myesp + ExprInt_fromsize(s, (s / 8))
    if ir.do_stk_segm:
        c = ExprOp('segm', SS, c)
    e.append(ExprAff(CS, ExprMem(c, size=16)))

    return meip, e, []


def leave(ir, instr):
    opmode, admode = instr.v_opmode(), instr.v_admode()
    s = opmode
    myesp = mRSP[instr.mode]

    e = []
    e.append(ExprAff(mRBP[s], ExprMem(mRBP[instr.mode], size=s)))
    e.append(ExprAff(myesp,
    ExprInt_fromsize(instr.mode, instr.mode / 8) + mRBP[instr.mode]))
    return None, e, []


def enter(ir, instr, a, b):
    opmode, admode = instr.v_opmode(), instr.v_admode()
    s = opmode
    myesp = mRSP[instr.mode][:s]
    myebp = mRBP[instr.mode][:s]

    a = a.zeroExtend(s)

    e = []
    esp_tmp = myesp - ExprInt_fromsize(s, s / 8)
    e.append(ExprAff(ExprMem(esp_tmp,
                             size=s),
                     myebp))
    e.append(ExprAff(myebp, esp_tmp))
    e.append(ExprAff(myesp, myesp - (a + ExprInt_fromsize(s, s / 8))))
    return None, e, []


def jmp(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    e.append(ExprAff(meip, dst))  # dst.zeroExtend(instr.mode)))
    if isinstance(dst, ExprMem):
        dst = meip
    return dst, e, []


def jmpf(ir, instr, a):
    e = []
    meip = mRIP[instr.mode]
    s = instr.mode
    if (isinstance(a, ExprOp) and a.op == "segm"):
        segm = a.args[0]
        base = a.args[1]
        m1 = segm.zeroExtend(CS.size)#ExprMem(ExprOp('segm', segm, base), 16)
        m2 = base.zeroExtend(meip.size)#ExprMem(ExprOp('segm', segm, base + ExprInt_from(base, 2)), s)
    else:
        m1 = ExprMem(a, 16)
        m2 = ExprMem(a + ExprInt_from(a, 2), meip.size)

    e.append(ExprAff(CS, m1))
    e.append(ExprAff(meip, m2))
    return meip, e, []


def jz(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(zf, dst, n).zeroExtend(instr.mode)
    e = [ExprAff(meip, dst_o)]
    return dst_o, e, []


def jcxz(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(mRCX[instr.mode][:16], n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jecxz(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(mRCX[instr.mode][:32], n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jrcxz(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(mRCX[instr.mode], n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jnz(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(zf, n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jp(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(pf, dst, n).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jnp(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(pf, n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def ja(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(cf | zf, n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jae(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(cf, n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jb(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(cf, dst, n).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jbe(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(cf | zf, dst, n).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jge(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(nf - of, n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jg(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(zf | (nf - of), n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jl(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(nf - of, dst, n).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jle(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(zf | (nf - of), dst, n).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def js(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(nf, dst, n).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jns(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(nf, n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jo(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(of, dst, n).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def jno(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    n = ExprId(ir.get_next_label(instr), dst.size)
    dst_o = ExprCond(of, n, dst).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))
    return dst_o, e, []


def loop(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    s = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = ExprId(ir.get_next_label(instr), instr.mode)
    c = myecx - ExprInt_from(myecx, 1)
    e.append(ExprAff(myecx, c))
    e.append(ExprAff(meip, ExprCond(c, dst, n).zeroExtend(instr.mode)))
    dst_o = ExprCond(myecx, dst, n).zeroExtend(instr.mode)
    return dst_o, e, []


def loopne(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    s = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = ExprId(ir.get_next_label(instr), instr.mode)

    c = ExprCond(mRCX[instr.mode][:s] - ExprInt_fromsize(s, 1),
                 ExprInt1(1),
                 ExprInt1(0))
    c &= zf ^ ExprInt1(1)

    e.append(ExprAff(myecx, myecx - ExprInt_from(myecx, 1)))
    e.append(ExprAff(meip, ExprCond(c, dst, n).zeroExtend(instr.mode)))

    # for dst, ecx has been modified!
    c = ExprCond(mRCX[instr.mode][:s],
                 ExprInt1(1),
                 ExprInt1(0))
    c &= zf ^ ExprInt1(1)
    dst_o = ExprCond(c, dst, n).zeroExtend(instr.mode)
    return dst_o, e, []


def loope(ir, instr, dst):
    e = []
    meip = mRIP[instr.mode]
    s = instr.v_opmode()
    opmode, admode = s, instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = ExprId(ir.get_next_label(instr), instr.mode)
    c = ExprCond(mRCX[instr.mode][:s] - ExprInt_fromsize(s, 1),
                 ExprInt1(1),
                 ExprInt1(0))
    c &= zf
    e.append(ExprAff(myecx, myecx - ExprInt_from(myecx, 1)))
    dst_o = ExprCond(c, dst, n).zeroExtend(instr.mode)
    e.append(ExprAff(meip, dst_o))

    # for dst, ecx has been modified!
    c = ExprCond(mRCX[instr.mode][:s],
                 ExprInt1(1),
                 ExprInt1(0))
    c &= zf
    dst_o = ExprCond(c, dst, n).zeroExtend(instr.mode)
    return dst_o, e, []


# XXX size to do; eflag
def div(ir, instr, a):
    e = []
    s = a.size
    if s == 8:
        b = mRAX[instr.mode][:16]
    elif s == 16:
        s1, s2 = mRDX[instr.mode][:16], mRAX[instr.mode][:16]
        b = ExprCompose([(s1, 0, 16),
                         (s1, 16, 32)])
    elif s == 32:
        s1, s2 = mRDX[instr.mode][:32], mRAX[instr.mode][:32]
        b = ExprCompose([(s2, 0, 32),
                         (s1, 32, 64)])
    elif s == 64:
        s1, s2 = mRDX[instr.mode], mRAX[instr.mode]
        b = ExprCompose([(s2, 0, 64),
                         (s1, 64, 128)])
    else:
        raise ValueError('div arg not impl', a)

    c_d = ExprOp('udiv', b, a.zeroExtend(b.size))
    c_r = ExprOp('umod', b, a.zeroExtend(b.size))

    # if 8 bit div, only ax is affected
    if s == 8:
        e.append(ExprAff(b, ExprCompose([(c_d[:8], 0, 8),
                                         (c_r[:8], 8, 16)])))
    else:
        e.append(ExprAff(s1, c_r[:s]))
        e.append(ExprAff(s2, c_d[:s]))
    return None, e, []

# XXX size to do; eflag


def idiv(ir, instr, a):
    e = []
    s = a.size

    if s == 8:
        b = mRAX[instr.mode][:16]
    elif s == 16:
        s1, s2 = mRDX[instr.mode][:16], mRAX[instr.mode][:16]
        b = ExprCompose([(s1, 0, 16),
                         (s1, 16, 32)])
    elif s == 32:
        s1, s2 = mRDX[instr.mode][:32], mRAX[instr.mode][:32]
        b = ExprCompose([(s2, 0, 32),
                         (s1, 32, 64)])
    else:
        raise ValueError('div arg not impl', a)

    c_d = ExprOp('idiv', b, a.signExtend(b.size))
    c_r = ExprOp('imod', b, a.signExtend(b.size))

    # if 8 bit div, only ax is affected
    if s == 8:
        e.append(ExprAff(b, ExprCompose([(c_d[:8], 0, 8),
                                         (c_r[:8], 8, 16)])))
    else:
        e.append(ExprAff(s1, c_r[:s]))
        e.append(ExprAff(s2, c_d[:s]))
    return None, e, []

# XXX size to do; eflag


def mul(ir, instr, a):
    e = []
    size = a.size
    if a.size in [16, 32, 64]:
        result = ExprOp('*',
                        mRAX[instr.mode][:size].zeroExtend(size * 2),
                        a.zeroExtend(size * 2))
        e.append(ExprAff(mRAX[instr.mode][:size], result[:size]))
        e.append(ExprAff(mRDX[instr.mode][:size], result[size:size * 2]))

    elif a.size == 8:
        result = ExprOp('*',
                        mRAX[instr.mode][:8].zeroExtend(16),
                        a.zeroExtend(16))
        e.append(ExprAff(mRAX[instr.mode][:16], result))
    else:
        raise ValueError('unknow size')

    e.append(ExprAff(of, ExprCond(result[size:size * 2],
                                  ExprInt1(1),
                                  ExprInt1(0))))
    e.append(ExprAff(cf, ExprCond(result[size:size * 2],
                                  ExprInt1(1),
                                  ExprInt1(0))))

    return None, e, []


def imul(ir, instr, a, b=None, c=None):
    e = []
    size = a.size
    if b is None:
        if size in [16, 32, 64]:
            result = ExprOp('*',
                            mRAX[instr.mode][:size].signExtend(size * 2),
                            a.signExtend(size * 2))
            e.append(ExprAff(mRAX[instr.mode][:size], result[:size]))
            e.append(ExprAff(mRDX[instr.mode][:size], result[size:size * 2]))
        elif size == 8:
            dst = mRAX[instr.mode][:16]
            result = ExprOp('*',
                            mRAX[instr.mode][:8].signExtend(16),
                            a.signExtend(16))

            e.append(ExprAff(dst, result))
        e.append(
            ExprAff(cf, ExprCond(result - result[:size].signExtend(size * 2),
                                 ExprInt1(1),
                    ExprInt1(0))))
        e.append(
            ExprAff(of, ExprCond(result - result[:size].signExtend(size * 2),
                                 ExprInt1(1),
                    ExprInt1(0))))

    else:
        if c is None:
            c = b
            b = a
        result = ExprOp('*',
                        b.signExtend(size * 2),
                        c.signExtend(size * 2))
        e.append(ExprAff(a, result[:size]))

        e.append(
            ExprAff(cf, ExprCond(result - result[:size].signExtend(size * 2),
                                 ExprInt1(1),
                    ExprInt1(0))))
        e.append(
            ExprAff(of, ExprCond(result - result[:size].signExtend(size * 2),
                                 ExprInt1(1),
                    ExprInt1(0))))
    return None, e, []


def cbw(ir, instr):
    e = []
    tempAL = mRAX[instr.mode][:8]
    tempAX = mRAX[instr.mode][:16]
    e.append(ExprAff(tempAX, tempAL.signExtend(16)))
    return None, e, []


def cwde(ir, instr):
    e = []
    tempAX = mRAX[instr.mode][:16]
    tempEAX = mRAX[instr.mode][:32]
    e.append(ExprAff(tempEAX, tempAX.signExtend(32)))
    return None, e, []


def cdqe(ir, instr):
    e = []
    tempEAX = mRAX[instr.mode][:32]
    tempRAX = mRAX[instr.mode][:64]
    e.append(ExprAff(tempRAX, tempEAX.signExtend(64)))
    return None, e, []


def cwd(ir, instr):
    e = []
    tempAX = mRAX[instr.mode][:16]
    tempDX = mRDX[instr.mode][:16]
    c = tempAX.signExtend(32)
    e.append(ExprAff(tempAX, c[:16]))
    e.append(ExprAff(tempDX, c[16:32]))
    return None, e, []


def cdq(ir, instr):
    e = []
    tempEAX = mRAX[instr.mode][:32]
    tempEDX = mRDX[instr.mode][:32]
    c = tempEAX.signExtend(64)
    e.append(ExprAff(tempEAX, c[:32]))
    e.append(ExprAff(tempEDX, c[32:64]))
    return None, e, []


def cqo(ir, instr):
    e = []
    tempRAX = mRAX[instr.mode][:64]
    tempRDX = mRDX[instr.mode][:64]
    c = tempEAX.signExtend(128)
    e.append(ExprAff(tempRAX, c[:64]))
    e.append(ExprAff(tempRDX, c[64:127]))
    return None, e, []


def stos(ir, instr, size):
    lbl_df_0 = ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = ExprId(ir.gen_label(), instr.mode)
    lbl_next = ExprId(ir.get_next_label(instr), instr.mode)

    s = instr.v_admode()

    addr_o = mRDI[instr.mode][:s]
    addr = addr_o
    addr_p = addr + ExprInt_from(addr, size / 8)
    addr_m = addr - ExprInt_from(addr, size / 8)
    if ir.do_str_segm:
        mss = ES
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        addr = ExprOp('segm', mss, addr)

    b = mRAX[instr.mode][:size]

    e0 = []
    e0.append(ExprAff(addr_o, addr_p))
    e0 = irbloc(lbl_df_0.name, lbl_next, [e0])

    e1 = []
    e1.append(ExprAff(addr_o, addr_m))
    e1 = irbloc(lbl_df_1.name, lbl_next, [e1])

    e = []
    e.append(ExprAff(ExprMem(addr, size), b))

    return ExprCond(df, lbl_df_1, lbl_df_0), e, [e0, e1]


def lods(ir, instr, size):
    lbl_df_0 = ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = ExprId(ir.gen_label(), instr.mode)
    lbl_next = ExprId(ir.get_next_label(instr), instr.mode)
    e = []
    s = instr.v_admode()

    addr_o = mRSI[instr.mode][:s]
    addr = addr_o
    addr_p = addr + ExprInt_from(addr, size / 8)
    addr_m = addr - ExprInt_from(addr, size / 8)
    if ir.do_str_segm:
        mss = DS
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        addr = ExprOp('segm', mss, addr)

    b = mRAX[instr.mode][:size]

    e0 = []
    e0.append(ExprAff(addr_o, addr_p))
    e0 = irbloc(lbl_df_0.name, lbl_next, [e0])

    e1 = []
    e1.append(ExprAff(addr_o, addr_m))
    e1 = irbloc(lbl_df_1.name, lbl_next, [e1])

    e = []
    e.append(ExprAff(b, ExprMem(addr, size)))

    return ExprCond(df, lbl_df_1, lbl_df_0), e, [e0, e1]


def movs(ir, instr, size):
    lbl_df_0 = ExprId(ir.gen_label(), instr.mode)
    lbl_df_1 = ExprId(ir.gen_label(), instr.mode)
    lbl_next = ExprId(ir.get_next_label(instr), instr.mode)

    s = instr.v_admode()
    # a = ExprMem(mRDI[instr.mode][:s], size)
    # b = ExprMem(mRSI[instr.mode][:s], size)

    a = mRDI[instr.mode][:s]
    b = mRSI[instr.mode][:s]

    e = []
    src = b
    dst = a
    if ir.do_str_segm:
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        src = ExprOp('segm', DS, src)
        dst = ExprOp('segm', ES, dst)
    e.append(ExprAff(ExprMem(dst, size), ExprMem(src, size)))

    e0 = []
    e0.append(ExprAff(a, a + ExprInt_from(a, size / 8)))
    e0.append(ExprAff(b, b + ExprInt_from(b, size / 8)))
    e0 = irbloc(lbl_df_0.name, lbl_next, [e0])

    e1 = []
    e1.append(ExprAff(a, a - ExprInt_from(a, size / 8)))
    e1.append(ExprAff(b, b - ExprInt_from(b, size / 8)))
    e1 = irbloc(lbl_df_1.name, lbl_next, [e1])

    return ExprCond(df, lbl_df_1, lbl_df_0), e, [e0, e1]


def float_prev(flt):
    if not flt in float_list:
        return None
    i = float_list.index(flt)
    if i == 0:
        raise ValueError('broken index')
    flt = float_list[i - 1]
    return flt


def float_pop(avoid_flt=None):
    avoid_flt = float_prev(avoid_flt)
    e = []
    if avoid_flt != float_st0:
        e.append(ExprAff(float_st0, float_st1))
    if avoid_flt != float_st1:
        e.append(ExprAff(float_st1, float_st2))
    if avoid_flt != float_st2:
        e.append(ExprAff(float_st2, float_st3))
    if avoid_flt != float_st3:
        e.append(ExprAff(float_st3, float_st4))
    if avoid_flt != float_st4:
        e.append(ExprAff(float_st4, float_st5))
    if avoid_flt != float_st5:
        e.append(ExprAff(float_st5, float_st6))
    if avoid_flt != float_st6:
        e.append(ExprAff(float_st6, float_st7))
    if avoid_flt != float_st7:
        e.append(ExprAff(float_st7, ExprInt_from(float_st7, 0)))
    e.append(
        ExprAff(float_stack_ptr, float_stack_ptr - ExprInt_fromsize(3, 1)))
    return e

# XXX TODO


def fcom(ir, instr, a, b = None):

    if b is None:
        b = a
        a = float_st0

    e = []
    if isinstance(b, ExprMem):
        b = ExprOp('mem_%.2d_to_double'%b.size, b)


    e.append(ExprAff(float_c0, ExprOp('fcom_c0', a, b)))
    e.append(ExprAff(float_c1, ExprOp('fcom_c1', a, b)))
    e.append(ExprAff(float_c2, ExprOp('fcom_c2', a, b)))
    e.append(ExprAff(float_c3, ExprOp('fcom_c3', a, b)))

    e += set_float_cs_eip(instr)
    return None, e, []


def ficom(ir, instr, a, b = None):

    if b is None:
        b = a
        a = float_st0

    e = []

    e.append(ExprAff(float_c0, ExprOp('fcom_c0', a, b.zeroExtend(a.size))))
    e.append(ExprAff(float_c1, ExprOp('fcom_c1', a, b.zeroExtend(a.size))))
    e.append(ExprAff(float_c2, ExprOp('fcom_c2', a, b.zeroExtend(a.size))))
    e.append(ExprAff(float_c3, ExprOp('fcom_c3', a, b.zeroExtend(a.size))))

    e += set_float_cs_eip(instr)
    return None, e, []



def fcomi(ir, instr, a):
    # Invalid emulation
    InvalidEmulation


def fcomip(ir, instr, a):
    # Invalid emulation
    InvalidEmulation


def fucomi(ir, instr, a):
    # Invalid emulation
    InvalidEmulation


def fucomip(ir, instr, a, b):
    e = []
    # XXX TODO add exception on NaN
    e.append(ExprAff(cf, ExprOp('fcom_c0', a, b)))
    #e.append(ExprAff(float_c1, ExprOp('fcom_c1', a, b)))
    e.append(ExprAff(pf, ExprOp('fcom_c2', a, b)))
    e.append(ExprAff(zf, ExprOp('fcom_c3', a, b)))

    e += float_pop()

    e += set_float_cs_eip(instr)
    return None, e, []


def fcomp(ir, instr, a, b = None):
    dst, e, extra = fcom(ir, instr, a, b)
    e += float_pop()
    e += set_float_cs_eip(instr)
    return dst, e, extra

def ficomp(ir, instr, a, b = None):
    dst, e, extra = ficom(ir, instr, a, b)
    e += float_pop()
    e += set_float_cs_eip(instr)
    return dst, e, extra


def fld(ir, instr, a):
    if isinstance(a, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % a.size, a)
    else:
        src = a

    e = []
    e.append(ExprAff(float_st7, float_st6))
    e.append(ExprAff(float_st6, float_st5))
    e.append(ExprAff(float_st5, float_st4))
    e.append(ExprAff(float_st4, float_st3))
    e.append(ExprAff(float_st3, float_st2))
    e.append(ExprAff(float_st2, float_st1))
    e.append(ExprAff(float_st1, float_st0))
    e.append(ExprAff(float_st0, src))
    e.append(
        ExprAff(float_stack_ptr, float_stack_ptr + ExprInt_fromsize(3, 1)))

    e += set_float_cs_eip(instr)
    return None, e, []


def fst(ir, instr, a):
    e = []
    if isinstance(a, ExprMem):
        src = ExprOp('double_to_mem_%2d' % a.size, float_st0)
    else:
        src = float_st0
    e.append(ExprAff(a, src))

    e += set_float_cs_eip(instr)
    return None, e, []


def fstp(ir, instr, a):
    dst, e, extra = fst(ir, instr, a)
    e += float_pop(a)
    return dst, e, extra


def fist(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprOp('double_to_int_%d' % a.size, float_st0)))

    e += set_float_cs_eip(instr)
    return None, e, []

def fistp(ir, instr, a):
    dst, e, extra = fist(ir, instr, a)
    e += float_pop(a)
    return dst, e, extra

def fist(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprOp('double_to_int_%d' % a.size, float_st0)))

    e += set_float_cs_eip(instr)
    return None, e, []

def fisttp(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprOp('double_trunc_to_int_%d' % a.size, float_st0)))

    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return None, e, []


def fild(ir, instr, a):
    # XXXXX
    src = ExprOp('int_%.2d_to_double' % a.size, a)
    e = []
    e += set_float_cs_eip(instr)
    dst, e_fld, extra = fld(ir, instr, src)
    e += e_fld
    return dst, e, extra


def fldz(ir, instr):
    return fld(ir, instr, ExprOp('int_32_to_double', ExprInt32(0)))


def fld1(ir, instr):
    return fld(ir, instr, ExprOp('int_32_to_double', ExprInt32(1)))


def fldl2e(ir, instr):
    x = struct.pack('d', 1 / math.log(2))
    x = struct.unpack('Q', x)[0]
    return fld(ir, instr, ExprOp('mem_64_to_double', ExprInt64(x)))


def fldlg2(ir, instr):
    x = struct.pack('d', math.log10(2))
    x = struct.unpack('Q', x)[0]
    return fld(ir, instr, ExprOp('mem_64_to_double', ExprInt64(x)))


def fadd(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fadd', a, src)))

    e += set_float_cs_eip(instr)
    return None, e, []

def fiadd(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fiadd', a, src)))
    e += set_float_cs_eip(instr)
    return None, e, []


def faddp(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(float_prev(a), ExprOp('fadd', a, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return None, e, []


def fninit(ir, instr):
    e = []
    e += set_float_cs_eip(instr)
    return None, e, []


def fnstenv(ir, instr, a):
    e = []
    # XXX TODO tag word, ...
    status_word = ExprCompose([(ExprInt8(0), 0, 8),
                               (float_c0,           8, 9),
                               (float_c1,           9, 10),
                               (float_c2,           10, 11),
                               (float_stack_ptr,    11, 14),
                               (float_c3,           14, 15),
                               (ExprInt1(0), 15, 16),
                               ])

    s = instr.mode
    ad = ExprMem(a.arg, size=16)
    e.append(ExprAff(ad, float_control))
    ad = ExprMem(a.arg + ExprInt_from(a.arg, s / 8 * 1), size=16)
    e.append(ExprAff(ad, status_word))
    ad = ExprMem(a.arg + ExprInt_from(a.arg, s / 8 * 3), size=s)
    e.append(ExprAff(ad, float_eip[:s]))
    ad = ExprMem(a.arg + ExprInt_from(a.arg, s / 8 * 4), size=16)
    e.append(ExprAff(ad, float_cs))
    ad = ExprMem(a.arg + ExprInt_from(a.arg, s / 8 * 5), size=s)
    e.append(ExprAff(ad, float_address[:s]))
    ad = ExprMem(a.arg + ExprInt_from(a.arg, s / 8 * 6), size=16)
    e.append(ExprAff(ad, float_ds))
    return None, e, []


def fsub(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fsub', a, src)))
    e += set_float_cs_eip(instr)
    return None, e, []

def fsubp(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(float_prev(a), ExprOp('fsub', a, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return None, e, []


def fsubr(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fsub', src, a)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fmul(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fmul', a, src)))
    e += set_float_cs_eip(instr)
    return None, e, []

def fimul(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fimul', a, src)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fdiv(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fdiv', a, src)))
    e += set_float_cs_eip(instr)
    return None, e, []

def fdivr(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fdiv', src, a)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fidiv(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fidiv', a, src)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fidivr(ir, instr, a, b=None):
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fidiv', src, a)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fdivp(ir, instr, a, b=None):
    # Invalid emulation
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(float_prev(a), ExprOp('fdiv', a, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return None, e, []


def fmulp(ir, instr, a, b=None):
    # Invalid emulation
    if b is None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % b.size, b)
    else:
        src = b
    e.append(ExprAff(float_prev(a), ExprOp('fmul', a, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return None, e, []


def ftan(ir, instr, a):
    e = []
    if isinstance(a, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % a.size, a)
    else:
        src = a
    e.append(ExprAff(float_st0, ExprOp('ftan', src)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fxch(ir, instr, a):
    e = []
    if isinstance(a, ExprMem):
        src = ExprOp('mem_%.2d_to_double' % a.size, a)
    else:
        src = a
    e.append(ExprAff(float_st0, src))
    e.append(ExprAff(src, float_st0))
    e += set_float_cs_eip(instr)
    return None, e, []


def fptan(ir, instr):
    e = []
    e.append(ExprAff(float_st7, float_st6))
    e.append(ExprAff(float_st6, float_st5))
    e.append(ExprAff(float_st5, float_st4))
    e.append(ExprAff(float_st4, float_st3))
    e.append(ExprAff(float_st3, float_st2))
    e.append(ExprAff(float_st2, float_st1))
    e.append(ExprAff(float_st1, ExprOp('ftan', float_st0)))
    e.append(ExprAff(float_st0, ExprOp('int_32_to_double', ExprInt32(1))))
    e.append(
        ExprAff(float_stack_ptr, float_stack_ptr + ExprInt_fromsize(3, 1)))
    return None, e, []


def frndint(ir, instr):
    e = []
    e.append(ExprAff(float_st0, ExprOp('frndint', float_st0)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fsin(ir, instr):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fsin', float_st0)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fcos(ir, instr):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fcos', float_st0)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fscale(ir, instr):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fscale', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    return None, e, []


def f2xm1(ir, instr):
    e = []
    e.append(ExprAff(float_st0, ExprOp('f2xm1', float_st0)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fsqrt(ir, instr):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fsqrt', float_st0)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fabs(ir, instr):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fabs', float_st0)))
    e += set_float_cs_eip(instr)
    return None, e, []


def fnstsw(ir, instr, dst):
    args = [(ExprInt8(0),        0, 8),
            (float_c0,           8, 9),
            (float_c1,           9, 10),
            (float_c2,           10, 11),
            (float_stack_ptr,    11, 14),
            (float_c3,           14, 15),
            (ExprInt1(0), 15, 16)]
    e = [ExprAff(dst, ExprCompose(args))]
    return None, e, []


def fnstcw(ir, instr, a):
    e = []
    e.append(ExprAff(a, float_control))
    return None, e, []


def fldcw(ir, instr, a):
    e = []
    e.append(ExprAff(float_control, a))
    return None, e, []


def fwait(ir, instr):
    return None, [], None


def nop(ir, instr, a=None):
    return None, [], []


def hlt(ir, instr):
    e = []
    except_int = EXCEPT_PRIV_INSN
    e.append(ExprAff(exception_flags, ExprInt32(except_int)))
    return None, e, []


def rdtsc(ir, instr):
    e = []
    myEAX = mRAX[instr.mode]
    myEDX = mRDX[instr.mode]
    e.append(ExprAff(tsc1, tsc1 + ExprInt32(1)))
    e.append(ExprAff(myEAX, tsc1))
    e.append(ExprAff(myEDX, tsc2))
    return None, e, []


# XXX TODO
def daa(ir, instr):
    return None, [], None


def aam(ir, instr, a):
    e = []
    tempAL = mRAX[instr.mode][0:8]
    newEAX = ExprCompose([
                         (tempAL % a,           0,  8),
                        (tempAL / a,           8,  16),
                        (mRAX[instr.mode][16:], 16, mRAX[instr.mode].size),
                         ])
    e += [ExprAff(mRAX[instr.mode], newEAX)]
    e += update_flag_arith(newEAX)
    return None, e, []


def aad(ir, instr, a):
    e = []
    tempAL = mRAX[instr.mode][0:8]
    tempAH = mRAX[instr.mode][8:16]
    newEAX = ExprCompose([
                         ((tempAL + (tempAH * a)) & ExprInt8(0xFF), 0,  8),
                        (ExprInt8(0),                              8,  16),
                        (mRAX[instr.mode][16:],
                         16, mRAX[instr.mode].size),
                         ])
    e += [ExprAff(mRAX[instr.mode], newEAX)]
    e += update_flag_arith(newEAX)
    return None, e, []


def aaa(ir, instr, ):
    e = []
    c = (mRAX[instr.mode][:8] & ExprInt8(0xf)) - ExprInt8(9)

    c = ExprCond(c.msb(),
                 ExprInt1(0),
                 ExprInt1(1)) & \
        ExprCond(c,
                 ExprInt1(1),
                 ExprInt1(0))

    c |= af & ExprInt1(1)
    # set AL
    m_al = ExprCond(c,
                   (mRAX[instr.mode][:8] + ExprInt8(6)) & ExprInt8(0xF),
                    mRAX[instr.mode][:8] & ExprInt8(0xF))
    m_ah = ExprCond(c,
                    mRAX[instr.mode][8:16] + ExprInt8(1),
                    mRAX[instr.mode][8:16])

    e.append(ExprAff(mRAX[instr.mode], ExprCompose([
        (m_al, 0, 8), (m_ah, 8, 16),
        (mRAX[instr.mode][16:], 16, mRAX[instr.mode].size)])))
    e.append(ExprAff(af, c))
    e.append(ExprAff(cf, c))
    return None, e, []


def aas(ir, instr, ):
    e = []
    c = (mRAX[instr.mode][:8] & ExprInt8(0xf)) - ExprInt8(9)

    c = ExprCond(c.msb(),
                 ExprInt1(0),
                 ExprInt1(1)) & \
        ExprCond(c,
                 ExprInt1(1),
                 ExprInt1(0))

    c |= af & ExprInt1(1)
    # set AL
    m_al = ExprCond(c,
                   (mRAX[instr.mode][:8] - ExprInt8(6)) & ExprInt8(0xF),
                    mRAX[instr.mode][:8] & ExprInt8(0xF))
    m_ah = ExprCond(c,
                    mRAX[instr.mode][8:16] - ExprInt8(1),
                    mRAX[instr.mode][8:16])

    e.append(ExprAff(mRAX[instr.mode], ExprCompose([
        (m_al, 0, 8), (m_ah, 8, 16),
        (mRAX[instr.mode][16:], 16, mRAX[instr.mode].size)])))
    e.append(ExprAff(af, c))
    e.append(ExprAff(cf, c))
    return None, e, []


def bsf(ir, instr, a, b):
    lbl_do = ExprId(ir.gen_label(), instr.mode)
    lbl_skip = ExprId(ir.get_next_label(instr), instr.mode)

    e = [ExprAff(zf, ExprCond(b, ExprInt_from(zf, 0), ExprInt_from(zf, 1)))]

    e_do = []
    e_do.append(ExprAff(a, ExprOp('bsf', b)))
    return ExprCond(b, lbl_do, lbl_skip), e, [irbloc(lbl_do.name, lbl_skip, [e_do])]


def bsr(ir, instr, a, b):
    lbl_do = ExprId(ir.gen_label(), instr.mode)
    lbl_skip = ExprId(ir.get_next_label(instr), instr.mode)

    e = [ExprAff(zf, ExprCond(b, ExprInt_from(zf, 0), ExprInt_from(zf, 1)))]

    e_do = []
    e_do.append(ExprAff(a, ExprOp('bsr', b)))
    return ExprCond(b, lbl_do, lbl_skip), e, [irbloc(lbl_do.name, lbl_skip, [e_do])]


def arpl(ir, instr, a, b):
    e = []
    e.append(ExprAff(exception_flags, ExprInt32(1 << 7)))
    return None, e, []


def ins(ir, instr, size):
    e = []
    e.append(ExprAff(exception_flags, ExprInt32(1 << 7)))
    return None, e, []


def sidt(ir, instr, a):
    e = []
    if not isinstance(a, ExprMem) or a.size != 32:
        raise ValueError('not exprmem 32bit instance!!')
    b = a.arg
    print "DEFAULT SIDT ADDRESS %s!!" % str(a)
    e.append(ExprAff(ExprMem(b, 32), ExprInt32(0xe40007ff)))
    e.append(
        ExprAff(ExprMem(ExprOp("+", b,
        ExprInt_from(b, 4)), 16), ExprInt16(0x8245)))
    return None, e, []


def sldt(ir, instr, a):
    # XXX TOOD
    e = [ExprAff(exception_flags, ExprInt32(EXCEPT_PRIV_INSN))]
    return None, e, []


def cmovz(ir, instr, a, b):
    lbl_do = ExprId(ir.gen_label(), instr.mode)
    lbl_skip = ExprId(ir.get_next_label(instr), instr.mode)

    dum, e_do, extra_irs = mov(ir, instr, a, b)
    return ExprCond(zf, lbl_do, lbl_skip), [], [irbloc(lbl_do.name, lbl_skip, [e_do])]


def cmovnz(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCond(zf, a, b)))
    return None, e, []


def cmovge(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCond(nf ^ of, a, b)))
    return None, e, []


def cmovg(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCond(zf | (nf ^ of), a, b)))
    return None, e, []


def cmovl(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCond(nf ^ of, b, a)))
    return None, e, []


def cmovle(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCond((nf ^ of) | zf, b, a)))
    return None, e, []


def cmova(ir, instr, a, b):
    lbl_do = ExprId(ir.gen_label(), instr.mode)
    lbl_skip = ExprId(ir.get_next_label(instr), instr.mode)
    dum, e_do, extra_irs = mov(ir, instr, a, b)
    return ExprCond(cf | zf, lbl_skip, lbl_do), [], [irbloc(lbl_do.name, lbl_skip, [e_do])]


def cmovae(ir, instr, a, b):
    lbl_do = ExprId(ir.gen_label(), instr.mode)
    lbl_skip = ExprId(ir.get_next_label(instr), instr.mode)
    dum, e_do, extra_irs = mov(ir, instr, a, b)
    return ExprCond(cf, lbl_skip, lbl_do), [], [irbloc(lbl_do.name, lbl_skip, [e_do])]


def cmovbe(ir, instr, a, b):
    lbl_do = ExprId(ir.gen_label(), instr.mode)
    lbl_skip = ExprId(ir.get_next_label(instr), instr.mode)
    dum, e_do, extra_irs = mov(ir, instr, a, b)
    return ExprCond(cf | zf, lbl_do, lbl_skip), [], [irbloc(lbl_do.name, lbl_skip, [e_do])]


def cmovb(ir, instr, a, b):
    lbl_do = ExprId(ir.gen_label(), instr.mode)
    lbl_skip = ExprId(ir.get_next_label(instr), instr.mode)
    dum, e_do, extra_irs = mov(ir, instr, a, b)
    return ExprCond(cf, lbl_do, lbl_skip), [], [irbloc(lbl_do.name, lbl_skip, [e_do])]


def cmovo(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCond(of, b, a)))
    return None, e, []


def cmovno(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCond(of, a, b)))
    return None, e, []


def cmovs(ir, instr, a, b):
    e = []
    # SF is called nf in miasm
    e.append(ExprAff(a, ExprCond(nf, b, a)))
    return None, e, []


def cmovns(ir, instr, a, b):
    e = []
    # SF is called nf in miasm
    e.append(ExprAff(a, ExprCond(nf, a, b)))
    return None, e, []


def icebp(ir, instr):
    e = []
    e.append(ExprAff(exception_flags,
                     ExprInt32(EXCEPT_PRIV_INSN)))
    return None, e, []
# XXX


def l_int(ir, instr, a):
    e = []
    # XXX
    if a.arg in [1, 3]:
        except_int = EXCEPT_SOFT_BP
    else:
        except_int = EXCEPT_INT_XX
    e.append(ExprAff(exception_flags,
                     ExprInt32(except_int)))
    return None, e, []


def l_sysenter(ir, instr):
    e = []
    e.append(ExprAff(exception_flags,
                     ExprInt32(EXCEPT_PRIV_INSN)))
    return None, e, []

# XXX


def l_out(ir, instr, a, b):
    e = []
    e.append(ExprAff(exception_flags,
                     ExprInt32(EXCEPT_PRIV_INSN)))
    return None, e, []

# XXX


def l_outs(ir, instr, size):
    e = []
    e.append(ExprAff(exception_flags,
                     ExprInt32(EXCEPT_PRIV_INSN)))
    return None, e, []

# XXX actually, xlat performs al = (ds:[e]bx + ZeroExtend(al))


def xlat(ir, instr):
    e = []
    a = ExprCompose([(ExprInt_fromsize(24, 0), 8, 32),
                     (mRAX[instr.mode][0:8], 0, 8)])
    b = ExprMem(ExprOp('+', mRBX[instr.mode], a), 8)
    e.append(ExprAff(mRAX[instr.mode][0:8], b))
    return None, e, []


def cpuid(ir, instr):
    e = []
    e.append(
        ExprAff(mRAX[instr.mode],
        ExprOp('cpuid', mRAX[instr.mode], ExprInt32(0))))
    e.append(
        ExprAff(mRBX[instr.mode],
        ExprOp('cpuid', mRAX[instr.mode], ExprInt32(1))))
    e.append(
        ExprAff(mRCX[instr.mode],
        ExprOp('cpuid', mRAX[instr.mode], ExprInt32(2))))
    e.append(
        ExprAff(mRDX[instr.mode],
        ExprOp('cpuid', mRAX[instr.mode], ExprInt32(3))))
    return None, e, []


def bittest_get(a, b):
    b = b.zeroExtend(a.size)
    if isinstance(a, ExprMem):
        b_mask = {16:4, 32:5, 64:6}
        b_decal = {16:1, 32:3, 64:7}
        ptr = a.arg
        off_bit = b.zeroExtend(a.size) & ExprInt_fromsize(a.size,
                                                          (1<<b_mask[a.size])-1)
        off_byte = ((b.zeroExtend(ptr.size) >> ExprInt_from(ptr, 3)) &
                    ExprInt_from(ptr, ((1<<a.size)-1) ^ b_decal[a.size]))

        d = ExprMem(ptr + off_byte, a.size)
    else:
        off_bit = ExprOp('&', b, ExprInt_from(a, a.size - 1))
        d = a
    return d, off_bit


def bt(ir, instr, a, b):
    e = []
    b = b.zeroExtend(a.size)
    d, off_bit = bittest_get(a, b)
    d = d >> off_bit
    e.append(ExprAff(cf, d[:1]))
    return None, e, []


def btc(ir, instr, a, b):
    e = []
    d, off_bit = bittest_get(a, b)
    e.append(ExprAff(cf, (d >> off_bit)[:1]))

    m = ExprInt_from(a, 1) << off_bit
    e.append(ExprAff(d, d ^ m))

    return None, e, []


def bts(ir, instr, a, b):
    e = []
    d, off_bit = bittest_get(a, b)
    e.append(ExprAff(cf, (d >> off_bit)[:1]))
    m = ExprInt_from(a, 1) << off_bit
    e.append(ExprAff(d, d | m))

    return None, e, []


def btr(ir, instr, a, b):
    e = []
    d, off_bit = bittest_get(a, b)
    e.append(ExprAff(cf, (d >> off_bit)[:1]))
    m = ~(ExprInt_from(a, 1) << off_bit)
    e.append(ExprAff(d, d & m))

    return None, e, []


def into(ir, instr):
    return None, [], None


def l_in(ir, instr, a, b):
    e = []
    e.append(ExprAff(exception_flags,
                     ExprInt32(EXCEPT_PRIV_INSN)))
    return None, e, []


def cmpxchg(ir, instr, a, b):
    e = []

    c = mRAX[instr.mode][:a.size]
    cond = c - a
    e.append(
        ExprAff(zf, ExprCond(cond, ExprInt_from(zf, 0), ExprInt_from(zf, 1))))
    e.append(ExprAff(a, ExprCond(cond,
                                 b,
                                 a)
                     ))
    e.append(ExprAff(c, ExprCond(cond,
                                 a,
                                 c)
                     ))
    return None, e, []


def lds(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprMem(b.arg, size=a.size)))
    e.append(ExprAff(ds, ExprMem(b.arg + ExprInt_from(a, 2),
                                 size=16)))
    return None, e, []


def les(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprMem(b.arg, size=a.size)))
    e.append(ExprAff(es, ExprMem(b.arg + ExprInt_from(a, 2),
                                 size=16)))
    return None, e, []


def lss(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprMem(b.arg, size=a.size)))
    e.append(ExprAff(ss, ExprMem(b.arg + ExprInt_from(a, 2),
                                 size=16)))
    return None, e, []


def lahf(ir, instr):
    e = []
    args = []
    regs = [cf, ExprInt1(1), pf, ExprInt1(0), af, ExprInt1(0), zf, nf]
    for i in xrange(len(regs)):
        args.append((regs[i], i, i + 1))
    e.append(ExprAff(mRAX[instr.mode][8:16], ExprCompose(args)))
    return None, e, []


def sahf(ir, instr):
    tmp = mRAX[instr.mode][8:16]
    e = []
    e.append(ExprAff(cf, tmp[0:1]))
    e.append(ExprAff(pf, tmp[2:3]))
    e.append(ExprAff(af, tmp[4:5]))
    e.append(ExprAff(zf, tmp[6:7]))
    e.append(ExprAff(nf, tmp[7:8]))
    return None, e, []


def lar(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprOp('access_segment', b)))
    e.append(ExprAff(zf, ExprOp('access_segment_ok', b)))
    return None, e, []


def lsl(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprOp('load_segment_limit', b)))
    e.append(ExprAff(zf, ExprOp('load_segment_limit_ok', b)))
    return None, e, []


def fclex(ir, instr):
    # XXX TODO
    return None, [], None


def fnclex(ir, instr):
    # XXX TODO
    return None, [], None


def l_str(ir, instr, a):
    e = []
    e.append(ExprAff(a, ExprOp('load_tr_segment_selector', ExprInt32(0))))
    return None, e, []


def movd(ir, instr, a, b):
    e = []
    if a.size == 64:
        e.append(ExprAff(a, ExprCompose([(ExprInt32(0), 32, 64), (b, 0, 32)])))
    else:
        e.append(ExprAff(a, b[0:32]))
    return None, e, []


def xorps(ir, instr, a, b):
    e = []
    if isinstance(b, ExprMem):
        b = ExprMem(b.arg, a.size)
    e.append(ExprAff(a, ExprOp('xorps', a, b)))
    return None, e, []

### MMX/SSE/AVX operations
###

# Generic vertical operation
def vec_vertical_sem(op, elt_size, reg_size, a, b):
    assert(reg_size % elt_size == 0)
    n = reg_size/elt_size
    ops = [(ExprOp(op, a[i*elt_size:(i+1)*elt_size],
                   b[i*elt_size:(i+1)*elt_size]),
            i*elt_size,
            (i+1)*elt_size) for i in xrange(0, n)]
    return ExprCompose(ops)

def float_vec_vertical_sem(op, elt_size, reg_size, a, b):
    assert(reg_size % elt_size == 0)
    n = reg_size/elt_size
    ops = [(ExprOp('double_to_int_%d' % elt_size, ExprOp(op,
                   ExprOp('int_%d_to_double' % elt_size,
                          a[i*elt_size:(i+1)*elt_size]),
                   ExprOp('int_%d_to_double' % elt_size,
                          b[i*elt_size:(i+1)*elt_size]))
                  ),
            i*elt_size, (i+1)*elt_size) for i in xrange(0, n)]
    return ExprCompose(ops)

def __vec_vertical_instr_gen(op, elt_size, sem):
    def vec_instr(ir, instr, a, b):
        e = []
        if isinstance(b, ExprMem):
            b = ExprMem(b.arg, a.size)
        reg_size = a.size
        e.append(ExprAff(a, sem(op, elt_size, reg_size, a, b)))
        return None, e, []
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
addps = float_vec_vertical_instr('+', 32)
addpd = float_vec_vertical_instr('+', 64)
subps = float_vec_vertical_instr('-', 32)
subpd = float_vec_vertical_instr('-', 64)
mulps = float_vec_vertical_instr('*', 32)
mulpd = float_vec_vertical_instr('*', 64)
divps = float_vec_vertical_instr('/', 32)
divpd = float_vec_vertical_instr('/', 64)

### Logical (floating-point)
###

# MMX/SSE/AVX
def pand(ir, instr, a, b):
    e = []
    c = a & b
    # No flag affected
    e.append(ExprAff(a, c))
    return None, e, []

def movaps(ir, instr, a, b):
    e = []
    if isinstance(a, ExprMem):
        a = ExprMem(a.arg, b.size)
    if isinstance(b, ExprMem):
        b = ExprMem(b.arg, a.size)
    e.append(ExprAff(a, b))
    return None, e, []


def pminsw(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCond((a - b).msb(), a, b)))
    return None, e, []


def cvtsi2sd(ir, instr, a, b):
    e = []
    e.append(ExprAff(a[:b.size], ExprOp('cvtsi2sd', b)))
    return None, e, []


def movss(ir, instr, a, b):
    e = []
    e.append(ExprAff(a[:b.size], ExprOp('movss', b)))
    return None, e, []


def ucomiss(ir, instr, a, b):
    e = []
    e.append(ExprAff(zf, ExprOp('ucomiss_zf', a[:32], b[:32])))
    e.append(ExprAff(pf, ExprOp('ucomiss_pf', a[:32], b[:32])))
    e.append(ExprAff(cf, ExprOp('ucomiss_cf', a[:32], b[:32])))

    e.append(ExprAff(of, ExprInt1(0)))
    e.append(ExprAff(af, ExprInt1(0)))
    e.append(ExprAff(nf, ExprInt1(0)))

    return None, e, []

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
              'pop': pop,
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
              'pushfw': pushfw,
              'popfd': popfd,
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

              'movsb': lambda ir, instr: movs(ir, instr, 8),
              'movsw': lambda ir, instr: movs(ir, instr, 16),
              'movsd': lambda ir, instr: movs(ir, instr, 32),
              'movsq': lambda ir, instr: movs(ir, instr, 64),
              'fcomp': fcomp,
              'ficomp': ficomp,
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
              'fldl2e': fldl2e,
              'fldlg2': fldlg2,
              'fild': fild,
              'fadd': fadd,
              'fiadd': fiadd,
              'fninit': fninit,
              'faddp': faddp,
              'fsub': fsub,
              'fsubp': fsubp,
              'fsubr': fsubr,
              'fmul': fmul,
              'fimul': fimul,
              'fmulp': fmulp,
              'fdiv': fdiv,
              'fdivr': fdivr,
              'fidiv': fidiv,
              'fidivr': fidivr,
              'fdivp': fdivp,
              'fxch': fxch,
              'fptan': fptan,
              'frndint': frndint,
              'fsin': fsin,
              'fcos': fcos,
              'fscale': fscale,
              'f2xm1': f2xm1,
              'fsqrt': fsqrt,
              'fabs': fabs,
              'fnstsw': fnstsw,
              'fnstcw': fnstcw,
              'fldcw': fldcw,
              'fwait': fwait,
              'fnstenv': fnstenv,
              'sidt': sidt,
              'sldt': sldt,
              'arpl': arpl,
              'cmovz': cmovz,
              'cmove': cmovz,
              'cmovnz': cmovnz,
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
              "lahf": lahf,
              "sahf": sahf,
              "lar": lar,
              "lsl": lsl,
              "fclex": fclex,
              "fnclex": fnclex,
              "str": l_str,
              "movd": movd,
              "movaps": movaps,
              "xorps": xorps,

              "pminsw": pminsw,
              "cvtsi2sd": cvtsi2sd,
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
              "addps": addps,
              "addpd": addpd,

              ## Substractions
              # SSE
              "subps": subps,
              "subpd": subpd,

              ## Multiplications
              # SSE
              "mulps": mulps,
              "mulpd": mulpd,

              ## Divisions
              # SSE
              "divps": divps,
              "divpd": divpd,

              ### Logical (floating-point)
              ###

              "pand": pand

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

    def mod_pc(self, instr, instr_ir, extra_ir):
        pass

    def get_ir(self, instr):
        args = instr.args[:]
        my_ss = None
        if self.do_ds_segm:
            my_ss = DS
        if self.do_all_segm and instr.additional_info.g2.value:
            my_ss = {1: CS, 2: SS, 3: DS, 4: ES, 5: FS, 6: GS}[
                instr.additional_info.g2.value]
        if my_ss is not None:
            for i, a in enumerate(args):
                if isinstance(a, ExprMem) and not a.is_op_segm():
                    args[i] = ExprMem(ExprOp('segm', my_ss, a.arg), a.size)

        dst, instr_ir, extra_ir = mnemo_func[
            instr.name.lower()](self, instr, *args)
        self.mod_pc(instr, instr_ir, extra_ir)

        self.mod_pc(instr, instr_ir, extra_ir)
        instr.additional_info.except_on_instr = False
        if instr.additional_info.g1.value & 6 == 0 or \
                not instr.name in repeat_mn:
            return dst, instr_ir, extra_ir
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

        # end condition
        if zf_val is None:
            c_cond = ExprCond(c_reg, ExprInt1(0), ExprInt1(1))
        elif instr.additional_info.g1.value & 2:  # REPNE
            # c_cond = ExprCond(c_reg, ExprInt1(0), ExprInt1(1)) | (zf_val)
            c_cond = ExprCond(c_reg, ExprInt1(0), ExprInt1(1)) | (zf)
        elif instr.additional_info.g1.value & 4:  # REP
            # c_cond = ExprCond(c_reg, ExprInt1(0), ExprInt1(1)) |
            # (zf_val^ExprInt32(1))
            c_cond = ExprCond(
                c_reg, ExprInt1(0), ExprInt1(1)) | (zf ^ ExprInt1(1))

        # gen while
        lbl_do = ExprId(self.gen_label(), instr.mode)
        lbl_end = ExprId(self.gen_label(), instr.mode)
        lbl_skip = ExprId(self.get_next_label(instr), instr.mode)
        lbl_next = ExprId(self.get_next_label(instr), instr.mode)

        for b in extra_ir:
            # print repr(b)
            # print b
            # self.replace_expr_in_ir(b, {lbl_next:lbl_end})
            b.dst = b.dst.replace_expr({lbl_next: lbl_end})
            # print b

        cond_bloc = []
        cond_bloc.append(ExprAff(c_reg, c_reg - ExprInt_from(c_reg, 1)))
        cond_bloc = irbloc(
            lbl_end.name, ExprCond(c_cond, lbl_skip, lbl_do), [cond_bloc])
        e_do = instr_ir

        c = irbloc(lbl_do.name, dst, [e_do])
        c.except_automod = False
        return ExprCond(c_reg, lbl_do, lbl_skip), [], [cond_bloc, c] + extra_ir

    def expr_fix_regs_for_mode(self, e, mode=64):
        return e.replace_expr(replace_regs[mode])

    def expraff_fix_regs_for_mode(self, e, mode=64):
        dst = self.expr_fix_regs_for_mode(e.dst, mode)
        src = self.expr_fix_regs_for_mode(e.src, mode)
        return ExprAff(dst, src)

    def irbloc_fix_regs_for_mode(self, irbloc, mode=64):
        for irs in irbloc.irs:
            for i, e in enumerate(irs):
                """
                special case for 64 bits:
                if destination is a 32 bit reg, zero extend the 64 bit reg
                """
                if mode == 64:
                    if (isinstance(e.dst, ExprId) and e.dst.size == 32 and
                            e.dst in replace_regs[64]):
                        src = self.expr_fix_regs_for_mode(e.src, mode)
                        dst = replace_regs[64][e.dst].arg
                        e = ExprAff(dst, src.zeroExtend(64))
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


class ir_x86_64(ir_x86_16):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_x86, 64, symbol_pool)
        self.do_stk_segm = False
        self.do_ds_segm = False
        self.do_str_segm = False
        self.do_all_segm = False
        self.pc = RIP
        self.sp = RSP

    def mod_pc(self, instr, instr_ir, extra_ir):
        # fix RIP for 64 bit
        for i, x in enumerate(instr_ir):
            if x.dst != self.pc:
                x.dst = x.dst.replace_expr(
                    {self.pc: ExprInt64(instr.offset + instr.l)})
            x = ExprAff(x.dst, x.src.replace_expr(
                {self.pc: ExprInt64(instr.offset + instr.l)}))
            instr_ir[i] = x
        for b in extra_ir:
            for irs in b.irs:
                for i, x in enumerate(irs):
                    if x.dst != self.pc:
                        x.dst = x.dst.replace_expr(
                            {self.pc: ExprInt64(instr.offset + instr.l)})
                    x = ExprAff(x.dst, x.src.replace_expr(
                        {self.pc: ExprInt64(instr.offset + instr.l)}))
                    irs[i] = x
