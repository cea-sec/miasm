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
from miasm2.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock
from miasm2.core.sembuilder import SemBuilder
import math
import struct


# SemBuilder context
ctx = {'mRAX': mRAX,
       'mRBX': mRBX,
       'mRCX': mRCX,
       'mRDX': mRDX,
       'zf': zf,
       }
sbuild = SemBuilder(ctx)

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
    return [m2_expr.ExprAff(
        zf, m2_expr.ExprCond(a, m2_expr.ExprInt(0, zf.size),
                             m2_expr.ExprInt(1, zf.size)))]


def update_flag_nf(a):
    return [m2_expr.ExprAff(nf, a.msb())]


def update_flag_pf(a):
    return [m2_expr.ExprAff(pf,
                            m2_expr.ExprOp('parity',
                                           a & m2_expr.ExprInt(0xFF, a.size)))]


def update_flag_af(op1, op2, res):
    return [m2_expr.ExprAff(af, (op1 ^ op2 ^ res)[4:5])]


def update_flag_znp(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    e += update_flag_pf(a)
    return e


def update_flag_logic(a):
    e = []
    e += update_flag_znp(a)
    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt(0, of.size)))
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprInt(0, cf.size)))
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
                             m2_expr.ExprInt(instr.offset, float_eip.size)))
    e.append(m2_expr.ExprAff(float_cs, CS))
    return e


def mode2addrsize(mode):
    """Returns the address size for a given @mode"""

    mode2size = {16:32, 32:32, 64:64}
    if mode not in mode2size:
        raise RuntimeError("Unknown size %s", mode)
    return mode2size[mode]


def instr2addrsize(instr):
    """Returns the address size for a given @instr"""

    return mode2addrsize(instr.mode)


def expraddr(mode, ptr):
    """Returns memory address pointer with size according to current @mode"""
    return ptr.zeroExtend(mode2addrsize(mode))


def fix_mem_args_size(instr, *args):
    out = []
    for arg in args:
        if not arg.is_mem():
            out.append(arg)
            continue
        ptr = arg.arg
        size = arg.size
        if ptr.is_op('segm'):
            ptr = m2_expr.ExprOp(
                'segm', ptr.args[0], expraddr(instr.mode, ptr.args[1]))
        else:
            ptr = expraddr(instr.mode, ptr)
        out.append(m2_expr.ExprMem(ptr, size))
    return out


def mem2double(instr, arg):
    """
    Add float convertion if argument is an ExprMem
    @arg: argument to tranform
    """
    if isinstance(arg, m2_expr.ExprMem):
        if arg.size > 64:
            # TODO: move to 80 bits
            arg = m2_expr.ExprMem(expraddr(instr.mode, arg.arg), size=64)
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
    meip = mRIP[ir.IRDst.size]
    next_lbl = m2_expr.ExprId(ir.get_next_label(instr), dst.size)
    if jmp_if:
        dstA, dstB = dst, next_lbl
    else:
        dstA, dstB = next_lbl, dst
    mn_dst = m2_expr.ExprCond(cond,
                              dstA.zeroExtend(ir.IRDst.size),
                              dstB.zeroExtend(ir.IRDst.size))
    e.append(m2_expr.ExprAff(meip, mn_dst))
    e.append(m2_expr.ExprAff(ir.IRDst, mn_dst))
    return e, []


def gen_fcmov(ir, instr, cond, arg1, arg2, mov_if):
    """Generate fcmov
    @ir: ir instance
    @instr: instruction instance
    @cond: condition
    @mov_if: invert condition if False"""

    lbl_do = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
    if mov_if:
        dstA, dstB = lbl_do, lbl_skip
    else:
        dstA, dstB = lbl_skip, lbl_do
    e = []
    e_do, extra_irs = [m2_expr.ExprAff(arg1, arg2)], []
    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
    e.append(m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(cond, dstA, dstB)))
    return e, [IRBlock(lbl_do.name, [e_do])]


def gen_cmov(ir, instr, cond, dst, src, mov_if):
    """Generate cmov
    @ir: ir instance
    @instr: instruction instance
    @cond: condition
    @mov_if: invert condition if False"""

    lbl_do = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
    if mov_if:
        dstA, dstB = lbl_do, lbl_skip
    else:
        dstA, dstB = lbl_skip, lbl_do
    e = []
    e_do, extra_irs = mov(ir, instr, dst, src)
    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
    e.append(m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(cond, dstA, dstB)))
    return e, [IRBlock(lbl_do.name, [e_do])]


def mov(_, instr, dst, src):
    if dst in [ES, CS, SS, DS, FS, GS]:
        src = src[:dst.size]
    if src in [ES, CS, SS, DS, FS, GS]:
        src = src.zeroExtend(dst.size)
    e = [m2_expr.ExprAff(dst, src)]
    return e, []


def movq(_, instr, dst, src):
    src_final = (src.zeroExtend(dst.size)
                 if dst.size >= src.size else
                 src[:dst.size])
    return [m2_expr.ExprAff(dst, src_final)], []


@sbuild.parse
def xchg(arg1, arg2):
    arg1 = arg2
    arg2 = arg1



def movzx(_, instr, dst, src):
    e = [m2_expr.ExprAff(dst, src.zeroExtend(dst.size))]
    return e, []


def movsx(_, instr, dst, src):
    e = [m2_expr.ExprAff(dst, src.signExtend(dst.size))]
    return e, []


def lea(_, instr, dst, src):
    ptr = src.arg
    if src.is_mem_segm():
        # Do not use segmentation here
        ptr = ptr.args[1]

    if ptr.size > dst.size:
        ptr = ptr[:dst.size]
    e = [m2_expr.ExprAff(dst, ptr.zeroExtend(dst.size))]
    return e, []


def add(_, instr, dst, src):
    e = []
    result = dst + src
    e += update_flag_arith(result)
    e += update_flag_af(dst, src, result)
    e += update_flag_add(dst, src, result)
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def xadd(_, instr, dst, src):
    e = []
    result = dst + src
    e += update_flag_arith(result)
    e += update_flag_af(dst, src, result)
    e += update_flag_add(src, dst, result)
    if dst != src:
        e.append(m2_expr.ExprAff(src, dst))
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def adc(_, instr, dst, src):
    e = []
    result = dst + (src + m2_expr.ExprCompose(cf,
                                              m2_expr.ExprInt(0, dst.size - 1)))
    e += update_flag_arith(result)
    e += update_flag_af(dst, src, result)
    e += update_flag_add(dst, src, result)
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def sub(_, instr, dst, src):
    e = []
    result = dst - src
    e += update_flag_arith(result)
    e += update_flag_af(dst, src, result)
    e += update_flag_sub(dst, src, result)
    e.append(m2_expr.ExprAff(dst, result))
    return e, []

# a-(b+cf)


def sbb(_, instr, dst, src):
    e = []
    result = dst - (src + m2_expr.ExprCompose(cf,
                                              m2_expr.ExprInt(0, dst.size - 1)))
    e += update_flag_arith(result)
    e += update_flag_af(dst, src, result)
    e += update_flag_sub(dst, src, result)
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def neg(_, instr, src):
    e = []
    dst = m2_expr.ExprInt(0, src.size)
    result = dst - src
    e += update_flag_arith(result)
    e += update_flag_sub(dst, src, result)
    e += update_flag_af(dst, src, result)
    e.append(m2_expr.ExprAff(src, result))
    return (e, [])


def l_not(_, instr, dst):
    e = []
    result = (~dst)
    e.append(m2_expr.ExprAff(dst, result))
    return (e, [])


def l_cmp(_, instr, dst, src):
    e = []
    result = dst - src
    e += update_flag_arith(result)
    e += update_flag_sub(dst, src, result)
    e += update_flag_af(dst, src, result)
    return (e, [])


def xor(_, instr, dst, src):
    e = []
    result = dst ^ src
    e += update_flag_logic(result)
    e.append(m2_expr.ExprAff(dst, result))
    return (e, [])


def pxor(_, instr, dst, src):
    e = []
    result = dst ^ src
    e.append(m2_expr.ExprAff(dst, result))
    return (e, [])


def l_or(_, instr, dst, src):
    e = []
    result = dst | src
    e += update_flag_logic(result)
    e.append(m2_expr.ExprAff(dst, result))
    return (e, [])


def l_and(_, instr, dst, src):
    e = []
    result = dst & src
    e += update_flag_logic(result)
    e.append(m2_expr.ExprAff(dst, result))
    return (e, [])


def l_test(_, instr, dst, src):
    e = []
    result = dst & src
    e += update_flag_logic(result)
    return (e, [])


def get_shift(dst, src):
    if isinstance(src, m2_expr.ExprInt):
        src = m2_expr.ExprInt(int(src), dst.size)
    else:
        src = src.zeroExtend(dst.size)
    if dst.size == 64:
        shift = src & m2_expr.ExprInt(63, src.size)
    else:
        shift = src & m2_expr.ExprInt(31, src.size)
    shift = expr_simp(shift)
    return shift


def _rotate_tpl(ir, instr, dst, src, op, left=False, include_cf=False):
    '''Template to generate a rotater with operation @op
    A temporary basic block is generated to handle 0-rotate
    @op: operation to execute
    @left (optional): indicates a left rotate if set, default is False
    @include_cf (optional): if set, add cf to @op inputs, default is False
    '''
    # Compute results
    shifter = get_shift(dst, src)
    extended_args = (cf.zeroExtend(dst.size),) if include_cf else ()
    res = m2_expr.ExprOp(op, dst, shifter, *extended_args)

    # CF is computed with 1-less round than `res`
    new_cf = m2_expr.ExprOp(
        op, dst, shifter - m2_expr.ExprInt(1, size=shifter.size), *extended_args)
    new_cf = new_cf.msb() if left else new_cf[:1]

    # OF is defined only for @b == 1
    new_of = m2_expr.ExprCond(src - m2_expr.ExprInt(1, size=src.size),
                              m2_expr.ExprInt(0, size=of.size),
                              res.msb() ^ new_cf if left else (dst ^ res).msb())

    # Build basic blocks
    e_do = [m2_expr.ExprAff(cf, new_cf),
            m2_expr.ExprAff(of, new_of),
            m2_expr.ExprAff(dst, res)
            ]
    # Don't generate conditional shifter on constant
    if isinstance(shifter, m2_expr.ExprInt):
        if int(shifter) != 0:
            return (e_do, [])
        else:
            return ([], [])
    e = []
    lbl_do = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
    e.append(m2_expr.ExprAff(
        ir.IRDst, m2_expr.ExprCond(shifter, lbl_do, lbl_skip)))
    return (e, [IRBlock(lbl_do.name, [e_do])])


def l_rol(ir, instr, dst, src):
    return _rotate_tpl(ir, instr, dst, src, '<<<', left=True)


def l_ror(ir, instr, dst, src):
    return _rotate_tpl(ir, instr, dst, src, '>>>')


def rcl(ir, instr, dst, src):
    return _rotate_tpl(ir, instr, dst, src, '<<<c_rez', left=True, include_cf=True)


def rcr(ir, instr, dst, src):
    return _rotate_tpl(ir, instr, dst, src, '>>>c_rez', include_cf=True)


def _shift_tpl(op, ir, instr, a, b, c=None, op_inv=None, left=False,
               custom_of=None):
    """Template to generate a shifter with operation @op
    A temporary basic block is generated to handle 0-shift
    @op: operation to execute
    @c (optional): if set, instruction has a bit provider
    @op_inv (optional): opposite operation of @op. Must be provided if @c
    @left (optional): indicates a left shift if set, default is False
    @custom_of (optional): if set, override the computed value of OF
    """
    if c is not None:
        shifter = get_shift(a, c)
    else:
        shifter = get_shift(a, b)

    res = m2_expr.ExprOp(op, a, shifter)
    cf_from_dst = m2_expr.ExprOp(op, a,
                                 (shifter - m2_expr.ExprInt(1, a.size)))
    cf_from_dst = cf_from_dst.msb() if left else cf_from_dst[:1]

    new_cf = cf_from_dst
    i1 = m2_expr.ExprInt(1, size=a.size)
    if c is not None:
        # There is a source for new bits
        isize = m2_expr.ExprInt(a.size, size=a.size)
        mask = m2_expr.ExprOp(op_inv, i1, (isize - shifter)) - i1

        # An overflow can occured, emulate the 'undefined behavior'
        # Overflow behavior if (shift / size % 2)
        base_cond_overflow = c if left else (
            c - m2_expr.ExprInt(1, size=c.size))
        cond_overflow = base_cond_overflow & m2_expr.ExprInt(a.size, c.size)
        if left:
            # Overflow occurs one round before right
            mask = m2_expr.ExprCond(cond_overflow, mask, ~mask)
        else:
            mask = m2_expr.ExprCond(cond_overflow, ~mask, mask)

        # Build res with dst and src
        res = ((m2_expr.ExprOp(op, a, shifter) & mask) |
               (m2_expr.ExprOp(op_inv, b, (isize - shifter)) & ~mask))

        # Overflow case: cf come from src (bit number shifter % size)
        cf_from_src = m2_expr.ExprOp(op, b,
                                     (c.zeroExtend(b.size) &
                                      m2_expr.ExprInt(a.size - 1, b.size)) - i1)
        cf_from_src = cf_from_src.msb() if left else cf_from_src[:1]
        new_cf = m2_expr.ExprCond(cond_overflow, cf_from_src, cf_from_dst)

    # Overflow flag, only occured when shifter is equal to 1
    if custom_of is None:
        value_of = a.msb() ^ a[-2:-1] if left else b[:1] ^ a.msb()
    else:
        value_of = custom_of

    # Build basic blocks
    e_do = [
        m2_expr.ExprAff(cf, new_cf),
        m2_expr.ExprAff(of, m2_expr.ExprCond(shifter - i1,
                                             m2_expr.ExprInt(0, of.size),
                                             value_of)),
        m2_expr.ExprAff(a, res),
    ]
    e_do += update_flag_znp(res)

    # Don't generate conditional shifter on constant
    if isinstance(shifter, m2_expr.ExprInt):
        if int(shifter) != 0:
            return e_do, []
        else:
            return [], []

    e = []
    lbl_do = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
    e.append(m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(shifter, lbl_do,
                                                        lbl_skip)))
    return e, [IRBlock(lbl_do.name, [e_do])]


def sar(ir, instr, dst, src):
    # Fixup OF, always cleared if src != 0
    i0 = m2_expr.ExprInt(0, size=of.size)
    return _shift_tpl("a>>", ir, instr, dst, src, custom_of=i0)


def shr(ir, instr, dst, src):
    return _shift_tpl(">>", ir, instr, dst, src, custom_of=dst.msb())


def shrd(ir, instr, dst, src1, src2):
    return _shift_tpl(">>>", ir, instr, dst, src1, src2, "<<<")


def shl(ir, instr, dst, src):
    return _shift_tpl("<<", ir, instr, dst, src, left=True)


def shld(ir, instr, dst, src1, src2):
    return _shift_tpl("<<<", ir, instr, dst, src1, src2, ">>>", left=True)


# XXX todo ###
def cmc(_, instr):
    e = [m2_expr.ExprAff(cf, m2_expr.ExprCond(cf, m2_expr.ExprInt(0, cf.size),
                                              m2_expr.ExprInt(1, cf.size)))]
    return e, []


def clc(_, instr):
    e = [m2_expr.ExprAff(cf, m2_expr.ExprInt(0, cf.size))]
    return e, []


def stc(_, instr):
    e = [m2_expr.ExprAff(cf, m2_expr.ExprInt(1, cf.size))]
    return e, []


def cld(_, instr):
    e = [m2_expr.ExprAff(df, m2_expr.ExprInt(0, df.size))]
    return e, []


def std(_, instr):
    e = [m2_expr.ExprAff(df, m2_expr.ExprInt(1, df.size))]
    return e, []


def cli(_, instr):
    e = [m2_expr.ExprAff(i_f, m2_expr.ExprInt(0, i_f.size))]
    return e, []


def sti(_, instr):
    e = [m2_expr.ExprAff(exception_flags, m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32))]
    return e, []


def inc(_, instr, dst):
    e = []
    src = m2_expr.ExprInt(1, dst.size)
    result = dst + src
    e += update_flag_arith(result)
    e += update_flag_af(dst, src, result)

    e.append(update_flag_add_of(dst, src, result))
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def dec(_, instr, dst):
    e = []
    src = m2_expr.ExprInt(-1, dst.size)
    result = dst + src
    e += update_flag_arith(result)
    e += update_flag_af(dst, src, ~result)

    e.append(update_flag_add_of(dst, src, result))
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def push_gen(ir, instr, src, size):
    e = []
    if not size in [16, 32, 64]:
        raise ValueError('bad size stacker!')
    if src.size < size:
        src = src.zeroExtend(size)
    elif src.size == size:
        pass
    else:
        raise ValueError('strange arg size')

    sp = mRSP[instr.mode]
    new_sp = sp - m2_expr.ExprInt(size / 8, sp.size)
    e.append(m2_expr.ExprAff(sp, new_sp))
    if ir.do_stk_segm:
        new_sp = m2_expr.ExprOp('segm', SS, new_sp)
    e.append(m2_expr.ExprAff(ir.ExprMem(new_sp, size),
                             src))
    return e, []


def push(ir, instr, src):
    return push_gen(ir, instr, src, instr.mode)


def pushw(ir, instr, src):
    return push_gen(ir, instr, src, 16)


def pop_gen(ir, instr, src, size):
    e = []
    if not size in [16, 32, 64]:
        raise ValueError('bad size stacker!')

    sp = mRSP[instr.mode]
    new_sp = sp + m2_expr.ExprInt(size / 8, sp.size)
    # don't generate ESP incrementation on POP ESP
    if src != ir.sp:
        e.append(m2_expr.ExprAff(sp, new_sp))
    # XXX FIX XXX for pop [esp]
    if isinstance(src, m2_expr.ExprMem):
        src = src.replace_expr({sp: new_sp})
    result = sp
    if ir.do_stk_segm:
        result = m2_expr.ExprOp('segm', SS, result)
    e.append(m2_expr.ExprAff(src, ir.ExprMem(result, src.size)))
    return e, []


def pop(ir, instr, src):
    return pop_gen(ir, instr, src, instr.mode)


def popw(ir, instr, src):
    return pop_gen(ir, instr, src, 16)


def sete(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(zf, m2_expr.ExprInt(1, dst.size),
                                              m2_expr.ExprInt(0, dst.size))))
    return e, []


def setnz(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(zf, m2_expr.ExprInt(0, dst.size),
                                              m2_expr.ExprInt(1, dst.size))))
    return e, []


def setl(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(
            dst, m2_expr.ExprCond(nf - of, m2_expr.ExprInt(1, dst.size),
                                  m2_expr.ExprInt(0, dst.size))))
    return e, []


def setg(_, instr, dst):
    e = []
    a0 = m2_expr.ExprInt(0, dst.size)
    a1 = m2_expr.ExprInt(1, dst.size)
    ret = m2_expr.ExprCond(zf, a0, a1) & m2_expr.ExprCond(nf - of, a0, a1)
    e.append(m2_expr.ExprAff(dst, ret))
    return e, []


def setge(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(
            dst, m2_expr.ExprCond(nf - of, m2_expr.ExprInt(0, dst.size),
                                  m2_expr.ExprInt(1, dst.size))))
    return e, []


def seta(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprCond(cf | zf,
                                                   m2_expr.ExprInt(
                                                       0, dst.size),
                                                   m2_expr.ExprInt(1, dst.size))))

    return e, []


def setae(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(cf, m2_expr.ExprInt(0, dst.size),
                                              m2_expr.ExprInt(1, dst.size))))
    return e, []


def setb(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(cf, m2_expr.ExprInt(1, dst.size),
                                              m2_expr.ExprInt(0, dst.size))))
    return e, []


def setbe(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprCond(cf | zf,
                                                   m2_expr.ExprInt(
                                                       1, dst.size),
                                                   m2_expr.ExprInt(0, dst.size)))
             )
    return e, []


def setns(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(nf, m2_expr.ExprInt(0, dst.size),
                                              m2_expr.ExprInt(1, dst.size))))
    return e, []


def sets(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(nf, m2_expr.ExprInt(1, dst.size),
                                              m2_expr.ExprInt(0, dst.size))))
    return e, []


def seto(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(of, m2_expr.ExprInt(1, dst.size),
                                              m2_expr.ExprInt(0, dst.size))))
    return e, []


def setp(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(pf, m2_expr.ExprInt(1, dst.size),
                                              m2_expr.ExprInt(0, dst.size))))
    return e, []


def setnp(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(pf, m2_expr.ExprInt(0, dst.size),
                                              m2_expr.ExprInt(1, dst.size))))
    return e, []


def setle(_, instr, dst):
    e = []
    a0 = m2_expr.ExprInt(0, dst.size)
    a1 = m2_expr.ExprInt(1, dst.size)
    ret = m2_expr.ExprCond(zf, a1, a0) | m2_expr.ExprCond(nf ^ of, a1, a0)
    e.append(m2_expr.ExprAff(dst, ret))
    return e, []


def setna(_, instr, dst):
    e = []
    a0 = m2_expr.ExprInt(0, dst.size)
    a1 = m2_expr.ExprInt(1, dst.size)
    ret = m2_expr.ExprCond(cf, a1, a0) & m2_expr.ExprCond(zf, a1, a0)
    e.append(m2_expr.ExprAff(dst, ret))
    return e, []


def setnbe(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprCond(cf | zf,
                                                   m2_expr.ExprInt(
                                                       0, dst.size),
                                                   m2_expr.ExprInt(1, dst.size)))
             )
    return e, []


def setno(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(of, m2_expr.ExprInt(0, dst.size),
                                              m2_expr.ExprInt(1, dst.size))))
    return e, []


def setnb(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(cf, m2_expr.ExprInt(0, dst.size),
                                              m2_expr.ExprInt(1, dst.size))))
    return e, []


def setalc(_, instr):
    dst = mRAX[instr.mode][0:8]
    e = []
    e.append(
        m2_expr.ExprAff(dst, m2_expr.ExprCond(cf, m2_expr.ExprInt(0xff, dst.size),
                                              m2_expr.ExprInt(0, dst.size))))
    return e, []


def bswap(_, instr, dst):
    e = []
    if dst.size == 16:
        result = m2_expr.ExprCompose(dst[8:16], dst[:8])
    elif dst.size == 32:
        result = m2_expr.ExprCompose(
            dst[24:32], dst[16:24], dst[8:16], dst[:8])
    elif dst.size == 64:
        result = m2_expr.ExprCompose(dst[56:64], dst[48:56], dst[40:48], dst[32:40],
                                     dst[24:32], dst[16:24], dst[8:16], dst[:8])
    else:
        raise ValueError('the size DOES matter')
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def cmps(ir, instr, size):
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

    s = instr.v_admode()
    a = ir.ExprMem(mRDI[instr.mode][:s], size)
    b = ir.ExprMem(mRSI[instr.mode][:s], size)

    e, _ = l_cmp(ir, instr, b, a)

    e0 = []
    e0.append(m2_expr.ExprAff(a.arg,
                              a.arg + m2_expr.ExprInt(size / 8, a.arg.size)))
    e0.append(m2_expr.ExprAff(b.arg,
                              b.arg + m2_expr.ExprInt(size / 8, b.arg.size)))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = IRBlock(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(a.arg,
                              a.arg - m2_expr.ExprInt(size / 8, a.arg.size)))
    e1.append(m2_expr.ExprAff(b.arg,
                              b.arg - m2_expr.ExprInt(size / 8, b.arg.size)))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = IRBlock(lbl_df_1.name, [e1])

    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))
    return e, [e0, e1]


def scas(ir, instr, size):
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

    s = instr.v_admode()
    a = ir.ExprMem(mRDI[instr.mode][:s], size)

    e, extra = l_cmp(ir, instr, mRAX[instr.mode][:size], a)

    e0 = []
    e0.append(m2_expr.ExprAff(a.arg,
                              a.arg + m2_expr.ExprInt(size / 8, a.arg.size)))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = IRBlock(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(a.arg,
                              a.arg - m2_expr.ExprInt(size / 8, a.arg.size)))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = IRBlock(lbl_df_1.name, [e1])

    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))

    return e, [e0, e1]


def compose_eflag(s=32):
    args = []

    args = [cf, m2_expr.ExprInt(1, 1), pf, m2_expr.ExprInt(0, 1), af,
            m2_expr.ExprInt(0, 1), zf, nf, tf, i_f, df, of, iopl]

    if s == 32:
        args += [nt, m2_expr.ExprInt(0, 1), rf, vm, ac, vif, vip, i_d]
    elif s == 16:
        args += [nt, m2_expr.ExprInt(0, 1)]
    else:
        raise ValueError('unk size')
    if s == 32:
        args.append(m2_expr.ExprInt(0, 10))
    return m2_expr.ExprCompose(*args)


def pushfd(ir, instr):
    return push(ir, instr, compose_eflag())


def pushfq(ir, instr):
    return push(ir, instr, compose_eflag().zeroExtend(64))


def pushfw(ir, instr):
    return pushw(ir, instr, compose_eflag(16))


def popfd(ir, instr):
    tmp = ir.ExprMem(mRSP[instr.mode])
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
                             mRSP[instr.mode] + m2_expr.ExprInt(instr.mode / 8, mRSP[instr.mode].size)))
    e.append(m2_expr.ExprAff(exception_flags,
                             m2_expr.ExprCond(m2_expr.ExprSlice(tmp, 8, 9),
                                              m2_expr.ExprInt(
                                                  EXCEPT_SOFT_BP, 32),
                                              exception_flags
                                              )
                             )
             )
    return e, []


def _tpl_eflags(tmp):
    """Extract eflags from @tmp
    @tmp: Expr instance with a size >= 16
    """
    return [m2_expr.ExprAff(dest, tmp[base:base + dest.size])
            for base, dest in ((0, cf), (2, pf), (4, af), (6, zf), (7, nf),
                               (8, tf), (9, i_f), (10, df), (11, of),
                               (12, iopl), (14, nt))]


def popfw(ir, instr):
    tmp = ir.ExprMem(mRSP[instr.mode])
    e = _tpl_eflags(tmp)
    e.append(
        m2_expr.ExprAff(mRSP[instr.mode], mRSP[instr.mode] + m2_expr.ExprInt(2, mRSP[instr.mode].size)))
    return e, []

pa_regs = [
    mRAX, mRCX,
    mRDX, mRBX,
    mRSP, mRBP,
    mRSI, mRDI
]


def pusha_gen(ir, instr, size):
    e = []
    for i, reg in enumerate(pa_regs):
        stk_ptr = mRSP[instr.mode] + \
            m2_expr.ExprInt(-(reg[size].size / 8) * (i + 1), instr.mode)
        e.append(m2_expr.ExprAff(ir.ExprMem(
            stk_ptr, reg[size].size), reg[size]))
    e.append(m2_expr.ExprAff(mRSP[instr.mode], stk_ptr))
    return e, []


def pusha(ir, instr):
    return pusha_gen(ir, instr, 16)


def pushad(ir, instr):
    return pusha_gen(ir, instr, 32)


def popa_gen(ir, instr, size):
    e = []
    for i, reg in enumerate(reversed(pa_regs)):
        if reg == mRSP:
            continue
        stk_ptr = mRSP[instr.mode] + \
            m2_expr.ExprInt((reg[size].size / 8) * i, instr.mode)
        e.append(m2_expr.ExprAff(reg[size], ir.ExprMem(stk_ptr, instr.mode)))

    stk_ptr = mRSP[instr.mode] + \
        m2_expr.ExprInt((instr.mode / 8) * (i + 1), instr.mode)
    e.append(m2_expr.ExprAff(mRSP[instr.mode], stk_ptr))

    return e, []


def popa(ir, instr):
    return popa_gen(ir, instr, 16)


def popad(ir, instr):
    return popa_gen(ir, instr, 32)


def call(ir, instr, dst):
    e = []
    # opmode, admode = instr.opmode, instr.admode
    s = dst.size
    meip = mRIP[ir.IRDst.size]
    opmode, admode = s, instr.v_admode()
    myesp = mRSP[instr.mode][:opmode]
    n = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

    if isinstance(dst, m2_expr.ExprOp):
        if dst.op == "segm":
            # Far call segm:addr
            if instr.mode not in [16, 32]:
                raise RuntimeError('not supported')
            segm = dst.args[0]
            base = dst.args[1]
            m1 = segm.zeroExtend(CS.size)
            m2 = base.zeroExtend(meip.size)
        elif dst.op == "far":
            # Far call far [eax]
            addr = dst.args[0].arg
            m1 = ir.ExprMem(addr, CS.size)
            m2 = ir.ExprMem(addr + m2_expr.ExprInt(2, addr.size), meip.size)
        else:
            raise RuntimeError("bad call operator")

        e.append(m2_expr.ExprAff(CS, m1))
        e.append(m2_expr.ExprAff(meip, m2))

        e.append(m2_expr.ExprAff(ir.IRDst, m2))

        c = myesp + m2_expr.ExprInt(-s / 8, s)
        e.append(m2_expr.ExprAff(ir.ExprMem(c, size=s).zeroExtend(s),
                                 CS.zeroExtend(s)))

        c = myesp + m2_expr.ExprInt(-2 * s / 8, s)
        e.append(m2_expr.ExprAff(ir.ExprMem(c, size=s).zeroExtend(s),
                                 meip.zeroExtend(s)))

        c = myesp + m2_expr.ExprInt((-2 * s) / 8, s)
        e.append(m2_expr.ExprAff(myesp, c))
        return e, []

    c = myesp + m2_expr.ExprInt((-s / 8), s)
    e.append(m2_expr.ExprAff(myesp, c))
    if ir.do_stk_segm:
        c = m2_expr.ExprOp('segm', SS, c)
    e.append(m2_expr.ExprAff(ir.ExprMem(c, size=s), n))
    e.append(m2_expr.ExprAff(meip, dst.zeroExtend(ir.IRDst.size)))
    e.append(m2_expr.ExprAff(ir.IRDst, dst.zeroExtend(ir.IRDst.size)))
    # if not expr_is_int_or_label(dst):
    #    dst = meip
    return e, []


def ret(ir, instr, src=None):
    e = []
    meip = mRIP[ir.IRDst.size]
    size, admode = instr.v_opmode(), instr.v_admode()
    myesp = mRSP[instr.mode][:size]

    if src is None:
        src = m2_expr.ExprInt(0, size)
        value = (myesp + (m2_expr.ExprInt((size / 8), size)))
    else:
        src = m2_expr.ExprInt(int(src), size)
        value = (myesp + (m2_expr.ExprInt((size / 8), size) + src))

    e.append(m2_expr.ExprAff(myesp, value))
    result = myesp
    if ir.do_stk_segm:
        result = m2_expr.ExprOp('segm', SS, result)
    e.append(m2_expr.ExprAff(meip, ir.ExprMem(
        result, size=size).zeroExtend(size)))
    e.append(m2_expr.ExprAff(ir.IRDst,
                             ir.ExprMem(result, size=size).zeroExtend(size)))
    return e, []


def retf(ir, instr, src=None):
    e = []
    meip = mRIP[ir.IRDst.size]
    size, admode = instr.v_opmode(), instr.v_admode()
    if src is None:
        src = m2_expr.ExprInt(0, instr.mode)
    myesp = mRSP[instr.mode][:size]

    src = src.zeroExtend(size)

    result = myesp
    if ir.do_stk_segm:
        result = m2_expr.ExprOp('segm', SS, result)
    e.append(m2_expr.ExprAff(meip, ir.ExprMem(
        result, size=size).zeroExtend(size)))
    e.append(m2_expr.ExprAff(ir.IRDst,
                             ir.ExprMem(result, size=size).zeroExtend(size)))
    # e.append(m2_expr.ExprAff(meip, ir.ExprMem(c, size = s)))
    result = myesp + m2_expr.ExprInt(size / 8, size)
    if ir.do_stk_segm:
        result = m2_expr.ExprOp('segm', SS, result)
    e.append(m2_expr.ExprAff(CS, ir.ExprMem(result, size=16)))

    value = myesp + (m2_expr.ExprInt((2 * size) / 8, size) + src)
    e.append(m2_expr.ExprAff(myesp, value))
    return e, []


def leave(ir, instr):
    opmode, admode = instr.v_opmode(), instr.v_admode()
    size = instr.mode
    myesp = mRSP[size]
    e = []
    e.append(m2_expr.ExprAff(mRBP[size], ir.ExprMem(mRBP[size], size=size)))
    e.append(m2_expr.ExprAff(myesp,
                             m2_expr.ExprInt(size / 8, size) + mRBP[size]))
    return e, []


def enter(ir, instr, src1, src2):
    size, admode = instr.v_opmode(), instr.v_admode()
    myesp = mRSP[instr.mode][:size]
    myebp = mRBP[instr.mode][:size]

    src1 = src1.zeroExtend(size)

    e = []
    esp_tmp = myesp - m2_expr.ExprInt(size / 8, size)
    e.append(m2_expr.ExprAff(ir.ExprMem(esp_tmp, size=size),
                             myebp))
    e.append(m2_expr.ExprAff(myebp, esp_tmp))
    e.append(m2_expr.ExprAff(myesp,
                             myesp - (src1 + m2_expr.ExprInt(size / 8, size))))
    return e, []


def jmp(ir, instr, dst):
    e = []
    meip = mRIP[ir.IRDst.size]

    if isinstance(dst, m2_expr.ExprOp):
        if dst.op == "segm":
            # Far jmp segm:addr
            segm = dst.args[0]
            base = dst.args[1]
            m1 = segm.zeroExtend(CS.size)
            m2 = base.zeroExtend(meip.size)
        elif dst.op == "far":
            # Far jmp far [eax]
            addr = dst.args[0].arg
            m1 = ir.ExprMem(addr, CS.size)
            m2 = ir.ExprMem(addr + m2_expr.ExprInt(2, addr.size), meip.size)
        else:
            raise RuntimeError("bad jmp operator")

        e.append(m2_expr.ExprAff(CS, m1))
        e.append(m2_expr.ExprAff(meip, m2))
        e.append(m2_expr.ExprAff(ir.IRDst, m2))

    else:
        # Classic jmp
        e.append(m2_expr.ExprAff(meip, dst))
        e.append(m2_expr.ExprAff(ir.IRDst, dst))

        if isinstance(dst, m2_expr.ExprMem):
            dst = meip
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
    return gen_jcc(ir, instr, cf | zf, dst, False)


def jae(ir, instr, dst):
    return gen_jcc(ir, instr, cf, dst, False)


def jb(ir, instr, dst):
    return gen_jcc(ir, instr, cf, dst, True)


def jbe(ir, instr, dst):
    return gen_jcc(ir, instr, cf | zf, dst, True)


def jge(ir, instr, dst):
    return gen_jcc(ir, instr, nf - of, dst, False)


def jg(ir, instr, dst):
    return gen_jcc(ir, instr, zf | (nf - of), dst, False)


def jl(ir, instr, dst):
    return gen_jcc(ir, instr, nf - of, dst, True)


def jle(ir, instr, dst):
    return gen_jcc(ir, instr, zf | (nf - of), dst, True)


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
    meip = mRIP[ir.IRDst.size]
    admode = instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
    c = myecx - m2_expr.ExprInt(1, myecx.size)
    dst_o = m2_expr.ExprCond(c,
                             dst.zeroExtend(ir.IRDst.size),
                             n.zeroExtend(ir.IRDst.size))
    e.append(m2_expr.ExprAff(myecx, c))
    e.append(m2_expr.ExprAff(meip, dst_o))
    e.append(m2_expr.ExprAff(ir.IRDst, dst_o))
    return e, []


def loopne(ir, instr, dst):
    e = []
    meip = mRIP[ir.IRDst.size]
    admode = instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

    c = m2_expr.ExprCond(myecx - m2_expr.ExprInt(1, size=myecx.size),
                         m2_expr.ExprInt(1, 1),
                         m2_expr.ExprInt(0, 1))
    c &= zf ^ m2_expr.ExprInt(1, 1)

    e.append(m2_expr.ExprAff(myecx, myecx - m2_expr.ExprInt(1, myecx.size)))
    dst_o = m2_expr.ExprCond(c,
                             dst.zeroExtend(ir.IRDst.size),
                             n.zeroExtend(ir.IRDst.size))
    e.append(m2_expr.ExprAff(meip, dst_o))
    e.append(m2_expr.ExprAff(ir.IRDst, dst_o))
    return e, []


def loope(ir, instr, dst):
    e = []
    meip = mRIP[ir.IRDst.size]
    admode = instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
    c = m2_expr.ExprCond(myecx - m2_expr.ExprInt(1, size=myecx.size),
                         m2_expr.ExprInt(1, 1),
                         m2_expr.ExprInt(0, 1))
    c &= zf
    e.append(m2_expr.ExprAff(myecx, myecx - m2_expr.ExprInt(1, myecx.size)))
    dst_o = m2_expr.ExprCond(c,
                             dst.zeroExtend(ir.IRDst.size),
                             n.zeroExtend(ir.IRDst.size))
    e.append(m2_expr.ExprAff(meip, dst_o))
    e.append(m2_expr.ExprAff(ir.IRDst, dst_o))
    return e, []

# XXX size to do; eflag


def div(_, instr, src1):
    e = []
    size = src1.size
    if size == 8:
        src2 = mRAX[instr.mode][:16]
    elif size in [16, 32, 64]:
        s1, s2 = mRDX[size], mRAX[size]
        src2 = m2_expr.ExprCompose(s2, s1)
    else:
        raise ValueError('div arg not impl', src1)

    c_d = m2_expr.ExprOp('udiv', src2, src1.zeroExtend(src2.size))
    c_r = m2_expr.ExprOp('umod', src2, src1.zeroExtend(src2.size))

    # if 8 bit div, only ax is affected
    if size == 8:
        e.append(m2_expr.ExprAff(src2, m2_expr.ExprCompose(c_d[:8], c_r[:8])))
    else:
        e.append(m2_expr.ExprAff(s1, c_r[:size]))
        e.append(m2_expr.ExprAff(s2, c_d[:size]))
    return e, []


# XXX size to do; eflag

def idiv(_, instr, src1):
    e = []
    size = src1.size

    if size == 8:
        src2 = mRAX[instr.mode][:16]
    elif size in [16, 32, 64]:
        s1, s2 = mRDX[size], mRAX[size]
        src2 = m2_expr.ExprCompose(s2, s1)
    else:
        raise ValueError('div arg not impl', src1)

    c_d = m2_expr.ExprOp('idiv', src2, src1.signExtend(src2.size))
    c_r = m2_expr.ExprOp('imod', src2, src1.signExtend(src2.size))

    # if 8 bit div, only ax is affected
    if size == 8:
        e.append(m2_expr.ExprAff(src2, m2_expr.ExprCompose(c_d[:8], c_r[:8])))
    else:
        e.append(m2_expr.ExprAff(s1, c_r[:size]))
        e.append(m2_expr.ExprAff(s2, c_d[:size]))
    return e, []


# XXX size to do; eflag


def mul(_, instr, src1):
    e = []
    size = src1.size
    if src1.size in [16, 32, 64]:
        result = m2_expr.ExprOp('*',
                                mRAX[size].zeroExtend(size * 2),
                                src1.zeroExtend(size * 2))
        e.append(m2_expr.ExprAff(mRAX[size], result[:size]))
        e.append(m2_expr.ExprAff(mRDX[size], result[size:size * 2]))

    elif src1.size == 8:
        result = m2_expr.ExprOp('*',
                                mRAX[instr.mode][:8].zeroExtend(16),
                                src1.zeroExtend(16))
        e.append(m2_expr.ExprAff(mRAX[instr.mode][:16], result))
    else:
        raise ValueError('unknow size')

    e.append(m2_expr.ExprAff(of, m2_expr.ExprCond(result[size:size * 2],
                                                  m2_expr.ExprInt(1, 1),
                                                  m2_expr.ExprInt(0, 1))))
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprCond(result[size:size * 2],
                                                  m2_expr.ExprInt(1, 1),
                                                  m2_expr.ExprInt(0, 1))))

    return e, []


def imul(_, instr, src1, src2=None, src3=None):
    e = []
    size = src1.size
    if src2 is None:
        if size in [16, 32, 64]:
            result = m2_expr.ExprOp('*',
                                    mRAX[size].signExtend(size * 2),
                                    src1.signExtend(size * 2))
            e.append(m2_expr.ExprAff(mRAX[size], result[:size]))
            e.append(m2_expr.ExprAff(mRDX[size], result[size:size * 2]))
        elif size == 8:
            dst = mRAX[instr.mode][:16]
            result = m2_expr.ExprOp('*',
                                    mRAX[instr.mode][:8].signExtend(16),
                                    src1.signExtend(16))

            e.append(m2_expr.ExprAff(dst, result))
        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt(1, 1),
                                 m2_expr.ExprInt(0, 1))
        e.append(m2_expr.ExprAff(cf, value))
        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt(1, 1),
                                 m2_expr.ExprInt(0, 1))
        e.append(m2_expr.ExprAff(of, value))

    else:
        if src3 is None:
            src3 = src2
            src2 = src1
        result = m2_expr.ExprOp('*',
                                src2.signExtend(size * 2),
                                src3.signExtend(size * 2))
        e.append(m2_expr.ExprAff(src1, result[:size]))

        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt(1, 1),
                                 m2_expr.ExprInt(0, 1))
        e.append(m2_expr.ExprAff(cf, value))
        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt(1, 1),
                                 m2_expr.ExprInt(0, 1))
        e.append(m2_expr.ExprAff(of, value))
    return e, []


def cbw(_, instr):
    e = []
    tempAL = mRAX[instr.mode][:8]
    tempAX = mRAX[instr.mode][:16]
    e.append(m2_expr.ExprAff(tempAX, tempAL.signExtend(16)))
    return e, []


def cwde(_, instr):
    e = []
    tempAX = mRAX[instr.mode][:16]
    tempEAX = mRAX[instr.mode][:32]
    e.append(m2_expr.ExprAff(tempEAX, tempAX.signExtend(32)))
    return e, []


def cdqe(_, instr):
    e = []
    tempEAX = mRAX[instr.mode][:32]
    tempRAX = mRAX[instr.mode][:64]
    e.append(m2_expr.ExprAff(tempRAX, tempEAX.signExtend(64)))
    return e, []


def cwd(_, instr):
    e = []
    tempAX = mRAX[instr.mode][:16]
    tempDX = mRDX[instr.mode][:16]
    c = tempAX.signExtend(32)
    e.append(m2_expr.ExprAff(tempAX, c[:16]))
    e.append(m2_expr.ExprAff(tempDX, c[16:32]))
    return e, []


def cdq(_, instr):
    e = []
    tempEAX = mRAX[instr.mode][:32]
    tempEDX = mRDX[instr.mode][:32]
    c = tempEAX.signExtend(64)
    e.append(m2_expr.ExprAff(tempEAX, c[:32]))
    e.append(m2_expr.ExprAff(tempEDX, c[32:64]))
    return e, []


def cqo(_, instr):
    e = []
    tempRAX = mRAX[instr.mode][:64]
    tempRDX = mRDX[instr.mode][:64]
    c = tempRAX.signExtend(128)
    e.append(m2_expr.ExprAff(tempRAX, c[:64]))
    e.append(m2_expr.ExprAff(tempRDX, c[64:128]))
    return e, []


def stos(ir, instr, size):
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

    addr_o = mRDI[instr.mode][:instr.v_admode()]
    addr = addr_o
    addr_p = addr + m2_expr.ExprInt(size / 8, addr.size)
    addr_m = addr - m2_expr.ExprInt(size / 8, addr.size)
    if ir.do_str_segm:
        mss = ES
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        addr = m2_expr.ExprOp('segm', mss, addr)

    b = mRAX[instr.mode][:size]

    e0 = []
    e0.append(m2_expr.ExprAff(addr_o, addr_p))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = IRBlock(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(addr_o, addr_m))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = IRBlock(lbl_df_1.name, [e1])

    e = []
    e.append(m2_expr.ExprAff(ir.ExprMem(addr, size), b))
    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))
    return e, [e0, e1]


def lods(ir, instr, size):
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
    e = []

    addr_o = mRSI[instr.mode][:instr.v_admode()]
    addr = addr_o
    addr_p = addr + m2_expr.ExprInt(size / 8, addr.size)
    addr_m = addr - m2_expr.ExprInt(size / 8, addr.size)
    if ir.do_str_segm:
        mss = DS
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        addr = m2_expr.ExprOp('segm', mss, addr)

    b = mRAX[instr.mode][:size]

    e0 = []
    e0.append(m2_expr.ExprAff(addr_o, addr_p))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = IRBlock(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(addr_o, addr_m))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = IRBlock(lbl_df_1.name, [e1])

    e = []
    if instr.mode == 64 and b.size == 32:
        e.append(m2_expr.ExprAff(mRAX[instr.mode],
                                 ir.ExprMem(addr, size).zeroExtend(64)))
    else:
        e.append(m2_expr.ExprAff(b, ir.ExprMem(addr, size)))

    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))
    return e, [e0, e1]


def movs(ir, instr, size):
    lbl_df_0 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_df_1 = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

    a = mRDI[instr.mode][:instr.v_admode()]
    b = mRSI[instr.mode][:instr.v_admode()]

    e = []
    src = b
    dst = a
    if ir.do_str_segm:
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        src = m2_expr.ExprOp('segm', DS, src)
        dst = m2_expr.ExprOp('segm', ES, dst)
    e.append(m2_expr.ExprAff(ir.ExprMem(dst, size),
                             ir.ExprMem(src, size)))

    e0 = []
    e0.append(m2_expr.ExprAff(a, a + m2_expr.ExprInt(size / 8, a.size)))
    e0.append(m2_expr.ExprAff(b, b + m2_expr.ExprInt(size / 8, b.size)))
    e0.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e0 = IRBlock(lbl_df_0.name, [e0])

    e1 = []
    e1.append(m2_expr.ExprAff(a, a - m2_expr.ExprInt(size / 8, a.size)))
    e1.append(m2_expr.ExprAff(b, b - m2_expr.ExprInt(size / 8, b.size)))
    e1.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    e1 = IRBlock(lbl_df_1.name, [e1])

    e.append(m2_expr.ExprAff(ir.IRDst,
                             m2_expr.ExprCond(df, lbl_df_1, lbl_df_0)))
    return e, [e0, e1]


def movsd(_, instr, dst, src):
    e = []
    if isinstance(dst, m2_expr.ExprId) and isinstance(src, m2_expr.ExprMem):
        src = m2_expr.ExprMem(src.arg, dst.size)
    elif isinstance(dst, m2_expr.ExprMem) and isinstance(src, m2_expr.ExprId):
        dst = m2_expr.ExprMem(dst.arg, src.size)

    e.append(m2_expr.ExprAff(dst, src))
    return e, []


def movsd_dispatch(ir, instr, dst=None, src=None):
    if dst is None and src is None:
        return movs(ir, instr, 32)
    else:
        return movsd(ir, instr, dst, src)


def float_prev(flt, popcount=1):
    if not flt in float_list:
        return None
    i = float_list.index(flt)
    if i < popcount:
        # Drop value (ex: FSTP ST(0))
        return None
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
    for i in xrange(8 - popcount):
        if avoid_flt != float_list[i]:
            e.append(m2_expr.ExprAff(float_list[i],
                                     float_list[i + popcount]))
    fill_value = m2_expr.ExprOp("int_64_to_double",
                                m2_expr.ExprInt(0, float_list[i].size))
    for i in xrange(8 - popcount, 8):
        e.append(m2_expr.ExprAff(float_list[i],
                                 fill_value))
    e.append(
        m2_expr.ExprAff(float_stack_ptr,
                        float_stack_ptr - m2_expr.ExprInt(popcount, 3)))
    return e

# XXX TODO


def fcom(_, instr, dst=None, src=None):

    if dst is None and src is None:
        dst, src = float_st0, float_st1
    elif src is None:
        src = mem2double(instr, dst)
        dst = float_st0

    e = []

    e.append(m2_expr.ExprAff(float_c0, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAff(float_c1, m2_expr.ExprOp('fcom_c1', dst, src)))
    e.append(m2_expr.ExprAff(float_c2, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAff(float_c3, m2_expr.ExprOp('fcom_c3', dst, src)))

    e += set_float_cs_eip(instr)
    return e, []


def ftst(_, instr):
    dst = float_st0

    e = []
    src = m2_expr.ExprOp('int_32_to_double', m2_expr.ExprInt(0, 32))
    e.append(m2_expr.ExprAff(float_c0, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAff(float_c1, m2_expr.ExprOp('fcom_c1', dst, src)))
    e.append(m2_expr.ExprAff(float_c2, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAff(float_c3, m2_expr.ExprOp('fcom_c3', dst, src)))

    e += set_float_cs_eip(instr)
    return e, []


def fxam(_, instr):
    dst = float_st0

    e = []
    e.append(m2_expr.ExprAff(float_c0, m2_expr.ExprOp('fxam_c0', dst)))
    e.append(m2_expr.ExprAff(float_c1, m2_expr.ExprOp('fxam_c1', dst)))
    e.append(m2_expr.ExprAff(float_c2, m2_expr.ExprOp('fxam_c2', dst)))
    e.append(m2_expr.ExprAff(float_c3, m2_expr.ExprOp('fxam_c3', dst)))

    e += set_float_cs_eip(instr)
    return e, []


def ficom(_, instr, dst, src=None):

    dst, src = float_implicit_st0(dst, src)

    e = []

    e.append(m2_expr.ExprAff(float_c0,
                             m2_expr.ExprOp('fcom_c0', dst,
                                            src.zeroExtend(dst.size))))
    e.append(m2_expr.ExprAff(float_c1,
                             m2_expr.ExprOp('fcom_c1', dst,
                                            src.zeroExtend(dst.size))))
    e.append(m2_expr.ExprAff(float_c2,
                             m2_expr.ExprOp('fcom_c2', dst,
                                            src.zeroExtend(dst.size))))
    e.append(m2_expr.ExprAff(float_c3,
                             m2_expr.ExprOp('fcom_c3', dst,
                                            src.zeroExtend(dst.size))))

    e += set_float_cs_eip(instr)
    return e, []


def fcomi(_, instr, dst=None, src=None):
    # TODO unordered float
    if dst is None and src is None:
        dst, src = float_st0, float_st1
    elif src is None:
        src = dst
        dst = float_st0

    e = []

    e.append(m2_expr.ExprAff(cf, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('fcom_c3', dst, src)))

    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt(0, 1)))

    e += set_float_cs_eip(instr)
    return e, []


def fcomip(ir, instr, dst=None, src=None):
    e, extra = fcomi(ir, instr, dst, src)
    e += float_pop()
    e += set_float_cs_eip(instr)
    return e, extra


def fucomi(ir, instr, dst=None, src=None):
    # TODO unordered float
    return fcomi(ir, instr, dst, src)


def fucomip(ir, instr, dst=None, src=None):
    # TODO unordered float
    return fcomip(ir, instr, dst, src)


def fcomp(ir, instr, dst=None, src=None):
    e, extra = fcom(ir, instr, dst, src)
    e += float_pop()
    e += set_float_cs_eip(instr)
    return e, extra


def fcompp(ir, instr, dst=None, src=None):
    e, extra = fcom(ir, instr, dst, src)
    e += float_pop(popcount=2)
    e += set_float_cs_eip(instr)
    return e, extra


def ficomp(ir, instr, dst, src=None):
    e, extra = ficom(ir, instr, dst, src)
    e += float_pop()
    e += set_float_cs_eip(instr)
    return e, extra


def fucom(ir, instr, dst=None, src=None):
    # TODO unordered float
    return fcom(ir, instr, dst, src)


def fucomp(ir, instr, dst=None, src=None):
    # TODO unordered float
    return fcomp(ir, instr, dst, src)


def fucompp(ir, instr, dst=None, src=None):
    # TODO unordered float
    return fcompp(ir, instr, dst, src)


def comiss(_, instr, dst, src):
    # TODO unordered float

    e = []

    dst = m2_expr.ExprOp('int_32_to_float', dst[:32])
    src = m2_expr.ExprOp('int_32_to_float', src[:32])

    e.append(m2_expr.ExprAff(cf, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('fcom_c3', dst, src)))

    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt(0, 1)))

    e += set_float_cs_eip(instr)
    return e, []


def comisd(_, instr, dst, src):
    # TODO unordered float

    e = []

    dst = m2_expr.ExprOp('int_64_to_double', dst[:64])
    src = m2_expr.ExprOp('int_64_to_double', src[:64])

    e.append(m2_expr.ExprAff(cf, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('fcom_c3', dst, src)))

    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt(0, 1)))

    e += set_float_cs_eip(instr)
    return e, []


def fld(_, instr, src):
    src = mem2double(instr, src)

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


def fst(_, instr, dst):
    e = []

    if isinstance(dst, m2_expr.ExprMem):
        if dst.size > 64:
            raise NotImplementedError('float to long')
        src = m2_expr.ExprOp('double_to_mem_%.2d' % dst.size, float_st0)
    else:
        src = float_st0

    e.append(m2_expr.ExprAff(dst, src))
    e += set_float_cs_eip(instr)
    return e, []


def fstp(ir, instr, dst):
    e = []

    if isinstance(dst, m2_expr.ExprMem):
        if dst.size > 64:
            # TODO: move to 80 bits
            dst = ir.ExprMem(dst.arg, size=64)

        src = m2_expr.ExprOp('double_to_mem_%.2d' % dst.size, float_st0)
        e.append(m2_expr.ExprAff(dst, src))
    else:
        src = float_st0
        if float_list.index(dst) > 1:
            # a = st0 -> st0 is dropped
            # a = st1 -> st0 = st0, useless
            e.append(m2_expr.ExprAff(float_prev(dst), src))

    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fist(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('double_to_int_%d' % dst.size,
                                                 float_st0)))

    e += set_float_cs_eip(instr)
    return e, []


def fistp(ir, instr, dst):
    e, extra = fist(ir, instr, dst)
    e += float_pop(dst)
    return e, extra


def fisttp(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAff(dst,
                             m2_expr.ExprOp('double_trunc_to_int_%d' % dst.size,
                                            float_st0)))

    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fild(ir, instr, src):
    # XXXXX
    src = m2_expr.ExprOp('int_%.2d_to_double' % src.size, src)
    e = []
    e += set_float_cs_eip(instr)
    e_fld, extra = fld(ir, instr, src)
    e += e_fld
    return e, extra


def fldz(ir, instr):
    return fld(ir, instr, m2_expr.ExprOp('int_32_to_double',
                                         m2_expr.ExprInt(0, 32)))


def fld1(ir, instr):
    return fld(ir, instr, m2_expr.ExprOp('int_32_to_double',
                                         m2_expr.ExprInt(1, 32)))


def fldl2t(ir, instr):
    value_f = math.log(10) / math.log(2)
    value = struct.unpack('I', struct.pack('f', value_f))[0]
    return fld(ir, instr, m2_expr.ExprOp('int_32_to_double',
                                         m2_expr.ExprInt(value, 32)))


def fldpi(ir, instr):
    value_f = math.pi
    value = struct.unpack('I', struct.pack('f', value_f))[0]
    return fld(ir, instr, m2_expr.ExprOp('int_32_to_double',
                                         m2_expr.ExprInt(value, 32)))


def fldln2(ir, instr):
    value_f = math.log(2)
    value = struct.unpack('Q', struct.pack('d', value_f))[0]
    return fld(ir, instr, m2_expr.ExprOp('mem_64_to_double',
                                         m2_expr.ExprInt(value, 64)))


def fldl2e(ir, instr):
    x = struct.pack('d', 1 / math.log(2))
    x = struct.unpack('Q', x)[0]
    return fld(ir, instr, m2_expr.ExprOp('mem_64_to_double',
                                         m2_expr.ExprInt(x, 64)))


def fldlg2(ir, instr):
    x = struct.pack('d', math.log10(2))
    x = struct.unpack('Q', x)[0]
    return fld(ir, instr, m2_expr.ExprOp('mem_64_to_double',
                                         m2_expr.ExprInt(x, 64)))


def fadd(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fadd', dst, src)))

    e += set_float_cs_eip(instr)
    return e, []


def fiadd(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fiadd', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fisub(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fisub', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fisubr(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fisub', src, dst)))
    e += set_float_cs_eip(instr)
    return e, []


def fpatan(_, instr):
    e = []
    a = float_st1
    e.append(m2_expr.ExprAff(float_prev(a),
                             m2_expr.ExprOp('fpatan', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fprem(_, instr):
    e = []
    e.append(
        m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fprem', float_st0, float_st1)))
    # Remaining bits (ex: used in argument reduction in tan)
    remain = m2_expr.ExprOp('fprem_lsb', float_st0, float_st1)
    e += [m2_expr.ExprAff(float_c0, remain[2:3]),
          m2_expr.ExprAff(float_c3, remain[1:2]),
          m2_expr.ExprAff(float_c1, remain[0:1]),
          # Consider the reduction is always completed
          m2_expr.ExprAff(float_c2, m2_expr.ExprInt(0, 1)),
          ]
    e += set_float_cs_eip(instr)
    return e, []


def fprem1(_, instr):
    e = []
    e.append(
        m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fprem1', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    return e, []


def faddp(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(float_prev(dst), m2_expr.ExprOp('fadd', dst, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fninit(_, instr):
    e = []
    e += set_float_cs_eip(instr)
    return e, []


def fyl2x(_, instr):
    e = []
    a = float_st1
    e.append(
        m2_expr.ExprAff(float_prev(a), m2_expr.ExprOp('fyl2x', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fnstenv(ir, instr, dst):
    e = []
    # XXX TODO tag word, ...
    status_word = m2_expr.ExprCompose(m2_expr.ExprInt(0, 8),
                                      float_c0, float_c1, float_c2,
                                      float_stack_ptr, float_c3,
                                      m2_expr.ExprInt(0, 1))

    s = instr.mode
    # The behaviour in 64bit is identical to 32 bit
    # This will truncate addresses
    size = min(32, s)
    ad = ir.ExprMem(dst.arg, size=16)
    e.append(m2_expr.ExprAff(ad, float_control))
    ad = ir.ExprMem(dst.arg + m2_expr.ExprInt(size /
                                              8 * 1, dst.arg.size), size=16)
    e.append(m2_expr.ExprAff(ad, status_word))
    ad = ir.ExprMem(dst.arg + m2_expr.ExprInt(size /
                                              8 * 3, dst.arg.size), size=size)
    e.append(m2_expr.ExprAff(ad, float_eip[:size]))
    ad = ir.ExprMem(dst.arg + m2_expr.ExprInt(size /
                                              8 * 4, dst.arg.size), size=16)
    e.append(m2_expr.ExprAff(ad, float_cs))
    ad = ir.ExprMem(dst.arg + m2_expr.ExprInt(size /
                                              8 * 5, dst.arg.size), size=size)
    e.append(m2_expr.ExprAff(ad, float_address[:size]))
    ad = ir.ExprMem(dst.arg + m2_expr.ExprInt(size /
                                              8 * 6, dst.arg.size), size=16)
    e.append(m2_expr.ExprAff(ad, float_ds))
    return e, []


def fldenv(ir, instr, src):
    e = []
    # Inspired from fnstenv (same TODOs / issues)

    s = instr.mode
    # The behaviour in 64bit is identical to 32 bit
    # This will truncate addresses
    size = min(32, s)

    # Float control
    ad = ir.ExprMem(src.arg, size=16)
    e.append(m2_expr.ExprAff(float_control, ad))

    # Status word
    ad = ir.ExprMem(src.arg + m2_expr.ExprInt(size / 8 * 1, size=src.arg.size),
                    size=16)
    e += [m2_expr.ExprAff(x, y) for x, y in ((float_c0, ad[8:9]),
                                             (float_c1, ad[9:10]),
                                             (float_c2, ad[10:11]),
                                             (float_stack_ptr, ad[11:14]),
                                             (float_c3, ad[14:15]))
          ]

    # EIP, CS, Address, DS
    for offset, target in ((3, float_eip[:size]),
                           (4, float_cs),
                           (5, float_address[:size]),
                           (6, float_ds)):
        ad = ir.ExprMem(src.arg + m2_expr.ExprInt(size / 8 * offset,
                                                  size=src.arg.size),
                        size=target.size)
        e.append(m2_expr.ExprAff(target, ad))

    return e, []


def fsub(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fsub', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fsubp(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(float_prev(dst), m2_expr.ExprOp('fsub', dst, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fsubr(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fsub', src, dst)))
    e += set_float_cs_eip(instr)
    return e, []


def fsubrp(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(float_prev(dst), m2_expr.ExprOp('fsub', src, dst)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fmul(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fmul', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fimul(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fimul', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fdiv(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fdiv', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fdivr(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fdiv', src, dst)))
    e += set_float_cs_eip(instr)
    return e, []


def fdivrp(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(float_prev(dst), m2_expr.ExprOp('fdiv', src, dst)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fidiv(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fidiv', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fidivr(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('fidiv', src, dst)))
    e += set_float_cs_eip(instr)
    return e, []


def fdivp(_, instr, dst, src=None):
    # Invalid emulation
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(float_prev(dst), m2_expr.ExprOp('fdiv', dst, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fmulp(_, instr, dst, src=None):
    # Invalid emulation
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(float_prev(dst), m2_expr.ExprOp('fmul', dst, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def ftan(_, instr, src):
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('ftan', src)))
    e += set_float_cs_eip(instr)
    return e, []


def fxch(_, instr, src):
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAff(float_st0, src))
    e.append(m2_expr.ExprAff(src, float_st0))
    e += set_float_cs_eip(instr)
    return e, []


def fptan(_, instr):
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
                                            m2_expr.ExprInt(1, 32))))
    e.append(
        m2_expr.ExprAff(float_stack_ptr,
                        float_stack_ptr + m2_expr.ExprInt(1, 3)))
    return e, []


def frndint(_, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('frndint', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fsin(_, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fsin', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fcos(_, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fcos', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fsincos(_, instr):
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


def fscale(_, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fscale', float_st0,
                                                       float_st1)))
    e += set_float_cs_eip(instr)
    return e, []


def f2xm1(_, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('f2xm1', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fchs(_, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fchs', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fsqrt(_, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fsqrt', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fabs(_, instr):
    e = []
    e.append(m2_expr.ExprAff(float_st0, m2_expr.ExprOp('fabs', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fnstsw(_, instr, dst):
    args = [
        # Exceptions -> 0
        m2_expr.ExprInt(0, 8),
        float_c0,
        float_c1,
        float_c2,
        float_stack_ptr,
        float_c3,
        # B: FPU is not busy -> 0
        m2_expr.ExprInt(0, 1)]
    e = [m2_expr.ExprAff(dst, m2_expr.ExprCompose(*args))]
    return e, []


def fnstcw(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAff(dst, float_control))
    return e, []


def fldcw(_, instr, src):
    e = []
    e.append(m2_expr.ExprAff(float_control, src))
    return e, []


def fwait(_, instr):
    return [], []


def fcmovb(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, cf, arg1, arg2, True)


def fcmove(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, zf, arg1, arg2, True)


def fcmovbe(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, cf | zf, arg1, arg2, True)


def fcmovu(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, pf, arg1, arg2, True)


def fcmovnb(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, cf, arg1, arg2, False)


def fcmovne(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, zf, arg1, arg2, False)


def fcmovnbe(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, cf | zf, arg1, arg2, False)


def fcmovnu(ir, instr, arg1, arg2):
    return gen_fcmov(ir, instr, pf, arg1, arg2, False)


def nop(_, instr, a=None):
    return [], []


def prefetchw(_, instr, src=None):
    # see 4-201 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []


def lfence(_, instr, src=None):
    # see 3-485 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []


def ud2(_, instr, src=None):
    e = [m2_expr.ExprAff(exception_flags, m2_expr.ExprInt(
        EXCEPT_ILLEGAL_INSN, exception_flags.size))]
    return e, []


def hlt(_, instr):
    e = []
    except_int = EXCEPT_PRIV_INSN
    e.append(m2_expr.ExprAff(exception_flags, m2_expr.ExprInt(except_int, 32)))
    return e, []


def rdtsc(_, instr):
    e = []
    e.append(m2_expr.ExprAff(tsc1, tsc1 + m2_expr.ExprInt(1, 32)))
    e.append(m2_expr.ExprAff(tsc2, tsc2 + m2_expr.ExprCond(tsc1 - tsc1.mask,
                                                           m2_expr.ExprInt(0, 32),
                                                           m2_expr.ExprInt(1, 32))))
    e.append(m2_expr.ExprAff(mRAX[32], tsc1))
    e.append(m2_expr.ExprAff(mRDX[32], tsc2))
    return e, []


def daa(_, instr):
    e = []
    r_al = mRAX[instr.mode][:8]

    cond1 = expr_cmpu(r_al[:4], m2_expr.ExprInt(0x9, 4)) | af
    e.append(m2_expr.ExprAff(af, cond1))

    cond2 = expr_cmpu(m2_expr.ExprInt(6, 8), r_al)
    cond3 = expr_cmpu(r_al, m2_expr.ExprInt(0x99, 8)) | cf

    cf_c1 = m2_expr.ExprCond(cond1,
                             cf | (cond2),
                             m2_expr.ExprInt(0, 1))
    new_cf = m2_expr.ExprCond(cond3,
                              m2_expr.ExprInt(1, 1),
                              m2_expr.ExprInt(0, 1))
    e.append(m2_expr.ExprAff(cf, new_cf))

    al_c1 = m2_expr.ExprCond(cond1,
                             r_al + m2_expr.ExprInt(6, 8),
                             r_al)

    new_al = m2_expr.ExprCond(cond3,
                              al_c1 + m2_expr.ExprInt(0x60, 8),
                              al_c1)
    e.append(m2_expr.ExprAff(r_al, new_al))
    e += update_flag_znp(new_al)
    return e, []


def das(_, instr):
    e = []
    r_al = mRAX[instr.mode][:8]

    cond1 = expr_cmpu(r_al[:4], m2_expr.ExprInt(0x9, 4)) | af
    e.append(m2_expr.ExprAff(af, cond1))

    cond2 = expr_cmpu(m2_expr.ExprInt(6, 8), r_al)
    cond3 = expr_cmpu(r_al, m2_expr.ExprInt(0x99, 8)) | cf

    cf_c1 = m2_expr.ExprCond(cond1,
                             cf | (cond2),
                             m2_expr.ExprInt(0, 1))
    new_cf = m2_expr.ExprCond(cond3,
                              m2_expr.ExprInt(1, 1),
                              cf_c1)
    e.append(m2_expr.ExprAff(cf, new_cf))

    al_c1 = m2_expr.ExprCond(cond1,
                             r_al - m2_expr.ExprInt(6, 8),
                             r_al)

    new_al = m2_expr.ExprCond(cond3,
                              al_c1 - m2_expr.ExprInt(0x60, 8),
                              al_c1)
    e.append(m2_expr.ExprAff(r_al, new_al))
    e += update_flag_znp(new_al)
    return e, []


def aam(_, instr, src):
    e = []
    tempAL = mRAX[instr.mode][0:8]
    newEAX = m2_expr.ExprCompose(tempAL % src,
                                 tempAL / src,
                                 mRAX[instr.mode][16:])
    e += [m2_expr.ExprAff(mRAX[instr.mode], newEAX)]
    e += update_flag_arith(newEAX)
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt(0, 1)))
    return e, []


def aad(_, instr, src):
    e = []
    tempAL = mRAX[instr.mode][0:8]
    tempAH = mRAX[instr.mode][8:16]
    newEAX = m2_expr.ExprCompose((tempAL + (tempAH * src)) & m2_expr.ExprInt(0xFF, 8),
                                 m2_expr.ExprInt(0, 8),
                                 mRAX[instr.mode][16:])
    e += [m2_expr.ExprAff(mRAX[instr.mode], newEAX)]
    e += update_flag_arith(newEAX)
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt(0, 1)))
    return e, []


def _tpl_aaa(_, instr, op):
    """Templating for aaa, aas with operation @op
    @op: operation to apply
    """
    e = []
    r_al = mRAX[instr.mode][:8]
    r_ah = mRAX[instr.mode][8:16]
    r_ax = mRAX[instr.mode][:16]
    i0 = m2_expr.ExprInt(0, 1)
    i1 = m2_expr.ExprInt(1, 1)
    # cond: if (al & 0xf) > 9 OR af == 1
    cond = (r_al & m2_expr.ExprInt(0xf, 8)) - m2_expr.ExprInt(9, 8)
    cond = ~cond.msb() & m2_expr.ExprCond(cond, i1, i0)
    cond |= af & i1

    to_add = m2_expr.ExprInt(0x106, size=r_ax.size)
    if op == "-":
        # Avoid ExprOp("-", A, B), should be ExprOp("+", A, ExprOp("-", B))
        first_part = r_ax - to_add
    else:
        first_part = m2_expr.ExprOp(op, r_ax, to_add)
    new_ax = first_part & m2_expr.ExprInt(0xff0f,
                                          size=r_ax.size)
    # set AL
    e.append(m2_expr.ExprAff(r_ax, m2_expr.ExprCond(cond, new_ax, r_ax)))
    e.append(m2_expr.ExprAff(af, cond))
    e.append(m2_expr.ExprAff(cf, cond))
    return e, []


def aaa(ir, instr):
    return _tpl_aaa(ir, instr, "+")


def aas(ir, instr):
    return _tpl_aaa(ir, instr, "-")


def bsr_bsf(ir, instr, dst, src, op_name):
    """
    IF SRC == 0
        ZF = 1
        DEST is left unchanged
    ELSE
        ZF = 0
        DEST = @op_name(SRC)
    """
    lbl_src_null = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_src_not_null = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

    aff_dst = m2_expr.ExprAff(ir.IRDst, lbl_next)
    e = [m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(src,
                                                    lbl_src_not_null,
                                                    lbl_src_null))]
    e_src_null = []
    e_src_null.append(m2_expr.ExprAff(zf, m2_expr.ExprInt(1, zf.size)))
    # XXX destination is undefined
    e_src_null.append(aff_dst)

    e_src_not_null = []
    e_src_not_null.append(m2_expr.ExprAff(zf, m2_expr.ExprInt(0, zf.size)))
    e_src_not_null.append(m2_expr.ExprAff(dst, m2_expr.ExprOp(op_name, src)))
    e_src_not_null.append(aff_dst)

    return e, [IRBlock(lbl_src_null.name, [e_src_null]),
               IRBlock(lbl_src_not_null.name, [e_src_not_null])]


def bsf(ir, instr, dst, src):
    return bsr_bsf(ir, instr, dst, src, "bsf")


def bsr(ir, instr, dst, src):
    return bsr_bsf(ir, instr, dst, src, "bsr")


def arpl(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(exception_flags, m2_expr.ExprInt(1 << 7, 32)))
    return e, []


def ins(_, instr, size):
    e = []
    e.append(m2_expr.ExprAff(exception_flags, m2_expr.ExprInt(1 << 7, 32)))
    return e, []


def sidt(ir, instr, dst):
    e = []
    if not isinstance(dst, m2_expr.ExprMem) or dst.size != 32:
        raise ValueError('not exprmem 32bit instance!!')
    ptr = dst.arg
    print "DEFAULT SIDT ADDRESS %s!!" % str(dst)
    e.append(m2_expr.ExprAff(ir.ExprMem(ptr, 32),
                             m2_expr.ExprInt(0xe40007ff, 32)))
    e.append(
        m2_expr.ExprAff(ir.ExprMem(ptr + m2_expr.ExprInt(4, ptr.size), 16),
                        m2_expr.ExprInt(0x8245, 16)))
    return e, []


def sldt(_, instr, dst):
    print "DEFAULT SLDT ADDRESS %s!!" % str(dst)
    e = [m2_expr.ExprAff(dst, m2_expr.ExprInt(0, dst.size))]
    return e, []


def cmovz(ir, instr, dst, src):
    return gen_cmov(ir, instr, zf, dst, src, True)


def cmovnz(ir, instr, dst, src):
    return gen_cmov(ir, instr, zf, dst, src, False)


def cmovpe(ir, instr, dst, src):
    return gen_cmov(ir, instr, pf, dst, src, True)


def cmovnp(ir, instr, dst, src):
    return gen_cmov(ir, instr, pf, dst, src, False)


def cmovge(ir, instr, dst, src):
    return gen_cmov(ir, instr, nf ^ of, dst, src, False)


def cmovg(ir, instr, dst, src):
    return gen_cmov(ir, instr, zf | (nf ^ of), dst, src, False)


def cmovl(ir, instr, dst, src):
    return gen_cmov(ir, instr, nf ^ of, dst, src, True)


def cmovle(ir, instr, dst, src):
    return gen_cmov(ir, instr, zf | (nf ^ of), dst, src, True)


def cmova(ir, instr, dst, src):
    return gen_cmov(ir, instr, cf | zf, dst, src, False)


def cmovae(ir, instr, dst, src):
    return gen_cmov(ir, instr, cf, dst, src, False)


def cmovbe(ir, instr, dst, src):
    return gen_cmov(ir, instr, cf | zf, dst, src, True)


def cmovb(ir, instr, dst, src):
    return gen_cmov(ir, instr, cf, dst, src, True)


def cmovo(ir, instr, dst, src):
    return gen_cmov(ir, instr, of, dst, src, True)


def cmovno(ir, instr, dst, src):
    return gen_cmov(ir, instr, of, dst, src, False)


def cmovs(ir, instr, dst, src):
    return gen_cmov(ir, instr, nf, dst, src, True)


def cmovns(ir, instr, dst, src):
    return gen_cmov(ir, instr, nf, dst, src, False)


def icebp(_, instr):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                             m2_expr.ExprInt(EXCEPT_SOFT_BP, 32)))
    return e, []
# XXX


def l_int(_, instr, src):
    e = []
    # XXX
    if src.arg in [1, 3]:
        except_int = EXCEPT_SOFT_BP
    else:
        except_int = EXCEPT_INT_XX
    e.append(m2_expr.ExprAff(exception_flags,
                             m2_expr.ExprInt(except_int, 32)))
    e.append(m2_expr.ExprAff(interrupt_num, src))
    return e, []


def l_sysenter(_, instr):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                             m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32)))
    return e, []


def l_syscall(_, instr):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                             m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32)))
    return e, []

# XXX


def l_out(_, instr, src1, src2):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                             m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32)))
    return e, []

# XXX


def l_outs(_, instr, size):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                             m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32)))
    return e, []

# XXX actually, xlat performs al = (ds:[e]bx + ZeroExtend(al))


def xlat(ir, instr):
    e = []
    ptr = mRAX[instr.mode][0:8].zeroExtend(mRBX[instr.mode].size)
    src = ir.ExprMem(mRBX[instr.mode] + ptr, 8)
    e.append(m2_expr.ExprAff(mRAX[instr.mode][0:8], src))
    return e, []


def cpuid(_, instr):
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


def bittest_get(ir, instr, src, index):
    index = index.zeroExtend(src.size)
    if isinstance(src, m2_expr.ExprMem):
        b_mask = {16: 4, 32: 5, 64: 6}
        b_decal = {16: 1, 32: 3, 64: 7}
        ptr = src.arg
        segm = src.is_mem_segm()
        if segm:
            ptr = ptr.args[1]

        off_bit = index.zeroExtend(
            src.size) & m2_expr.ExprInt((1 << b_mask[src.size]) - 1,
                                        src.size)
        off_byte = ((index.zeroExtend(ptr.size) >> m2_expr.ExprInt(3, ptr.size)) &
                    m2_expr.ExprInt(((1 << src.size) - 1) ^ b_decal[src.size], ptr.size))

        addr = ptr + off_byte
        if segm:
            addr = m2_expr.ExprOp("segm", src.arg.args[0], addr)
        d = ir.ExprMem(addr, src.size)
    else:
        off_bit = m2_expr.ExprOp(
            '&', index, m2_expr.ExprInt(src.size - 1, src.size))
        d = src
    return d, off_bit


def bt(ir, instr, src, index):
    e = []
    index = index.zeroExtend(src.size)
    d, off_bit = bittest_get(ir, instr, src, index)
    d = d >> off_bit
    e.append(m2_expr.ExprAff(cf, d[:1]))
    return e, []


def btc(ir, instr, src, index):
    e = []
    d, off_bit = bittest_get(ir, instr, src, index)
    e.append(m2_expr.ExprAff(cf, (d >> off_bit)[:1]))

    m = m2_expr.ExprInt(1, src.size) << off_bit
    e.append(m2_expr.ExprAff(d, d ^ m))

    return e, []


def bts(ir, instr, src, index):
    e = []
    d, off_bit = bittest_get(ir, instr, src, index)
    e.append(m2_expr.ExprAff(cf, (d >> off_bit)[:1]))
    m = m2_expr.ExprInt(1, src.size) << off_bit
    e.append(m2_expr.ExprAff(d, d | m))

    return e, []


def btr(ir, instr, src, index):
    e = []
    d, off_bit = bittest_get(ir, instr, src, index)
    e.append(m2_expr.ExprAff(cf, (d >> off_bit)[:1]))
    m = ~(m2_expr.ExprInt(1, src.size) << off_bit)
    e.append(m2_expr.ExprAff(d, d & m))

    return e, []


def into(_, instr):
    return [], []


def l_in(_, instr, src1, src2):
    e = []
    e.append(m2_expr.ExprAff(exception_flags,
                             m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32)))
    return e, []


@sbuild.parse
def cmpxchg(arg1, arg2):
    accumulator = mRAX[instr.mode][:arg1.size]
    if (accumulator - arg1):
        zf = i1(0)
        accumulator = arg1
    else:
        zf = i1(1)
        arg1 = arg2


@sbuild.parse
def cmpxchg8b(arg1):
    accumulator = {mRAX[instr.mode], mRDX[instr.mode]}
    if accumulator - arg1:
        zf = i1(0)
        mRAX[instr.mode] = arg1[:instr.mode]
        mRDX[instr.mode] = arg1[instr.mode:]
    else:
        zf = i1(1)
        arg1 = {mRBX[instr.mode], mRCX[instr.mode]}


def lds(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, ir.ExprMem(src.arg, size=dst.size)))
    DS_value = ir.ExprMem(src.arg + m2_expr.ExprInt(dst.size / 8, src.arg.size),
                          size=16)
    e.append(m2_expr.ExprAff(DS, DS_value))
    return e, []


def les(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, ir.ExprMem(src.arg, size=dst.size)))
    ES_value = ir.ExprMem(src.arg + m2_expr.ExprInt(dst.size / 8, src.arg.size),
                          size=16)
    e.append(m2_expr.ExprAff(ES, ES_value))
    return e, []


def lss(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, ir.ExprMem(src.arg, size=dst.size)))
    SS_value = ir.ExprMem(src.arg + m2_expr.ExprInt(dst.size / 8, src.arg.size),
                          size=16)
    e.append(m2_expr.ExprAff(SS, SS_value))
    return e, []


def lfs(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, ir.ExprMem(src.arg, size=dst.size)))
    FS_value = ir.ExprMem(src.arg + m2_expr.ExprInt(dst.size / 8, src.arg.size),
                          size=16)
    e.append(m2_expr.ExprAff(FS, FS_value))
    return e, []


def lgs(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, ir.ExprMem(src.arg, size=dst.size)))
    GS_value = ir.ExprMem(src.arg + m2_expr.ExprInt(dst.size / 8, src.arg.size),
                          size=16)
    e.append(m2_expr.ExprAff(GS, GS_value))
    return e, []


def lahf(_, instr):
    e = []
    args = [cf, m2_expr.ExprInt(1, 1), pf, m2_expr.ExprInt(0, 1), af,
            m2_expr.ExprInt(0, 1), zf, nf]
    e.append(
        m2_expr.ExprAff(mRAX[instr.mode][8:16], m2_expr.ExprCompose(*args)))
    return e, []


def sahf(_, instr):
    tmp = mRAX[instr.mode][8:16]
    e = []
    e.append(m2_expr.ExprAff(cf, tmp[0:1]))
    e.append(m2_expr.ExprAff(pf, tmp[2:3]))
    e.append(m2_expr.ExprAff(af, tmp[4:5]))
    e.append(m2_expr.ExprAff(zf, tmp[6:7]))
    e.append(m2_expr.ExprAff(nf, tmp[7:8]))
    return e, []


def lar(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('access_segment', src)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('access_segment_ok', src)))
    return e, []


def lsl(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('load_segment_limit', src)))
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp('load_segment_limit_ok', src)))
    return e, []


def fclex(_, instr):
    # XXX TODO
    return [], []


def fnclex(_, instr):
    # XXX TODO
    return [], []


def l_str(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('load_tr_segment_selector',
                                                 m2_expr.ExprInt(0, 32))))
    return e, []


def movd(_, instr, dst, src):
    e = []
    if dst in regs_mm_expr:
        e.append(m2_expr.ExprAff(
            dst, m2_expr.ExprCompose(src, m2_expr.ExprInt(0, 32))))
    elif dst in regs_xmm_expr:
        e.append(m2_expr.ExprAff(
            dst, m2_expr.ExprCompose(src, m2_expr.ExprInt(0, 96))))
    else:
        e.append(m2_expr.ExprAff(dst, src[:32]))
    return e, []


def movdqu(_, instr, dst, src):
    # XXX TODO alignement check
    return [m2_expr.ExprAff(dst, src)], []


def movapd(_, instr, dst, src):
    # XXX TODO alignement check
    return [m2_expr.ExprAff(dst, src)], []


def andps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('&', dst, src)))
    return e, []


def andnps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('&', dst ^ dst.mask, src)))
    return e, []


def orps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('|', dst, src)))
    return e, []


def xorps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprOp('^', dst, src)))
    return e, []


def rdmsr(ir, instr):
    msr_addr = m2_expr.ExprId('MSR') + m2_expr.ExprInt(
        0,
        8) * mRCX[instr.mode][:32]
    e = []
    e.append(
        m2_expr.ExprAff(mRAX[instr.mode][:32], ir.ExprMem(msr_addr, 32)))
    e.append(m2_expr.ExprAff(mRDX[instr.mode][:32], m2_expr.ExprMem(
        msr_addr + m2_expr.ExprInt(4, msr_addr.size), 32)))
    return e, []


def wrmsr(ir, instr):
    msr_addr = m2_expr.ExprId('MSR') + m2_expr.ExprInt(
        8,
        32) * mRCX[instr.mode][:32]
    e = []
    src = m2_expr.ExprCompose(mRAX[instr.mode][:32], mRDX[instr.mode][:32])
    e.append(m2_expr.ExprAff(ir.ExprMem(msr_addr, 64), src))
    return e, []

# MMX/SSE/AVX operations
#


def vec_op_clip(op, size):
    """
    Generate simd operations
    @op: the operator
    @size: size of an element
    """
    def vec_op_clip_instr(ir, instr, dst, src):
        if op == '-':
            return [m2_expr.ExprAff(dst[:size], dst[:size] - src[:size])], []
        else:
            return [m2_expr.ExprAff(dst[:size], m2_expr.ExprOp(op, dst[:size], src[:size]))], []
    return vec_op_clip_instr

# Generic vertical operation


def vec_vertical_sem(op, elt_size, reg_size, dst, src):
    assert reg_size % elt_size == 0
    n = reg_size / elt_size
    if op == '-':
        ops = [
            (dst[i * elt_size:(i + 1) * elt_size]
             - src[i * elt_size:(i + 1) * elt_size]) for i in xrange(0, n)]
    else:
        ops = [m2_expr.ExprOp(op, dst[i * elt_size:(i + 1) * elt_size],
                              src[i * elt_size:(i + 1) * elt_size]) for i in xrange(0, n)]

    return m2_expr.ExprCompose(*ops)


def float_vec_vertical_sem(op, elt_size, reg_size, dst, src):
    assert reg_size % elt_size == 0
    n = reg_size / elt_size

    x_to_int, int_to_x = {32: ('float_to_int_%d', 'int_%d_to_float'),
                          64: ('double_to_int_%d', 'int_%d_to_double')}[elt_size]
    if op == '-':
        ops = [m2_expr.ExprOp(x_to_int % elt_size,
                              m2_expr.ExprOp(int_to_x % elt_size, dst[i * elt_size:(i + 1) * elt_size]) -
                              m2_expr.ExprOp(
                                  int_to_x % elt_size, src[i * elt_size:(
                                      i + 1) * elt_size])) for i in xrange(0, n)]
    else:
        ops = [m2_expr.ExprOp(x_to_int % elt_size,
                              m2_expr.ExprOp(op,
                                             m2_expr.ExprOp(
                                                 int_to_x % elt_size, dst[i * elt_size:(
                                                     i + 1) * elt_size]),
                                             m2_expr.ExprOp(
                                                 int_to_x % elt_size, src[i * elt_size:(
                                                     i + 1) * elt_size]))) for i in xrange(0, n)]

    return m2_expr.ExprCompose(*ops)


def __vec_vertical_instr_gen(op, elt_size, sem):
    def vec_instr(ir, instr, dst, src):
        e = []
        if isinstance(src, m2_expr.ExprMem):
            src = ir.ExprMem(src.arg, dst.size)
        reg_size = dst.size
        e.append(m2_expr.ExprAff(dst, sem(op, elt_size, reg_size, dst, src)))
        return e, []
    return vec_instr


def vec_vertical_instr(op, elt_size):
    return __vec_vertical_instr_gen(op, elt_size, vec_vertical_sem)


def float_vec_vertical_instr(op, elt_size):
    return __vec_vertical_instr_gen(op, elt_size, float_vec_vertical_sem)


# Integer arithmetic
#

# Additions
#

# SSE
paddb = vec_vertical_instr('+', 8)
paddw = vec_vertical_instr('+', 16)
paddd = vec_vertical_instr('+', 32)
paddq = vec_vertical_instr('+', 64)

# Substractions
#

# SSE
psubb = vec_vertical_instr('-', 8)
psubw = vec_vertical_instr('-', 16)
psubd = vec_vertical_instr('-', 32)
psubq = vec_vertical_instr('-', 64)

# Floating-point arithmetic
#

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

# Logical (floating-point)
#

# MMX/SSE/AVX


def pand(_, instr, dst, src):
    e = []
    result = dst & src
    # No flag affected
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def pandn(_, instr, dst, src):
    e = []
    result = (dst ^ dst.mask) & src
    # No flag affected
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def por(_, instr, dst, src):
    e = []
    result = dst | src
    e.append(m2_expr.ExprAff(dst, result))
    return e, []


def pminsw(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprCond((dst - src).msb(), dst, src)))
    return e, []


def cvtdq2pd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:64], m2_expr.ExprOp('int_32_to_double', src[:32])))
    e.append(
        m2_expr.ExprAff(dst[64:128], m2_expr.ExprOp('int_32_to_double', src[32:64])))
    return e, []


def cvtdq2ps(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('int_32_to_float', src[:32])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('int_32_to_float', src[32:64])))
    e.append(
        m2_expr.ExprAff(dst[64:96], m2_expr.ExprOp('int_32_to_float', src[64:96])))
    e.append(
        m2_expr.ExprAff(dst[96:128], m2_expr.ExprOp('int_32_to_float', src[96:128])))
    return e, []


def cvtpd2dq(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('double_to_int_32', src[:64])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('double_to_int_32', src[64:128])))
    e.append(m2_expr.ExprAff(dst[64:128], m2_expr.ExprInt(0, 64)))
    return e, []


def cvtpd2pi(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('double_to_int_32', src[:64])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('double_to_int_32', src[64:128])))
    return e, []


def cvtpd2ps(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('double_to_float', src[:64])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('double_to_float', src[64:128])))
    e.append(m2_expr.ExprAff(dst[64:128], m2_expr.ExprInt(0, 64)))
    return e, []


def cvtpi2pd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:64], m2_expr.ExprOp('int_32_to_double', src[:32])))
    e.append(
        m2_expr.ExprAff(dst[64:128], m2_expr.ExprOp('int_32_to_double', src[32:64])))
    return e, []


def cvtpi2ps(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('int_32_to_float', src[:32])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('int_32_to_float', src[32:64])))
    return e, []


def cvtps2dq(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('float_to_int_32', src[:32])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('float_to_int_32', src[32:64])))
    e.append(
        m2_expr.ExprAff(dst[64:96], m2_expr.ExprOp('float_to_int_32', src[64:96])))
    e.append(
        m2_expr.ExprAff(dst[96:128], m2_expr.ExprOp('float_to_int_32', src[96:128])))
    return e, []


def cvtps2pd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:64], m2_expr.ExprOp('float_to_double', src[:32])))
    e.append(
        m2_expr.ExprAff(dst[64:128], m2_expr.ExprOp('float_to_double', src[32:64])))
    return e, []


def cvtps2pi(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('float_to_int_32', src[:32])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('float_to_int_32', src[32:64])))
    return e, []


def cvtsd2si(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('double_to_int_32', src[:64])))
    return e, []


def cvtsd2ss(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('double_to_float', src[:64])))
    return e, []


def cvtsi2sd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:64], m2_expr.ExprOp('int_32_to_double', src[:32])))
    return e, []


def cvtsi2ss(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('int_32_to_float', src[:32])))
    return e, []


def cvtss2sd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:64], m2_expr.ExprOp('float_to_double', src[:32])))
    return e, []


def cvtss2si(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('float_to_int_32', src[:32])))
    return e, []


def cvttpd2pi(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('double_trunc_to_int_32', src[:64])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('double_trunc_to_int_32', src[64:128])))
    return e, []


def cvttpd2dq(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('double_trunc_to_int_32', src[:64])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('double_trunc_to_int_32', src[64:128])))
    e.append(m2_expr.ExprAff(dst[64:128], m2_expr.ExprInt(0, 64)))
    return e, []


def cvttps2dq(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('float_trunc_to_int_32', src[:32])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('float_trunc_to_int_32', src[32:64])))
    e.append(
        m2_expr.ExprAff(dst[64:96], m2_expr.ExprOp('float_trunc_to_int_32', src[64:96])))
    e.append(
        m2_expr.ExprAff(dst[96:128], m2_expr.ExprOp('float_trunc_to_int_32', src[96:128])))
    return e, []


def cvttps2pi(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('float_trunc_to_int_32', src[:32])))
    e.append(
        m2_expr.ExprAff(dst[32:64], m2_expr.ExprOp('float_trunc_to_int_32', src[32:64])))
    return e, []


def cvttsd2si(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('double_trunc_to_int_32', src[:64])))
    return e, []


def cvttss2si(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAff(dst[:32], m2_expr.ExprOp('float_trunc_to_int_32', src[:32])))
    return e, []


def movss(_, instr, dst, src):
    e = []
    if not isinstance(dst, m2_expr.ExprMem) and not isinstance(src, m2_expr.ExprMem):
        # Source and Destination xmm
        e.append(m2_expr.ExprAff(dst[:32], src[:32]))
    elif not isinstance(src, m2_expr.ExprMem) and isinstance(dst, m2_expr.ExprMem):
        # Source XMM Destination Mem
        e.append(m2_expr.ExprAff(dst, src[:32]))
    else:
        # Source Mem Destination XMM
        e.append(m2_expr.ExprAff(
            dst, m2_expr.ExprCompose(src, m2_expr.ExprInt(0, 96))))
    return e, []


def ucomiss(_, instr, src1, src2):
    e = []
    e.append(m2_expr.ExprAff(zf, m2_expr.ExprOp(
        'ucomiss_zf', src1[:32], src2[:32])))
    e.append(m2_expr.ExprAff(pf, m2_expr.ExprOp(
        'ucomiss_pf', src1[:32], src2[:32])))
    e.append(m2_expr.ExprAff(cf, m2_expr.ExprOp(
        'ucomiss_cf', src1[:32], src2[:32])))

    e.append(m2_expr.ExprAff(of, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAff(af, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAff(nf, m2_expr.ExprInt(0, 1)))

    return e, []


def pshufb(_, instr, dst, src):
    e = []
    if dst.size == 64:
        bit_l = 3
    elif dst.size == 128:
        bit_l = 4
    else:
        raise NotImplementedError("bad size")
    for i in xrange(0, src.size, 8):
        index = src[
            i:i + bit_l].zeroExtend(dst.size) << m2_expr.ExprInt(3, dst.size)
        value = (dst >> index)[:8]
        e.append(m2_expr.ExprAff(dst[i:i + 8],
                                 m2_expr.ExprCond(src[i + 7:i + 8],
                                                  m2_expr.ExprInt(0, 8),
                                                  value)))
    return e, []


def pshufd(_, instr, dst, src, imm):
    e = []
    for i in xrange(4):
        index = imm[2 * i:2 * (i + 1)].zeroExtend(dst.size)
        index <<= m2_expr.ExprInt(5, dst.size)
        value = (dst >> index)[:32]
        e.append(m2_expr.ExprAff(dst[32 * i:32 * (i + 1)], value))
    return e, []


def ps_rl_ll(ir, instr, dst, src, op, size):
    lbl_zero = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_do = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
    lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

    if src.size == 8:
        count = src.zeroExtend(dst.size)
    else:
        count = src.zeroExtend(dst.size)

    mask = {16: 0xF,
            32: 0x1F,
            64: 0x3F}[size]
    test = expr_simp(count & m2_expr.ExprInt(
        ((1 << dst.size) - 1) ^ mask, dst.size))
    e = [m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(test,
                                                    lbl_zero,
                                                    lbl_do))]

    slices = []
    for i in xrange(0, dst.size, size):
        slices.append(m2_expr.ExprOp(op, dst[i:i + size], count[:size]))

    if isinstance(test, m2_expr.ExprInt):
        if int(test) == 0:
            return [m2_expr.ExprAff(dst[0:dst.size], m2_expr.ExprCompose(*slices))], []
        else:
            return [m2_expr.ExprAff(dst, m2_expr.ExprInt(0, dst.size))], []

    e_zero = [m2_expr.ExprAff(dst, m2_expr.ExprInt(0, dst.size)),
              m2_expr.ExprAff(ir.IRDst, lbl_next)]
    e_do = []
    e.append(m2_expr.ExprAff(dst[0:dst.size], m2_expr.ExprCompose(*slices)))
    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
    return e, [IRBlock(lbl_do.name, [e_do]), IRBlock(lbl_zero.name, [e_zero])]


def psrlw(ir, instr, dst, src):
    return ps_rl_ll(ir, instr, dst, src, ">>", 16)


def psrld(ir, instr, dst, src):
    return ps_rl_ll(ir, instr, dst, src, ">>", 32)


def psrlq(ir, instr, dst, src):
    return ps_rl_ll(ir, instr, dst, src, ">>", 64)


def psllw(ir, instr, dst, src):
    return ps_rl_ll(ir, instr, dst, src, "<<", 16)


def pslld(ir, instr, dst, src):
    return ps_rl_ll(ir, instr, dst, src, "<<",  32)


def psllq(ir, instr, dst, src):
    return ps_rl_ll(ir, instr, dst, src, "<<",  64)


def pslldq(_, instr, dst, src):
    assert src.is_int()
    e = []
    count = int(src)
    if count > 15:
        return [m2_expr.ExprAff(dst, m2_expr.ExprInt(0, dst.size))], []
    else:
        return [m2_expr.ExprAff(dst, dst << m2_expr.ExprInt(8 * count, dst.size))], []


def iret(ir, instr):
    """IRET implementation
    XXX: only support "no-privilege change"
    """
    size = instr.v_opmode()
    exprs, _ = retf(ir, instr, m2_expr.ExprInt(size / 8, size=size))
    tmp = mRSP[instr.mode][:size] + m2_expr.ExprInt((2 * size) / 8, size=size)
    exprs += _tpl_eflags(tmp)
    return exprs, []


def pmaxu(_, instr, dst, src, size):
    e = []
    for i in xrange(0, dst.size, size):
        op1 = dst[i:i + size]
        op2 = src[i:i + size]
        res = op1 - op2
        # Compote CF in @res = @op1 - @op2
        ret = (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))).msb()

        e.append(m2_expr.ExprAff(dst[i:i + size],
                                 m2_expr.ExprCond(ret,
                                                  src[i:i + size],
                                                  dst[i:i + size])))
    return e, []


def pmaxub(ir, instr, dst, src):
    return pmaxu(ir, instr, dst, src, 8)


def pmaxuw(ir, instr, dst, src):
    return pmaxu(ir, instr, dst, src, 16)


def pmaxud(ir, instr, dst, src):
    return pmaxu(ir, instr, dst, src, 32)


def pminu(_, instr, dst, src, size):
    e = []
    for i in xrange(0, dst.size, size):
        op1 = dst[i:i + size]
        op2 = src[i:i + size]
        res = op1 - op2
        # Compote CF in @res = @op1 - @op2
        ret = (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))).msb()

        e.append(m2_expr.ExprAff(dst[i:i + size],
                                 m2_expr.ExprCond(ret,
                                                  dst[i:i + size],
                                                  src[i:i + size])))
    return e, []


def pminub(ir, instr, dst, src):
    return pminu(ir, instr, dst, src, 8)


def pminuw(ir, instr, dst, src):
    return pminu(ir, instr, dst, src, 16)


def pminud(ir, instr, dst, src):
    return pminu(ir, instr, dst, src, 32)


def pcmpeq(_, instr, dst, src, size):
    e = []
    for i in xrange(0, dst.size, size):
        test = dst[i:i + size] - src[i:i + size]
        e.append(m2_expr.ExprAff(dst[i:i + size],
                                 m2_expr.ExprCond(test,
                                                  m2_expr.ExprInt(0, size),
                                                  m2_expr.ExprInt(-1, size))))
    return e, []


def pcmpeqb(ir, instr, dst, src):
    return pcmpeq(ir, instr, dst, src, 8)


def pcmpeqw(ir, instr, dst, src):
    return pcmpeq(ir, instr, dst, src, 16)


def pcmpeqd(ir, instr, dst, src):
    return pcmpeq(ir, instr, dst, src, 32)


def punpck(_, instr, dst, src, size, off):
    e = []
    slices = []
    for i in xrange(dst.size / (2 * size)):
        slices.append(dst[size * i + off: size * i + off + size])
        slices.append(src[size * i + off: size * i + off + size])
    e.append(m2_expr.ExprAff(dst, m2_expr.ExprCompose(*slices)))
    return e, []


def punpckhbw(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 8, dst.size / 2)


def punpckhwd(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 16, dst.size / 2)


def punpckhdq(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 32, dst.size / 2)


def punpckhqdq(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 64, dst.size / 2)


def punpcklbw(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 8, 0)


def punpcklwd(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 16, 0)


def punpckldq(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 32, 0)


def punpcklqdq(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 64, 0)


def pinsr(_, instr, dst, src, imm, size):
    e = []

    mask = {8: 0xF,
            16: 0x7,
            32: 0x3,
            64: 0x1}[size]

    sel = (int(imm) & mask) * size
    e.append(m2_expr.ExprAff(dst[sel:sel + size], src[:size]))

    return e, []


def pinsrb(ir, instr, dst, src, imm):
    return pinsr(ir, instr, dst, src, imm, 8)


def pinsrw(ir, instr, dst, src, imm):
    return pinsr(ir, instr, dst, src, imm, 16)


def pinsrd(ir, instr, dst, src, imm):
    return pinsr(ir, instr, dst, src, imm, 32)


def pinsrq(ir, instr, dst, src, imm):
    return pinsr(ir, instr, dst, src, imm, 64)


def pextr(_, instr, dst, src, imm, size):
    e = []

    mask = {8: 0xF,
            16: 0x7,
            32: 0x3,
            64: 0x1}[size]

    sel = (int(imm) & mask) * size
    e.append(m2_expr.ExprAff(dst, src[sel:sel + size].zeroExtend(dst.size)))

    return e, []


def pextrb(ir, instr, dst, src, imm):
    return pextr(ir, instr, dst, src, imm, 8)


def pextrw(ir, instr, dst, src, imm):
    return pextr(ir, instr, dst, src, imm, 16)


def pextrd(ir, instr, dst, src, imm):
    return pextr(ir, instr, dst, src, imm, 32)


def pextrq(ir, instr, dst, src, imm):
    return pextr(ir, instr, dst, src, imm, 64)


def unpckhps(_, instr, dst, src):
    e = []
    src = m2_expr.ExprCompose(dst[64:96], src[64:96], dst[96:128], src[96:128])
    e.append(m2_expr.ExprAff(dst, src))
    return e, []


def unpckhpd(_, instr, dst, src):
    e = []
    src = m2_expr.ExprCompose(dst[64:128], src[64:128])
    e.append(m2_expr.ExprAff(dst, src))
    return e, []


def unpcklps(_, instr, dst, src):
    e = []
    src = m2_expr.ExprCompose(dst[0:32], src[0:32], dst[32:64], src[32:64])
    e.append(m2_expr.ExprAff(dst, src))
    return e, []


def unpcklpd(_, instr, dst, src):
    e = []
    src = m2_expr.ExprCompose(dst[0:64], src[0:64])
    e.append(m2_expr.ExprAff(dst, src))
    return e, []


def movlpd(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst[:64], src[:64]))
    return e, []


def movlps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst[:64], src[:64]))
    return e, []


def movhpd(_, instr, dst, src):
    e = []
    if src.size == 64:
        e.append(m2_expr.ExprAff(dst[64:128], src))
    elif dst.size == 64:
        e.append(m2_expr.ExprAff(dst, src[64:128]))
    else:
        raise RuntimeError("bad encoding!")
    return e, []


def movlhps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst[64:128], src[:64]))
    return e, []


def movhlps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst[:64], src[64:128]))
    return e, []


def movdq2q(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst, src[:64]))
    return e, []


def sqrt_gen(_, instr, dst, src, size):
    e = []
    out = []
    for i in src.size / size:
        out.append(m2_expr.ExprOp('fsqrt' % size,
                                  src[i * size: (i + 1) * size]))
    src = m2_expr.ExprCompose(*out)
    e.append(m2_expr.ExprAff(dst, src))
    return e, []


def sqrtpd(ir, instr, dst, src):
    return sqrt_gen(ir, instr, dst, src, 64)


def sqrtps(ir, instr, dst, src):
    return sqrt_gen(ir, instr, dst, src, 32)


def sqrtsd(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst[:64],
                             m2_expr.ExprOp('fsqrt',
                                            src[:64])))
    return e, []


def sqrtss(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAff(dst[:32],
                             m2_expr.ExprOp('fsqrt',
                                            src[:32])))
    return e, []


def pmovmskb(_, instr, dst, src):
    e = []
    out = []
    for i in xrange(src.size / 8):
        out.append(src[8 * i + 7:8 * (i + 1)])
    src = m2_expr.ExprCompose(*out)
    e.append(m2_expr.ExprAff(dst, src.zeroExtend(dst.size)))
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
              'sal': shl,
              'shl': shl,
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
              'cmpsq': lambda ir, instr: cmps(ir, instr, 64),
              'scasb': lambda ir, instr: scas(ir, instr, 8),
              'scasw': lambda ir, instr: scas(ir, instr, 16),
              'scasd': lambda ir, instr: scas(ir, instr, 32),
              'scasq': lambda ir, instr: scas(ir, instr, 64),
              'pushfd': pushfd,
              'pushfq': pushfq,
              'pushfw': pushfw,
              'popfd': popfd,
              'popfq': popfd,
              'popfw': popfw,
              'pusha': pusha,
              'pushad': pushad,
              'popad': popad,
              'popa': popa,
              'call': call,
              'ret': ret,
              'retf': retf,
              'iret': iret,
              'iretd': iret,
              'leave': leave,
              'enter': enter,
              'jmp': jmp,
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
              'ud2': ud2,
              'prefetchw': prefetchw,
              'lfence': lfence,
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
              'fldenv': fldenv,
              'sidt': sidt,
              'sldt': sldt,
              'arpl': arpl,
              'cmovz': cmovz,
              'cmove': cmovz,
              'cmovnz': cmovnz,
              'cmovpe': cmovpe,
              'cmovnp': cmovnp,
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
              "syscall": l_syscall,
              "cmpxchg": cmpxchg,
              "cmpxchg8b": cmpxchg8b,
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
              "movdqu": movdqu,
              "movdqa": movdqu,
              "movapd": movapd,  # XXX TODO alignement check
              "movupd": movapd,  # XXX TODO alignement check
              "movaps": movapd,  # XXX TODO alignement check
              "movups": movapd,  # XXX TODO alignement check
              "andps": andps,
              "andpd": andps,
              "andnps": andnps,
              "andnpd": andnps,
              "orps": orps,
              "orpd": orps,
              "xorps": xorps,
              "xorpd": xorps,

              "movq": movq,

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

              #
              # MMX/AVX/SSE operations

              # Arithmetic (integers)
              #

              # Additions
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

              # Arithmetic (floating-point)
              #

              # Additions
              # SSE
              "addss": addss,
              "addsd": addsd,
              "addps": addps,
              "addpd": addpd,

              # Substractions
              # SSE
              "subss": subss,
              "subsd": subsd,
              "subps": subps,
              "subpd": subpd,

              # Multiplications
              # SSE
              "mulss": mulss,
              "mulsd": mulsd,
              "mulps": mulps,
              "mulpd": mulpd,

              # Divisions
              # SSE
              "divss": divss,
              "divsd": divsd,
              "divps": divps,
              "divpd": divpd,

              # Logical (floating-point)
              #

              "pand": pand,
              "pandn": pandn,
              "por": por,

              "rdmsr": rdmsr,
              "wrmsr": wrmsr,
              "pshufb": pshufb,
              "pshufd": pshufd,

              "psrlw": psrlw,
              "psrld": psrld,
              "psrlq": psrlq,
              "psllw": psllw,
              "pslld": pslld,
              "psllq": psllq,
              "pslldq": pslldq,

              "pmaxub": pmaxub,
              "pmaxuw": pmaxuw,
              "pmaxud": pmaxud,

              "pminub": pminub,
              "pminuw": pminuw,
              "pminud": pminud,

              "pcmpeqb": pcmpeqb,
              "pcmpeqw": pcmpeqw,
              "pcmpeqd": pcmpeqd,

              "punpckhbw": punpckhbw,
              "punpckhwd": punpckhwd,
              "punpckhdq": punpckhdq,
              "punpckhqdq": punpckhqdq,


              "punpcklbw": punpcklbw,
              "punpcklwd": punpcklwd,
              "punpckldq": punpckldq,
              "punpcklqdq": punpcklqdq,

              "pinsrb": pinsrb,
              "pinsrw": pinsrw,
              "pinsrd": pinsrd,
              "pinsrq": pinsrq,

              "pextrb": pextrb,
              "pextrw": pextrw,
              "pextrd": pextrd,
              "pextrq": pextrq,

              "unpckhps": unpckhps,
              "unpckhpd": unpckhpd,
              "unpcklps": unpcklps,
              "unpcklpd": unpcklpd,

              "movlpd": movlpd,
              "movlps": movlps,
              "movhpd": movhpd,
              "movhps": movhpd,
              "movlhps": movlhps,
              "movhlps": movhlps,
              "movdq2q": movdq2q,

              "sqrtpd": sqrtpd,
              "sqrtps": sqrtps,
              "sqrtsd": sqrtsd,
              "sqrtss": sqrtss,

              "pmovmskb": pmovmskb,

              }


class ir_x86_16(IntermediateRepresentation):

    def __init__(self, symbol_pool=None):
        IntermediateRepresentation.__init__(self, mn_x86, 16, symbol_pool)
        self.do_stk_segm = False
        self.do_ds_segm = False
        self.do_str_segm = False
        self.do_all_segm = False
        self.pc = IP
        self.sp = SP
        self.IRDst = m2_expr.ExprId('IRDst', 16)
        # Size of memory pointer access in IR
        # 16 bit mode memory accesses may be greater than 16 bits
        # 32 bit size may be enought
        self.addrsize = 32

    def mod_pc(self, instr, instr_ir, extra_ir):
        pass

    def ExprMem(self, ptr, size=32):
        """Generate a memory access to @ptr
        The ptr is resized to a fixed size self.addrsize

        @ptr: Expr instance to the memory address
        @size: size of the memory"""

        return m2_expr.ExprMem(expraddr(self.addrsize, ptr), size)

    def get_ir(self, instr):
        args = instr.args[:]
        args = [arg.replace_expr(float_replace) for arg in args]
        args = fix_mem_args_size(instr, *args)
        my_ss = None
        if self.do_ds_segm:
            my_ss = DS
        if self.do_all_segm and instr.additional_info.g2.value:
            my_ss = {1: CS, 2: SS, 3: DS, 4: ES, 5: FS, 6: GS}[
                instr.additional_info.g2.value]
        if my_ss is not None:
            for i, a in enumerate(args):
                if a.is_mem() and not a.is_mem_segm():
                    args[i] = self.ExprMem(m2_expr.ExprOp('segm', my_ss,
                                                          a.arg), a.size)

        if not instr.name.lower() in mnemo_func:
            raise NotImplementedError(
                "Mnemonic %s not implemented" % instr.name)

        instr_ir, extra_ir = mnemo_func[
            instr.name.lower()](self, instr, *args)

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

        cond_dec = m2_expr.ExprCond(c_reg - m2_expr.ExprInt(1, c_reg.size),
                                    m2_expr.ExprInt(0, 1), m2_expr.ExprInt(1, 1))
        # end condition
        if zf_val is None:
            c_cond = cond_dec
        elif instr.additional_info.g1.value & 2:  # REPNE
            c_cond = cond_dec | zf
        elif instr.additional_info.g1.value & 4:  # REP
            c_cond = cond_dec | (zf ^ m2_expr.ExprInt(1, 1))

        # gen while
        lbl_do = m2_expr.ExprId(self.gen_label(), self.IRDst.size)
        lbl_end = m2_expr.ExprId(self.gen_label(), self.IRDst.size)
        lbl_skip = m2_expr.ExprId(self.get_next_label(instr), self.IRDst.size)
        lbl_next = m2_expr.ExprId(self.get_next_label(instr), self.IRDst.size)

        for irblock in extra_ir:
            for ir in irblock.irs:
                for i, e in enumerate(ir):
                    src = e.src.replace_expr({lbl_next: lbl_end})
                    ir[i] = m2_expr.ExprAff(e.dst, src)
        cond_bloc = []
        cond_bloc.append(m2_expr.ExprAff(c_reg,
                                         c_reg - m2_expr.ExprInt(1,
                                                                 c_reg.size)))
        cond_bloc.append(m2_expr.ExprAff(self.IRDst, m2_expr.ExprCond(c_cond,
                                                                      lbl_skip,
                                                                      lbl_do)))
        cond_bloc = IRBlock(lbl_end.name, [cond_bloc])
        e_do = instr_ir

        c = IRBlock(lbl_do.name, [e_do])
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
        for idx, assignblk in enumerate(irbloc.irs):
            new_assignblk = dict(assignblk)
            for dst, src in assignblk.iteritems():
                del new_assignblk[dst]
                # Special case for 64 bits:
                # If destination is a 32 bit reg, zero extend the 64 bit reg
                if mode == 64:
                    if (isinstance(dst, m2_expr.ExprId) and
                            dst.size == 32 and
                            dst in replace_regs[64]):
                        src = src.zeroExtend(64)
                        dst = replace_regs[64][dst].arg
                dst = self.expr_fix_regs_for_mode(dst, mode)
                src = self.expr_fix_regs_for_mode(src, mode)
                new_assignblk[dst] = src
            irbloc.irs[idx] = AssignBlock(new_assignblk, assignblk.instr)
        if irbloc.dst is not None:
            irbloc.dst = self.expr_fix_regs_for_mode(irbloc.dst, mode)


class ir_x86_32(ir_x86_16):

    def __init__(self, symbol_pool=None):
        IntermediateRepresentation.__init__(self, mn_x86, 32, symbol_pool)
        self.do_stk_segm = False
        self.do_ds_segm = False
        self.do_str_segm = False
        self.do_all_segm = False
        self.pc = EIP
        self.sp = ESP
        self.IRDst = m2_expr.ExprId('IRDst', 32)
        self.addrsize = 32


class ir_x86_64(ir_x86_16):

    def __init__(self, symbol_pool=None):
        IntermediateRepresentation.__init__(self, mn_x86, 64, symbol_pool)
        self.do_stk_segm = False
        self.do_ds_segm = False
        self.do_str_segm = False
        self.do_all_segm = False
        self.pc = RIP
        self.sp = RSP
        self.IRDst = m2_expr.ExprId('IRDst', 64)
        self.addrsize = 64

    def mod_pc(self, instr, instr_ir, extra_ir):
        # fix RIP for 64 bit
        for i, expr in enumerate(instr_ir):
            dst, src = expr.dst, expr.src
            if dst != self.pc:
                dst = dst.replace_expr(
                    {self.pc: m2_expr.ExprInt(instr.offset + instr.l, 64)})
            src = src.replace_expr(
                {self.pc: m2_expr.ExprInt(instr.offset + instr.l, 64)})
            instr_ir[i] = m2_expr.ExprAff(dst, src)
        for irblock in extra_ir:
            for irs in irblock.irs:
                for i, expr in enumerate(irs):
                    dst, src = expr.dst, expr.src
                    if dst != self.pc:
                        new_pc = m2_expr.ExprInt(instr.offset + instr.l, 64)
                        dst = dst.replace_expr({self.pc: new_pc})
                    src = src.replace_expr(
                        {self.pc: m2_expr.ExprInt(instr.offset + instr.l, 64)})
                    irs[i] = m2_expr.ExprAff(dst, src)
