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

from builtins import range

from future.utils import viewitems

import logging
import miasm.expression.expression as m2_expr
from miasm.expression.simplifications import expr_simp
from miasm.arch.x86.regs import *
from miasm.arch.x86.arch import mn_x86, repeat_mn, replace_regs, is_mem_segm
from miasm.ir.ir import Lifter, IRBlock, AssignBlock
from miasm.core.sembuilder import SemBuilder
from miasm.jitter.csts import EXCEPT_DIV_BY_ZERO, EXCEPT_ILLEGAL_INSN, \
    EXCEPT_PRIV_INSN, EXCEPT_SOFT_BP, EXCEPT_INT_XX, EXCEPT_INT_1, \
    EXCEPT_SYSCALL
import math
import struct


LOG_X86_SEM = logging.getLogger("x86_sem")
CONSOLE_HANDLER = logging.StreamHandler()
CONSOLE_HANDLER.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
LOG_X86_SEM.addHandler(CONSOLE_HANDLER)
LOG_X86_SEM.setLevel(logging.WARNING)


# SemBuilder context
ctx = {'mRAX': mRAX,
       'mRBX': mRBX,
       'mRCX': mRCX,
       'mRDX': mRDX,
       'zf': zf,
       }
sbuild = SemBuilder(ctx)



"""
http://www.emulators.com/docs/nx11_flags.htm

CF(A+B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND NOT (A XOR B)) < 0)
CF(A-B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND (A XOR B)) < 0)

OF(A+B) = ((A XOR D) AND NOT (A XOR B)) < 0
OF(A-B) = ((A XOR D) AND (A XOR B)) < 0
"""


# XXX TODO make default check against 0 or not 0 (same eq as in C)
def update_flag_zf_eq(a, b):
    return [m2_expr.ExprAssign(zf, m2_expr.ExprOp("FLAG_EQ_CMP", a, b))]


def update_flag_zf(a):
    return [
        m2_expr.ExprAssign(
            zf,
            m2_expr.ExprCond(
                a,
                m2_expr.ExprInt(0, zf.size),
                m2_expr.ExprInt(1, zf.size)
            )
        )
    ]


def update_flag_nf(arg):
    return [
        m2_expr.ExprAssign(
            nf,
            m2_expr.ExprOp("FLAG_SIGN_SUB", arg, m2_expr.ExprInt(0, arg.size))
        )
    ]


def update_flag_pf(a):
    return [m2_expr.ExprAssign(pf,
                            m2_expr.ExprOp('parity',
                                           a & m2_expr.ExprInt(0xFF, a.size)))]


def update_flag_af(op1, op2, res):
    return [m2_expr.ExprAssign(af, (op1 ^ op2 ^ res)[4:5])]


def update_flag_znp(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    e += update_flag_pf(a)
    return e


def update_flag_np(result):
    e = []
    e += update_flag_nf(result)
    e += update_flag_pf(result)
    return e


def null_flag_co():
    e = []
    e.append(m2_expr.ExprAssign(of, m2_expr.ExprInt(0, of.size)))
    e.append(m2_expr.ExprAssign(cf, m2_expr.ExprInt(0, cf.size)))
    return e


def update_flag_arith(a):
    e = []
    e += update_flag_znp(a)
    return e


def update_flag_zfaddwc_eq(arg1, arg2, arg3):
    return [m2_expr.ExprAssign(zf, m2_expr.ExprOp("FLAG_EQ_ADDWC", arg1, arg2, arg3))]

def update_flag_zfsubwc_eq(arg1, arg2, arg3):
    return [m2_expr.ExprAssign(zf, m2_expr.ExprOp("FLAG_EQ_SUBWC", arg1, arg2, arg3))]


def update_flag_arith_add_znp(arg1, arg2):
    """
    Compute znp flags for (arg1 + arg2)
    """
    e = []
    e += update_flag_zf_eq(arg1, -arg2)
    e += [m2_expr.ExprAssign(nf, m2_expr.ExprOp("FLAG_SIGN_SUB", arg1, -arg2))]
    e += update_flag_pf(arg1+arg2)
    return e


def update_flag_arith_addwc_znp(arg1, arg2, arg3):
    """
    Compute znp flags for (arg1 + arg2 + cf)
    """
    e = []
    e += update_flag_zfaddwc_eq(arg1, arg2, arg3)
    e += [m2_expr.ExprAssign(nf, m2_expr.ExprOp("FLAG_SIGN_ADDWC", arg1, arg2, arg3))]
    e += update_flag_pf(arg1+arg2+arg3.zeroExtend(arg2.size))
    return e




def update_flag_arith_sub_znp(arg1, arg2):
    """
    Compute znp flags for (arg1 - arg2)
    """
    e = []
    e += update_flag_zf_eq(arg1, arg2)
    e += [m2_expr.ExprAssign(nf, m2_expr.ExprOp("FLAG_SIGN_SUB", arg1, arg2))]
    e += update_flag_pf(arg1 - arg2)
    return e


def update_flag_arith_subwc_znp(arg1, arg2, arg3):
    """
    Compute znp flags for (arg1 - (arg2 + cf))
    """
    e = []
    e += update_flag_zfsubwc_eq(arg1, arg2, arg3)
    e += [m2_expr.ExprAssign(nf, m2_expr.ExprOp("FLAG_SIGN_SUBWC", arg1, arg2, arg3))]
    e += update_flag_pf(arg1 - (arg2+arg3.zeroExtend(arg2.size)))
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
    #return [m2_expr.ExprAssign(cf, m2_expr.ExprOp("FLAG_SUB_CF", op1, -op2))]
    return [m2_expr.ExprAssign(cf, m2_expr.ExprOp("FLAG_ADD_CF", op1, op2))]


def update_flag_add_of(op1, op2, res):
    "Compute of in @res = @op1 + @op2"
    return [m2_expr.ExprAssign(of, m2_expr.ExprOp("FLAG_ADD_OF", op1, op2))]


# checked: ok for sbb add because b & c before +cf
def update_flag_sub_cf(op1, op2, res):
    "Compote CF in @res = @op1 - @op2"
    return [m2_expr.ExprAssign(cf, m2_expr.ExprOp("FLAG_SUB_CF", op1, op2))]


def update_flag_sub_of(op1, op2, res):
    "Compote OF in @res = @op1 - @op2"
    return [m2_expr.ExprAssign(of, m2_expr.ExprOp("FLAG_SUB_OF", op1, op2))]


def update_flag_addwc_cf(op1, op2, op3):
    "Compute cf in @res = @op1 + @op2 + @op3"
    return [m2_expr.ExprAssign(cf, m2_expr.ExprOp("FLAG_ADDWC_CF", op1, op2, op3))]


def update_flag_addwc_of(op1, op2, op3):
    "Compute of in @res = @op1 + @op2 + @op3"
    return [m2_expr.ExprAssign(of, m2_expr.ExprOp("FLAG_ADDWC_OF", op1, op2, op3))]



def update_flag_subwc_cf(op1, op2, op3):
    "Compute cf in @res = @op1 + @op2 + @op3"
    return [m2_expr.ExprAssign(cf, m2_expr.ExprOp("FLAG_SUBWC_CF", op1, op2, op3))]


def update_flag_subwc_of(op1, op2, op3):
    "Compute of in @res = @op1 + @op2 + @op3"
    return [m2_expr.ExprAssign(of, m2_expr.ExprOp("FLAG_SUBWC_OF", op1, op2, op3))]




def update_flag_arith_add_co(x, y, z):
    e = []
    e += update_flag_add_cf(x, y, z)
    e += update_flag_add_of(x, y, z)
    return e


def update_flag_arith_sub_co(x, y, z):
    e = []
    e += update_flag_sub_cf(x, y, z)
    e += update_flag_sub_of(x, y, z)
    return e




def update_flag_arith_addwc_co(arg1, arg2, arg3):
    e = []
    e += update_flag_addwc_cf(arg1, arg2, arg3)
    e += update_flag_addwc_of(arg1, arg2, arg3)
    return e


def update_flag_arith_subwc_co(arg1, arg2, arg3):
    e = []
    e += update_flag_subwc_cf(arg1, arg2, arg3)
    e += update_flag_subwc_of(arg1, arg2, arg3)
    return e



def set_float_cs_eip(instr):
    e = []
    # XXX TODO check float updt
    e.append(m2_expr.ExprAssign(float_eip,
                             m2_expr.ExprInt(instr.offset, float_eip.size)))
    e.append(m2_expr.ExprAssign(float_cs, CS))
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
        ptr = arg.ptr
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
    Add float conversion if argument is an ExprMem
    @arg: argument to transform
    """
    if isinstance(arg, m2_expr.ExprMem):
        if arg.size > 64:
            # TODO: move to 80 bits
            arg = m2_expr.ExprMem(expraddr(instr.mode, arg.ptr), size=64)
        return m2_expr.ExprOp('sint_to_fp', arg.signExtend(64))
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
    @cond: condition of the jcc
    @dst: the destination if jcc is taken
    @jmp_if: jump if/notif cond
    """

    e = []
    meip = mRIP[ir.IRDst.size]
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = m2_expr.ExprLoc(loc_next, dst.size)

    if jmp_if:
        dstA, dstB = dst, loc_next_expr
    else:
        dstA, dstB = loc_next_expr, dst
    mn_dst = m2_expr.ExprCond(cond,
                              dstA.zeroExtend(ir.IRDst.size),
                              dstB.zeroExtend(ir.IRDst.size))
    e.append(m2_expr.ExprAssign(meip, mn_dst))
    e.append(m2_expr.ExprAssign(ir.IRDst, mn_dst))
    return e, []


def gen_fcmov(ir, instr, cond, arg1, arg2, mov_if):
    """Generate fcmov
    @ir: ir instance
    @instr: instruction instance
    @cond: condition
    @mov_if: invert condition if False"""

    loc_do, loc_do_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_skip = ir.get_next_loc_key(instr)
    loc_skip_expr = m2_expr.ExprLoc(loc_skip, ir.IRDst.size)
    if mov_if:
        dstA, dstB = loc_do_expr, loc_skip_expr
    else:
        dstA, dstB = loc_skip_expr, loc_do_expr
    e = []
    e_do, extra_irs = [m2_expr.ExprAssign(arg1, arg2)], []
    e_do.append(m2_expr.ExprAssign(ir.IRDst, loc_skip_expr))
    e.append(m2_expr.ExprAssign(ir.IRDst, m2_expr.ExprCond(cond, dstA, dstB)))
    return e, [IRBlock(ir.loc_db, loc_do, [AssignBlock(e_do, instr)])]


def gen_cmov(ir, instr, cond, dst, src, mov_if):
    """Generate cmov
    @ir: ir instance
    @instr: instruction instance
    @cond: condition
    @mov_if: invert condition if False"""

    loc_do, loc_do_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_skip = ir.get_next_loc_key(instr)
    loc_skip_expr = m2_expr.ExprLoc(loc_skip, ir.IRDst.size)
    if mov_if:
        dstA, dstB = loc_do_expr, loc_skip_expr
    else:
        dstA, dstB = loc_skip_expr, loc_do_expr
    e = []
    if instr.mode == 64:
        # Force destination set in order to zero high bit orders
        # In 64 bit:
        # cmovz eax, ebx
        # if zf == 0 => high part of RAX is set to zero
        e.append(m2_expr.ExprAssign(dst, dst))
    e_do, extra_irs = mov(ir, instr, dst, src)
    e_do.append(m2_expr.ExprAssign(ir.IRDst, loc_skip_expr))
    e.append(m2_expr.ExprAssign(ir.IRDst, m2_expr.ExprCond(cond, dstA, dstB)))
    return e, [IRBlock(ir.loc_db, loc_do, [AssignBlock(e_do, instr)])]


def mov(_, instr, dst, src):
    if dst in [ES, CS, SS, DS, FS, GS]:
        src = src[:dst.size]
    if src in [ES, CS, SS, DS, FS, GS]:
        src = src.zeroExtend(dst.size)
    e = [m2_expr.ExprAssign(dst, src)]
    return e, []


def movq(_, instr, dst, src):
    src_final = (src.zeroExtend(dst.size)
                 if dst.size >= src.size else
                 src[:dst.size])
    return [m2_expr.ExprAssign(dst, src_final)], []


@sbuild.parse
def xchg(arg1, arg2):
    arg1 = arg2
    arg2 = arg1



def movzx(_, instr, dst, src):
    e = [m2_expr.ExprAssign(dst, src.zeroExtend(dst.size))]
    return e, []


def movsx(_, instr, dst, src):
    e = [m2_expr.ExprAssign(dst, src.signExtend(dst.size))]
    return e, []


def lea(_, instr, dst, src):
    ptr = src.ptr
    if is_mem_segm(src):
        # Do not use segmentation here
        ptr = ptr.args[1]

    if ptr.size > dst.size:
        ptr = ptr[:dst.size]
    e = [m2_expr.ExprAssign(dst, ptr.zeroExtend(dst.size))]
    return e, []


def add(_, instr, dst, src):
    e = []

    result = dst + src

    e += update_flag_arith_add_znp(dst, src)
    e += update_flag_arith_add_co(dst, src, result)
    e += update_flag_af(dst, src, result)
    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def xadd(_, instr, dst, src):
    e = []

    result = dst + src
    e += update_flag_arith_add_znp(dst, src)
    e += update_flag_arith_add_co(src, dst, result)
    e += update_flag_af(dst, src, result)
    if dst != src:
        e.append(m2_expr.ExprAssign(src, dst))
    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def adc(_, instr, dst, src):
    e = []

    arg1 = dst
    arg2 = src
    result = arg1 + (arg2 + cf.zeroExtend(src.size))

    e += update_flag_arith_addwc_znp(arg1, arg2, cf)
    e += update_flag_arith_addwc_co(arg1, arg2, cf)
    e += update_flag_af(arg1, arg2, result)
    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def sub(_, instr, dst, src):
    e = []
    arg1, arg2 = dst, src
    result = dst - src

    e += update_flag_arith_sub_znp(arg1, arg2)
    e += update_flag_arith_sub_co(arg1, arg2, result)
    e += update_flag_af(dst, src, result)

    e.append(m2_expr.ExprAssign(dst, result))
    return e, []

# a-(b+cf)


def sbb(_, instr, dst, src):
    e = []
    arg1 = dst
    arg2 = src
    result = arg1 - (arg2 + cf.zeroExtend(src.size))

    e += update_flag_arith_subwc_znp(arg1, arg2, cf)
    e += update_flag_af(arg1, arg2, result)
    e += update_flag_arith_subwc_co(arg1, arg2, cf)
    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def neg(_, instr, src):
    e = []
    dst = m2_expr.ExprInt(0, src.size)
    arg1, arg2 = dst, src
    result = arg1 - arg2

    e += update_flag_arith_sub_znp(arg1, arg2)
    e += update_flag_arith_sub_co(arg1, arg2, result)
    e += update_flag_af(arg1, arg2, result)
    e.append(m2_expr.ExprAssign(src, result))
    return (e, [])


def l_not(_, instr, dst):
    e = []
    result = (~dst)
    e.append(m2_expr.ExprAssign(dst, result))
    return (e, [])


def l_cmp(_, instr, dst, src):
    e = []
    arg1, arg2 = dst, src
    result = dst - src

    e += update_flag_arith_sub_znp(arg1, arg2)
    e += update_flag_arith_sub_co(arg1, arg2, result)
    e += update_flag_af(dst, src, result)
    return (e, [])


def xor(_, instr, dst, src):
    e = []
    result = dst ^ src
    e += [m2_expr.ExprAssign(zf, m2_expr.ExprOp('FLAG_EQ_CMP', dst, src))]
    e += update_flag_np(result)
    e += null_flag_co()
    e.append(m2_expr.ExprAssign(dst, result))
    return (e, [])


def pxor(_, instr, dst, src):
    e = []
    result = dst ^ src
    e.append(m2_expr.ExprAssign(dst, result))
    return (e, [])


def l_or(_, instr, dst, src):
    e = []
    result = dst | src
    e += [m2_expr.ExprAssign(zf, m2_expr.ExprOp('FLAG_EQ', dst | src))]
    e += update_flag_np(result)
    e += null_flag_co()
    e.append(m2_expr.ExprAssign(dst, result))
    return (e, [])


def l_and(_, instr, dst, src):
    e = []
    result = dst & src
    e += [m2_expr.ExprAssign(zf, m2_expr.ExprOp('FLAG_EQ_AND', dst, src))]
    e += update_flag_np(result)
    e += null_flag_co()

    e.append(m2_expr.ExprAssign(dst, result))
    return (e, [])


def l_test(_, instr, dst, src):
    e = []
    result = dst & src

    e += [m2_expr.ExprAssign(zf, m2_expr.ExprOp('FLAG_EQ_CMP', result, m2_expr.ExprInt(0, result.size)))]
    e += [m2_expr.ExprAssign(nf, m2_expr.ExprOp("FLAG_SIGN_SUB", result, m2_expr.ExprInt(0, result.size)))]
    e += update_flag_pf(result)
    e += null_flag_co()

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


def _rotate_tpl(ir, instr, dst, src, op, left=False):
    '''Template to generate a rotater with operation @op
    A temporary basic block is generated to handle 0-rotate
    @op: operation to execute
    @left (optional): indicates a left rotate if set, default is False
    '''
    # Compute results
    shifter = get_shift(dst, src)
    res = m2_expr.ExprOp(op, dst, shifter)

    # CF is computed with 1-less round than `res`
    new_cf = m2_expr.ExprOp(
        op, dst, shifter - m2_expr.ExprInt(1, size=shifter.size))
    new_cf = new_cf.msb() if left else new_cf[:1]

    # OF is defined only for @b == 1
    new_of = m2_expr.ExprCond(src - m2_expr.ExprInt(1, size=src.size),
                              m2_expr.ExprInt(0, size=of.size),
                              res.msb() ^ new_cf if left else (dst ^ res).msb())

    # Build basic blocks
    e_do = [m2_expr.ExprAssign(cf, new_cf),
            m2_expr.ExprAssign(of, new_of),
            m2_expr.ExprAssign(dst, res)
            ]
    e = []
    if instr.mode == 64:
        # Force destination set in order to zero high bit orders
        # In 64 bit:
        # rol eax, cl
        # if cl == 0 => high part of RAX is set to zero
        e.append(m2_expr.ExprAssign(dst, dst))
    # Don't generate conditional shifter on constant
    if isinstance(shifter, m2_expr.ExprInt):
        if int(shifter) != 0:
            return (e_do, [])
        else:
            return (e, [])
    loc_do, loc_do_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_skip = ir.get_next_loc_key(instr)
    loc_skip_expr = m2_expr.ExprLoc(loc_skip, ir.IRDst.size)
    e_do.append(m2_expr.ExprAssign(ir.IRDst, loc_skip_expr))
    e.append(m2_expr.ExprAssign(
        ir.IRDst, m2_expr.ExprCond(shifter, loc_do_expr, loc_skip_expr)))
    return (e, [IRBlock(ir.loc_db, loc_do, [AssignBlock(e_do, instr)])])


def l_rol(ir, instr, dst, src):
    return _rotate_tpl(ir, instr, dst, src, '<<<', left=True)


def l_ror(ir, instr, dst, src):
    return _rotate_tpl(ir, instr, dst, src, '>>>')


def rotate_with_carry_tpl(ir, instr, op, dst, src):
    # Compute results
    shifter = get_shift(dst, src).zeroExtend(dst.size + 1)
    result = m2_expr.ExprOp(op, m2_expr.ExprCompose(dst, cf), shifter)

    new_cf = result[dst.size:dst.size +1]
    new_dst = result[:dst.size]

    result_trunc = result[:dst.size]
    if op == '<<<':
        of_value = result_trunc.msb() ^ new_cf
    else:
        of_value = (dst ^ result_trunc).msb()
    # OF is defined only for @b == 1
    new_of = m2_expr.ExprCond(src - m2_expr.ExprInt(1, size=src.size),
                              m2_expr.ExprInt(0, size=of.size),
                              of_value)


    # Build basic blocks
    e_do = [m2_expr.ExprAssign(cf, new_cf),
            m2_expr.ExprAssign(of, new_of),
            m2_expr.ExprAssign(dst, new_dst)
            ]
    e = [m2_expr.ExprAssign(dst, dst)]
    # Don't generate conditional shifter on constant
    if isinstance(shifter, m2_expr.ExprInt):
        if int(shifter) != 0:
            return (e_do, [])
        else:
            return (e, [])
    loc_do, loc_do_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_skip = ir.get_next_loc_key(instr)
    loc_skip_expr = m2_expr.ExprLoc(loc_skip, ir.IRDst.size)
    e_do.append(m2_expr.ExprAssign(ir.IRDst, loc_skip_expr))
    e.append(m2_expr.ExprAssign(
        ir.IRDst, m2_expr.ExprCond(shifter, loc_do_expr, loc_skip_expr)))
    return (e, [IRBlock(ir.loc_db, loc_do, [AssignBlock(e_do, instr)])])

def rcl(ir, instr, dst, src):
    return rotate_with_carry_tpl(ir, instr, '<<<', dst, src)

def rcr(ir, instr, dst, src):
    return rotate_with_carry_tpl(ir, instr, '>>>', dst, src)


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

        # An overflow can occurred, emulate the 'undefined behavior'
        # Overflow behavior if (shift / size % 2)
        base_cond_overflow = shifter if left else (
            shifter - m2_expr.ExprInt(1, size=shifter.size))
        cond_overflow = base_cond_overflow & m2_expr.ExprInt(a.size, shifter.size)
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
                                     (shifter.zeroExtend(b.size) &
                                      m2_expr.ExprInt(a.size - 1, b.size)) - i1)
        cf_from_src = cf_from_src.msb() if left else cf_from_src[:1]
        new_cf = m2_expr.ExprCond(cond_overflow, cf_from_src, cf_from_dst)

    # Overflow flag, only occurred when shifter is equal to 1
    if custom_of is None:
        value_of = a.msb() ^ a[-2:-1] if left else b[:1] ^ a.msb()
    else:
        value_of = custom_of

    # Build basic blocks
    e_do = [
        m2_expr.ExprAssign(cf, new_cf),
        m2_expr.ExprAssign(of, m2_expr.ExprCond(shifter - i1,
                                             m2_expr.ExprInt(0, of.size),
                                             value_of)),
        m2_expr.ExprAssign(a, res),
    ]
    e_do += update_flag_znp(res)
    e = []
    if instr.mode == 64:
        # Force destination set in order to zero high bit orders
        # In 64 bit:
        # shr eax, cl
        # if cl == 0 => high part of RAX is set to zero
        e.append(m2_expr.ExprAssign(a, a))
    # Don't generate conditional shifter on constant
    if isinstance(shifter, m2_expr.ExprInt):
        if int(shifter) != 0:
            return (e_do, [])
        else:
            return (e, [])
    loc_do, loc_do_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_skip = ir.get_next_loc_key(instr)
    loc_skip_expr = m2_expr.ExprLoc(loc_skip, ir.IRDst.size)
    e_do.append(m2_expr.ExprAssign(ir.IRDst, loc_skip_expr))
    e.append(m2_expr.ExprAssign(ir.IRDst, m2_expr.ExprCond(shifter, loc_do_expr,
                                                        loc_skip_expr)))
    return e, [IRBlock(ir.loc_db, loc_do, [AssignBlock(e_do, instr)])]


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
    e = [m2_expr.ExprAssign(cf, m2_expr.ExprCond(cf, m2_expr.ExprInt(0, cf.size),
                                              m2_expr.ExprInt(1, cf.size)))]
    return e, []


def clc(_, instr):
    e = [m2_expr.ExprAssign(cf, m2_expr.ExprInt(0, cf.size))]
    return e, []


def stc(_, instr):
    e = [m2_expr.ExprAssign(cf, m2_expr.ExprInt(1, cf.size))]
    return e, []


def cld(_, instr):
    e = [m2_expr.ExprAssign(df, m2_expr.ExprInt(0, df.size))]
    return e, []


def std(_, instr):
    e = [m2_expr.ExprAssign(df, m2_expr.ExprInt(1, df.size))]
    return e, []


def cli(_, instr):
    e = [m2_expr.ExprAssign(i_f, m2_expr.ExprInt(0, i_f.size))]
    return e, []


def sti(_, instr):
    e = [m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32))]
    return e, []


def inc(_, instr, dst):
    e = []
    src = m2_expr.ExprInt(1, dst.size)
    arg1, arg2 = dst, src
    result = dst + src

    e += update_flag_arith_add_znp(arg1, arg2)
    e += update_flag_af(arg1, arg2, result)
    e += update_flag_add_of(arg1, arg2, result)

    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def dec(_, instr, dst):
    e = []
    src = m2_expr.ExprInt(1, dst.size)
    arg1, arg2 = dst, src
    result = dst - src

    e += update_flag_arith_sub_znp(arg1, arg2)
    e += update_flag_af(arg1, arg2, result)
    e += update_flag_sub_of(arg1, arg2, result)

    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def push_gen(ir, instr, src, size):
    e = []
    if not size in [16, 32, 64]:
        raise ValueError('bad size stacker!')
    if src.size < size:
        src = src.zeroExtend(size)
    off_size = src.size

    sp = mRSP[instr.mode]
    new_sp = sp - m2_expr.ExprInt(off_size // 8, sp.size)
    e.append(m2_expr.ExprAssign(sp, new_sp))
    if ir.do_stk_segm:
        new_sp = ir.gen_segm_expr(SS, new_sp)
    e.append(m2_expr.ExprAssign(ir.ExprMem(new_sp, off_size),
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
    new_sp = sp + m2_expr.ExprInt(src.size // 8, sp.size)
    # Don't generate SP/ESP/RSP incrementation on POP SP/ESP/RSP
    if not (src in mRSP.values()):
        e.append(m2_expr.ExprAssign(sp, new_sp))
    # XXX FIX XXX for pop [esp]
    if isinstance(src, m2_expr.ExprMem):
        src = expr_simp(src.replace_expr({sp: new_sp}))
    result = sp
    if ir.do_stk_segm:
        result = ir.gen_segm_expr(SS, result)

    e.append(m2_expr.ExprAssign(src, ir.ExprMem(result, src.size)))
    return e, []


def pop(ir, instr, src):
    return pop_gen(ir, instr, src, instr.mode)


def popw(ir, instr, src):
    return pop_gen(ir, instr, src, 16)


def sete(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_EQ", zf).zeroExtend(dst.size),
        )
    )
    return e, []


def setnz(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_EQ", ~zf).zeroExtend(dst.size),
        )
    )
    return e, []


def setl(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_S<", nf, of).zeroExtend(dst.size),
        )
    )
    return e, []


def setg(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_S>", nf, of, zf).zeroExtend(dst.size),
        )
    )
    return e, []


def setge(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_S>=", nf, of).zeroExtend(dst.size),
        )
    )
    return e, []


def seta(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_U>", cf, zf).zeroExtend(dst.size),
        )
    )
    return e, []


def setae(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_U>=", cf).zeroExtend(dst.size),
        )
    )
    return e, []


def setb(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_U<", cf).zeroExtend(dst.size),
        )
    )
    return e, []


def setbe(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_U<=", cf, zf).zeroExtend(dst.size),
        )
    )
    return e, []


def setns(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_NEG", ~nf).zeroExtend(dst.size),
        )
    )
    return e, []


def sets(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_NEG", nf).zeroExtend(dst.size),
        )
    )
    return e, []


def seto(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            of.zeroExtend(dst.size)
        )
    )
    return e, []


def setp(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            pf.zeroExtend(dst.size)
        )
    )
    return e, []


def setnp(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprCond(
                pf,
                m2_expr.ExprInt(0, dst.size),
                m2_expr.ExprInt(1, dst.size)
            )
        )
    )
    return e, []


def setle(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_S<=", nf, of, zf).zeroExtend(dst.size),
        )
    )
    return e, []


def setna(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_U<=", cf, zf).zeroExtend(dst.size),
        )
    )
    return e, []


def setnbe(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_U>", cf, zf).zeroExtend(dst.size),
        )
    )
    return e, []


def setno(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprCond(
                of,
                m2_expr.ExprInt(0, dst.size),
                m2_expr.ExprInt(1, dst.size)
            )
        )
    )
    return e, []


def setnb(_, instr, dst):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst,
            m2_expr.ExprOp("CC_U>=", cf).zeroExtend(dst.size),
        )
    )
    return e, []


def setalc(_, instr):
    dst = mRAX[instr.mode][0:8]
    e = []
    e.append(
        m2_expr.ExprAssign(dst, m2_expr.ExprCond(cf, m2_expr.ExprInt(0xff, dst.size),
                                              m2_expr.ExprInt(0, dst.size))))
    return e, []


def bswap(_, instr, dst):
    e = []
    if dst.size == 16:
        # BSWAP referencing a 16-bit register is undefined
        # Seems to return 0 actually
        result = m2_expr.ExprInt(0, 16)
    elif dst.size == 32:
        result = m2_expr.ExprCompose(
            dst[24:32], dst[16:24], dst[8:16], dst[:8])
    elif dst.size == 64:
        result = m2_expr.ExprCompose(dst[56:64], dst[48:56], dst[40:48], dst[32:40],
                                     dst[24:32], dst[16:24], dst[8:16], dst[:8])
    else:
        raise ValueError('the size DOES matter')
    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def cmps(ir, instr, size):
    loc_df_0, loc_df_0_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_df_1, loc_df_1_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next_expr = m2_expr.ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

    src1 = mRSI[instr.mode][:instr.v_admode()]
    src2 = mRDI[instr.mode][:instr.v_admode()]

    if ir.do_str_segm:
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        src1_sgm = ir.gen_segm_expr(DS, src1)
        src2_sgm = ir.gen_segm_expr(ES, src2)
    else:
        src1_sgm = src1
        src2_sgm = src2

    offset = m2_expr.ExprInt(size // 8, src1.size)

    e, _ = l_cmp(ir, instr,
                 ir.ExprMem(src1_sgm, size),
                 ir.ExprMem(src2_sgm, size))


    e0 = []
    e0.append(m2_expr.ExprAssign(src1, src1 + offset))
    e0.append(m2_expr.ExprAssign(src2, src2 + offset))
    e0.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e0 = IRBlock(ir.loc_db, loc_df_0, [AssignBlock(e0, instr)])

    e1 = []
    e1.append(m2_expr.ExprAssign(src1, src1 - offset))
    e1.append(m2_expr.ExprAssign(src2, src2 - offset))
    e1.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e1 = IRBlock(ir.loc_db, loc_df_1, [AssignBlock(e1, instr)])

    e.append(m2_expr.ExprAssign(ir.IRDst,
                             m2_expr.ExprCond(df, loc_df_1_expr, loc_df_0_expr)))
    return e, [e0, e1]


def scas(ir, instr, size):
    loc_df_0, loc_df_0_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_df_1, loc_df_1_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next_expr = m2_expr.ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

    src = mRDI[instr.mode][:instr.v_admode()]

    if ir.do_str_segm:
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        src_sgm = ir.gen_segm_expr(ES, src)

    else:
        src_sgm = src

    offset = m2_expr.ExprInt(size // 8, src.size)
    e, extra = l_cmp(ir, instr,
                     mRAX[instr.mode][:size],
                     ir.ExprMem(src_sgm, size))

    e0 = []
    e0.append(m2_expr.ExprAssign(src, src + offset))

    e0.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e0 = IRBlock(ir.loc_db, loc_df_0, [AssignBlock(e0, instr)])

    e1 = []
    e1.append(m2_expr.ExprAssign(src, src - offset))
    e1.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e1 = IRBlock(ir.loc_db, loc_df_1, [AssignBlock(e1, instr)])

    e.append(m2_expr.ExprAssign(ir.IRDst,
                             m2_expr.ExprCond(df, loc_df_1_expr, loc_df_0_expr)))

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
    tmp = ir.ExprMem(mRSP[instr.mode], 32)
    e = []
    e.append(m2_expr.ExprAssign(cf, m2_expr.ExprSlice(tmp, 0, 1)))
    e.append(m2_expr.ExprAssign(pf, m2_expr.ExprSlice(tmp, 2, 3)))
    e.append(m2_expr.ExprAssign(af, m2_expr.ExprSlice(tmp, 4, 5)))
    e.append(m2_expr.ExprAssign(zf, m2_expr.ExprSlice(tmp, 6, 7)))
    e.append(m2_expr.ExprAssign(nf, m2_expr.ExprSlice(tmp, 7, 8)))
    e.append(m2_expr.ExprAssign(tf, m2_expr.ExprSlice(tmp, 8, 9)))
    e.append(m2_expr.ExprAssign(i_f, m2_expr.ExprSlice(tmp, 9, 10)))
    e.append(m2_expr.ExprAssign(df, m2_expr.ExprSlice(tmp, 10, 11)))
    e.append(m2_expr.ExprAssign(of, m2_expr.ExprSlice(tmp, 11, 12)))
    e.append(m2_expr.ExprAssign(iopl, m2_expr.ExprSlice(tmp, 12, 14)))
    e.append(m2_expr.ExprAssign(nt, m2_expr.ExprSlice(tmp, 14, 15)))
    e.append(m2_expr.ExprAssign(rf, m2_expr.ExprSlice(tmp, 16, 17)))
    e.append(m2_expr.ExprAssign(vm, m2_expr.ExprSlice(tmp, 17, 18)))
    e.append(m2_expr.ExprAssign(ac, m2_expr.ExprSlice(tmp, 18, 19)))
    e.append(m2_expr.ExprAssign(vif, m2_expr.ExprSlice(tmp, 19, 20)))
    e.append(m2_expr.ExprAssign(vip, m2_expr.ExprSlice(tmp, 20, 21)))
    e.append(m2_expr.ExprAssign(i_d, m2_expr.ExprSlice(tmp, 21, 22)))
    e.append(m2_expr.ExprAssign(mRSP[instr.mode],
                             mRSP[instr.mode] + m2_expr.ExprInt(instr.mode // 8, mRSP[instr.mode].size)))
    e.append(m2_expr.ExprAssign(exception_flags,
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
    return [m2_expr.ExprAssign(dest, tmp[base:base + dest.size])
            for base, dest in ((0, cf), (2, pf), (4, af), (6, zf), (7, nf),
                               (8, tf), (9, i_f), (10, df), (11, of),
                               (12, iopl), (14, nt))]


def popfw(ir, instr):
    tmp = ir.ExprMem(mRSP[instr.mode], 16)
    e = _tpl_eflags(tmp)
    e.append(
        m2_expr.ExprAssign(mRSP[instr.mode], mRSP[instr.mode] + m2_expr.ExprInt(2, mRSP[instr.mode].size)))
    return e, []

pa_regs = [
    mRAX, mRCX,
    mRDX, mRBX,
    mRSP, mRBP,
    mRSI, mRDI
]


def pusha_gen(ir, instr, size):
    e = []
    cur_sp = mRSP[instr.mode]
    for i, reg in enumerate(pa_regs):
        stk_ptr = cur_sp + m2_expr.ExprInt(-(size // 8) * (i + 1), instr.mode)
        e.append(m2_expr.ExprAssign(ir.ExprMem(stk_ptr, size), reg[size]))
    e.append(m2_expr.ExprAssign(cur_sp, stk_ptr))
    return e, []


def pusha(ir, instr):
    return pusha_gen(ir, instr, 16)


def pushad(ir, instr):
    return pusha_gen(ir, instr, 32)


def popa_gen(ir, instr, size):
    e = []
    cur_sp = mRSP[instr.mode]
    for i, reg in enumerate(reversed(pa_regs)):
        if reg == mRSP:
            continue
        stk_ptr = cur_sp + m2_expr.ExprInt((size // 8) * i, instr.mode)
        e.append(m2_expr.ExprAssign(reg[size], ir.ExprMem(stk_ptr, size)))

    stk_ptr = cur_sp + m2_expr.ExprInt((size // 8) * (i + 1), instr.mode)
    e.append(m2_expr.ExprAssign(cur_sp, stk_ptr))

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
    n = m2_expr.ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

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
            addr = dst.args[0].ptr
            m1 = ir.ExprMem(addr, CS.size)
            m2 = ir.ExprMem(addr + m2_expr.ExprInt(2, addr.size), meip.size)
        else:
            raise RuntimeError("bad call operator")

        e.append(m2_expr.ExprAssign(CS, m1))
        e.append(m2_expr.ExprAssign(meip, m2))

        e.append(m2_expr.ExprAssign(ir.IRDst, m2))

        c = myesp + m2_expr.ExprInt(-s // 8, s)
        e.append(m2_expr.ExprAssign(ir.ExprMem(c, size=s).zeroExtend(s),
                                 CS.zeroExtend(s)))

        c = myesp + m2_expr.ExprInt((-2 * s) // 8, s)
        e.append(m2_expr.ExprAssign(ir.ExprMem(c, size=s).zeroExtend(s),
                                 meip.zeroExtend(s)))

        c = myesp + m2_expr.ExprInt((-2 * s) // 8, s)
        e.append(m2_expr.ExprAssign(myesp, c))
        return e, []

    c = myesp + m2_expr.ExprInt(-s // 8, s)
    e.append(m2_expr.ExprAssign(myesp, c))
    if ir.do_stk_segm:
        c = ir.gen_segm_expr(SS, c)

    e.append(m2_expr.ExprAssign(ir.ExprMem(c, size=s), n))
    e.append(m2_expr.ExprAssign(meip, dst.zeroExtend(ir.IRDst.size)))
    e.append(m2_expr.ExprAssign(ir.IRDst, dst.zeroExtend(ir.IRDst.size)))
    return e, []


def ret(ir, instr, src=None):
    e = []
    meip = mRIP[ir.IRDst.size]
    size, admode = instr.v_opmode(), instr.v_admode()
    myesp = mRSP[instr.mode][:size]

    if src is None:
        value = (myesp + (m2_expr.ExprInt(size // 8, size)))
    else:
        src = m2_expr.ExprInt(int(src), size)
        value = (myesp + (m2_expr.ExprInt(size // 8, size) + src))

    e.append(m2_expr.ExprAssign(myesp, value))
    result = myesp
    if ir.do_stk_segm:
        result = ir.gen_segm_expr(SS, result)

    e.append(m2_expr.ExprAssign(meip, ir.ExprMem(
        result, size=size).zeroExtend(size)))
    e.append(m2_expr.ExprAssign(ir.IRDst,
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
        result = ir.gen_segm_expr(SS, result)

    e.append(m2_expr.ExprAssign(meip, ir.ExprMem(
        result, size=size).zeroExtend(size)))
    e.append(m2_expr.ExprAssign(ir.IRDst,
                             ir.ExprMem(result, size=size).zeroExtend(size)))
    # e.append(m2_expr.ExprAssign(meip, ir.ExprMem(c, size = s)))
    result = myesp + m2_expr.ExprInt(size // 8, size)
    if ir.do_stk_segm:
        result = ir.gen_segm_expr(SS, result)

    e.append(m2_expr.ExprAssign(CS, ir.ExprMem(result, size=16)))

    value = myesp + (m2_expr.ExprInt((2 * size) // 8, size) + src)
    e.append(m2_expr.ExprAssign(myesp, value))
    return e, []


def leave(ir, instr):
    size = instr.mode
    myesp = mRSP[size]
    e = []
    e.append(m2_expr.ExprAssign(mRBP[size], ir.ExprMem(mRBP[size], size=size)))
    e.append(m2_expr.ExprAssign(myesp,
                             m2_expr.ExprInt(size // 8, size) + mRBP[size]))
    return e, []


def enter(ir, instr, src1, src2):
    size, admode = instr.v_opmode(), instr.v_admode()
    myesp = mRSP[instr.mode][:size]
    myebp = mRBP[instr.mode][:size]

    src1 = src1.zeroExtend(size)

    e = []
    esp_tmp = myesp - m2_expr.ExprInt(size // 8, size)
    e.append(m2_expr.ExprAssign(ir.ExprMem(esp_tmp, size=size),
                             myebp))
    e.append(m2_expr.ExprAssign(myebp, esp_tmp))
    e.append(m2_expr.ExprAssign(myesp,
                             myesp - (src1 + m2_expr.ExprInt(size // 8, size))))
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
            addr = dst.args[0].ptr
            m1 = ir.ExprMem(addr, CS.size)
            m2 = ir.ExprMem(addr + m2_expr.ExprInt(2, addr.size), meip.size)
        else:
            raise RuntimeError("bad jmp operator")

        e.append(m2_expr.ExprAssign(CS, m1))
        e.append(m2_expr.ExprAssign(meip, m2))
        e.append(m2_expr.ExprAssign(ir.IRDst, m2))

    else:
        # Classic jmp
        e.append(m2_expr.ExprAssign(meip, dst))
        e.append(m2_expr.ExprAssign(ir.IRDst, dst))

        if isinstance(dst, m2_expr.ExprMem):
            dst = meip
    return e, []


def jz(ir, instr, dst):
    #return gen_jcc(ir, instr, zf, dst, True)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_EQ", zf), dst, True)


def jcxz(ir, instr, dst):
    return gen_jcc(ir, instr, mRCX[instr.mode][:16], dst, False)


def jecxz(ir, instr, dst):
    return gen_jcc(ir, instr, mRCX[instr.mode][:32], dst, False)


def jrcxz(ir, instr, dst):
    return gen_jcc(ir, instr, mRCX[instr.mode], dst, False)


def jnz(ir, instr, dst):
    #return gen_jcc(ir, instr, zf, dst, False)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_EQ", zf), dst, False)



def jp(ir, instr, dst):
    return gen_jcc(ir, instr, pf, dst, True)


def jnp(ir, instr, dst):
    return gen_jcc(ir, instr, pf, dst, False)


def ja(ir, instr, dst):
    #return gen_jcc(ir, instr, cf | zf, dst, False)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_U>", cf, zf), dst, True)


def jae(ir, instr, dst):
    #return gen_jcc(ir, instr, cf, dst, False)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_U>=", cf), dst, True)


def jb(ir, instr, dst):
    #return gen_jcc(ir, instr, cf, dst, True)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_U<", cf), dst, True)


def jbe(ir, instr, dst):
    #return gen_jcc(ir, instr, cf | zf, dst, True)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_U<=", cf, zf), dst, True)


def jge(ir, instr, dst):
    #return gen_jcc(ir, instr, nf - of, dst, False)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_S>=", nf, of), dst, True)


def jg(ir, instr, dst):
    #return gen_jcc(ir, instr, zf | (nf - of), dst, False)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_S>", nf, of, zf), dst, True)


def jl(ir, instr, dst):
    #return gen_jcc(ir, instr, nf - of, dst, True)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_S<", nf, of), dst, True)


def jle(ir, instr, dst):
    #return gen_jcc(ir, instr, zf | (nf - of), dst, True)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_S<=", nf, of, zf), dst, True)



def js(ir, instr, dst):
    #return gen_jcc(ir, instr, nf, dst, True)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_NEG", nf), dst, True)



def jns(ir, instr, dst):
    #return gen_jcc(ir, instr, nf, dst, False)
    return gen_jcc(ir, instr, m2_expr.ExprOp("CC_NEG", nf), dst, False)


def jo(ir, instr, dst):
    return gen_jcc(ir, instr, of, dst, True)


def jno(ir, instr, dst):
    return gen_jcc(ir, instr, of, dst, False)


def loop(ir, instr, dst):
    e = []
    meip = mRIP[ir.IRDst.size]
    admode = instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = m2_expr.ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)
    c = myecx - m2_expr.ExprInt(1, myecx.size)
    dst_o = m2_expr.ExprCond(c,
                             dst.zeroExtend(ir.IRDst.size),
                             n.zeroExtend(ir.IRDst.size))
    e.append(m2_expr.ExprAssign(myecx, c))
    e.append(m2_expr.ExprAssign(meip, dst_o))
    e.append(m2_expr.ExprAssign(ir.IRDst, dst_o))
    return e, []


def loopne(ir, instr, dst):
    e = []
    meip = mRIP[ir.IRDst.size]
    admode = instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = m2_expr.ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

    c = m2_expr.ExprCond(myecx - m2_expr.ExprInt(1, size=myecx.size),
                         m2_expr.ExprInt(1, 1),
                         m2_expr.ExprInt(0, 1))
    c &= zf ^ m2_expr.ExprInt(1, 1)

    e.append(m2_expr.ExprAssign(myecx, myecx - m2_expr.ExprInt(1, myecx.size)))
    dst_o = m2_expr.ExprCond(c,
                             dst.zeroExtend(ir.IRDst.size),
                             n.zeroExtend(ir.IRDst.size))
    e.append(m2_expr.ExprAssign(meip, dst_o))
    e.append(m2_expr.ExprAssign(ir.IRDst, dst_o))
    return e, []


def loope(ir, instr, dst):
    e = []
    meip = mRIP[ir.IRDst.size]
    admode = instr.v_admode()
    myecx = mRCX[instr.mode][:admode]

    n = m2_expr.ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)
    c = m2_expr.ExprCond(myecx - m2_expr.ExprInt(1, size=myecx.size),
                         m2_expr.ExprInt(1, 1),
                         m2_expr.ExprInt(0, 1))
    c &= zf
    e.append(m2_expr.ExprAssign(myecx, myecx - m2_expr.ExprInt(1, myecx.size)))
    dst_o = m2_expr.ExprCond(c,
                             dst.zeroExtend(ir.IRDst.size),
                             n.zeroExtend(ir.IRDst.size))
    e.append(m2_expr.ExprAssign(meip, dst_o))
    e.append(m2_expr.ExprAssign(ir.IRDst, dst_o))
    return e, []

# XXX size to do; eflag


def div(ir, instr, src1):
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

    # if 8 bit div, only ax is assigned
    if size == 8:
        e.append(m2_expr.ExprAssign(src2, m2_expr.ExprCompose(c_d[:8], c_r[:8])))
    else:
        e.append(m2_expr.ExprAssign(s1, c_r[:size]))
        e.append(m2_expr.ExprAssign(s2, c_d[:size]))

    loc_div, loc_div_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_except, loc_except_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = m2_expr.ExprLoc(loc_next, ir.IRDst.size)

    do_div = []
    do_div += e
    do_div.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    blk_div = IRBlock(ir.loc_db, loc_div, [AssignBlock(do_div, instr)])

    do_except = []
    do_except.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(
        EXCEPT_DIV_BY_ZERO, exception_flags.size)))
    do_except.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    blk_except = IRBlock(ir.loc_db, loc_except, [AssignBlock(do_except, instr)])

    e = []
    e.append(m2_expr.ExprAssign(ir.IRDst,
                             m2_expr.ExprCond(src1, loc_div_expr, loc_except_expr)))

    return e, [blk_div, blk_except]


# XXX size to do; eflag

def idiv(ir, instr, src1):
    e = []
    size = src1.size

    if size == 8:
        src2 = mRAX[instr.mode][:16]
    elif size in [16, 32, 64]:
        s1, s2 = mRDX[size], mRAX[size]
        src2 = m2_expr.ExprCompose(s2, s1)
    else:
        raise ValueError('div arg not impl', src1)

    c_d = m2_expr.ExprOp('sdiv', src2, src1.signExtend(src2.size))
    c_r = m2_expr.ExprOp('smod', src2, src1.signExtend(src2.size))

    # if 8 bit div, only ax is assigned
    if size == 8:
        e.append(m2_expr.ExprAssign(src2, m2_expr.ExprCompose(c_d[:8], c_r[:8])))
    else:
        e.append(m2_expr.ExprAssign(s1, c_r[:size]))
        e.append(m2_expr.ExprAssign(s2, c_d[:size]))

    loc_div, loc_div_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_except, loc_except_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = m2_expr.ExprLoc(loc_next, ir.IRDst.size)

    do_div = []
    do_div += e
    do_div.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    blk_div = IRBlock(ir.loc_db, loc_div, [AssignBlock(do_div, instr)])

    do_except = []
    do_except.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(
        EXCEPT_DIV_BY_ZERO, exception_flags.size)))
    do_except.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    blk_except = IRBlock(ir.loc_db, loc_except, [AssignBlock(do_except, instr)])

    e = []
    e.append(m2_expr.ExprAssign(ir.IRDst,
                             m2_expr.ExprCond(src1, loc_div_expr, loc_except_expr)))

    return e, [blk_div, blk_except]


# XXX size to do; eflag


def mul(_, instr, src1):
    e = []
    size = src1.size
    if src1.size in [16, 32, 64]:
        result = m2_expr.ExprOp('*',
                                mRAX[size].zeroExtend(size * 2),
                                src1.zeroExtend(size * 2))
        e.append(m2_expr.ExprAssign(mRAX[size], result[:size]))
        e.append(m2_expr.ExprAssign(mRDX[size], result[size:size * 2]))

    elif src1.size == 8:
        result = m2_expr.ExprOp('*',
                                mRAX[instr.mode][:8].zeroExtend(16),
                                src1.zeroExtend(16))
        e.append(m2_expr.ExprAssign(mRAX[instr.mode][:16], result))
    else:
        raise ValueError('unknow size')

    e.append(m2_expr.ExprAssign(of, m2_expr.ExprCond(result[size:size * 2],
                                                  m2_expr.ExprInt(1, 1),
                                                  m2_expr.ExprInt(0, 1))))
    e.append(m2_expr.ExprAssign(cf, m2_expr.ExprCond(result[size:size * 2],
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
            e.append(m2_expr.ExprAssign(mRAX[size], result[:size]))
            e.append(m2_expr.ExprAssign(mRDX[size], result[size:size * 2]))
        elif size == 8:
            dst = mRAX[instr.mode][:16]
            result = m2_expr.ExprOp('*',
                                    mRAX[instr.mode][:8].signExtend(16),
                                    src1.signExtend(16))

            e.append(m2_expr.ExprAssign(dst, result))
        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt(1, 1),
                                 m2_expr.ExprInt(0, 1))
        e.append(m2_expr.ExprAssign(cf, value))
        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt(1, 1),
                                 m2_expr.ExprInt(0, 1))
        e.append(m2_expr.ExprAssign(of, value))

    else:
        if src3 is None:
            src3 = src2
            src2 = src1
        result = m2_expr.ExprOp('*',
                                src2.signExtend(size * 2),
                                src3.signExtend(size * 2))
        e.append(m2_expr.ExprAssign(src1, result[:size]))

        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt(1, 1),
                                 m2_expr.ExprInt(0, 1))
        e.append(m2_expr.ExprAssign(cf, value))
        value = m2_expr.ExprCond(result - result[:size].signExtend(size * 2),
                                 m2_expr.ExprInt(1, 1),
                                 m2_expr.ExprInt(0, 1))
        e.append(m2_expr.ExprAssign(of, value))
    return e, []


def cbw(_, instr):
    # Only in 16 bit
    e = []
    tempAL = mRAX[instr.v_opmode()][:8]
    tempAX = mRAX[instr.v_opmode()][:16]
    e.append(m2_expr.ExprAssign(tempAX, tempAL.signExtend(16)))
    return e, []


def cwde(_, instr):
    # Only in 32/64 bit
    e = []
    tempAX = mRAX[instr.v_opmode()][:16]
    tempEAX = mRAX[instr.v_opmode()][:32]
    e.append(m2_expr.ExprAssign(tempEAX, tempAX.signExtend(32)))
    return e, []


def cdqe(_, instr):
    # Only in 64 bit
    e = []
    tempEAX = mRAX[instr.mode][:32]
    tempRAX = mRAX[instr.mode][:64]
    e.append(m2_expr.ExprAssign(tempRAX, tempEAX.signExtend(64)))
    return e, []


def cwd(_, instr):
    # Only in 16 bit
    e = []
    tempAX = mRAX[instr.mode][:16]
    tempDX = mRDX[instr.mode][:16]
    result = tempAX.signExtend(32)
    e.append(m2_expr.ExprAssign(tempAX, result[:16]))
    e.append(m2_expr.ExprAssign(tempDX, result[16:32]))
    return e, []


def cdq(_, instr):
    # Only in 32/64 bit
    e = []
    tempEAX = mRAX[instr.v_opmode()]
    tempEDX = mRDX[instr.v_opmode()]
    result = tempEAX.signExtend(64)
    e.append(m2_expr.ExprAssign(tempEDX, result[32:64]))
    return e, []


def cqo(_, instr):
    # Only in 64 bit
    e = []
    tempRAX = mRAX[instr.mode][:64]
    tempRDX = mRDX[instr.mode][:64]
    result = tempRAX.signExtend(128)
    e.append(m2_expr.ExprAssign(tempRAX, result[:64]))
    e.append(m2_expr.ExprAssign(tempRDX, result[64:128]))
    return e, []


def stos(ir, instr, size):
    loc_df_0, loc_df_0_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_df_1, loc_df_1_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next_expr = m2_expr.ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

    addr_o = mRDI[instr.mode][:instr.v_admode()]
    addr = addr_o
    addr_p = addr + m2_expr.ExprInt(size // 8, addr.size)
    addr_m = addr - m2_expr.ExprInt(size // 8, addr.size)
    if ir.do_str_segm:
        mss = ES
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        addr = ir.gen_segm_expr(mss, addr)


    b = mRAX[instr.mode][:size]

    e0 = []
    e0.append(m2_expr.ExprAssign(addr_o, addr_p))
    e0.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e0 = IRBlock(ir.loc_db, loc_df_0, [AssignBlock(e0, instr)])

    e1 = []
    e1.append(m2_expr.ExprAssign(addr_o, addr_m))
    e1.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e1 = IRBlock(ir.loc_db, loc_df_1, [AssignBlock(e1, instr)])

    e = []
    e.append(m2_expr.ExprAssign(ir.ExprMem(addr, size), b))
    e.append(m2_expr.ExprAssign(ir.IRDst,
                             m2_expr.ExprCond(df, loc_df_1_expr, loc_df_0_expr)))
    return e, [e0, e1]


def lods(ir, instr, size):
    loc_df_0, loc_df_0_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_df_1, loc_df_1_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next_expr = m2_expr.ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)
    e = []

    addr_o = mRSI[instr.mode][:instr.v_admode()]
    addr = addr_o
    addr_p = addr + m2_expr.ExprInt(size // 8, addr.size)
    addr_m = addr - m2_expr.ExprInt(size // 8, addr.size)
    if ir.do_str_segm:
        mss = DS
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        addr = ir.gen_segm_expr(mss, addr)


    b = mRAX[instr.mode][:size]

    e0 = []
    e0.append(m2_expr.ExprAssign(addr_o, addr_p))
    e0.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e0 = IRBlock(ir.loc_db, loc_df_0, [AssignBlock(e0, instr)])

    e1 = []
    e1.append(m2_expr.ExprAssign(addr_o, addr_m))
    e1.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e1 = IRBlock(ir.loc_db, loc_df_1, [AssignBlock(e1, instr)])

    e = []
    if instr.mode == 64 and b.size == 32:
        e.append(m2_expr.ExprAssign(mRAX[instr.mode],
                                 ir.ExprMem(addr, size).zeroExtend(64)))
    else:
        e.append(m2_expr.ExprAssign(b, ir.ExprMem(addr, size)))

    e.append(m2_expr.ExprAssign(ir.IRDst,
                             m2_expr.ExprCond(df, loc_df_1_expr, loc_df_0_expr)))
    return e, [e0, e1]


def movs(ir, instr, size):
    loc_df_0, loc_df_0_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_df_1, loc_df_1_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next_expr = m2_expr.ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

    dst = mRDI[instr.mode][:instr.v_admode()]
    src = mRSI[instr.mode][:instr.v_admode()]

    e = []
    if ir.do_str_segm:
        if instr.additional_info.g2.value:
            raise NotImplementedError("add segm support")
        src_sgm = ir.gen_segm_expr(DS, src)
        dst_sgm = ir.gen_segm_expr(ES, dst)

    else:
        src_sgm = src
        dst_sgm = dst

    offset = m2_expr.ExprInt(size // 8, src.size)

    e.append(m2_expr.ExprAssign(ir.ExprMem(dst_sgm, size),
                             ir.ExprMem(src_sgm, size)))

    e0 = []
    e0.append(m2_expr.ExprAssign(src, src + offset))
    e0.append(m2_expr.ExprAssign(dst, dst + offset))
    e0.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e0 = IRBlock(ir.loc_db, loc_df_0, [AssignBlock(e0, instr)])

    e1 = []
    e1.append(m2_expr.ExprAssign(src, src - offset))
    e1.append(m2_expr.ExprAssign(dst, dst - offset))
    e1.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    e1 = IRBlock(ir.loc_db, loc_df_1, [AssignBlock(e1, instr)])

    e.append(m2_expr.ExprAssign(ir.IRDst,
                             m2_expr.ExprCond(df, loc_df_1_expr, loc_df_0_expr)))
    return e, [e0, e1]


def movsd(_, instr, dst, src):
    # 64 bits access
    if dst.is_id() and src.is_id():
        src = src[:64]
        dst = dst[:64]
    elif dst.is_mem() and src.is_id():
        dst = m2_expr.ExprMem(dst.ptr, 64)
        src = src[:64]
    else:
        src = m2_expr.ExprMem(src.ptr, 64)
        # Erase dst high bits
        src = src.zeroExtend(dst.size)
    return [m2_expr.ExprAssign(dst, src)], []


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
    for i in range(8 - popcount):
        if avoid_flt != float_list[i]:
            e.append(m2_expr.ExprAssign(float_list[i],
                                     float_list[i + popcount]))
    fill_value = m2_expr.ExprOp("sint_to_fp", m2_expr.ExprInt(0, 64))
    for i in range(8 - popcount, 8):
        e.append(m2_expr.ExprAssign(float_list[i],
                                 fill_value))
    e.append(
        m2_expr.ExprAssign(float_stack_ptr,
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

    e.append(m2_expr.ExprAssign(float_c0, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAssign(float_c1, m2_expr.ExprOp('fcom_c1', dst, src)))
    e.append(m2_expr.ExprAssign(float_c2, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAssign(float_c3, m2_expr.ExprOp('fcom_c3', dst, src)))

    e += set_float_cs_eip(instr)
    return e, []


def ftst(_, instr):
    dst = float_st0

    e = []
    src = m2_expr.ExprOp('sint_to_fp', m2_expr.ExprInt(0, 64))
    e.append(m2_expr.ExprAssign(float_c0, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAssign(float_c1, m2_expr.ExprOp('fcom_c1', dst, src)))
    e.append(m2_expr.ExprAssign(float_c2, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAssign(float_c3, m2_expr.ExprOp('fcom_c3', dst, src)))

    e += set_float_cs_eip(instr)
    return e, []


def fxam(ir, instr):
    """
    NaN:
        C3, C2, C0 = 001;
    Normal:
        C3, C2, C0 = 010;
    Infinity:
        C3, C2, C0 = 011;
    Zero:
        C3, C2, C0 = 100;
    Empty:
        C3, C2, C0 = 101;
    Denormal:
        C3, C2, C0 = 110;

    C1 = sign bit of ST; (* 0 for positive, 1 for negative *)
    """
    dst = float_st0

    # Empty not handled
    locs = {}
    for name in ["NaN", "Normal", "Infinity", "Zero", "Denormal"]:
        locs[name] = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = m2_expr.ExprLoc(loc_next, ir.IRDst.size)

    # if Denormal:
    #     if zero:
    #         do_zero
    #     else:
    #         do_denormal
    # else:
    #     if Nan:
    #         do_nan
    #     else:
    #         if infinity:
    #             do_infinity
    #         else:
    #             do_normal

    irdst = m2_expr.ExprCond(
        m2_expr.expr_is_IEEE754_denormal(dst),
        m2_expr.ExprCond(m2_expr.expr_is_IEEE754_zero(dst),
                 locs["Zero"][1],
                 locs["Denormal"][1],
        ),
        m2_expr.ExprCond(m2_expr.expr_is_NaN(dst),
                 locs["NaN"][1],
                 m2_expr.ExprCond(m2_expr.expr_is_infinite(dst),
                          locs["Infinity"][1],
                          locs["Normal"][1],
                 )
        )
    )
    base = [m2_expr.ExprAssign(ir.IRDst, irdst),
         m2_expr.ExprAssign(float_c1, dst.msb())
    ]
    base += set_float_cs_eip(instr)

    out = [
        IRBlock(ir.loc_db, locs["Zero"][0], [AssignBlock({
            float_c0: m2_expr.ExprInt(0, float_c0.size),
            float_c2: m2_expr.ExprInt(0, float_c2.size),
            float_c3: m2_expr.ExprInt(1, float_c3.size),
            ir.IRDst: loc_next_expr,
        }, instr)]),
        IRBlock(ir.loc_db, locs["Denormal"][0], [AssignBlock({
            float_c0: m2_expr.ExprInt(0, float_c0.size),
            float_c2: m2_expr.ExprInt(1, float_c2.size),
            float_c3: m2_expr.ExprInt(1, float_c3.size),
            ir.IRDst: loc_next_expr,
        }, instr)]),
        IRBlock(ir.loc_db, locs["NaN"][0], [AssignBlock({
            float_c0: m2_expr.ExprInt(1, float_c0.size),
            float_c2: m2_expr.ExprInt(0, float_c2.size),
            float_c3: m2_expr.ExprInt(0, float_c3.size),
            ir.IRDst: loc_next_expr,
        }, instr)]),
        IRBlock(ir.loc_db, locs["Infinity"][0], [AssignBlock({
            float_c0: m2_expr.ExprInt(1, float_c0.size),
            float_c2: m2_expr.ExprInt(1, float_c2.size),
            float_c3: m2_expr.ExprInt(0, float_c3.size),
            ir.IRDst: loc_next_expr,
        }, instr)]),
        IRBlock(ir.loc_db, locs["Normal"][0], [AssignBlock({
            float_c0: m2_expr.ExprInt(0, float_c0.size),
            float_c2: m2_expr.ExprInt(1, float_c2.size),
            float_c3: m2_expr.ExprInt(0, float_c3.size),
            ir.IRDst: loc_next_expr,
        }, instr)]),
    ]
    return base, out


def ficom(_, instr, dst, src=None):

    dst, src = float_implicit_st0(dst, src)

    e = []

    e.append(m2_expr.ExprAssign(float_c0,
                             m2_expr.ExprOp('fcom_c0', dst,
                                            src.zeroExtend(dst.size))))
    e.append(m2_expr.ExprAssign(float_c1,
                             m2_expr.ExprOp('fcom_c1', dst,
                                            src.zeroExtend(dst.size))))
    e.append(m2_expr.ExprAssign(float_c2,
                             m2_expr.ExprOp('fcom_c2', dst,
                                            src.zeroExtend(dst.size))))
    e.append(m2_expr.ExprAssign(float_c3,
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

    e.append(m2_expr.ExprAssign(cf, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAssign(pf, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAssign(zf, m2_expr.ExprOp('fcom_c3', dst, src)))

    e.append(m2_expr.ExprAssign(of, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(nf, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(af, m2_expr.ExprInt(0, 1)))

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

    dst = m2_expr.ExprOp('sint_to_fp', dst[:32])
    src = m2_expr.ExprOp('sint_to_fp', src[:32])

    e.append(m2_expr.ExprAssign(cf, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAssign(pf, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAssign(zf, m2_expr.ExprOp('fcom_c3', dst, src)))

    e.append(m2_expr.ExprAssign(of, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(nf, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(af, m2_expr.ExprInt(0, 1)))

    e += set_float_cs_eip(instr)
    return e, []


def comisd(_, instr, dst, src):
    # TODO unordered float

    e = []

    dst = m2_expr.ExprOp('sint_to_fp', dst[:64])
    src = m2_expr.ExprOp('sint_to_fp', src[:64])

    e.append(m2_expr.ExprAssign(cf, m2_expr.ExprOp('fcom_c0', dst, src)))
    e.append(m2_expr.ExprAssign(pf, m2_expr.ExprOp('fcom_c2', dst, src)))
    e.append(m2_expr.ExprAssign(zf, m2_expr.ExprOp('fcom_c3', dst, src)))

    e.append(m2_expr.ExprAssign(of, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(nf, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(af, m2_expr.ExprInt(0, 1)))

    e += set_float_cs_eip(instr)
    return e, []


def fld(_, instr, src):

    if src.size == 32:
        src = m2_expr.ExprOp("fpconvert_fp64", src)
    if isinstance(src, m2_expr.ExprMem) and src.size > 64:
        raise NotImplementedError('convert from 80bits')

    e = []
    e.append(m2_expr.ExprAssign(float_st7, float_st6))
    e.append(m2_expr.ExprAssign(float_st6, float_st5))
    e.append(m2_expr.ExprAssign(float_st5, float_st4))
    e.append(m2_expr.ExprAssign(float_st4, float_st3))
    e.append(m2_expr.ExprAssign(float_st3, float_st2))
    e.append(m2_expr.ExprAssign(float_st2, float_st1))
    e.append(m2_expr.ExprAssign(float_st1, float_st0))
    e.append(m2_expr.ExprAssign(float_st0, src))
    e.append(
        m2_expr.ExprAssign(float_stack_ptr,
                        float_stack_ptr + m2_expr.ExprInt(1, 3)))

    e += set_float_cs_eip(instr)
    return e, []


def fst(_, instr, dst):
    e = []

    if isinstance(dst, m2_expr.ExprMem) and dst.size > 64:
        raise NotImplementedError('convert to 80bits')
    src = float_st0

    if dst.size == 32:
        src = m2_expr.ExprOp("fpconvert_fp32", src)
    e.append(m2_expr.ExprAssign(dst, src))
    e += set_float_cs_eip(instr)
    return e, []


def fstp(ir, instr, dst):
    e = []

    if isinstance(dst, m2_expr.ExprMem) and dst.size > 64:
        raise NotImplementedError('convert to 80bits')

    if isinstance(dst, m2_expr.ExprMem):
        src = float_st0
        if dst.size == 32:
            src = m2_expr.ExprOp("fpconvert_fp32", src)
        e.append(m2_expr.ExprAssign(dst, src))
    else:
        src = float_st0
        if float_list.index(dst) > 1:
            # a = st0 -> st0 is dropped
            # a = st1 -> st0 = st0, useless
            e.append(m2_expr.ExprAssign(float_prev(dst), src))

    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fist(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fp_to_sint%d' % dst.size,
                                                 float_st0)))

    e += set_float_cs_eip(instr)
    return e, []


def fistp(ir, instr, dst):
    e, extra = fist(ir, instr, dst)
    e += float_pop(dst)
    return e, extra


def fisttp(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAssign(
        dst,
        m2_expr.ExprOp('fp_to_sint%d' % dst.size,
                       m2_expr.ExprOp('fpround_towardszero', float_st0)
        )))

    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fild(ir, instr, src):
    # XXXXX
    src = m2_expr.ExprOp('sint_to_fp', src.signExtend(64))
    e = []
    e += set_float_cs_eip(instr)
    e_fld, extra = fld(ir, instr, src)
    e += e_fld
    return e, extra


def fldz(ir, instr):
    return fld(ir, instr, m2_expr.ExprOp('sint_to_fp', m2_expr.ExprInt(0, 64)))


def fld1(ir, instr):
    return fld(ir, instr, m2_expr.ExprOp('sint_to_fp', m2_expr.ExprInt(1, 64)))


def fldl2t(ir, instr):
    value_f = math.log(10) / math.log(2)
    value = struct.unpack('Q', struct.pack('d', value_f))[0]
    return fld(ir, instr, m2_expr.ExprOp(
        'sint_to_fp',
        m2_expr.ExprInt(value, 64)
    ))


def fldpi(ir, instr):
    value_f = math.pi
    value = struct.unpack('Q', struct.pack('d', value_f))[0]
    return fld(ir, instr, m2_expr.ExprOp(
        'sint_to_fp',
        m2_expr.ExprInt(value, 64)
    ))


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
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fadd', dst, src)))

    e += set_float_cs_eip(instr)
    return e, []


def fiadd(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fiadd', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fisub(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fisub', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fisubr(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fisub', src, dst)))
    e += set_float_cs_eip(instr)
    return e, []


def fpatan(_, instr):
    e = []
    a = float_st1
    e.append(m2_expr.ExprAssign(float_prev(a),
                             m2_expr.ExprOp('fpatan', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    e += float_pop(a)
    return e, []


def fprem(_, instr):
    e = []
    e.append(
        m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('fprem', float_st0, float_st1)))
    # Remaining bits (ex: used in argument reduction in tan)
    quotient = m2_expr.ExprOp('fp_to_sint32', m2_expr.ExprOp('fpround_towardszero', m2_expr.ExprOp('fdiv', float_st0, float_st1)))
    e += [m2_expr.ExprAssign(float_c0, quotient[2:3]),
          m2_expr.ExprAssign(float_c3, quotient[1:2]),
          m2_expr.ExprAssign(float_c1, quotient[0:1]),
          # Consider the reduction is always completed
          m2_expr.ExprAssign(float_c2, m2_expr.ExprInt(0, 1)),
          ]
    e += set_float_cs_eip(instr)
    return e, []


def fprem1(_, instr):
    e = []
    e.append(
        m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('fprem1', float_st0, float_st1)))
    e += set_float_cs_eip(instr)
    return e, []


def faddp(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(float_prev(dst), m2_expr.ExprOp('fadd', dst, src)))
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
        m2_expr.ExprAssign(float_prev(a), m2_expr.ExprOp('fyl2x', float_st0, float_st1)))
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
    ad = ir.ExprMem(dst.ptr, size=16)
    e.append(m2_expr.ExprAssign(ad, float_control))
    ad = ir.ExprMem(
        dst.ptr + m2_expr.ExprInt(
            (size // 8) * 1,
            dst.ptr.size
        ),
        size=16
    )
    e.append(m2_expr.ExprAssign(ad, status_word))
    ad = ir.ExprMem(
        dst.ptr + m2_expr.ExprInt(
            (size // 8) * 3,
            dst.ptr.size
        ),
        size=size
    )
    e.append(m2_expr.ExprAssign(ad, float_eip[:size]))
    ad = ir.ExprMem(
        dst.ptr + m2_expr.ExprInt(
            (size // 8) * 4,
            dst.ptr.size
        ),
        size=16
    )
    e.append(m2_expr.ExprAssign(ad, float_cs))
    ad = ir.ExprMem(
        dst.ptr + m2_expr.ExprInt(
            (size // 8) * 5,
            dst.ptr.size
        ),
        size=size
    )
    e.append(m2_expr.ExprAssign(ad, float_address[:size]))
    ad = ir.ExprMem(
        dst.ptr + m2_expr.ExprInt(
            (size // 8) * 6,
            dst.ptr.size
        ),
        size=16
    )
    e.append(m2_expr.ExprAssign(ad, float_ds))
    return e, []


def fldenv(ir, instr, src):
    e = []
    # Inspired from fnstenv (same TODOs / issues)

    s = instr.mode
    # The behaviour in 64bit is identical to 32 bit
    # This will truncate addresses
    size = min(32, s)

    # Float control
    ad = ir.ExprMem(src.ptr, size=16)
    e.append(m2_expr.ExprAssign(float_control, ad))

    # Status word
    ad = ir.ExprMem(
        src.ptr + m2_expr.ExprInt(
            size // (8 * 1),
            size=src.ptr.size
        ),
        size=16
    )
    e += [
        m2_expr.ExprAssign(x, y) for x, y in ((float_c0, ad[8:9]),
                                              (float_c1, ad[9:10]),
                                              (float_c2, ad[10:11]),
                                              (float_stack_ptr, ad[11:14]),
                                              (float_c3, ad[14:15]))
    ]

    # EIP, CS, Address, DS
    for offset, target in (
            (3, float_eip[:size]),
            (4, float_cs),
            (5, float_address[:size]),
            (6, float_ds)
    ):
        ad = ir.ExprMem(
            src.ptr + m2_expr.ExprInt(
                size // ( 8 * offset),
                size=src.ptr.size
            ),
            size=target.size
        )
        e.append(m2_expr.ExprAssign(target, ad))

    return e, []


def fsub(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fsub', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fsubp(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(float_prev(dst), m2_expr.ExprOp('fsub', dst, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fsubr(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fsub', src, dst)))
    e += set_float_cs_eip(instr)
    return e, []


def fsubrp(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(float_prev(dst), m2_expr.ExprOp('fsub', src, dst)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fmul(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fmul', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fimul(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fimul', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fdiv(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fdiv', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fdivr(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fdiv', src, dst)))
    e += set_float_cs_eip(instr)
    return e, []


def fdivrp(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(float_prev(dst), m2_expr.ExprOp('fdiv', src, dst)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fidiv(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fidiv', dst, src)))
    e += set_float_cs_eip(instr)
    return e, []


def fidivr(_, instr, dst, src=None):
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('fidiv', src, dst)))
    e += set_float_cs_eip(instr)
    return e, []


def fdivp(_, instr, dst, src=None):
    # Invalid emulation
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(float_prev(dst), m2_expr.ExprOp('fdiv', dst, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def fmulp(_, instr, dst, src=None):
    # Invalid emulation
    dst, src = float_implicit_st0(dst, src)
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(float_prev(dst), m2_expr.ExprOp('fmul', dst, src)))
    e += set_float_cs_eip(instr)
    e += float_pop(dst)
    return e, []


def ftan(_, instr, src):
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('ftan', src)))
    e += set_float_cs_eip(instr)
    return e, []


def fxch(_, instr, src):
    e = []
    src = mem2double(instr, src)
    e.append(m2_expr.ExprAssign(float_st0, src))
    e.append(m2_expr.ExprAssign(src, float_st0))
    e += set_float_cs_eip(instr)
    return e, []


def fptan(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st7, float_st6))
    e.append(m2_expr.ExprAssign(float_st6, float_st5))
    e.append(m2_expr.ExprAssign(float_st5, float_st4))
    e.append(m2_expr.ExprAssign(float_st4, float_st3))
    e.append(m2_expr.ExprAssign(float_st3, float_st2))
    e.append(m2_expr.ExprAssign(float_st2, float_st1))
    e.append(m2_expr.ExprAssign(float_st1, m2_expr.ExprOp('ftan', float_st0)))
    e.append(
        m2_expr.ExprAssign(
            float_st0,
            m2_expr.ExprOp(
                'sint_to_fp',
                m2_expr.ExprInt(1, 64)
            )
        )
    )
    e.append(
        m2_expr.ExprAssign(float_stack_ptr,
                        float_stack_ptr + m2_expr.ExprInt(1, 3)))
    return e, []


def frndint(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('frndint', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fsin(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('fsin', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fcos(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('fcos', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fsincos(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st7, float_st6))
    e.append(m2_expr.ExprAssign(float_st6, float_st5))
    e.append(m2_expr.ExprAssign(float_st5, float_st4))
    e.append(m2_expr.ExprAssign(float_st4, float_st3))
    e.append(m2_expr.ExprAssign(float_st3, float_st2))
    e.append(m2_expr.ExprAssign(float_st2, float_st1))
    e.append(m2_expr.ExprAssign(float_st1, m2_expr.ExprOp('fsin', float_st0)))
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('fcos', float_st0)))
    e.append(
        m2_expr.ExprAssign(float_stack_ptr,
                        float_stack_ptr + m2_expr.ExprInt(1, 3)))
    return e, []


def fscale(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('fscale', float_st0,
                                                       float_st1)))
    e += set_float_cs_eip(instr)
    return e, []


def f2xm1(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('f2xm1', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fchs(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('fchs', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fsqrt(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('fsqrt', float_st0)))
    e += set_float_cs_eip(instr)
    return e, []


def fabs(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(float_st0, m2_expr.ExprOp('fabs', float_st0)))
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
    e = [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*args))]
    return e, []


def fnstcw(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAssign(dst, float_control))
    return e, []


def fldcw(_, instr, src):
    e = []
    e.append(m2_expr.ExprAssign(float_control, src))
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


def prefetch0(_, instr, src=None):
    # see 4-198 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []


def prefetch1(_, instr, src=None):
    # see 4-198 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []


def prefetch2(_, instr, src=None):
    # see 4-198 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []


def prefetchw(_, instr, src=None):
    # see 4-201 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []

def prefetchnta(_, instr, src=None):
    # see 4-201 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []


def lfence(_, instr, src=None):
    # see 3-485 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []


def mfence(_, instr, src=None):
    # see 3-516 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []


def sfence(_, instr, src=None):
    # see 3-356 on this documentation
    # https://www-ssl.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
    return [], []


def ud2(_, instr, src=None):
    e = [m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(
        EXCEPT_ILLEGAL_INSN, exception_flags.size))]
    return e, []


def hlt(_, instr):
    e = []
    except_int = EXCEPT_PRIV_INSN
    e.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(except_int, 32)))
    return e, []


def rdtsc(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(tsc, tsc + m2_expr.ExprInt(1, 64)))
    e.append(m2_expr.ExprAssign(mRAX[32], tsc[:32]))
    e.append(m2_expr.ExprAssign(mRDX[32], tsc[32:]))
    return e, []


def daa(_, instr):
    e = []
    r_al = mRAX[instr.mode][:8]

    cond1 = m2_expr.expr_is_unsigned_greater(r_al[:4], m2_expr.ExprInt(0x9, 4)) | af
    e.append(m2_expr.ExprAssign(af, cond1))

    cond2 = m2_expr.expr_is_unsigned_greater(m2_expr.ExprInt(6, 8), r_al)
    cond3 = m2_expr.expr_is_unsigned_greater(r_al, m2_expr.ExprInt(0x99, 8)) | cf

    cf_c1 = m2_expr.ExprCond(cond1,
                             cf | (cond2),
                             m2_expr.ExprInt(0, 1))
    new_cf = m2_expr.ExprCond(cond3,
                              m2_expr.ExprInt(1, 1),
                              m2_expr.ExprInt(0, 1))
    e.append(m2_expr.ExprAssign(cf, new_cf))

    al_c1 = m2_expr.ExprCond(cond1,
                             r_al + m2_expr.ExprInt(6, 8),
                             r_al)

    new_al = m2_expr.ExprCond(cond3,
                              al_c1 + m2_expr.ExprInt(0x60, 8),
                              al_c1)
    e.append(m2_expr.ExprAssign(r_al, new_al))
    e += update_flag_znp(new_al)
    return e, []


def das(_, instr):
    e = []
    r_al = mRAX[instr.mode][:8]

    cond1 = m2_expr.expr_is_unsigned_greater(r_al[:4], m2_expr.ExprInt(0x9, 4)) | af
    e.append(m2_expr.ExprAssign(af, cond1))

    cond2 = m2_expr.expr_is_unsigned_greater(m2_expr.ExprInt(6, 8), r_al)
    cond3 = m2_expr.expr_is_unsigned_greater(r_al, m2_expr.ExprInt(0x99, 8)) | cf

    cf_c1 = m2_expr.ExprCond(cond1,
                             cf | (cond2),
                             m2_expr.ExprInt(0, 1))
    new_cf = m2_expr.ExprCond(cond3,
                              m2_expr.ExprInt(1, 1),
                              cf_c1)
    e.append(m2_expr.ExprAssign(cf, new_cf))

    al_c1 = m2_expr.ExprCond(cond1,
                             r_al - m2_expr.ExprInt(6, 8),
                             r_al)

    new_al = m2_expr.ExprCond(cond3,
                              al_c1 - m2_expr.ExprInt(0x60, 8),
                              al_c1)
    e.append(m2_expr.ExprAssign(r_al, new_al))
    e += update_flag_znp(new_al)
    return e, []


def aam(ir, instr, src):
    e = []
    assert src.is_int()

    value = int(src)
    if value:
        tempAL = mRAX[instr.mode][0:8]
        newEAX = m2_expr.ExprCompose(
            m2_expr.ExprOp("umod", tempAL, src),
            m2_expr.ExprOp("udiv", tempAL, src),
            mRAX[instr.mode][16:]
        )
        e += [m2_expr.ExprAssign(mRAX[instr.mode], newEAX)]
        e += update_flag_arith(newEAX)
        e.append(m2_expr.ExprAssign(af, m2_expr.ExprInt(0, 1)))
    else:
        e.append(
            m2_expr.ExprAssign(
                exception_flags,
                m2_expr.ExprInt(EXCEPT_DIV_BY_ZERO, exception_flags.size)
            )
        )
    return e, []


def aad(_, instr, src):
    e = []
    tempAL = mRAX[instr.mode][0:8]
    tempAH = mRAX[instr.mode][8:16]
    newEAX = m2_expr.ExprCompose((tempAL + (tempAH * src)) & m2_expr.ExprInt(0xFF, 8),
                                 m2_expr.ExprInt(0, 8),
                                 mRAX[instr.mode][16:])
    e += [m2_expr.ExprAssign(mRAX[instr.mode], newEAX)]
    e += update_flag_arith(newEAX)
    e.append(m2_expr.ExprAssign(af, m2_expr.ExprInt(0, 1)))
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
    e.append(m2_expr.ExprAssign(r_ax, m2_expr.ExprCond(cond, new_ax, r_ax)))
    e.append(m2_expr.ExprAssign(af, cond))
    e.append(m2_expr.ExprAssign(cf, cond))
    return e, []


def aaa(ir, instr):
    return _tpl_aaa(ir, instr, "+")


def aas(ir, instr):
    return _tpl_aaa(ir, instr, "-")


def bsr_bsf(ir, instr, dst, src, op_func):
    """
    IF SRC == 0
        ZF = 1
        DEST is left unchanged
    ELSE
        ZF = 0
        DEST = @op_func(SRC)
    """
    loc_src_null, loc_src_null_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_src_not_null, loc_src_not_null_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = m2_expr.ExprLoc(loc_next, ir.IRDst.size)

    aff_dst = m2_expr.ExprAssign(ir.IRDst, loc_next_expr)
    e = [m2_expr.ExprAssign(ir.IRDst, m2_expr.ExprCond(src,
                                                    loc_src_not_null_expr,
                                                    loc_src_null_expr))]
    e_src_null = []
    e_src_null.append(m2_expr.ExprAssign(zf, m2_expr.ExprInt(1, zf.size)))
    # XXX destination is undefined
    e_src_null.append(aff_dst)

    e_src_not_null = []
    e_src_not_null.append(m2_expr.ExprAssign(zf, m2_expr.ExprInt(0, zf.size)))
    e_src_not_null.append(m2_expr.ExprAssign(dst, op_func(src)))
    e_src_not_null.append(aff_dst)

    return e, [IRBlock(ir.loc_db, loc_src_null, [AssignBlock(e_src_null, instr)]),
               IRBlock(ir.loc_db, loc_src_not_null, [AssignBlock(e_src_not_null, instr)])]


def bsf(ir, instr, dst, src):
    return bsr_bsf(ir, instr, dst, src,
                   lambda src: m2_expr.ExprOp("cnttrailzeros", src))


def bsr(ir, instr, dst, src):
    return bsr_bsf(
        ir, instr, dst, src,
        lambda src: m2_expr.ExprInt(src.size - 1, src.size) - m2_expr.ExprOp("cntleadzeros", src)
    )


def arpl(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(1 << 7, 32)))
    return e, []


def ins(_, instr, size):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(1 << 7, 32)))
    return e, []


def sidt(ir, instr, dst):
    e = []
    if not isinstance(dst, m2_expr.ExprMem) or dst.size != 32:
        raise ValueError('not exprmem 32bit instance!!')
    ptr = dst.ptr
    LOG_X86_SEM.warning("DEFAULT SIDT ADDRESS %s!!", dst)
    e.append(m2_expr.ExprAssign(ir.ExprMem(ptr, 32),
                             m2_expr.ExprInt(0xe40007ff, 32)))
    e.append(
        m2_expr.ExprAssign(ir.ExprMem(ptr + m2_expr.ExprInt(4, ptr.size), 16),
                        m2_expr.ExprInt(0x8245, 16)))
    return e, []


def sldt(_, instr, dst):
    LOG_X86_SEM.warning("DEFAULT SLDT ADDRESS %s!!", dst)
    e = [m2_expr.ExprAssign(dst, m2_expr.ExprInt(0, dst.size))]
    return e, []


def cmovz(ir, instr, dst, src):
    #return gen_cmov(ir, instr, zf, dst, src, True)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_EQ", zf), dst, src, True)


def cmovnz(ir, instr, dst, src):
    #return gen_cmov(ir, instr, zf, dst, src, False)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_EQ", zf), dst, src, False)


def cmovpe(ir, instr, dst, src):
    return gen_cmov(ir, instr, pf, dst, src, True)


def cmovnp(ir, instr, dst, src):
    return gen_cmov(ir, instr, pf, dst, src, False)


def cmovge(ir, instr, dst, src):
    #return gen_cmov(ir, instr, nf ^ of, dst, src, False)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_S>=", nf, of), dst, src, True)


def cmovg(ir, instr, dst, src):
    #return gen_cmov(ir, instr, zf | (nf ^ of), dst, src, False)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_S>", nf, of, zf), dst, src, True)


def cmovl(ir, instr, dst, src):
    #return gen_cmov(ir, instr, nf ^ of, dst, src, True)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_S<", nf, of), dst, src, True)


def cmovle(ir, instr, dst, src):
    #return gen_cmov(ir, instr, zf | (nf ^ of), dst, src, True)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_S<=", nf, of, zf), dst, src, True)


def cmova(ir, instr, dst, src):
    #return gen_cmov(ir, instr, cf | zf, dst, src, False)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_U>", cf, zf), dst, src, True)


def cmovae(ir, instr, dst, src):
    #return gen_cmov(ir, instr, cf, dst, src, False)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_U>=", cf), dst, src, True)


def cmovbe(ir, instr, dst, src):
    #return gen_cmov(ir, instr, cf | zf, dst, src, True)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_U<=", cf, zf), dst, src, True)


def cmovb(ir, instr, dst, src):
    #return gen_cmov(ir, instr, cf, dst, src, True)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_U<", cf), dst, src, True)


def cmovo(ir, instr, dst, src):
    return gen_cmov(ir, instr, of, dst, src, True)


def cmovno(ir, instr, dst, src):
    return gen_cmov(ir, instr, of, dst, src, False)


def cmovs(ir, instr, dst, src):
    #return gen_cmov(ir, instr, nf, dst, src, True)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_NEG", nf), dst, src, True)


def cmovns(ir, instr, dst, src):
    #return gen_cmov(ir, instr, nf, dst, src, False)
    return gen_cmov(ir, instr, m2_expr.ExprOp("CC_NEG", nf), dst, src, False)


def icebp(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags,
                             m2_expr.ExprInt(EXCEPT_SOFT_BP, 32)))
    return e, []
# XXX


def l_int(_, instr, src):
    e = []
    # XXX
    assert src.is_int()
    value = int(src)
    if value == 1:
        except_int = EXCEPT_INT_1
    elif value == 3:
        except_int = EXCEPT_SOFT_BP
    else:
        except_int = EXCEPT_INT_XX
    e.append(m2_expr.ExprAssign(exception_flags,
                             m2_expr.ExprInt(except_int, 32)))
    e.append(m2_expr.ExprAssign(interrupt_num, src))
    return e, []


def l_sysenter(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags,
                             m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32)))
    return e, []


def l_syscall(_, instr):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags,
                             m2_expr.ExprInt(EXCEPT_SYSCALL, 32)))
    return e, []

# XXX


def l_out(_, instr, src1, src2):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags,
                             m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32)))
    return e, []

# XXX


def l_outs(_, instr, size):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags,
                             m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32)))
    return e, []

# XXX actually, xlat performs al = (ds:[e]bx + ZeroExtend(al))


def xlat(ir, instr):
    e = []
    ptr = mRAX[instr.mode][0:8].zeroExtend(mRBX[instr.mode].size)
    src = ir.ExprMem(mRBX[instr.mode] + ptr, 8)
    e.append(m2_expr.ExprAssign(mRAX[instr.mode][0:8], src))
    return e, []


def cpuid(_, instr):
    e = []
    e.append(
        m2_expr.ExprAssign(mRAX[instr.mode],
                        m2_expr.ExprOp('x86_cpuid', mRAX[instr.mode], m2_expr.ExprInt(0, instr.mode))))
    e.append(
        m2_expr.ExprAssign(mRBX[instr.mode],
                        m2_expr.ExprOp('x86_cpuid', mRAX[instr.mode], m2_expr.ExprInt(1, instr.mode))))
    e.append(
        m2_expr.ExprAssign(mRCX[instr.mode],
                        m2_expr.ExprOp('x86_cpuid', mRAX[instr.mode], m2_expr.ExprInt(2, instr.mode))))
    e.append(
        m2_expr.ExprAssign(mRDX[instr.mode],
                        m2_expr.ExprOp('x86_cpuid', mRAX[instr.mode], m2_expr.ExprInt(3, instr.mode))))
    return e, []


def bittest_get(ir, instr, src, index):
    index = index.zeroExtend(src.size)
    if isinstance(src, m2_expr.ExprMem):
        b_mask = {16: 4, 32: 5, 64: 6}
        b_decal = {16: 1, 32: 3, 64: 7}
        ptr = src.ptr
        segm = is_mem_segm(src)
        if segm:
            ptr = ptr.args[1]

        off_bit = index.zeroExtend(
            src.size) & m2_expr.ExprInt((1 << b_mask[src.size]) - 1,
                                        src.size)
        off_byte = ((index.zeroExtend(ptr.size) >> m2_expr.ExprInt(3, ptr.size)) &
                    m2_expr.ExprInt(((1 << src.size) - 1) ^ b_decal[src.size], ptr.size))

        addr = ptr + off_byte
        if segm:
            addr = ir.gen_segm_expr(src.ptr.args[0], addr)

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
    e.append(m2_expr.ExprAssign(cf, d[:1]))
    return e, []


def btc(ir, instr, src, index):
    e = []
    d, off_bit = bittest_get(ir, instr, src, index)
    e.append(m2_expr.ExprAssign(cf, (d >> off_bit)[:1]))

    m = m2_expr.ExprInt(1, src.size) << off_bit
    e.append(m2_expr.ExprAssign(d, d ^ m))

    return e, []


def bts(ir, instr, src, index):
    e = []
    d, off_bit = bittest_get(ir, instr, src, index)
    e.append(m2_expr.ExprAssign(cf, (d >> off_bit)[:1]))
    m = m2_expr.ExprInt(1, src.size) << off_bit
    e.append(m2_expr.ExprAssign(d, d | m))

    return e, []


def btr(ir, instr, src, index):
    e = []
    d, off_bit = bittest_get(ir, instr, src, index)
    e.append(m2_expr.ExprAssign(cf, (d >> off_bit)[:1]))
    m = ~(m2_expr.ExprInt(1, src.size) << off_bit)
    e.append(m2_expr.ExprAssign(d, d & m))

    return e, []


def into(_, instr):
    return [], []


def l_in(_, instr, src1, src2):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags,
                             m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32)))
    return e, []


@sbuild.parse
def cmpxchg(arg1, arg2):
    accumulator = mRAX[instr.v_opmode()][:arg1.size]
    if (accumulator - arg1):
        zf = i1(0)
        accumulator = arg1
    else:
        zf = i1(1)
        arg1 = arg2


@sbuild.parse
def cmpxchg8b(arg1):
    accumulator = {mRAX[32], mRDX[32]}
    if accumulator - arg1:
        zf = i1(0)
        mRAX[32] = arg1[:32]
        mRDX[32] = arg1[32:]
    else:
        zf = i1(1)
        arg1 = {mRBX[32], mRCX[32]}


@sbuild.parse
def cmpxchg16b(arg1):
    accumulator = {mRAX[64], mRDX[64]}
    if accumulator - arg1:
        zf = i1(0)
        mRAX[64] = arg1[:64]
        mRDX[64] = arg1[64:]
    else:
        zf = i1(1)
        arg1 = {mRBX[64], mRCX[64]}


def lds(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, ir.ExprMem(src.ptr, size=dst.size)))
    DS_value = ir.ExprMem(src.ptr + m2_expr.ExprInt(dst.size // 8, src.ptr.size),
                          size=16)
    e.append(m2_expr.ExprAssign(DS, DS_value))
    return e, []


def les(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, ir.ExprMem(src.ptr, size=dst.size)))
    ES_value = ir.ExprMem(src.ptr + m2_expr.ExprInt(dst.size // 8, src.ptr.size),
                          size=16)
    e.append(m2_expr.ExprAssign(ES, ES_value))
    return e, []


def lss(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, ir.ExprMem(src.ptr, size=dst.size)))
    SS_value = ir.ExprMem(src.ptr + m2_expr.ExprInt(dst.size // 8, src.ptr.size),
                          size=16)
    e.append(m2_expr.ExprAssign(SS, SS_value))
    return e, []


def lfs(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, ir.ExprMem(src.ptr, size=dst.size)))
    FS_value = ir.ExprMem(src.ptr + m2_expr.ExprInt(dst.size // 8, src.ptr.size),
                          size=16)
    e.append(m2_expr.ExprAssign(FS, FS_value))
    return e, []


def lgs(ir, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, ir.ExprMem(src.ptr, size=dst.size)))
    GS_value = ir.ExprMem(src.ptr + m2_expr.ExprInt(dst.size // 8, src.ptr.size),
                          size=16)
    e.append(m2_expr.ExprAssign(GS, GS_value))
    return e, []


def lahf(_, instr):
    e = []
    args = [cf, m2_expr.ExprInt(1, 1), pf, m2_expr.ExprInt(0, 1), af,
            m2_expr.ExprInt(0, 1), zf, nf]
    e.append(
        m2_expr.ExprAssign(mRAX[instr.mode][8:16], m2_expr.ExprCompose(*args)))
    return e, []


def sahf(_, instr):
    tmp = mRAX[instr.mode][8:16]
    e = []
    e.append(m2_expr.ExprAssign(cf, tmp[0:1]))
    e.append(m2_expr.ExprAssign(pf, tmp[2:3]))
    e.append(m2_expr.ExprAssign(af, tmp[4:5]))
    e.append(m2_expr.ExprAssign(zf, tmp[6:7]))
    e.append(m2_expr.ExprAssign(nf, tmp[7:8]))
    return e, []


def lar(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('access_segment', src)))
    e.append(m2_expr.ExprAssign(zf, m2_expr.ExprOp('access_segment_ok', src)))
    return e, []


def lsl(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('load_segment_limit', src)))
    e.append(m2_expr.ExprAssign(zf, m2_expr.ExprOp('load_segment_limit_ok', src)))
    return e, []


def fclex(_, instr):
    # XXX TODO
    return [], []


def fnclex(_, instr):
    # XXX TODO
    return [], []


def l_str(_, instr, dst):
    e = []
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('load_tr_segment_selector',
                                                 m2_expr.ExprInt(0, 32))))
    return e, []


def movd(_, instr, dst, src):
    e = []
    if dst in regs_mm_expr:
        e.append(m2_expr.ExprAssign(
            dst, m2_expr.ExprCompose(src, m2_expr.ExprInt(0, 32))))
    elif dst in regs_xmm_expr:
        e.append(m2_expr.ExprAssign(
            dst, m2_expr.ExprCompose(src, m2_expr.ExprInt(0, 96))))
    else:
        e.append(m2_expr.ExprAssign(dst, src[:32]))
    return e, []


def movdqu(_, instr, dst, src):
    # XXX TODO alignment check
    return [m2_expr.ExprAssign(dst, src)], []


def movapd(_, instr, dst, src):
    # XXX TODO alignment check
    return [m2_expr.ExprAssign(dst, src)], []


def andps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('&', dst, src)))
    return e, []


def andnps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('&', dst ^ dst.mask, src)))
    return e, []


def orps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('|', dst, src)))
    return e, []


def xorps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprOp('^', dst, src)))
    return e, []


def rdmsr(ir, instr):
    e = [m2_expr.ExprAssign(exception_flags,m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32))]
    return e, []


def wrmsr(ir, instr):
    e = [m2_expr.ExprAssign(exception_flags,m2_expr.ExprInt(EXCEPT_PRIV_INSN, 32))]
    return e, []

# MMX/SSE/AVX operations
#

def vec_op_clip(op, size, callback=None):
    """
    Generate simd operations
    @op: the operator
    @size: size of an element
    """
    def vec_op_clip_instr(ir, instr, dst, src):
        if op == '-':
            result = dst[:size] - src[:size]
        else:
            result = m2_expr.ExprOp(op, dst[:size], src[:size])
        if callback is not None:
            result = callback(result)
        return [m2_expr.ExprAssign(dst[:size], result)], []
    return vec_op_clip_instr

# Generic vertical operation


def vec_vertical_sem(op, elt_size, reg_size, dst, src, apply_on_output):
    assert reg_size % elt_size == 0
    n = reg_size // elt_size
    if op == '-':
        ops = [
            apply_on_output((dst[i * elt_size:(i + 1) * elt_size]
                             - src[i * elt_size:(i + 1) * elt_size]))
            for i in range(0, n)
        ]
    else:
        ops = [
            apply_on_output(m2_expr.ExprOp(op, dst[i * elt_size:(i + 1) * elt_size],
                                           src[i * elt_size:(i + 1) * elt_size]))
            for i in range(0, n)
        ]

    return m2_expr.ExprCompose(*ops)


def __vec_vertical_instr_gen(op, elt_size, sem, apply_on_output):
    def vec_instr(ir, instr, dst, src):
        e = []
        if isinstance(src, m2_expr.ExprMem):
            src = ir.ExprMem(src.ptr, dst.size)
        reg_size = dst.size
        e.append(m2_expr.ExprAssign(dst, sem(op, elt_size, reg_size, dst, src,
                                          apply_on_output)))
        return e, []
    return vec_instr


def vec_vertical_instr(op, elt_size, apply_on_output=lambda x: x):
    return __vec_vertical_instr_gen(op, elt_size, vec_vertical_sem,
                                    apply_on_output)


def _keep_mul_high(expr, signed=False):
    assert expr.is_op("*") and len(expr.args) == 2

    if signed:
        arg1 = expr.args[0].signExtend(expr.size * 2)
        arg2 = expr.args[1].signExtend(expr.size * 2)
    else:
        arg1 = expr.args[0].zeroExtend(expr.size * 2)
        arg2 = expr.args[1].zeroExtend(expr.size * 2)
    return m2_expr.ExprOp("*", arg1, arg2)[expr.size:]

# Op, signed => associated comparison
_min_max_func = {
    ("min", False): m2_expr.expr_is_unsigned_lower,
    ("min", True): m2_expr.expr_is_signed_lower,
    ("max", False): m2_expr.expr_is_unsigned_greater,
    ("max", True): m2_expr.expr_is_signed_greater,
}
def _min_max(expr, signed):
    assert (expr.is_op("min") or expr.is_op("max")) and len(expr.args) == 2
    return m2_expr.ExprCond(
        _min_max_func[(expr.op, signed)](expr.args[1], expr.args[0]),
        expr.args[1],
        expr.args[0],
    )

def _float_min_max(expr):
    assert (expr.is_op("fmin") or expr.is_op("fmax")) and len(expr.args) == 2
    src1 = expr.args[0]
    src2 = expr.args[1]
    if expr.is_op("fmin"):
        comp = m2_expr.expr_is_float_lower(src1, src2)
    elif expr.is_op("fmax"):
        comp = m2_expr.expr_is_float_lower(src2, src1)

    # x86 documentation (for MIN):
    # IF ((SRC1 = 0.0) and (SRC2 = 0.0)) THEN DEST <-SRC2;
    # ELSE IF (SRC1 = SNaN) THEN DEST <-SRC2; FI;
    # ELSE IF (SRC2 = SNaN) THEN DEST <-SRC2; FI;
    # ELSE IF (SRC1 < SRC2) THEN DEST <-SRC1;
    # ELSE DEST<-SRC2;
    #
    # But this includes the NaN output of "SRC1 < SRC2"
    # Associated text is more detailed, and this is the version impl here
    return m2_expr.ExprCond(
        m2_expr.expr_is_sNaN(src2), src2,
        m2_expr.ExprCond(
            m2_expr.expr_is_NaN(src2) | m2_expr.expr_is_NaN(src1), src2,
            m2_expr.ExprCond(comp, src1, src2)
        )
    )


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

# Multiplications
#

# SSE
pmullb = vec_vertical_instr('*', 8)
pmullw = vec_vertical_instr('*', 16)
pmulld = vec_vertical_instr('*', 32)
pmullq = vec_vertical_instr('*', 64)
pmulhub = vec_vertical_instr('*', 8, _keep_mul_high)
pmulhuw = vec_vertical_instr('*', 16, _keep_mul_high)
pmulhud = vec_vertical_instr('*', 32, _keep_mul_high)
pmulhuq = vec_vertical_instr('*', 64, _keep_mul_high)
pmulhb = vec_vertical_instr('*', 8, lambda x: _keep_mul_high(x, signed=True))
pmulhw = vec_vertical_instr('*', 16, lambda x: _keep_mul_high(x, signed=True))
pmulhd = vec_vertical_instr('*', 32, lambda x: _keep_mul_high(x, signed=True))
pmulhq = vec_vertical_instr('*', 64, lambda x: _keep_mul_high(x, signed=True))

def pmuludq(ir, instr, dst, src):
    e = []
    if dst.size == 64:
        e.append(m2_expr.ExprAssign(
            dst,
            src[:32].zeroExtend(64) * dst[:32].zeroExtend(64)
        ))
    elif dst.size == 128:
        e.append(m2_expr.ExprAssign(
            dst[:64],
            src[:32].zeroExtend(64) * dst[:32].zeroExtend(64)
        ))
        e.append(m2_expr.ExprAssign(
            dst[64:],
            src[64:96].zeroExtend(64) * dst[64:96].zeroExtend(64)
        ))
    else:
        raise RuntimeError("Unsupported size %d" % dst.size)
    return e, []

# Mix
#

# SSE
def pmaddwd(ir, instr, dst, src):
    sizedst = 32
    sizesrc = 16
    out = []
    for start in range(0, dst.size, sizedst):
        base = start
        mul1 = src[base: base + sizesrc].signExtend(sizedst) * dst[base: base + sizesrc].signExtend(sizedst)
        base += sizesrc
        mul2 = src[base: base + sizesrc].signExtend(sizedst) * dst[base: base + sizesrc].signExtend(sizedst)
        out.append(mul1 + mul2)
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []


def _absolute(expr):
    """Return abs(@expr)"""
    signed = expr.msb()
    value_unsigned = (expr ^ expr.mask) + m2_expr.ExprInt(1, expr.size)
    return m2_expr.ExprCond(signed, value_unsigned, expr)


def psadbw(ir, instr, dst, src):
    sizedst = 16
    sizesrc = 8
    out_dst = []
    for start in range(0, dst.size, 64):
        out = []
        for src_start in range(0, 64, sizesrc):
            beg = start + src_start
            end = beg + sizesrc
            # Not clear in the doc equations, but in the text, src and dst are:
            # "8 unsigned byte integers"
            out.append(_absolute(dst[beg: end].zeroExtend(sizedst) - src[beg: end].zeroExtend(sizedst)))
        out_dst.append(m2_expr.ExprOp("+", *out))
        out_dst.append(m2_expr.ExprInt(0, 64 - sizedst))

    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out_dst))], []

def _average(expr):
    assert expr.is_op("avg") and len(expr.args) == 2

    arg1 = expr.args[0].zeroExtend(expr.size * 2)
    arg2 = expr.args[1].zeroExtend(expr.size * 2)
    one = m2_expr.ExprInt(1, arg1.size)
    # avg(unsigned) = (a + b + 1) >> 1, addition being at least on one more bit
    return ((arg1 + arg2 + one) >> one)[:expr.size]

pavgb = vec_vertical_instr('avg', 8, _average)
pavgw = vec_vertical_instr('avg', 16, _average)

# Comparisons
#

# SSE
pminsw = vec_vertical_instr('min', 16, lambda x: _min_max(x, signed=True))
pminub = vec_vertical_instr('min', 8, lambda x: _min_max(x, signed=False))
pminuw = vec_vertical_instr('min', 16, lambda x: _min_max(x, signed=False))
pminud = vec_vertical_instr('min', 32, lambda x: _min_max(x, signed=False))
pmaxub = vec_vertical_instr('max', 8, lambda x: _min_max(x, signed=False))
pmaxuw = vec_vertical_instr('max', 16, lambda x: _min_max(x, signed=False))
pmaxud = vec_vertical_instr('max', 32, lambda x: _min_max(x, signed=False))
pmaxsw = vec_vertical_instr('max', 16, lambda x: _min_max(x, signed=True))

# Floating-point arithmetic
#

# SSE
addss = vec_op_clip('fadd', 32)
addsd = vec_op_clip('fadd', 64)
addps = vec_vertical_instr('fadd', 32)
addpd = vec_vertical_instr('fadd', 64)
subss = vec_op_clip('fsub', 32)
subsd = vec_op_clip('fsub', 64)
subps = vec_vertical_instr('fsub', 32)
subpd = vec_vertical_instr('fsub', 64)
mulss = vec_op_clip('fmul', 32)
mulsd = vec_op_clip('fmul', 64)
mulps = vec_vertical_instr('fmul', 32)
mulpd = vec_vertical_instr('fmul', 64)
divss = vec_op_clip('fdiv', 32)
divsd = vec_op_clip('fdiv', 64)
divps = vec_vertical_instr('fdiv', 32)
divpd = vec_vertical_instr('fdiv', 64)

# Comparisons (floating-point)

minps = vec_vertical_instr('fmin', 32, _float_min_max)
minpd = vec_vertical_instr('fmin', 64, _float_min_max)
minss = vec_op_clip('fmin', 32, _float_min_max)
minsd = vec_op_clip('fmin', 64, _float_min_max)
maxps = vec_vertical_instr('fmax', 32, _float_min_max)
maxpd = vec_vertical_instr('fmax', 64, _float_min_max)
maxss = vec_op_clip('fmax', 32, _float_min_max)
maxsd = vec_op_clip('fmax', 64, _float_min_max)

def _float_compare_to_mask(expr):
    if expr.op == 'unord':
        to_ext = m2_expr.expr_is_NaN(expr.args[0]) | m2_expr.expr_is_NaN(expr.args[1])
    elif expr.op == 'ord':
        to_ext = ~m2_expr.expr_is_NaN(expr.args[0]) & ~m2_expr.expr_is_NaN(expr.args[1])
    else:
        if expr.op == '==fu':
            to_ext = m2_expr.expr_is_float_equal(expr.args[0], expr.args[1])
            on_NaN = m2_expr.ExprInt(0, 1)
        elif expr.op == '<fu':
            to_ext = m2_expr.expr_is_float_lower(expr.args[0], expr.args[1])
            on_NaN = m2_expr.ExprInt(0, 1)
        elif expr.op == '<=fu':
            to_ext = (m2_expr.expr_is_float_equal(expr.args[0], expr.args[1]) |
                      m2_expr.expr_is_float_lower(expr.args[0], expr.args[1]))
            on_NaN = m2_expr.ExprInt(0, 1)
        elif expr.op == '!=fu':
            to_ext = ~m2_expr.expr_is_float_equal(expr.args[0], expr.args[1])
            on_NaN = m2_expr.ExprInt(1, 1)
        elif expr.op == '!<fu':
            to_ext = ~m2_expr.expr_is_float_lower(expr.args[0], expr.args[1])
            on_NaN = m2_expr.ExprInt(1, 1)
        elif expr.op == '!<=fu':
            to_ext = ~(m2_expr.expr_is_float_equal(expr.args[0], expr.args[1]) |
                      m2_expr.expr_is_float_lower(expr.args[0], expr.args[1]))
            on_NaN = m2_expr.ExprInt(1, 1)

        to_ext = m2_expr.ExprCond(
            m2_expr.expr_is_NaN(expr.args[0]) | m2_expr.expr_is_NaN(expr.args[1]),
            on_NaN,
            to_ext
        )
    return to_ext.signExtend(expr.size)

cmpeqps = vec_vertical_instr('==fu', 32, lambda x: _float_compare_to_mask(x))
cmpeqpd = vec_vertical_instr('==fu', 64, lambda x: _float_compare_to_mask(x))
cmpeqss = vec_op_clip('==fu', 32, lambda x: _float_compare_to_mask(x))
cmpeqsd = vec_op_clip('==fu', 64, lambda x: _float_compare_to_mask(x))
cmpltps = vec_vertical_instr('<fu', 32, lambda x: _float_compare_to_mask(x))
cmpltpd = vec_vertical_instr('<fu', 64, lambda x: _float_compare_to_mask(x))
cmpltss = vec_op_clip('<fu', 32, lambda x: _float_compare_to_mask(x))
cmpltsd = vec_op_clip('<fu', 64, lambda x: _float_compare_to_mask(x))
cmpleps = vec_vertical_instr('<=fu', 32, lambda x: _float_compare_to_mask(x))
cmplepd = vec_vertical_instr('<=fu', 64, lambda x: _float_compare_to_mask(x))
cmpless = vec_op_clip('<=fu', 32, lambda x: _float_compare_to_mask(x))
cmplesd = vec_op_clip('<=fu', 64, lambda x: _float_compare_to_mask(x))
cmpunordps = vec_vertical_instr('unord', 32, lambda x: _float_compare_to_mask(x))
cmpunordpd = vec_vertical_instr('unord', 64, lambda x: _float_compare_to_mask(x))
cmpunordss = vec_op_clip('unord', 32, lambda x: _float_compare_to_mask(x))
cmpunordsd = vec_op_clip('unord', 64, lambda x: _float_compare_to_mask(x))
cmpneqps = vec_vertical_instr('!=fu', 32, lambda x: _float_compare_to_mask(x))
cmpneqpd = vec_vertical_instr('!=fu', 64, lambda x: _float_compare_to_mask(x))
cmpneqss = vec_op_clip('!=fu', 32, lambda x: _float_compare_to_mask(x))
cmpneqsd = vec_op_clip('!=fu', 64, lambda x: _float_compare_to_mask(x))
cmpnltps = vec_vertical_instr('!<fu', 32, lambda x: _float_compare_to_mask(x))
cmpnltpd = vec_vertical_instr('!<fu', 64, lambda x: _float_compare_to_mask(x))
cmpnltss = vec_op_clip('!<fu', 32, lambda x: _float_compare_to_mask(x))
cmpnltsd = vec_op_clip('!<fu', 64, lambda x: _float_compare_to_mask(x))
cmpnleps = vec_vertical_instr('!<=fu', 32, lambda x: _float_compare_to_mask(x))
cmpnlepd = vec_vertical_instr('!<=fu', 64, lambda x: _float_compare_to_mask(x))
cmpnless = vec_op_clip('!<=fu', 32, lambda x: _float_compare_to_mask(x))
cmpnlesd = vec_op_clip('!<=fu', 64, lambda x: _float_compare_to_mask(x))
cmpordps = vec_vertical_instr('ord', 32, lambda x: _float_compare_to_mask(x))
cmpordpd = vec_vertical_instr('ord', 64, lambda x: _float_compare_to_mask(x))
cmpordss = vec_op_clip('ord', 32, lambda x: _float_compare_to_mask(x))
cmpordsd = vec_op_clip('ord', 64, lambda x: _float_compare_to_mask(x))

# Logical (floating-point)
#

# MMX/SSE/AVX


def pand(_, instr, dst, src):
    e = []
    result = dst & src
    # No flag assigned
    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def pandn(_, instr, dst, src):
    e = []
    result = (dst ^ dst.mask) & src
    # No flag assigned
    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def por(_, instr, dst, src):
    e = []
    result = dst | src
    e.append(m2_expr.ExprAssign(dst, result))
    return e, []


def cvtdq2pd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst[:64],
            m2_expr.ExprOp(
                'sint_to_fp',
                src[:32].signExtend(64)
            )
        )
    )
    e.append(
        m2_expr.ExprAssign(
            dst[64:128],
            m2_expr.ExprOp(
                'sint_to_fp',
                src[32:64].signExtend(64)
            )
        )
    )
    return e, []


def cvtdq2ps(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('sint_to_fp', src[:32])))
    e.append(
        m2_expr.ExprAssign(dst[32:64], m2_expr.ExprOp('sint_to_fp', src[32:64])))
    e.append(
        m2_expr.ExprAssign(dst[64:96], m2_expr.ExprOp('sint_to_fp', src[64:96])))
    e.append(
        m2_expr.ExprAssign(dst[96:128], m2_expr.ExprOp('sint_to_fp', src[96:128])))
    return e, []


def cvtpd2dq(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('fp_to_sint32', src[:64])))
    e.append(
        m2_expr.ExprAssign(dst[32:64], m2_expr.ExprOp('fp_to_sint32', src[64:128])))
    e.append(m2_expr.ExprAssign(dst[64:128], m2_expr.ExprInt(0, 64)))
    return e, []


def cvtpd2pi(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('fp_to_sint32', src[:64])))
    e.append(
        m2_expr.ExprAssign(dst[32:64], m2_expr.ExprOp('fp_to_sint32', src[64:128])))
    return e, []


def cvtpd2ps(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('fpconvert_fp32', src[:64])))
    e.append(
        m2_expr.ExprAssign(dst[32:64], m2_expr.ExprOp('fpconvert_fp32', src[64:128])))
    e.append(m2_expr.ExprAssign(dst[64:128], m2_expr.ExprInt(0, 64)))
    return e, []


def cvtpi2pd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst[:64],
            m2_expr.ExprOp(
                'sint_to_fp',
                src[:32].signExtend(64)
            )
        )
    )
    e.append(
        m2_expr.ExprAssign(
            dst[64:128],
            m2_expr.ExprOp(
                'sint_to_fp',
                src[32:64].signExtend(64))
        )
    )
    return e, []


def cvtpi2ps(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('sint_to_fp', src[:32])))
    e.append(
        m2_expr.ExprAssign(dst[32:64], m2_expr.ExprOp('sint_to_fp', src[32:64])))
    return e, []


def cvtps2dq(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('fp_to_sint32', src[:32])))
    e.append(
        m2_expr.ExprAssign(dst[32:64], m2_expr.ExprOp('fp_to_sint32', src[32:64])))
    e.append(
        m2_expr.ExprAssign(dst[64:96], m2_expr.ExprOp('fp_to_sint32', src[64:96])))
    e.append(
        m2_expr.ExprAssign(dst[96:128], m2_expr.ExprOp('fp_to_sint32', src[96:128])))
    return e, []


def cvtps2pd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:64], m2_expr.ExprOp('fpconvert_fp64', src[:32])))
    e.append(
        m2_expr.ExprAssign(dst[64:128], m2_expr.ExprOp('fpconvert_fp64', src[32:64])))
    return e, []


def cvtps2pi(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('fp_to_sint32', src[:32])))
    e.append(
        m2_expr.ExprAssign(dst[32:64], m2_expr.ExprOp('fp_to_sint32', src[32:64])))
    return e, []


def cvtsd2si(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('fp_to_sint32', src[:64])))
    return e, []


def cvtsd2ss(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('fpconvert_fp32', src[:64])))
    return e, []


def cvtsi2sd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(
            dst[:64],
            m2_expr.ExprOp(
                'sint_to_fp',
                src[:32].signExtend(64)
            )
        )
    )
    return e, []


def cvtsi2ss(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('sint_to_fp', src[:32])))
    return e, []


def cvtss2sd(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:64], m2_expr.ExprOp('fpconvert_fp64', src[:32])))
    return e, []


def cvtss2si(_, instr, dst, src):
    e = []
    e.append(
        m2_expr.ExprAssign(dst[:32], m2_expr.ExprOp('fp_to_sint32', src[:32])))
    return e, []


def _cvtt_tpl(dst, src, numbers, double):
    e = []
    for i in numbers:
        # For CVTT*D2* (Convert with Truncation ... Double-Precision) to work,
        # a first conversion fp64 -> fp32 is needed
        if double:
            tmp_src = m2_expr.ExprOp('fpconvert_fp32', src[i*64:i*64 + 64])
        else:
            tmp_src = src[i*32:i*32 + 32]

        e.append(m2_expr.ExprAssign(
            dst[i*32:i*32 + 32],
            m2_expr.ExprOp('fp_to_sint32', m2_expr.ExprOp(
                'fpround_towardszero',
                tmp_src
            ))))
    return e

def cvttpd2pi(_, instr, dst, src):
    return _cvtt_tpl(dst, src, [0, 1], double=True), []

def cvttpd2dq(_, instr, dst, src):
    e = _cvtt_tpl(dst, src, [0, 1], double=True)
    e.append(m2_expr.ExprAssign(dst[64:128], m2_expr.ExprInt(0, 64)))
    return e, []

def cvttsd2si(_, instr, dst, src):
    return _cvtt_tpl(dst, src, [0], double=True), []

def cvttps2dq(_, instr, dst, src):
    return _cvtt_tpl(dst, src, [0, 1, 2, 3], double=False), []

def cvttps2pi(_, instr, dst, src):
    return _cvtt_tpl(dst, src, [0, 1], double=False), []

def cvttss2si(_, instr, dst, src):
    return _cvtt_tpl(dst, src, [0], double=False), []

def movss(_, instr, dst, src):
    e = []
    if not isinstance(dst, m2_expr.ExprMem) and not isinstance(src, m2_expr.ExprMem):
        # Source and Destination xmm
        e.append(m2_expr.ExprAssign(dst[:32], src[:32]))
    elif not isinstance(src, m2_expr.ExprMem) and isinstance(dst, m2_expr.ExprMem):
        # Source XMM Destination Mem
        e.append(m2_expr.ExprAssign(dst, src[:32]))
    else:
        # Source Mem Destination XMM
        e.append(m2_expr.ExprAssign(
            dst, m2_expr.ExprCompose(src, m2_expr.ExprInt(0, 96))))
    return e, []


def ucomiss(_, instr, src1, src2):
    e = []
    e.append(m2_expr.ExprAssign(zf, m2_expr.ExprOp(
        'ucomiss_zf', src1[:32], src2[:32])))
    e.append(m2_expr.ExprAssign(pf, m2_expr.ExprOp(
        'ucomiss_pf', src1[:32], src2[:32])))
    e.append(m2_expr.ExprAssign(cf, m2_expr.ExprOp(
        'ucomiss_cf', src1[:32], src2[:32])))

    e.append(m2_expr.ExprAssign(of, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(af, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(nf, m2_expr.ExprInt(0, 1)))

    return e, []

def ucomisd(_, instr, src1, src2):
    e = []
    e.append(m2_expr.ExprAssign(zf, m2_expr.ExprOp(
        'ucomisd_zf', src1[:64], src2[:64])))
    e.append(m2_expr.ExprAssign(pf, m2_expr.ExprOp(
        'ucomisd_pf', src1[:64], src2[:64])))
    e.append(m2_expr.ExprAssign(cf, m2_expr.ExprOp(
        'ucomisd_cf', src1[:64], src2[:64])))

    e.append(m2_expr.ExprAssign(of, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(af, m2_expr.ExprInt(0, 1)))
    e.append(m2_expr.ExprAssign(nf, m2_expr.ExprInt(0, 1)))

    return e, []


def pshufb(_, instr, dst, src):
    e = []
    if dst.size == 64:
        bit_l = 3
    elif dst.size == 128:
        bit_l = 4
    else:
        raise NotImplementedError("bad size")
    for i in range(0, src.size, 8):
        index = src[
            i:i + bit_l].zeroExtend(dst.size) << m2_expr.ExprInt(3, dst.size)
        value = (dst >> index)[:8]
        e.append(m2_expr.ExprAssign(dst[i:i + 8],
                                 m2_expr.ExprCond(src[i + 7:i + 8],
                                                  m2_expr.ExprInt(0, 8),
                                                  value)))
    return e, []


def pshufd(_, instr, dst, src, imm):
    control = int(imm)
    out = []
    for i in range(4):
        shift = ((control >> (i * 2)) & 3) * 32
        # shift is 2 bits long, expr.size is 128
        # => shift + 32 <= src.size
        out.append(src[shift: shift + 32])
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []


def pshuflw(_, instr, dst, src, imm):
    control = int(imm)
    out = []
    for i in range(4):
        shift = ((control >> (i * 2)) & 3) * 16
        out.append(src[shift: shift + 16])
    out.append(src[64:])
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []


def pshufhw(_, instr, dst, src, imm):
    control = int(imm)
    out = [src[:64]]
    for i in range(4):
        shift = ((control >> (i * 2)) & 3) * 16
        out.append(src[shift + 64: shift + 16 + 64])
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []


def ps_rl_ll(ir, instr, dst, src, op, size):
    mask = {16: 0xF,
            32: 0x1F,
            64: 0x3F}[size]
    mask = m2_expr.ExprInt(mask, dst.size)

    # Saturate the counter to 2**size
    count = src.zeroExtend(dst.size)
    count = m2_expr.ExprCond(count & expr_simp(~mask),
                             m2_expr.ExprInt(size, dst.size), # saturation
                             count, # count < 2**size
    )
    count = count[:size]
    if src.is_int():
        count = expr_simp(count)

    out = []
    for i in range(0, dst.size, size):
        out.append(m2_expr.ExprOp(op, dst[i:i + size], count))
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []


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


def psraw(ir, instr, dst, src):
    return ps_rl_ll(ir, instr, dst, src, "a>>", 16)


def psrad(ir, instr, dst, src):
    return ps_rl_ll(ir, instr, dst, src, "a>>", 32)


def pslldq(_, instr, dst, src):
    assert src.is_int()
    e = []
    count = int(src)
    if count > 15:
        return [m2_expr.ExprAssign(dst, m2_expr.ExprInt(0, dst.size))], []
    else:
        return [m2_expr.ExprAssign(dst, dst << m2_expr.ExprInt(8 * count, dst.size))], []


def psrldq(_, instr, dst, src):
    assert src.is_int()
    count = int(src)
    if count > 15:
        return [m2_expr.ExprAssign(dst, m2_expr.ExprInt(0, dst.size))], []
    else:
        return [m2_expr.ExprAssign(dst, dst >> m2_expr.ExprInt(8 * count, dst.size))], []


def iret(ir, instr):
    """IRET implementation
    XXX: only support "no-privilege change"
    """
    size = instr.v_opmode()
    exprs, _ = retf(ir, instr, m2_expr.ExprInt(size // 8, size=size))
    tmp = mRSP[instr.mode][:size] + m2_expr.ExprInt((2 * size) // 8, size=size)
    exprs += _tpl_eflags(tmp)
    return exprs, []


def pcmpeq(_, instr, dst, src, size):
    e = []
    for i in range(0, dst.size, size):
        test = m2_expr.expr_is_equal(dst[i:i + size], src[i:i + size])
        e.append(m2_expr.ExprAssign(dst[i:i + size],
                                 m2_expr.ExprCond(test,
                                                  m2_expr.ExprInt(-1, size),
                                                  m2_expr.ExprInt(0, size))))
    return e, []


def pcmpgt(_, instr, dst, src, size):
    e = []
    for i in range(0, dst.size, size):
        test = m2_expr.expr_is_signed_greater(dst[i:i + size], src[i:i + size])
        e.append(m2_expr.ExprAssign(dst[i:i + size],
                                 m2_expr.ExprCond(test,
                                                  m2_expr.ExprInt(-1, size),
                                                  m2_expr.ExprInt(0, size))))
    return e, []


def pcmpeqb(ir, instr, dst, src):
    return pcmpeq(ir, instr, dst, src, 8)

def pcmpeqw(ir, instr, dst, src):
    return pcmpeq(ir, instr, dst, src, 16)

def pcmpeqd(ir, instr, dst, src):
    return pcmpeq(ir, instr, dst, src, 32)

def pcmpeqq(ir, instr, dst, src):
    return pcmpeq(ir, instr, dst, src, 64)




def pcmpgtb(ir, instr, dst, src):
    return pcmpgt(ir, instr, dst, src, 8)

def pcmpgtw(ir, instr, dst, src):
    return pcmpgt(ir, instr, dst, src, 16)

def pcmpgtd(ir, instr, dst, src):
    return pcmpgt(ir, instr, dst, src, 32)

def pcmpgtq(ir, instr, dst, src):
    return pcmpgt(ir, instr, dst, src, 64)



def punpck(_, instr, dst, src, size, off):
    e = []
    slices = []
    for i in range(dst.size // (2 * size)):
        slices.append(dst[size * i + off: size * i + off + size])
        slices.append(src[size * i + off: size * i + off + size])
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*slices)))
    return e, []


def punpckhbw(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 8, dst.size // 2)


def punpckhwd(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 16, dst.size // 2)


def punpckhdq(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 32, dst.size // 2)


def punpckhqdq(ir, instr, dst, src):
    return punpck(ir, instr, dst, src, 64, dst.size // 2)


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
    e.append(m2_expr.ExprAssign(dst[sel:sel + size], src[:size]))

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
    e.append(m2_expr.ExprAssign(dst, src[sel:sel + size].zeroExtend(dst.size)))

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
    e.append(m2_expr.ExprAssign(dst, src))
    return e, []


def unpckhpd(_, instr, dst, src):
    e = []
    src = m2_expr.ExprCompose(dst[64:128], src[64:128])
    e.append(m2_expr.ExprAssign(dst, src))
    return e, []


def unpcklps(_, instr, dst, src):
    e = []
    src = m2_expr.ExprCompose(dst[0:32], src[0:32], dst[32:64], src[32:64])
    e.append(m2_expr.ExprAssign(dst, src))
    return e, []


def unpcklpd(_, instr, dst, src):
    e = []
    src = m2_expr.ExprCompose(dst[0:64], src[0:64])
    e.append(m2_expr.ExprAssign(dst, src))
    return e, []


def movlpd(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst[:64], src[:64]))
    return e, []


def movlps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst[:64], src[:64]))
    return e, []


def movhpd(_, instr, dst, src):
    e = []
    if src.size == 64:
        e.append(m2_expr.ExprAssign(dst[64:128], src))
    elif dst.size == 64:
        e.append(m2_expr.ExprAssign(dst, src[64:128]))
    else:
        raise RuntimeError("bad encoding!")
    return e, []


def movlhps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst[64:128], src[:64]))
    return e, []


def movhlps(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst[:64], src[64:128]))
    return e, []


def movdq2q(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, src[:64]))
    return e, []


def movq2dq(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst, src[:64].zeroExtend(dst.size)))
    return e, []


def sqrt_gen(_, instr, dst, src, size):
    e = []
    out = []
    for i in range(src.size // size):
        out.append(m2_expr.ExprOp('fsqrt',
                                  src[i * size: (i + 1) * size]))
    src = m2_expr.ExprCompose(*out)
    e.append(m2_expr.ExprAssign(dst, src))
    return e, []


def sqrtpd(ir, instr, dst, src):
    return sqrt_gen(ir, instr, dst, src, 64)


def sqrtps(ir, instr, dst, src):
    return sqrt_gen(ir, instr, dst, src, 32)


def sqrtsd(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst[:64],
                             m2_expr.ExprOp('fsqrt',
                                            src[:64])))
    return e, []


def sqrtss(_, instr, dst, src):
    e = []
    e.append(m2_expr.ExprAssign(dst[:32],
                             m2_expr.ExprOp('fsqrt',
                                            src[:32])))
    return e, []


def pmovmskb(_, instr, dst, src):
    e = []
    out = []
    for i in range(src.size // 8):
        out.append(src[8 * i + 7:8 * (i + 1)])
    src = m2_expr.ExprCompose(*out)
    e.append(m2_expr.ExprAssign(dst, src.zeroExtend(dst.size)))
    return e, []


def smsw(ir, instr, dst):
    e = []
    LOG_X86_SEM.warning("DEFAULT SMSW %s!!", str(dst))
    e.append(m2_expr.ExprAssign(dst, m2_expr.ExprInt(0x80050033, 32)[:dst.size]))
    return e, []


def bndmov(ir, instr, dst, src):
    # Implemented as a NOP, because BND side effects are not yet supported
    return [], []

def palignr(ir, instr, dst, src, imm):
    # dst.src >> imm * 8 [:dst.size]

    shift = int(imm) * 8
    if shift == 0:
        result = src
    elif shift == src.size:
        result = dst
    elif shift > src.size:
        result = dst >> m2_expr.ExprInt(shift - src.size, dst.size)
    else:
        # shift < src.size
        result = m2_expr.ExprCompose(
            src[shift:],
            dst[:shift],
        )

    return [m2_expr.ExprAssign(dst, result)], []


def _signed_to_signed_saturation(expr, dst_size):
    """Saturate the expr @expr for @dst_size bit
    Signed saturation return MAX_INT / MIN_INT or value depending on the value
    """
    assert expr.size > dst_size

    median = 1 << (dst_size - 1)

    min_int = m2_expr.ExprInt(- median, dst_size)
    max_int = m2_expr.ExprInt(median - 1, dst_size)

    test_min_int = min_int.signExtend(expr.size)
    test_max_int = max_int.signExtend(expr.size)

    value = expr[:dst_size]

    return m2_expr.ExprCond(
        m2_expr.ExprOp(
            m2_expr.TOK_INF_EQUAL_SIGNED,
            expr,
            test_min_int
        ),
        min_int,
        m2_expr.ExprCond(
            m2_expr.ExprOp(
                m2_expr.TOK_INF_SIGNED,
                expr,
                test_max_int
            ),
            value,
            max_int
        )
    )


def _signed_to_unsigned_saturation(expr, dst_size):
    """Saturate the expr @expr for @dst_size bit
    Unsigned saturation return MAX_INT or value depending on the value
    """
    assert expr.size > dst_size

    zero = m2_expr.ExprInt(0, dst_size)
    test_zero = m2_expr.ExprInt(0, expr.size)

    max_int = m2_expr.ExprInt(-1, dst_size)
    test_max_int = max_int.zeroExtend(expr.size)

    value = expr[:dst_size]

    return m2_expr.ExprCond(
        m2_expr.ExprOp(
            m2_expr.TOK_INF_EQUAL_SIGNED,
            expr,
            test_zero
        ),
        zero,
        m2_expr.ExprCond(
            m2_expr.ExprOp(
                m2_expr.TOK_INF_SIGNED,
                expr,
                test_max_int
            ),
            value,
            max_int
        )
    )



def packsswb(ir, instr, dst, src):
    out = []
    for source in [dst, src]:
        for start in range(0, dst.size, 16):
            out.append(_signed_to_signed_saturation(source[start:start + 16], 8))
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []


def packssdw(ir, instr, dst, src):
    out = []
    for source in [dst, src]:
        for start in range(0, dst.size, 32):
            out.append(_signed_to_signed_saturation(source[start:start + 32], 16))
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []


def packuswb(ir, instr, dst, src):
    out = []
    for source in [dst, src]:
        for start in range(0, dst.size, 16):
            out.append(_signed_to_unsigned_saturation(source[start:start + 16], 8))
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []


def _saturation_sub_unsigned(expr):
    assert expr.is_op("+") and len(expr.args) == 2 and expr.args[-1].is_op("-")

    # Compute the soustraction on one more bit to be able to distinguish cases:
    # 0x48 - 0xd7 in 8 bit, should saturate
    arg1 = expr.args[0].zeroExtend(expr.size + 1)
    arg2 = expr.args[1].args[0].zeroExtend(expr.size + 1)
    return _signed_to_unsigned_saturation(arg1 - arg2, expr.size)

def _saturation_sub_signed(expr):
    assert expr.is_op("+") and len(expr.args) == 2 and expr.args[-1].is_op("-")

    # Compute the subtraction on two more bits, see _saturation_sub_unsigned
    arg1 = expr.args[0].signExtend(expr.size + 2)
    arg2 = expr.args[1].args[0].signExtend(expr.size + 2)
    return _signed_to_signed_saturation(arg1 - arg2, expr.size)

def _saturation_add(expr):
    assert expr.is_op("+") and len(expr.args) == 2

    # Compute the addition on one more bit to be able to distinguish cases:
    # 0x48 + 0xd7 in 8 bit, should saturate

    arg1 = expr.args[0].zeroExtend(expr.size + 1)
    arg2 = expr.args[1].zeroExtend(expr.size + 1)

    # We can also use _signed_to_unsigned_saturation with two additional bits (to
    # distinguish minus and overflow case)
    # The resulting expression being more complicated with an impossible case
    # (signed=True), we rewrite the rule here

    return m2_expr.ExprCond((arg1 + arg2).msb(), m2_expr.ExprInt(-1, expr.size),
                            expr)

def _saturation_add_signed(expr):
    assert expr.is_op("+") and len(expr.args) == 2

    # Compute the subtraction on two more bits, see _saturation_add_unsigned

    arg1 = expr.args[0].signExtend(expr.size + 2)
    arg2 = expr.args[1].signExtend(expr.size + 2)

    return _signed_to_signed_saturation(arg1 + arg2, expr.size)


# Saturate SSE operations

psubusb = vec_vertical_instr('-', 8, _saturation_sub_unsigned)
psubusw = vec_vertical_instr('-', 16, _saturation_sub_unsigned)
paddusb = vec_vertical_instr('+', 8, _saturation_add)
paddusw = vec_vertical_instr('+', 16, _saturation_add)
psubsb = vec_vertical_instr('-', 8, _saturation_sub_signed)
psubsw = vec_vertical_instr('-', 16, _saturation_sub_signed)
paddsb = vec_vertical_instr('+', 8, _saturation_add_signed)
paddsw = vec_vertical_instr('+', 16, _saturation_add_signed)


# Others SSE operations

def maskmovq(ir, instr, src, mask):
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = m2_expr.ExprLoc(loc_next, ir.IRDst.size)
    blks = []

    # For each possibility, check if a write is necessary
    check_labels = [m2_expr.ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
                    for _ in range(0, mask.size, 8)]
    # If the write has to be done, do it (otherwise, nothing happen)
    write_labels = [m2_expr.ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
                    for _ in range(0, mask.size, 8)]

    # Build check blocks
    for i, start in enumerate(range(0, mask.size, 8)):
        bit = mask[start + 7: start + 8]
        cur_label = check_labels[i]
        next_check_label = check_labels[i + 1] if (i + 1) < len(check_labels) else loc_next_expr
        write_label = write_labels[i]
        check = m2_expr.ExprAssign(ir.IRDst,
                                m2_expr.ExprCond(bit,
                                                 write_label,
                                                 next_check_label))
        blks.append(IRBlock(ir.loc_db, cur_label.loc_key, [AssignBlock([check], instr)]))

    # Build write blocks
    dst_addr = mRDI[instr.mode]
    for i, start in enumerate(range(0, mask.size, 8)):
        cur_label = write_labels[i]
        next_check_label = check_labels[i + 1] if (i + 1) < len(check_labels) else loc_next_expr
        write_addr = dst_addr + m2_expr.ExprInt(i, dst_addr.size)

        # @8[DI/EDI/RDI + i] = src[byte i]
        write_mem = m2_expr.ExprAssign(m2_expr.ExprMem(write_addr, 8),
                                    src[start: start + 8])
        jump = m2_expr.ExprAssign(ir.IRDst, next_check_label)
        blks.append(IRBlock(ir.loc_db, cur_label.loc_key, [AssignBlock([write_mem, jump], instr)]))

    # If mask is null, bypass all
    e = [m2_expr.ExprAssign(ir.IRDst, m2_expr.ExprCond(mask,
                                                    check_labels[0],
                                                    loc_next_expr))]
    return e, blks


def emms(ir, instr):
    # Implemented as a NOP
    return [], []

def incssp(ir, instr, dst):
    # Implemented as a NOP
    return [], []

def rdssp(ir, instr, dst):
    # Implemented as a NOP
    return [], []

def saveprevssp(ir, instr):
    # Implemented as a NOP
    return [], []

def rstorssp(ir, instr, dst):
    # Implemented as a NOP
    return [], []

def wrss(ir, instr, src, dst):
    # Implemented as a NOP
    return [], []

def wruss(ir, instr, src, dst):
    # Implemented as a NOP
    return [], []

def setssbsy(ir, instr):
    # Implemented as a NOP
    return [], []

def clrssbsy(ir, instr, dst):
    # Implemented as a NOP
    return [], []

def endbr64(ir, instr):
    # Implemented as a NOP
    return [], []

def endbr32(ir, instr):
    # Implemented as a NOP
    return [], []

# Common value without too many option, 0x1fa0
STMXCSR_VALUE = 0x1fa0
def stmxcsr(ir, instr, dst):
    return [m2_expr.ExprAssign(dst, m2_expr.ExprInt(STMXCSR_VALUE, dst.size))], []

def ldmxcsr(ir, instr, dst):
    # Implemented as a NOP
    return [], []


def _select4(src, control):
    # Implementation inspired from Intel Intrisics Guide
    # @control is already resolved (was an immediate)

    if control == 0:
        return src[:32] # 0
    elif control == 1:
        return src[32:64]
    elif control == 2:
        return src[64:96]
    elif control == 3:
        return src[96:]
    else:
        raise ValueError("Control must be on 2 bits")


def shufps(ir, instr, dst, src, imm8):
    out = []
    control = int(imm8)
    for i in range(4):
        if i < 2:
            source = dst
        else:
            source = src
        out.append(_select4(source, (control >> (i * 2)) & 3))
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []


def shufpd(ir, instr, dst, src, imm8):
    out = []
    control = int(imm8)
    out.append(dst[64:] if control & 1 else dst[:64])
    out.append(src[64:] if control & 2 else src[:64])
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out))], []

def movmskps(ir, instr, dst, src):
    out = []
    for i in range(4):
        out.append(src[(32 * i) + 31:(32 * i) + 32])
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out).zeroExtend(dst.size))], []

def movmskpd(ir, instr, dst, src):
    out = []
    for i in range(2):
        out.append(src[(64 * i) + 63:(64 * i) + 64])
    return [m2_expr.ExprAssign(dst, m2_expr.ExprCompose(*out).zeroExtend(dst.size))], []

def _roundscalar(ir, inst, dst, src, imm8, double):
    res = None
    ctl = int(imm8)
    dst_expr = dst[:64] if double else dst[:32]
    src_expr = src[:64] if double else src[:32]
    if ctl & 0x4 != 0:
        # Use MXCSR rounding config
        # TODO: here we assume it's round to nearest, ties to even
        res = m2_expr.ExprOp('fpround_towardsnearest', src_expr)
    else:
        # Use encoded rounding mechanism
        rounding_mechanism = ctl & 0x3
        ROUNDING_MODE = {
            0x0: 'fpround_towardsnearest',
            0x1: 'fpround_down',
            0x2: 'fpround_up',
            0x3: 'fpround_towardszero'
        }
        res = m2_expr.ExprOp(ROUNDING_MODE[rounding_mechanism], src_expr)
    return [m2_expr.ExprAssign(dst_expr, res)], []

def roundss(ir, inst, dst, src, imm8):
    return _roundscalar(ir, inst, dst, src, imm8, False)

def roundsd(ir, inst, dst, src, imm8):
    return _roundscalar(ir, inst, dst, src, imm8, True)

def fxsave(_ir, _instr, _src):
    # Implemented as a NOP for now
    return [], []

def fxrstor(_ir, _instr, _dst):
    # Implemented as a NOP for now
    return [], []


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
              'nop': nop,
              'ud2': ud2,
              'prefetch0': prefetch0,
              'prefetch1': prefetch1,
              'prefetch2': prefetch2,
              'prefetchw': prefetchw,
              'prefetchnta': prefetchnta,
              'lfence': lfence,
              'mfence': mfence,
              'sfence': sfence,
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
              "movapd": movapd,  # XXX TODO alignment check
              "movupd": movapd,  # XXX TODO alignment check
              "movaps": movapd,  # XXX TODO alignment check
              "movups": movapd,  # XXX TODO alignment check
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


              "bndmov": bndmov,




              "movss": movss,

              "ucomiss": ucomiss,
              "ucomisd": ucomisd,

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

              # Multiplications
              # SSE
              "pmullb": pmullb,
              "pmullw": pmullw,
              "pmulld": pmulld,
              "pmullq": pmullq,
              "pmulhub": pmulhub,
              "pmulhuw": pmulhuw,
              "pmulhud": pmulhud,
              "pmulhuq": pmulhuq,
              "pmulhb": pmulhb,
              "pmulhw": pmulhw,
              "pmulhd": pmulhd,
              "pmulhq": pmulhq,
              "pmuludq": pmuludq,

              # Mix
              # SSE
              "pmaddwd": pmaddwd,
              "psadbw": psadbw,
              "pavgb": pavgb,
              "pavgw": pavgw,

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

              # Rounding
              "roundss": roundss,
              "roundsd": roundsd,

              # Comparisons (floating-point)
              #
              "minps": minps,
              "minpd": minpd,
              "minss": minss,
              "minsd": minsd,
              "maxps": maxps,
              "maxpd": maxpd,
              "maxss": maxss,
              "maxsd": maxsd,
              "cmpeqps": cmpeqps,
              "cmpeqpd": cmpeqpd,
              "cmpeqss": cmpeqss,
              "cmpeqsd": cmpeqsd,
              "cmpltps": cmpltps,
              "cmpltpd": cmpltpd,
              "cmpltss": cmpltss,
              "cmpltsd": cmpltsd,
              "cmpleps": cmpleps,
              "cmplepd": cmplepd,
              "cmpless": cmpless,
              "cmplesd": cmplesd,
              "cmpunordps": cmpunordps,
              "cmpunordpd": cmpunordpd,
              "cmpunordss": cmpunordss,
              "cmpunordsd": cmpunordsd,
              "cmpneqps": cmpneqps,
              "cmpneqpd": cmpneqpd,
              "cmpneqss": cmpneqss,
              "cmpneqsd": cmpneqsd,
              "cmpnltps": cmpnltps,
              "cmpnltpd": cmpnltpd,
              "cmpnltss": cmpnltss,
              "cmpnltsd": cmpnltsd,
              "cmpnleps": cmpnleps,
              "cmpnlepd": cmpnlepd,
              "cmpnless": cmpnless,
              "cmpnlesd": cmpnlesd,
              "cmpordps": cmpordps,
              "cmpordpd": cmpordpd,
              "cmpordss": cmpordss,
              "cmpordsd": cmpordsd,

              # Logical (floating-point)
              #

              "pand": pand,
              "pandn": pandn,
              "por": por,

              "rdmsr": rdmsr,
              "wrmsr": wrmsr,
              "pshufb": pshufb,
              "pshufd": pshufd,
              "pshuflw": pshuflw,
              "pshufhw": pshufhw,

              "psrlw": psrlw,
              "psrld": psrld,
              "psrlq": psrlq,
              "psllw": psllw,
              "pslld": pslld,
              "psllq": psllq,
              "pslldq": pslldq,
              "psrldq": psrldq,
              "psraw": psraw,
              "psrad": psrad,

              "palignr": palignr,

              "pmaxub": pmaxub,
              "pmaxuw": pmaxuw,
              "pmaxud": pmaxud,
              "pmaxsw": pmaxsw,

              "pminub": pminub,
              "pminuw": pminuw,
              "pminud": pminud,

              "pcmpeqb": pcmpeqb,
              "pcmpeqw": pcmpeqw,
              "pcmpeqd": pcmpeqd,
              "pcmpeqq": pcmpeqq,

              "pcmpgtb": pcmpgtb,
              "pcmpgtw": pcmpgtw,
              "pcmpgtd": pcmpgtd,
              "pcmpgtq": pcmpgtq,

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
              "movq2dq": movq2dq,

              "sqrtpd": sqrtpd,
              "sqrtps": sqrtps,
              "sqrtsd": sqrtsd,
              "sqrtss": sqrtss,

              "pmovmskb": pmovmskb,

              "packsswb": packsswb,
              "packssdw": packssdw,
              "packuswb": packuswb,

              "psubusb": psubusb,
              "psubusw": psubusw,
              "paddusb": paddusb,
              "paddusw": paddusw,
              "psubsb": psubsb,
              "psubsw": psubsw,
              "paddsb": paddsb,
              "paddsw": paddsw,

              "smsw": smsw,
              "maskmovq": maskmovq,
              "maskmovdqu": maskmovq,
              "emms": emms,
              "shufps": shufps,
              "shufpd": shufpd,
              "movmskps": movmskps,
              "movmskpd": movmskpd,
              "stmxcsr": stmxcsr,
              "ldmxcsr": ldmxcsr,

              # CET (Control-flow Enforcement Technology)
              "incssp": incssp,
              "rdssp": rdssp,
              "saveprevssp": saveprevssp,
              "rstorssp": rstorssp,
              "wrss": wrss,
              "wruss": wruss,
              "setssbsy": setssbsy,
              "clrssbsy": clrssbsy,
              "endbr64": endbr64,
              "endbr32": endbr32,
              "fxsave": fxsave,
              "fxrstor": fxrstor,
              }


class Lifter_X86_16(Lifter):

    def __init__(self, loc_db):
        Lifter.__init__(self, mn_x86, 16, loc_db)
        self.do_stk_segm = False
        self.do_ds_segm = False
        self.do_str_segm = False
        self.do_all_segm = False
        self.pc = IP
        self.sp = SP
        self.IRDst = m2_expr.ExprId('IRDst', 16)
        # Size of memory pointer access in IR
        # 16 bit mode memory accesses may be greater than 16 bits
        # 32 bit size may be enough
        self.addrsize = 32

    def mod_pc(self, instr, instr_ir, extra_ir):
        pass

    def ExprMem(self, ptr, size):
        """Generate a memory access to @ptr
        The ptr is resized to a fixed size self.addrsize

        @ptr: Expr instance to the memory address
        @size: size of the memory"""

        return m2_expr.ExprMem(expraddr(self.addrsize, ptr), size)

    def gen_segm_expr(self, selector, addr):
        ptr = m2_expr.ExprOp(
            'segm',
            selector,
            addr.zeroExtend(self.addrsize)
        )

        return ptr

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
                if a.is_mem() and not is_mem_segm(a):
                    args[i] = self.ExprMem(m2_expr.ExprOp('segm', my_ss,
                                                          a.ptr), a.size)

        if not instr.name.lower() in mnemo_func:
            raise NotImplementedError(
                "Mnemonic %s not implemented" % instr.name)

        instr_ir, extra_ir = mnemo_func[
            instr.name.lower()](self, instr, *args)
        self.mod_pc(instr, instr_ir, extra_ir)
        instr.additional_info.except_on_instr = False
        if instr.additional_info.g1.value & 14 == 0 or \
                not instr.name in repeat_mn:
            return instr_ir, extra_ir
        if instr.name == "MOVSD" and len(instr.args) == 2:
            return instr_ir, extra_ir

        instr.additional_info.except_on_instr = True
        admode = instr.v_admode()
        c_reg = mRCX[instr.mode][:admode]

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
        elif instr.additional_info.g1.value & 2:  # REPNE and REPNZ
            c_cond = cond_dec | zf
        elif instr.additional_info.g1.value & 12:  # REPE, REP and REPZ
            c_cond = cond_dec | (zf ^ m2_expr.ExprInt(1, 1))

        # gen while
        loc_do, loc_do_expr = self.gen_loc_key_and_expr(self.IRDst.size)
        loc_end, loc_end_expr = self.gen_loc_key_and_expr(self.IRDst.size)
        loc_skip = self.get_next_loc_key(instr)
        loc_skip_expr = m2_expr.ExprLoc(loc_skip, self.IRDst.size)
        loc_next = self.get_next_loc_key(instr)
        loc_next_expr = m2_expr.ExprLoc(loc_next, self.IRDst.size)

        fix_next_loc = {loc_next_expr: loc_end_expr}
        new_extra_ir = [irblock.modify_exprs(mod_src=lambda expr: expr.replace_expr(fix_next_loc))
                        for irblock in extra_ir]

        cond_bloc = []
        cond_bloc.append(m2_expr.ExprAssign(c_reg,
                                         c_reg - m2_expr.ExprInt(1,
                                                                 c_reg.size)))
        cond_bloc.append(m2_expr.ExprAssign(self.IRDst, m2_expr.ExprCond(c_cond,
                                                                      loc_skip_expr,
                                                                      loc_do_expr)))
        cond_bloc = IRBlock(self.loc_db, loc_end, [AssignBlock(cond_bloc, instr)])
        e_do = instr_ir

        c = IRBlock(self.loc_db, loc_do, [AssignBlock(e_do, instr)])
        e_n = [m2_expr.ExprAssign(self.IRDst, m2_expr.ExprCond(c_reg, loc_do_expr,
                                                            loc_skip_expr))]
        return e_n, [cond_bloc, c] + new_extra_ir

    def expr_fix_regs_for_mode(self, e, mode=64):
        return e.replace_expr(replace_regs[mode])

    def expraff_fix_regs_for_mode(self, e, mode=64):
        dst = self.expr_fix_regs_for_mode(e.dst, mode)
        src = self.expr_fix_regs_for_mode(e.src, mode)
        return m2_expr.ExprAssign(dst, src)

    def irbloc_fix_regs_for_mode(self, irblock, mode=64):
        irs = []
        for assignblk in irblock:
            new_assignblk = dict(assignblk)
            for dst, src in viewitems(assignblk):
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
            irs.append(AssignBlock(new_assignblk, assignblk.instr))
        return IRBlock(self.loc_db, irblock.loc_key, irs)


class Lifter_X86_32(Lifter_X86_16):

    def __init__(self, loc_db):
        Lifter.__init__(self, mn_x86, 32, loc_db)
        self.do_stk_segm = False
        self.do_ds_segm = False
        self.do_str_segm = False
        self.do_all_segm = False
        self.pc = EIP
        self.sp = ESP
        self.IRDst = m2_expr.ExprId('IRDst', 32)
        self.addrsize = 32


class Lifter_X86_64(Lifter_X86_16):

    def __init__(self, loc_db):
        Lifter.__init__(self, mn_x86, 64, loc_db)
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
        pc_fixed = {self.pc: m2_expr.ExprInt(instr.offset + instr.l, 64)}

        for i, expr in enumerate(instr_ir):
            dst, src = expr.dst, expr.src
            if dst != self.pc:
                dst = dst.replace_expr(pc_fixed)
            src = src.replace_expr(pc_fixed)
            instr_ir[i] = m2_expr.ExprAssign(dst, src)

        for idx, irblock in enumerate(extra_ir):
            extra_ir[idx] = irblock.modify_exprs(lambda expr: expr.replace_expr(pc_fixed) \
                                                 if expr != self.pc else expr,
                                                 lambda expr: expr.replace_expr(pc_fixed))
