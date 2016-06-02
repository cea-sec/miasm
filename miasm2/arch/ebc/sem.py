#!/usr/bin/env python
#-*- coding:utf-8 -*-

import sys
from miasm2.ir.ir         import ir
from miasm2.arch.ebc.arch import mn_ebc
from miasm2.arch.ebc.regs import *
from miasm2.expression.expression import *

def mnemo_call32(ir, instr, a):
    e = []
    e.append(ExprAff(R0, R0 - ExprInt64(16)))
    e.append(ExprAff(ExprMem(R0 - ExprInt64(16), 64), ExprInt64(instr.offset + instr.l)))
    e.append(ExprAff(IP, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []

def mnemo_call32exa(ir, instr, a):
    a = ExprMem(a.arg, 32).zeroExtend(64)
    e = []
    e.append(ExprAff(R0, R0 - ExprInt64(16)))
    e.append(ExprAff(ExprMem(R0 - ExprInt64(16), 64), ExprInt64(instr.offset + instr.l)))
    e.append(ExprAff(IP, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []

def mnemo_jmp8(ir, instr, a):
    e = []
    e.append(ExprAff(IP, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []

def mnemo_jmp8cc(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 64)
    e = []
    e.append(ExprAff(IP, ExprCond(cf, n, a)))
    e.append(ExprAff(ir.IRDst, ExprCond(cf, n, a)))
    return e, []

def mnemo_jmp8cs(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 64)
    e = []
    e.append(ExprAff(IP, ExprCond(cf, a, n)))
    e.append(ExprAff(ir.IRDst, ExprCond(cf, a, n)))
    return e, []

def mnemo_jmp32(ir, instr, a):
    e = []
    e.append(ExprAff(IP, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []

def mnemo_jmp32cc(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 64)
    e = []
    e.append(ExprAff(IP, ExprCond(cf, n, a)))
    e.append(ExprAff(ir.IRDst, ExprCond(cf, n, a)))
    return e, []

def mnemo_jmp32cs(ir, instr, a):
    n = ExprId(ir.get_next_label(instr), 64)
    e = []
    e.append(ExprAff(IP, ExprCond(cf, a, n)))
    e.append(ExprAff(ir.IRDst, ExprCond(cf, a, n)))
    return e, []

def mnemo_ret(ir, instr):
    e = []
    e.append(ExprAff(IP, ExprMem(R0, 64)))
    e.append(ExprAff(ir.IRDst, ExprMem(R0, 64)))
    e.append(ExprAff(R0, R0 + ExprInt64(16)))
    return e, []

def mnemo_break     (ir, instr, a):    return [], []
def mnemo_cmp32eq   (ir, instr, a, b): return [ExprAff(cf, ExprCond(a - b, ExprInt64(0), ExprInt64(1)))], []
def mnemo_cmp64eq   (ir, instr, a, b): return [ExprAff(cf, ExprCond(a - b, ExprInt64(0), ExprInt64(1)))], []
def mnemo_cmpi32weq (ir, instr, a, b): return [ExprAff(cf, ExprCond(a[:32] - b[:32], ExprInt64(0), ExprInt64(1)))], []
def mnemo_cmpi32wgte(ir, instr, a, b):
    if   isinstance(a, ExprMem):
         if  instr.mode == 32:
             a = ExprMem(a.arg, 32)
    else:
         a = a[:32]
    if   isinstance(b, ExprMem):
         if  instr.mode == 32:
             b = ExprMem(b.arg, 32)
    else:
         b = b[:32]
    return [ExprAff(cf, ExprCond((a - b).msb(), ExprInt64(0), ExprInt64(1)))], []
def mnemo_cmpi32wlte(ir, instr, a, b):
    if   isinstance(a, ExprMem):
         if  instr.mode == 32:
             a = ExprMem(a.arg, 32)
    else:
         a = a[:32]
    if   isinstance(b, ExprMem):
         if  instr.mode == 32:
             b = ExprMem(b.arg, 32)
    else:
         b = b[:32]
    return [ExprAff(cf, ExprCond((b - a).msb(), ExprInt64(0), ExprInt64(1)))], []
def mnemo_add32     (ir, instr, a, b): return [ExprAff(a, (a[:32] +  b[:32]).zeroExtend(64))], []
def mnemo_ashr32    (ir, instr, a, b): return [ExprAff(a, (a[:32] >> b[:32]).zeroExtend(64))], []
def mnemo_mod32     (ir, instr, a, b): return [ExprAff(a, (a[:32] %  b[:32]).zeroExtend(64))], []
def mnemo_neg32     (ir, instr, a, b): return [ExprAff(a, (       -  b[:32]).zeroExtend(64))], []
def mnemo_not32     (ir, instr, a, b): return [ExprAff(a, (       ~  b[:32]).zeroExtend(64))], []
def mnemo_or32      (ir, instr, a, b): return [ExprAff(a, (a[:32] |  b[:32]).zeroExtend(64))], []
def mnemo_shl32     (ir, instr, a, b): return [ExprAff(a, (a[:32] << b[:32]).zeroExtend(64))], []
def mnemo_xor32     (ir, instr, a, b): return [ExprAff(a, (a[:32] ^  b[:32]).zeroExtend(64))], []
def mnemo_add64     (ir, instr, a, b): return [ExprAff(a, a +  b)], []
def mnemo_mul64     (ir, instr, a, b): return [ExprAff(a, a *  b)], []
def mnemo_neg64     (ir, instr, a, b): return [ExprAff(a,   -  b)], []
def mnemo_shl64     (ir, instr, a, b): return [ExprAff(a, a << b)], []
def mnemo_extndd64  (ir, instr, a, b): return [ExprAff(a, b[:32].signExtend(64))], []
def mnemo_movbd     (ir, instr, a, b):
    if   isinstance(a, ExprMem) and isinstance(b, ExprId) and instr.mode == 32:
         return [ExprAff(ExprMem(a.arg, 8), b[:8])], []
    elif isinstance(a, ExprId)  and isinstance(b, ExprId) and instr.mode == 32:
         return [ExprAff(a[:8], b[:8])], []
    elif isinstance(a, ExprId)  and isinstance(b, ExprMem) and instr.mode == 32:
         return [ExprAff(a[:8], ExprMem(b.arg, 8))], []
    else:
         raise ValueError('movbd implem failure')
def mnemo_movbw     (ir, instr, a, b):
    if   isinstance(a, ExprId)  and isinstance(b, ExprMem):
         return [ExprAff(a, ExprMem(b.arg, 8).zeroExtend(64))], []
    elif isinstance(a, ExprMem) and isinstance(b, ExprId):
         return [ExprAff(ExprMem(a.arg, 8), b[:8])], []
    elif isinstance(a, ExprMem) and isinstance(b, ExprMem):
         return [ExprAff(ExprMem(a.arg, 8), ExprMem(b.arg, 8))], []
    else:
        raise ValueError('movbw implem failure')
def mnemo_movdd     (ir, instr, a, b): return [ExprAff(a, b)], []
def mnemo_movdw     (ir, instr, a, b): return [ExprAff(a, b)], []
def mnemo_movidw    (ir, instr, a, b): return [ExprAff(a, b)], []
def mnemo_moviqd    (ir, instr, a, b): return [ExprAff(a, b)], []
def mnemo_moviqq    (ir, instr, a, b): return [ExprAff(a, b)], []
def mnemo_moviqw    (ir, instr, a, b): return [ExprAff(a, b)], []
def mnemo_movnd     (ir, instr, a, b):
    if  isinstance(a, ExprId)  and isinstance(b, ExprMem) and instr.mode == 32:
        b = ExprMem(b.arg, 32).zeroExtend(64)
    return [ExprAff(a, b)], []
def mnemo_movnw     (ir, instr, a, b):
    if   isinstance(a, ExprMem) and isinstance(b, ExprMem) and instr.mode == 32:
         a, b = ExprMem(a.arg, 32), ExprMem(b.arg, 32)
    elif isinstance(a, ExprId)  and isinstance(b, ExprMem) and instr.mode == 32:
         b = ExprMem(b.arg, 32).zeroExtend(64)
    return [ExprAff(a, b)], []
def mnemo_movsnw    (ir, instr, a, b): return [ExprAff(a, b)], []
def mnemo_movqd     (ir, instr, a, b): return [ExprAff(a, b)], []
def mnemo_movqw     (ir, instr, a, b): return [ExprAff(a, b)], []
def mnemo_movwd     (ir, instr, a, b):
    if   isinstance(a, ExprId)  and isinstance(b, ExprMem) and instr.mode == 32:
         return [ExprAff(a, ExprMem(b.arg, 16).zeroExtend(64))], []
    elif isinstance(a, ExprMem) and isinstance(b, ExprMem) and instr.mode == 32:
         return [ExprAff(ExprMem(a.arg, 16), ExprMem(b.arg, 16))], []
    else:
         print >> sys.stderr, '\033[31mDEBUG\033[m', ir, instr, a, b
         raise ValueError('movwd implem failure')
def mnemo_movww     (ir, instr, a, b): return [ExprAff(a, b[:16].zeroExtend(64))], []

def mnemo_movreld(ir, instr, a, b):
    #print >> sys.stderr, '\033[34mDEBUG\033[m', IP + ExprInt64(instr.l) + b
    #return [ExprAff(a, ExprMem(IP + ExprInt64(instr.l) + b, 64))], []
    return [ExprAff(a, IP + ExprInt64(instr.l) + b)], []

class ir_ebc_32(ir):
    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_ebc, 32, symbol_pool)
        self.IRDst = ExprId('IRDst', 64)
    def get_ir(self, instr):
        return globals()['mnemo_' + instr.name.lower()](self, instr, *instr.args)

