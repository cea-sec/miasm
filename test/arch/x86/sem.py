#! /usr/bin/env python2
#-*- coding:utf-8 -*-

# Loosely based on ARM's sem.py

from __future__ import print_function
from builtins import range

from future.utils import viewitems

import unittest
import logging
import copy

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.arch.x86.arch import mn_x86 as mn
from miasm.arch.x86.sem import Lifter_X86_32, Lifter_X86_64
from miasm.arch.x86.regs import *
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp
from miasm.core import parse_asm, asmblock
from miasm.core.locationdb import LocationDB

logging.getLogger('cpuhelper').setLevel(logging.ERROR)
loc_db = LocationDB()
EXCLUDE_REGS = set([Lifter_X86_32(loc_db).IRDst, Lifter_X86_64(loc_db).IRDst])


m32 = 32
m64 = 64

def symb_exec(lbl, lifter, ircfg, inputstate, debug):
    sympool = dict(regs_init)
    sympool.update(inputstate)
    symexec = SymbolicExecutionEngine(lifter, sympool)
    symexec.run_at(ircfg, lbl)
    if debug:
        for k, v in viewitems(symexec.symbols):
            if regs_init.get(k, None) != v:
                print(k, v)
    return {
        k: v for k, v in viewitems(symexec.symbols)
        if k not in EXCLUDE_REGS and regs_init.get(k, None) != v
    }

def compute(Lifter, mode, asm, inputstate={}, debug=False):
    loc_db = LocationDB()
    instr = mn.fromstring(asm, loc_db, mode)
    code = mn.asm(instr)[0]
    instr = mn.dis(code, mode)
    instr.offset = inputstate.get(EIP, 0)
    lifter = Lifter(loc_db)
    ircfg = lifter.new_ircfg()
    lbl = lifter.add_instr_to_ircfg(instr, ircfg)
    return symb_exec(lbl, lifter, ircfg, inputstate, debug)


def compute_txt(Lifter, mode, txt, inputstate={}, debug=False):
    loc_db = LocationDB()
    asmcfg = parse_asm.parse_txt(mn, mode, txt, loc_db)
    loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)
    patches = asmblock.asm_resolve_final(mn, asmcfg)
    lifter = Lifter(loc_db)
    lbl = loc_db.get_name_location("main")
    ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
    return symb_exec(lbl, lifter, ircfg, inputstate, debug)

op_add = lambda a, b: a+b
op_sub = lambda a, b: a-b
op_mul = lambda a, b: a*b
op_div = lambda a, b: a //b

op_and = lambda a, b: a&b
op_or  = lambda a, b: a|b
op_xor = lambda a, b: a^b

def int_vec_op(op, elt_size, reg_size, arg1, arg2):
    arg1 = copy.deepcopy(arg1)
    arg2 = copy.deepcopy(arg2)
    assert(reg_size % elt_size == 0)
    ret = 0
    mask = (1<<elt_size)-1
    nelts = reg_size // elt_size
    for i in range(0, nelts):
        ret |= (op(arg1 & mask, arg2 & mask) & mask) << (i*elt_size)
        arg1 >>= elt_size
        arg2 >>= elt_size
    return ret

MMX_V0 = 0x0001020304050607
MMX_V1 = 0x0101010101010101
MMX_A = ExprId('A', 64)
MMX_B = ExprId('B', 64)

SSE_V0 = 0x00010203040506070001020304050607
SSE_V1 = 0x01010101010101010101010101010101
SSE_A = ExprId('A', 128)
SSE_B = ExprId('B', 128)

class TestX86Semantic(unittest.TestCase):

    def int_sse_op(self, name, op, elt_size, reg_size, arg1, arg2):
        arg1 = ExprInt(arg1, XMM0.size)
        arg2 = ExprInt(arg2, XMM0.size)
        sem = compute(Lifter_X86_32, m32, '%s XMM0, XMM1' % name,
                                  {XMM0: arg1, XMM1: arg2},
                                  False)
        ref = ExprInt(int_vec_op(op, elt_size, reg_size, int(arg1), int(arg2)), XMM0.size)
        self.assertEqual(sem, {XMM0: ref, XMM1: arg2})

    def symb_sse_ops(self, names, a, b, ref):
        asm = "\n\t".join(["%s XMM0, XMM1" % name for name in names])
        asm = "main:\n\t" + asm
        sem = compute_txt(Lifter_X86_32, m32, asm,
                                  {XMM0: a, XMM1: b},
                                  False)
        self.assertEqual(sem, {XMM0: ref, XMM1: b})

    def mmx_logical_op(self, name, op, arg1, arg2):
        arg1 = ExprInt(arg1, mm0.size)
        arg2 = ExprInt(arg2, mm0.size)
        sem = compute(Lifter_X86_32, m32, '%s MM0, MM1' % name,
                                  {mm0: arg1, mm1: arg2},
                                  False)
        ref = ExprInt(op(int(arg1), int(arg2)), mm0.size)
        self.assertEqual(sem, {mm0: ref, mm1: arg2})

    def sse_logical_op(self, name, op, arg1, arg2):
        arg1 = ExprInt(arg1, XMM0.size)
        arg2 = ExprInt(arg2, XMM1.size)
        sem = compute(Lifter_X86_32, m32, '%s XMM0, XMM1' % name,
                                  {XMM0: arg1, XMM1: arg2},
                                  False)
        ref = ExprInt(op(int(arg1), int(arg2)), XMM0.size)
        self.assertEqual(sem, {XMM0: ref, XMM1: arg2})

    def test_SSE_ADD(self):
        for op in (("PADDB", 8), ("PADDW", 16), ("PADDD", 32), ("PADDQ", 64)):
            self.int_sse_op(op[0], op_add, op[1], 128, SSE_V0, SSE_V0)
            self.int_sse_op(op[0], op_add, op[1], 128, SSE_V0, SSE_V1)
            self.int_sse_op(op[0], op_add, op[1], 128, SSE_V1, SSE_V0)
            self.int_sse_op(op[0], op_add, op[1], 128, SSE_V1, SSE_V1)

    def test_SSE_SUB(self):
        for op in (("PSUBB", 8), ("PSUBW", 16), ("PSUBD", 32), ("PSUBQ", 64)):
            self.int_sse_op(op[0], op_sub, op[1], 128, SSE_V0, SSE_V0)
            self.int_sse_op(op[0], op_sub, op[1], 128, SSE_V0, SSE_V1)
            self.int_sse_op(op[0], op_sub, op[1], 128, SSE_V1, SSE_V0)
            self.int_sse_op(op[0], op_sub, op[1], 128, SSE_V1, SSE_V1)

    def test_SSE_simp(self):
        self.symb_sse_ops(["PADDB", "PADDB", "PSUBB"], ExprInt(0, XMM0.size), SSE_A, SSE_A)
        self.symb_sse_ops(["PADDB", "PADDQ", "PSUBQ"], ExprInt(0, XMM0.size), SSE_A, SSE_A)
        self.symb_sse_ops(["PADDB", "PSUBQ", "PADDQ"], ExprInt(0, XMM0.size), SSE_A, SSE_A)

    def test_AND(self):
        self.mmx_logical_op("PAND", op_and, MMX_V0, MMX_V1)
        self.sse_logical_op("PAND", op_and, SSE_V0, SSE_V1)



if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestX86Semantic)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
