#! /usr/bin/env python2
#-*- coding:utf-8 -*-

from __future__ import print_function
import unittest
import logging

from future.utils import viewitems

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.arch.ppc.arch import mn_ppc as mn
from miasm.arch.ppc.sem import Lifter_PPC32b as Lifter
from miasm.arch.ppc.regs import *
from miasm.expression.expression import *
from miasm.core.locationdb import LocationDB
from pdb import pm

logging.getLogger('cpuhelper').setLevel(logging.ERROR)
loc_db = LocationDB()
EXCLUDE_REGS = set([Lifter(loc_db).IRDst])


def M(addr):
    return ExprMem(ExprInt(addr, 32), 32)


def compute(asm, inputstate={}, debug=False):
    loc_db = LocationDB()
    sympool = dict(regs_init)
    sympool.update({k: ExprInt(v, k.size) for k, v in viewitems(inputstate)})
    lifter = Lifter(loc_db)
    ircfg = lifter.new_ircfg()
    symexec = SymbolicExecutionEngine(lifter, sympool)
    instr = mn.fromstring(asm, loc_db, "b")
    code = mn.asm(instr)[0]
    instr = mn.dis(code, "b")
    instr.offset = inputstate.get(PC, 0)
    lbl = lifter.add_instr_to_ircfg(instr, ircfg)
    symexec.run_at(ircfg, lbl)
    if debug:
        for k, v in viewitems(symexec.symbols):
            if regs_init.get(k, None) != v:
                print(k, v)
    out = {}
    for k, v in viewitems(symexec.symbols):
        if k in EXCLUDE_REGS:
            continue
        elif regs_init.get(k, None) == v:
            continue
        elif isinstance(v, ExprInt):
            out[k] = int(v)
        else:
            out[k] = v
    return out

class TestPPC32Semantic(unittest.TestCase):

    # def test_condition(self):
    # §A8.3:                   Conditional execution
    #    pass

    def test_shift(self):
        self.assertEqual(
            compute('SLW R5, R4, R1',
                    {R1: 8, R4: 0xDEADBEEF, }),
            {R1: 8, R4: 0xDEADBEEF, R5: 0xADBEEF00, })
        self.assertEqual(
            compute('SLW. R5, R4, R1',
                    {R1: 8, R4: 0xDEADBEEF, }),
            {R1: 8, R4: 0xDEADBEEF, R5: 0xADBEEF00,
             CR0_LT: 1, CR0_GT: 0, CR0_EQ: 0, CR0_SO: ExprId('XER_SO_init', 1)})
        self.assertEqual(
            compute('SLW R5, R4, R1',
                    {R1: 32 | 0xbeef, R4: 0xDEADBEEF, }),
            {R1: 32 | 0xbeef, R4: 0xDEADBEEF, R5: 0x0, })
        self.assertEqual(
            compute('SLW. R5, R4, R1',
                    {R1: 32 | 0xbeef, R4: 0xDEADBEEF, }),
            {R1: 32 | 0xbeef, R4: 0xDEADBEEF, R5: 0x0,
             CR0_LT: 0, CR0_GT: 0, CR0_EQ: 1, CR0_SO: ExprId('XER_SO_init', 1)})
#        self.assertRaises(ValueError, compute, 'MOV R4, R4 LSL  0')

    def test_ADD(self):
        self.assertEqual(
            compute('ADD R5, R4, R1',
                    {R1: 0xCAFEBABE, R4: 0xDEADBEEF, }),
            {R1: 0xCAFEBABE, R4: 0xDEADBEEF, R5: 0xA9AC79AD, })
        self.assertEqual(
            compute('ADD. R5, R4, R1',
                    {R1: 0xCAFEBABE, R4: 0xDEADBEEF, }),
            {R1: 0xCAFEBABE, R4: 0xDEADBEEF, R5: 0xA9AC79AD,
             CR0_LT: 1, CR0_GT: 0, CR0_EQ: 0, CR0_SO: ExprId('XER_SO_init', 1)})
        pass

    def test_AND(self):
        self.assertEqual(
            compute('AND R5, R4, R1',
                    {R1: 0xCAFEBABE, R4: 0xDEADBEEF, }),
            {R1: 0xCAFEBABE, R4: 0xDEADBEEF, R5: 0xCAACBAAE, })
        self.assertEqual(
            compute('AND. R5, R4, R1',
                    {R1: 0xCAFEBABE, R4: 0xDEADBEEF, }),
            {R1: 0xCAFEBABE, R4: 0xDEADBEEF, R5: 0xCAACBAAE,
             CR0_LT: 1, CR0_GT: 0, CR0_EQ: 0, CR0_SO: ExprId('XER_SO_init', 1)})
        pass

    def test_SUB(self):
        self.assertEqual(
            compute('SUBF R5, R4, R1',
                    {R1: 0xCAFEBABE, R4: 0xDEADBEEF, }),
            {R1: 0xCAFEBABE, R4: 0xDEADBEEF, R5: 0xEC50FBCF, })
        self.assertEqual(
            compute('SUBF. R5, R4, R1',
                    {R1: 0xCAFEBABE, R4: 0xDEADBEEF, }),
            {R1: 0xCAFEBABE, R4: 0xDEADBEEF, R5: 0xEC50FBCF,
             CR0_LT: 1, CR0_GT: 0, CR0_EQ: 0, CR0_SO: ExprId('XER_SO_init', 1)})
        pass

    def test_CMP(self):
        self.assertEqual(
            compute('CMPW CR2, R4, R1',
                    {R1: 0xCAFEBABE, R4: 0xDEADBEEF, }),
            {R1: 0xCAFEBABE, R4: 0xDEADBEEF,
             CR2_LT: 0, CR2_GT: 1, CR2_EQ: 0, CR2_SO: ExprId('XER_SO_init', 1)})
        pass

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestPPC32Semantic)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
