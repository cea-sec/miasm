#! /usr/bin/env python2
#-*- coding:utf-8 -*-

from __future__ import print_function
import unittest
import logging

from future.utils import viewitems

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.arch.msp430.arch import mn_msp430 as mn, mode_msp430 as mode
from miasm.arch.msp430.sem import Lifter_MSP430 as Lifter
from miasm.arch.msp430.regs import *
from miasm.expression.expression import *
from miasm.core.locationdb import LocationDB

logging.getLogger('cpuhelper').setLevel(logging.ERROR)
loc_db = LocationDB()
EXCLUDE_REGS = set([res, Lifter(loc_db).IRDst])


def M(addr):
    return ExprMem(ExprInt(addr, 16), 16)


def compute(asm, inputstate={}, debug=False):
    loc_db = LocationDB()
    sympool = dict(regs_init)
    sympool.update({k: ExprInt(v, k.size) for k, v in viewitems(inputstate)})
    lifter = Lifter(loc_db)
    ircfg = lifter.new_ircfg()
    symexec = SymbolicExecutionEngine(lifter, sympool)
    instr = mn.fromstring(asm, mode)
    code = mn.asm(instr)[0]
    instr = mn.dis(code, mode)
    instr.offset = inputstate.get(PC, 0)
    loc_key = lifter.add_instr_to_ircfg(instr, ircfg)
    symexec.run_at(ircfg, loc_key)
    if debug:
        for k, v in viewitems(symexec.symbols):
            if regs_init.get(k, None) != v:
                print(k, v)

    result =  {
        k: int(v) for k, v in viewitems(symexec.symbols)
        if k not in EXCLUDE_REGS and regs_init.get(k, None) != v
    }
    return result


class TestMSP430Semantic(unittest.TestCase):

    def test_ADD_W(self):
        # Testing status flags
        self.assertEqual(compute('add.w  0x0000, R4', {R4: 0x0001, }), {
                         R4: 0x0001, nf: 0, zf: 0, cf: 0, of: 0})
        self.assertEqual(compute('add.w  0x0000, R4', {R4: 0xFFFF, }), {
                         R4: 0xFFFF, nf: 1, zf: 0, cf: 0, of: 0})
        self.assertEqual(compute('add.w  0x0000, R4', {R4: 0x0000, }), {
                         R4: 0x0000, nf: 0, zf: 1, cf: 0, of: 0})
        self.assertEqual(compute('add.w  0x0002, R4', {R4: 0xFFFF, }), {
                         R4: 0x0001, nf: 0, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('add.w  0x7FFF, R4', {R4: 0x7FFF, }), {
                         R4: 0xFFFE, nf: 1, zf: 0, cf: 0, of: 1})
        self.assertEqual(compute('add.w  0x8001, R4', {R4: 0x8001, }), {
                         R4: 0x0002, nf: 0, zf: 0, cf: 1, of: 1})
        # Testing addressing mode
        self.assertEqual(compute('add.w     R5,  R4', {R4: 0x1F53, R5: 0x28C4, }), {
                         R4: 0x4817, R5: 0x28C4,             nf: 0, zf: 0, cf: 0, of: 0})
        self.assertEqual(compute('add.w    @R5,  R4', {R4: 0x1F53, R5: 0x28C4, M(0x28C4): 0, }), {
                         R4: 0x1F53, R5: 0x28C4, M(0x28C4): 0, nf: 0, zf: 0, cf: 0, of: 0})
        self.assertEqual(compute('add.w    @R5+, R4', {R4: 0x1F53, R5: 0x28C4, M(0x28C4): 0, }), {
                         R4: 0x1F53, R5: 0x28C6, M(0x28C4): 0, nf: 0, zf: 0, cf: 0, of: 0})
        self.assertEqual(compute('add.w   1(R5), R4', {R4: 0x1F53, R5: 0x28C4, M(0x28C5): 0, }), {
                         R4: 0x1F53, R5: 0x28C4, M(0x28C5): 0, nf: 0, zf: 0, cf: 0, of: 0})
        self.assertEqual(compute('add.w @0x0000, R4', {R4: 0x1F53,          M(0): 0x28C4, }), {
                         R4: 0x4817,          M(0): 0x28C4, nf: 0, zf: 0, cf: 0, of: 0})
        self.assertEqual(compute('add.w  0x0000, R4', {R4: 0x1F53, }), {
                         R4: 0x1F53,                       nf: 0, zf: 0, cf: 0, of: 0})

    def test_AND_B(self):
        # Testing status flags
        self.assertEqual(compute('and.b  0x0001, R4', {R4: 0x0001, }), {
                         R4: 0x0001, nf: 0, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.b  0xFFFF, R4', {R4: 0xFFFF, }), {
                         R4: 0x00FF, nf: 1, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.b  0x0000, R4', {R4: 0x0000, }), {
                         R4: 0x0000, nf: 0, zf: 1, cf: 0, of: 0})
        # Testing addressing mode
        self.assertEqual(compute('and.b     R5,  R4', {R4: 0x1F53, R5: 0x38C4, }), {
                         R4: 0x0040, R5: 0x38C4,             nf: 0, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.b    @R5,  R4', {R4: 0x1F53, R5: 0x38C4, M(0x38C4): 0, }), {
                         R4: 0x0000, R5: 0x38C4, M(0x38C4): 0, nf: 0, zf: 1, cf: 0, of: 0})
        self.assertEqual(compute('and.b    @R5+, R4', {R4: 0x1F53, R5: 0x38C4, M(0x38C4): 0, }), {
                         R4: 0x0000, R5: 0x38C5, M(0x38C4): 0, nf: 0, zf: 1, cf: 0, of: 0})
        self.assertEqual(compute('and.b   1(R5), R4', {R4: 0x1F53, R5: 0x38C4, M(0x38C5): 1, }), {
                         R4: 0x0001, R5: 0x38C4, M(0x38C5): 1, nf: 0, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.b @0x0000, R4', {R4: 0x1F53,          M(0): 0x38C4, }), {
                         R4: 0x0040,          M(0): 0x38C4, nf: 0, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.b  0xFFFF, R4', {R4: 0x1F53, }), {
                         R4: 0x0053,                       nf: 0, zf: 0, cf: 1, of: 0})

    def test_AND_W(self):
        # Testing status flags
        self.assertEqual(compute('and.w  0x0001, R4', {R4: 0x0001, }), {
                         R4: 0x0001, nf: 0, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.w  0xFFFF, R4', {R4: 0xFFFF, }), {
                         R4: 0xFFFF, nf: 1, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.w  0x0000, R4', {R4: 0x0000, }), {
                         R4: 0x0000, nf: 0, zf: 1, cf: 0, of: 0})
        # Testing addressing mode
        self.assertEqual(compute('and.w     R5,  R4', {R4: 0x1F53, R5: 0x38C4, }), {
                         R4: 0x1840, R5: 0x38C4,             nf: 0, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.w    @R5,  R4', {R4: 0x1F53, R5: 0x38C4, M(0x38C4): 0, }), {
                         R4: 0x0000, R5: 0x38C4, M(0x38C4): 0, nf: 0, zf: 1, cf: 0, of: 0})
        self.assertEqual(compute('and.w    @R5+, R4', {R4: 0x1F53, R5: 0x38C4, M(0x38C4): 0, }), {
                         R4: 0x0000, R5: 0x38C6, M(0x38C4): 0, nf: 0, zf: 1, cf: 0, of: 0})
        self.assertEqual(compute('and.w   1(R5), R4', {R4: 0x1F53, R5: 0x38C4, M(0x38C5): 1, }), {
                         R4: 0x0001, R5: 0x38C4, M(0x38C5): 1, nf: 0, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.w @0x0000, R4', {R4: 0x1F53,          M(0): 0x38C4, }), {
                         R4: 0x1840,          M(0): 0x38C4, nf: 0, zf: 0, cf: 1, of: 0})
        self.assertEqual(compute('and.w  0xFFFF, R4', {R4: 0x1F53, }), {
                         R4: 0x1F53,                       nf: 0, zf: 0, cf: 1, of: 0})

    def test_BIC_B(self):
        # Testing addressing mode
        self.assertEqual(
            compute('bic.b 0x0000,     R4',  {R4: 0x1F53, }), {R4: 0x0053, })
        # self.assertEqual(compute('bic.b 0x0000,    @R4',  {R4:0x1F53,M(0x1F53):0x569D, }), {R4:0x1F53,M(0x1F53):0x38C4, })
        # self.assertEqual(compute('bic.b 0x38C4,    @R4+', {R4:0x1F53,M(0x1F53):0x569D, }), {R4:0x1F55,M(0x1F53):0x38C4, })
        # self.assertEqual(compute('bic.b 0x38C4,   1(R4)', {R4:0x1F53,M(0x1F54):0x569D, }), {R4:0x1F53,M(0x1F54):0x5619, })
        # self.assertEqual(compute('bic.b 0x0000, @0x0000', {          M(0x0000):0x569D, }), {          M(0x0000):0x38C4, })
        # self.assertEqual(compute('bic.b 0x38C4,  0xFFFE', {
        # }), {                            })

    def test_CALL(self):
        # Testing addressing mode
        self.assertEqual(compute('call     R4',  {PC: 0x0100, SP: 0x0400, R4: 0x1F53, }), {
                         PC: 0x1F53, SP: 0x03FE, R4: 0x1F53,                 M(0x03FE): 0x102, })
        self.assertEqual(compute('call    @R4',  {PC: 0x0100, SP: 0x0400, R4: 0x1F53, M(0x1F53): 0x38C4, }), {
                         PC: 0x38C4, SP: 0x03FE, R4: 0x1F53, M(0x1F53): 0x38C4, M(0x03FE): 0x102, })
        self.assertEqual(compute('call    @R4+', {PC: 0x0100, SP: 0x0400, R4: 0x1F53, M(0x1F53): 0x38C4, }), {
                         PC: 0x38C4, SP: 0x03FE, R4: 0x1F55, M(0x1F53): 0x38C4, M(0x03FE): 0x102, })
        self.assertEqual(compute('call   1(R4)', {PC: 0x0100, SP: 0x0400, R4: 0x1F53, M(0x1F54): 0x38C4, }), {
                         PC: 0x38C4, SP: 0x03FE, R4: 0x1F53, M(0x1F54): 0x38C4, M(0x03FE): 0x104, })
        self.assertEqual(compute('call @0x0000', {PC: 0x0100, SP: 0x0400,          M(0x0000): 0x38C4, }), {
                         PC: 0x38C4, SP: 0x03FE,          M(0x0000): 0x38C4, M(0x03FE): 0x104, })
        self.assertEqual(compute('call  0xFFFE', {PC: 0x0100, SP: 0x0400, }), {
                         PC: 0xFFFE, SP: 0x03FE,                           M(0x03FE): 0x104, })

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestMSP430Semantic)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
