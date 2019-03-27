#! /usr/bin/env python2
#-*- coding:utf-8 -*-

from builtins import range
import unittest
from miasm.expression.expression import TOK_EQUAL

class TestIrIr2C(unittest.TestCase):

    def translationTest(self, expr, expected):
        from miasm.ir.translators import Translator

        translator = Translator.to_language("C")
        self.assertEqual(translator.from_expr(expr), expected)

    def test_ExprOp_toC(self):
        from miasm.expression.expression import ExprInt, ExprOp
        from miasm.ir.translators.C import Translator

        args = [ExprInt(i, 32) for i in range(9)]
        translator = Translator.to_language("C")

        # Unary operators
        self.translationTest(
            ExprOp('parity',  *args[:1]), r'parity(0x0&0xffffffff)')
        self.translationTest(
            ExprOp('!',       *args[:1]), r'(~ 0x0)&0xffffffff')
        self.translationTest(
            ExprOp('hex2bcd', *args[:1]), r'hex2bcd_32(0x0)')
        self.translationTest(ExprOp('fabs',    *args[:1]), r'fabs(0x0)')
        self.assertRaises(NotImplementedError, translator.from_expr,
                          ExprOp('X', *args[:1]))

        # Binary operators
        self.translationTest(
            ExprOp(TOK_EQUAL,      *args[:2]), r'(((0x0&0xffffffff) == (0x1&0xffffffff))?1:0)')
        self.translationTest(
            ExprOp('%',       *args[:2]), r'(((0x0&0xffffffff)%(0x1&0xffffffff))&0xffffffff)')
        self.translationTest(
            ExprOp('-',       *args[:2]), r'(((0x0&0xffffffff) - (0x1&0xffffffff))&0xffffffff)')
        self.translationTest(
            ExprOp('cntleadzeros',     *args[:1]), r'cntleadzeros(0x0, 0x20)')
        self.translationTest(
            ExprOp('x86_cpuid',  *args[:2]), r'x86_cpuid(0x0, 0x1)')
        self.translationTest(
            ExprOp('fcom0',   *args[:2]), r'fcom0(0x0, 0x1)')
        self.translationTest(
            ExprOp('fadd',    *args[:2]), r'fadd(0x0, 0x1)')
        self.translationTest(
            ExprOp('segm',    *args[:2]), r'segm2addr(jitcpu, 0x0, 0x1)')
        self.translationTest(
            ExprOp('imod',    *args[:2]), r'imod32((struct vm_cpu*)jitcpu->cpu, 0x0, 0x1)')
        self.translationTest(
            ExprOp('bcdadd',  *args[:2]), r'bcdadd_32(0x0, 0x1)')
        self.assertRaises(NotImplementedError, translator.from_expr,
                          ExprOp('X', *args[:2]))

        # Other cases
        self.translationTest(
            ExprOp('+',       *args[:3]), r'(((0x0&0xffffffff)+(0x1&0xffffffff)+(0x2&0xffffffff))&0xffffffff)')
        self.assertRaises(NotImplementedError, translator.from_expr,
                          ExprOp('X', *args[:3]))

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestIrIr2C)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
