#! /usr/bin/env python2
#-*- coding:utf-8 -*-

from builtins import range
import unittest


class TestIrIr2STP(unittest.TestCase):

    def test_ExprOp_strcst(self):
        from miasm.expression.expression import ExprInt, ExprOp
        from miasm.ir.translators.translator  import Translator
        translator_smt2 = Translator.to_language("smt2")

        args = [ExprInt(i, 32) for i in range(9)]

        self.assertEqual(
            translator_smt2.from_expr(ExprOp('|',  *args[:2])), r'(bvor (_ bv0 32) (_ bv1 32))')
        self.assertEqual(
            translator_smt2.from_expr(ExprOp('-',  *args[:2])), r'(bvsub (_ bv0 32) (_ bv1 32))')
        self.assertEqual(
            translator_smt2.from_expr(ExprOp('+',  *args[:3])), r'(bvadd (bvadd (_ bv0 32) (_ bv1 32)) (_ bv2 32))')
        self.assertRaises(NotImplementedError, translator_smt2.from_expr, ExprOp('X', *args[:1]))

    def test_ExprSlice_strcst(self):
        from miasm.expression.expression import ExprInt, ExprOp
        from miasm.ir.translators.translator  import Translator
        translator_smt2 = Translator.to_language("smt2")

        args = [ExprInt(i, 32) for i in range(9)]

        self.assertEqual(
            translator_smt2.from_expr(args[0][1:2]), r'((_ extract 1 1) (_ bv0 32))')
        self.assertRaises(ValueError, args[0].__getitem__, slice(1,7,2))

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestIrIr2STP)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))

