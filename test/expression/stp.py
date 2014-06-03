#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest


class TestIrIr2STP(unittest.TestCase):

    def test_ExprOp_strcst(self):
        from miasm2.expression.expression import ExprInt32, ExprOp
        import miasm2.expression.stp   # /!\ REALLY DIRTY HACK
        args = [ExprInt32(i) for i in xrange(9)]

        self.assertEqual(
            ExprOp('|',  *args[:2]).strcst(), r'(0bin00000000000000000000000000000000 | 0bin00000000000000000000000000000001)')
        self.assertEqual(
            ExprOp('-',  *args[:2]).strcst(), r'BVUMINUS(0bin00000000000000000000000000000000)')
        self.assertEqual(
            ExprOp('+',  *args[:3]).strcst(), r'BVPLUS(32,BVPLUS(32,0bin00000000000000000000000000000000, 0bin00000000000000000000000000000001), 0bin00000000000000000000000000000010)')
        self.assertRaises(ValueError, ExprOp('X', *args[:1]).strcst)

    def test_ExprSlice_strcst(self):
        from miasm2.expression.expression import ExprInt32, ExprSlice
        import miasm2.expression.stp   # /!\ REALLY DIRTY HACK
        args = [ExprInt32(i) for i in xrange(9)]

        self.assertEqual(
            args[0][1:2].strcst(), r'(0bin00000000000000000000000000000000)[1:1]')
        self.assertRaises(ValueError, args[0].__getitem__, slice(1,7,2))

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestIrIr2STP)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))

