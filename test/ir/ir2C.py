#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest


class TestIrIr2C(unittest.TestCase):

    def test_ExprOp_toC(self):
        from miasm2.expression.expression import ExprInt32, ExprOp
        import miasm2.ir.ir2C   # /!\ REALLY DIRTY HACK
        args = [ExprInt32(i) for i in xrange(9)]

        # Unary operators
        self.assertEqual(
            ExprOp('parity',  *args[:1]).toC(), r'parity(0x0&0xffffffff)')
        self.assertEqual(
            ExprOp('!',       *args[:1]).toC(), r'(~ 0x0)&0xffffffff')
        self.assertEqual(
            ExprOp('hex2bcd', *args[:1]).toC(), r'hex2bcd_32(0x0)')
        self.assertEqual(ExprOp('fabs',    *args[:1]).toC(), r'fabs(0x0)')
        self.assertRaises(ValueError, ExprOp('X', *args[:1]).toC)

        # Binary operators
        self.assertEqual(
            ExprOp('==',      *args[:2]).toC(), r'(((0x0&0xffffffff) == (0x1&0xffffffff))?1:0)')
        self.assertEqual(
            ExprOp('%',       *args[:2]).toC(), r'(((0x0&0xffffffff)%(0x1&0xffffffff))&0xffffffff)')
        self.assertEqual(
            ExprOp('-',       *args[:2]).toC(), r'(((0x0&0xffffffff) - (0x1&0xffffffff))&0xffffffff)')
        self.assertEqual(
            ExprOp('bsr',     *args[:2]).toC(), r'my_bsr(0x0, 0x1)')
        self.assertEqual(
            ExprOp('cpuid0',  *args[:2]).toC(), r'cpuid0(0x0, 0x1)')
        self.assertEqual(
            ExprOp('fcom0',   *args[:2]).toC(), r'fcom0(0x0, 0x1)')
        self.assertEqual(
            ExprOp('fadd',    *args[:2]).toC(), r'fadd(0x0, 0x1)')
        self.assertEqual(
            ExprOp('segm',    *args[:2]).toC(), r'segm2addr(vmcpu, 0x0, 0x1)')
        self.assertEqual(
            ExprOp('imod',    *args[:2]).toC(), r'imod32(vmcpu, 0x0, 0x1)')
        self.assertEqual(
            ExprOp('bcdadd',  *args[:2]).toC(), r'bcdadd_32(0x0, 0x1)')
        self.assertRaises(ValueError, ExprOp('X', *args[:2]).toC)

        # Ternary operators
        self.assertEqual(
            ExprOp('div8',    *args[:3]).toC(), r'(div_op(32, 0x0, 0x1, 0x2) &0xffffffff)')

        # Other cases
        self.assertEqual(
            ExprOp('+',       *args[:3]).toC(), r'(((0x0&0xffffffff)+(0x1&0xffffffff)+(0x2&0xffffffff))&0xffffffff)')
        self.assertRaises(NotImplementedError, ExprOp('X', *args[:3]).toC)

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestIrIr2C)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
