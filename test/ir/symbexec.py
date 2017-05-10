#! /usr/bin/env python2
#-*- coding:utf-8 -*-

import unittest


class TestSymbExec(unittest.TestCase):

    def test_ClassDef(self):
        from miasm2.expression.expression import ExprInt, ExprId, ExprMem, \
            ExprCompose, ExprAff
        from miasm2.arch.x86.sem import ir_x86_32
        from miasm2.ir.symbexec import SymbolicExecutionEngine
        from miasm2.ir.ir import AssignBlock

        addrX = ExprInt(-1, 32)
        addr0 = ExprInt(0, 32)
        addr1 = ExprInt(1, 32)
        addr8 = ExprInt(8, 32)
        addr9 = ExprInt(9, 32)
        addr20 = ExprInt(20, 32)
        addr40 = ExprInt(40, 32)
        addr50 = ExprInt(50, 32)
        mem0 = ExprMem(addr0)
        mem1 = ExprMem(addr1, 8)
        mem8 = ExprMem(addr8)
        mem9 = ExprMem(addr9)
        mem20 = ExprMem(addr20)
        mem40v = ExprMem(addr40,  8)
        mem40w = ExprMem(addr40, 16)
        mem50v = ExprMem(addr50,  8)
        mem50w = ExprMem(addr50, 16)
        id_x = ExprId('x')
        id_y = ExprId('y', 8)
        id_a = ExprId('a')
        id_eax = ExprId('eax_init')

        e = SymbolicExecutionEngine(ir_x86_32(),
                                    {mem0: id_x, mem1: id_y, mem9: id_x,
                                     mem40w: id_x[:16], mem50v: id_y,
                                     id_a: addr0, id_eax: addr0})
        self.assertEqual(e.find_mem_by_addr(addr0), mem0)
        self.assertEqual(e.find_mem_by_addr(addrX), None)
        self.assertEqual(e.eval_expr(ExprMem(addr1 - addr1)), id_x)
        self.assertEqual(e.eval_expr(ExprMem(addr1, 8)), id_y)
        self.assertEqual(e.eval_expr(ExprMem(addr1 + addr1)), ExprCompose(
            id_x[16:32], ExprMem(ExprInt(4, 32), 16)))
        self.assertEqual(e.eval_expr(mem8), ExprCompose(
            id_x[0:24], ExprMem(ExprInt(11, 32), 8)))
        self.assertEqual(e.eval_expr(mem40v), id_x[:8])
        self.assertEqual(e.eval_expr(mem50w), ExprCompose(
            id_y, ExprMem(ExprInt(51, 32), 8)))
        self.assertEqual(e.eval_expr(mem20), mem20)
        e.func_read = lambda x: x
        self.assertEqual(e.eval_expr(mem20), mem20)
        self.assertEqual(set(e.modified()), set(e.symbols))
        self.assertRaises(
            KeyError, e.symbols.__getitem__, ExprMem(ExprInt(100, 32)))
        self.assertEqual(e.apply_expr(id_eax), addr0)
        self.assertEqual(e.apply_expr(ExprAff(id_eax, addr9)), addr9)
        self.assertEqual(e.apply_expr(id_eax), addr9)

        # apply_change / eval_ir / apply_expr

        ## x = a (with a = 0x0)
        assignblk = AssignBlock({id_x:id_a})
        e.eval_ir(assignblk)
        self.assertEqual(e.apply_expr(id_x), addr0)

        ## x = a (without replacing 'a' with 0x0)
        e.apply_change(id_x, id_a)
        self.assertEqual(e.apply_expr(id_x), id_a)

        ## x = a (with a = 0x0)
        self.assertEqual(e.apply_expr(assignblk.dst2ExprAff(id_x)), addr0)
        self.assertEqual(e.apply_expr(id_x), addr0)

        # state
        self.assertEqual(e.as_assignblock().get_r(), set([id_x, id_y]))


if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestSymbExec)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
