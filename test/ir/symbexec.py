#! /usr/bin/env python2
#-*- coding:utf-8 -*-

from __future__ import print_function

from future.utils import viewitems

import unittest


class TestSymbExec(unittest.TestCase):

    def test_ClassDef(self):
        from miasm.expression.expression import ExprInt, ExprId, ExprMem, \
            ExprCompose, ExprAssign
        from miasm.arch.x86.sem import Lifter_X86_32
        from miasm.core.locationdb import LocationDB
        from miasm.ir.symbexec import SymbolicExecutionEngine
        from miasm.ir.ir import AssignBlock


        loc_db = LocationDB()
        lifter_model_call = Lifter_X86_32(loc_db)
        ircfg = lifter_model_call.new_ircfg()

        id_x = ExprId('x', 32)
        id_a = ExprId('a', 32)
        id_b = ExprId('b', 32)
        id_c = ExprId('c', 32)
        id_d = ExprId('d', 32)
        id_e = ExprId('e', 64)

        class CustomSymbExec(SymbolicExecutionEngine):
            def mem_read(self, expr):
                if expr == ExprMem(ExprInt(0x1000, 32), 32):
                    return id_x
                return super(CustomSymbExec, self).mem_read(expr)

        sb = CustomSymbExec(lifter_model_call,
                            {
                                ExprMem(ExprInt(0x4, 32), 8): ExprInt(0x44, 8),
                                ExprMem(ExprInt(0x5, 32), 8): ExprInt(0x33, 8),
                                ExprMem(ExprInt(0x6, 32), 8): ExprInt(0x22, 8),
                                ExprMem(ExprInt(0x7, 32), 8): ExprInt(0x11, 8),

                                ExprMem(ExprInt(0x20, 32), 32): id_x,

                                ExprMem(ExprInt(0x40, 32), 32): id_x,
                                ExprMem(ExprInt(0x44, 32), 32): id_a,

                                ExprMem(ExprInt(0x54, 32), 32): ExprInt(0x11223344, 32),

                                ExprMem(id_a, 32): ExprInt(0x11223344, 32),
                                id_a: ExprInt(0, 32),
                                id_b: ExprInt(0, 32),

                                ExprMem(id_c, 32): ExprMem(id_d + ExprInt(0x4, 32), 32),
                                ExprMem(id_c + ExprInt(0x4, 32), 32): ExprMem(id_d + ExprInt(0x8, 32), 32),

                            })


        self.assertEqual(sb.eval_expr(ExprInt(1, 32)-ExprInt(1, 32)), ExprInt(0, 32))

        ## Test with unknown mem + integer
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0, 32), 32)), ExprMem(ExprInt(0, 32), 32))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(1, 32), 32)), ExprCompose(ExprMem(ExprInt(1, 32), 24), ExprInt(0x44, 8)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(2, 32), 32)), ExprCompose(ExprMem(ExprInt(2, 32), 16), ExprInt(0x3344, 16)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(3, 32), 32)), ExprCompose(ExprMem(ExprInt(3, 32), 8), ExprInt(0x223344, 24)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(4, 32), 32)), ExprInt(0x11223344, 32))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(5, 32), 32)), ExprCompose(ExprInt(0x112233, 24), ExprMem(ExprInt(8, 32), 8)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(6, 32), 32)), ExprCompose(ExprInt(0x1122, 16), ExprMem(ExprInt(8, 32), 16)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(7, 32), 32)), ExprCompose(ExprInt(0x11, 8), ExprMem(ExprInt(8, 32), 24)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(8, 32), 32)), ExprMem(ExprInt(8, 32), 32))

        ## Test with unknown mem + integer
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x50, 32), 32)), ExprMem(ExprInt(0x50, 32), 32))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x51, 32), 32)), ExprCompose(ExprMem(ExprInt(0x51, 32), 24), ExprInt(0x44, 8)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x52, 32), 32)), ExprCompose(ExprMem(ExprInt(0x52, 32), 16), ExprInt(0x3344, 16)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x53, 32), 32)), ExprCompose(ExprMem(ExprInt(0x53, 32), 8), ExprInt(0x223344, 24)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x54, 32), 32)), ExprInt(0x11223344, 32))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x55, 32), 32)), ExprCompose(ExprInt(0x112233, 24), ExprMem(ExprInt(0x58, 32), 8)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x56, 32), 32)), ExprCompose(ExprInt(0x1122, 16), ExprMem(ExprInt(0x58, 32), 16)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x57, 32), 32)), ExprCompose(ExprInt(0x11, 8), ExprMem(ExprInt(0x58, 32), 24)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x58, 32), 32)), ExprMem(ExprInt(0x58, 32), 32))



        ## Test with unknown mem + id
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x1D, 32), 32)), ExprCompose(ExprMem(ExprInt(0x1D, 32), 24), id_x[:8]))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x1E, 32), 32)), ExprCompose(ExprMem(ExprInt(0x1E, 32), 16), id_x[:16]))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x1F, 32), 32)), ExprCompose(ExprMem(ExprInt(0x1F, 32), 8), id_x[:24]))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x20, 32), 32)), id_x)
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x21, 32), 32)), ExprCompose(id_x[8:], ExprMem(ExprInt(0x24, 32), 8)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x22, 32), 32)), ExprCompose(id_x[16:], ExprMem(ExprInt(0x24, 32), 16)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x23, 32), 32)), ExprCompose(id_x[24:], ExprMem(ExprInt(0x24, 32), 24)))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x24, 32), 32)), ExprMem(ExprInt(0x24, 32), 32))


        ## Partial read
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(4, 32), 8)), ExprInt(0x44, 8))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x20, 32), 8)), id_x[:8])
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x23, 32), 8)), id_x[24:])


        ## Merge
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x40, 32), 64)), ExprCompose(id_x, id_a))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x42, 32), 32)), ExprCompose(id_x[16:], id_a[:16]))

        # Merge memory
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x100, 32), 32)), ExprMem(ExprInt(0x100, 32), 32))
        self.assertEqual(sb.eval_expr(ExprMem(id_c + ExprInt(0x2, 32), 32)), ExprMem(id_d  + ExprInt(0x6, 32), 32))

        ## Unmodified read
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(4, 32), 8)), ExprInt(0x44, 8))

        ## Modified read
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x1000, 32), 32)), id_x)


        ## Apply_change / eval_ir / apply_expr

        ## x = a (with a = 0x0)
        assignblk = AssignBlock({id_x:id_a})
        sb.eval_updt_assignblk(assignblk)
        self.assertEqual(sb.eval_expr(id_x), ExprInt(0, 32))

        ## x = a (without replacing 'a' with 0x0)
        sb.apply_change(id_x, id_a)
        self.assertEqual(sb.eval_expr(id_x), id_a)

        ## x = a (with a = 0x0)
        self.assertEqual(sb.eval_updt_expr(assignblk.dst2ExprAssign(id_x)), ExprInt(0, 32))
        self.assertEqual(sb.eval_expr(id_x), ExprInt(0, 32))
        self.assertEqual(sb.eval_updt_expr(id_x), ExprInt(0, 32))

        sb.dump()

        ## state
        reads = set()
        for dst, src in sb.modified():
            reads.update(ExprAssign(dst, src).get_r())

        self.assertEqual(reads, set([
            id_x, id_a,
            ExprMem(id_d + ExprInt(0x4, 32), 32),
            ExprMem(id_d + ExprInt(0x8, 32), 32),
        ]))

        # Erase low id_x byte with 0xFF
        sb.apply_change(ExprMem(ExprInt(0x20, 32), 8), ExprInt(0xFF, 8))
        state = dict(sb.modified(ids=False))
        self.assertEqual(state[ExprMem(ExprInt(0x20, 32), 8)], ExprInt(0xFF, 8))
        self.assertEqual(state[ExprMem(ExprInt(0x21, 32), 24)], id_x[8:32])

        # Erase high id_x byte with 0xEE
        sb.apply_change(ExprMem(ExprInt(0x23, 32), 8), ExprInt(0xEE, 8))

        state = dict(sb.modified(ids=False))
        self.assertEqual(state[ExprMem(ExprInt(0x20, 32), 8)], ExprInt(0xFF, 8))
        self.assertEqual(state[ExprMem(ExprInt(0x21, 32), 16)], id_x[8:24])
        self.assertEqual(state[ExprMem(ExprInt(0x23, 32), 8)], ExprInt(0xEE, 8))

        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x22, 32), 32)), ExprCompose(id_x[16:24], ExprInt(0xEE, 8), ExprMem(ExprInt(0x24, 32), 16)))

        # Erase low byte of 0x11223344 with 0xFF at 0x54
        sb.apply_change(ExprMem(ExprInt(0x54, 32), 8), ExprInt(0xFF, 8))

        # Erase low byte of 0x11223344 with 0xFF at id_a
        sb.apply_change(ExprMem(id_a + ExprInt(0x1, 32), 8), ExprInt(0xFF, 8))
        state = dict(sb.modified(ids=False))
        self.assertEqual(state[ExprMem(id_a + ExprInt(0x1, 32), 8)], ExprInt(0xFF, 8))
        self.assertEqual(state[ExprMem(id_a + ExprInt(0x2, 32), 16)], ExprInt(0x1122, 16))

        # Write uint32_t at 0xFFFFFFFE
        sb.apply_change(ExprMem(ExprInt(0xFFFFFFFE, 32), 32), ExprInt(0x11223344, 32))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0, 32), 16)), ExprInt(0x1122, 16))

        # Revert memory to original value at 0x42
        sb.apply_change(ExprMem(ExprInt(0x42, 32), 32), ExprMem(ExprInt(0x42, 32), 32))
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0x42, 32), 32)), ExprMem(ExprInt(0x42, 32), 32))

        # Revert memory to original value at c + 0x2
        sb.apply_change(ExprMem(id_c + ExprInt(0x2, 32), 32), ExprMem(id_c + ExprInt(0x2, 32), 32))
        self.assertEqual(sb.eval_expr(ExprMem(id_c + ExprInt(0x2, 32), 32)), ExprMem(id_c + ExprInt(0x2, 32), 32))

        # Test del symbol
        del sb.symbols[id_a]
        sb.dump()
        del sb.symbols[ExprMem(id_a, 8)]
        print("*"*40, 'Orig:')
        sb.dump()

        sb_cp = sb.symbols.copy()
        print("*"*40, 'Copy:')
        sb_cp.dump()

        # Add symbol at address limit
        sb.apply_change(ExprMem(ExprInt(0xFFFFFFFE, 32), 32), id_c)
        sb.dump()
        found = False
        for dst, src in viewitems(sb.symbols):
            if dst == ExprMem(ExprInt(0xFFFFFFFE, 32), 32) and src == id_c:
                found = True
        assert found


        # Add symbol at address limit
        sb.apply_change(ExprMem(ExprInt(0x7FFFFFFE, 32), 32), id_c)
        sb.dump()
        found = False
        for dst, src in viewitems(sb.symbols):
            if dst == ExprMem(ExprInt(0x7FFFFFFE, 32), 32) and src == id_c:
                found = True
        assert found



        # Add truncated symbol at address limit
        sb.apply_change(ExprMem(ExprInt(0xFFFFFFFC, 32), 64), id_e)
        # Revert parts of memory
        sb.apply_change(ExprMem(ExprInt(0xFFFFFFFC, 32), 16), ExprMem(ExprInt(0xFFFFFFFC, 32), 16))
        sb.apply_change(ExprMem(ExprInt(0x2, 32), 16), ExprMem(ExprInt(0x2, 32), 16))
        sb.dump()
        found = False
        for dst, src in viewitems(sb.symbols):
            if dst == ExprMem(ExprInt(0xFFFFFFFE, 32), 32) and src == id_e[16:48]:
                found = True
        assert found


        sb_empty = SymbolicExecutionEngine(lifter_model_call)
        sb_empty.dump()


        # Test memory full
        print('full')
        arch_addr8 = Lifter_X86_32(loc_db)
        ircfg = arch_addr8.new_ircfg()
        # Hack to obtain tiny address space
        arch_addr8.addrsize = 5
        sb_addr8 = SymbolicExecutionEngine(arch_addr8)
        sb_addr8.dump()
        # Fulfill memory
        sb_addr8.apply_change(ExprMem(ExprInt(0, 5), 256), ExprInt(0, 256))
        sb_addr8.dump()
        variables = list(viewitems(sb_addr8.symbols))
        assert variables == [(ExprMem(ExprInt(0, 5), 256), ExprInt(0, 256))]

        print(sb_addr8.symbols.symbols_mem)

        sb_addr8.apply_change(ExprMem(ExprInt(0x5, 5), 256), ExprInt(0x123, 256))
        sb_addr8.dump()
        variables = list(viewitems(sb_addr8.symbols))
        assert variables == [(ExprMem(ExprInt(0x5, 5), 256), ExprInt(0x123, 256))]
        print(sb_addr8.symbols.symbols_mem)

        print('dump')
        sb_addr8.symbols.symbols_mem.dump()


        sb.dump()
        try:
            del sb.symbols.symbols_mem[ExprMem(ExprInt(0xFFFFFFFF, 32), 32)]
        except KeyError:
            # ok
            pass
        else:
            raise RuntimeError("Should raise error!")


        del sb.symbols.symbols_mem[ExprMem(ExprInt(0xFFFFFFFF, 32), 16)]
        sb.dump()
        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0xFFFFFFFE, 32), 32)),
                         ExprCompose(id_e[16:24], ExprMem(ExprInt(0xFFFFFFFF, 32), 16), id_e[40:48]))
        sb.symbols.symbols_mem.delete_partial(ExprMem(ExprInt(0xFFFFFFFF, 32), 32))

        self.assertEqual(sb.eval_expr(ExprMem(ExprInt(0xFFFFFFFE, 32), 32)),
                         ExprCompose(id_e[16:24], ExprMem(ExprInt(0xFFFFFFFF, 32), 24)))

        sb.dump()

        assert ExprMem(ExprInt(0xFFFFFFFE, 32), 8) in sb.symbols
        assert ExprMem(ExprInt(0xFFFFFFFE, 32), 32) not in sb.symbols
        assert sb.symbols.symbols_mem.contains_partial(ExprMem(ExprInt(0xFFFFFFFE, 32), 32))
        assert not sb.symbols.symbols_mem.contains_partial(ExprMem(ExprInt(0xFFFFFFFF, 32), 8))

        assert list(sb_addr8.symbols) == [ExprMem(ExprInt(0x5, 5), 256)]


if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestSymbExec)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
