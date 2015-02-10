#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest


class TestExpressionExpressionHelper(unittest.TestCase):

    def test_Variables_Identifier(self):
        import miasm2.expression.expression as m2_expr
        from miasm2.expression.expression_helper import Variables_Identifier

        # Build a complex expression
        cst = m2_expr.ExprInt16(0x100)
        eax = m2_expr.ExprId("EAX")
        ebx = m2_expr.ExprId("EBX")
        ax = eax[0:16]
        expr = eax + ebx
        expr = m2_expr.ExprCompose([(ax, 0, 16), (expr[16:32], 16, 32)])
        expr2 = m2_expr.ExprMem((eax + ebx) ^ (eax), size=16)
        expr2 = expr2 | ax | expr2 | cst
        exprf = expr - expr + m2_expr.ExprCompose([(expr2, 0, 16),
                                                   (cst, 16, 32)])

        # Identify variables
        vi = Variables_Identifier(exprf)

        # Use __str__
        print vi

        # Test the result
        new_expr = vi.equation

        ## Force replace in the variable dependency order
        for var_id, var_value in reversed(vi.vars.items()):
            new_expr = new_expr.replace_expr({var_id: var_value})
        self.assertEqual(exprf, new_expr)

        # Test prefix
        vi = Variables_Identifier(exprf, var_prefix="prefix_v")

        ## Use __str__
        print vi

        ## Test the result
        new_expr = vi.equation
        ### Force replace in the variable dependency order
        for var_id, var_value in reversed(vi.vars.items()):
            new_expr = new_expr.replace_expr({var_id: var_value})
        self.assertEqual(exprf, new_expr)

        # Test an identify on an expression already containing identifier
        vi = Variables_Identifier(exprf)
        vi2 = Variables_Identifier(vi.equation)

        ## Test the result
        new_expr = vi2.equation
        ### Force replace in the variable dependency order
        for var_id, var_value in reversed(vi2.vars.items()):
            new_expr = new_expr.replace_expr({var_id: var_value})
        self.assertEqual(vi.equation, new_expr)

        ## Corner case: each sub var depends on itself
        mem1 = m2_expr.ExprMem(ebx, size=32)
        mem2 = m2_expr.ExprMem(mem1, size=32)
        cst2 = m2_expr.ExprInt32(-1)
        expr_mini = ((eax ^ mem2 ^ cst2) & (mem2 ^ (eax + mem2)))[31:32]

        ## Build
        vi = Variables_Identifier(expr_mini)
        vi2 = Variables_Identifier(vi.equation)

        ## Test the result
        new_expr = vi2.equation
        ### Force replace in the variable dependency order
        for var_id, var_value in reversed(vi2.vars.items()):
            new_expr = new_expr.replace_expr({var_id: var_value})
        self.assertEqual(vi.equation, new_expr)



if __name__ == '__main__':
    testcase = TestExpressionExpressionHelper
    testsuite = unittest.TestLoader().loadTestsFromTestCase(testcase)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))

