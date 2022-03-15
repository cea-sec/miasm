from __future__ import print_function

import miasm.expression.expression as m2_expr
from miasm.expression.simplifications import ExpressionSimplifier

# Creates an expression simplifier that (by default) applies no simplifications.
# Other instances with simplifications enabled by default can be found in `expressions/simplifications.py`.
simp = ExpressionSimplifier()

print("""
Expression simplification demo: Adding a simplification:
a + a + a == a * 3

More detailed examples can be found in miasm/expression/simplification*.
""")


# Define the simplification method
## @expr_simp is the current expression simplifier instance
## (for recursive simplifications)
## @expr is the expression to (perhaps) simplify
def simp_add_mul(expr_simp, expr):
    "Naive Simplification: a + a + a == a * 3"

    # Match the expected form
    ## isinstance(expr, m2_expr.ExprOp) is not needed: simplifications are
    ## attached to expression types
    if expr.op == "+" and \
            len(expr.args) == 3 and \
            expr.args.count(expr.args[0]) == len(expr.args):

        # Effective simplification
        return m2_expr.ExprOp("*", expr.args[0],
                              m2_expr.ExprInt(3, expr.args[0].size))
    else:
        # Do not simplify
        return expr


a = m2_expr.ExprId('a', 32)
base_expr = a + a + a
print("Without adding the simplification:")
print("\t%s = %s" % (base_expr, simp(base_expr)))

# Enable pass
simp.enable_passes({m2_expr.ExprOp: [simp_add_mul]})

print("After adding the simplification:")
print("\t%s = %s" % (base_expr, simp(base_expr)))

assert simp(base_expr) == m2_expr.ExprOp("*", a,
                                         m2_expr.ExprInt(3, a.size))
