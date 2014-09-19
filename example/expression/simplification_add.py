import miasm2.expression.expression as m2_expr
from miasm2.expression.simplifications import expr_simp
from pdb import pm
import os

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

print """
Expression simplification demo: Adding a simplification:
a + a + a == a * 3

More detailed examples can be found in miasm2/expression/simplification*.
"""

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
                              m2_expr.ExprInt_from(expr.args[0], 3))
    else:
        # Do not simplify
        return expr

a = m2_expr.ExprId('a')
base_expr = a + a + a
print "Without adding the simplification:"
print "\t%s = %s" % (base_expr, expr_simp(base_expr))

# Enable pass
expr_simp.enable_passes({m2_expr.ExprOp: [simp_add_mul]})

print "After adding the simplification:"
print "\t%s = %s" % (base_expr, expr_simp(base_expr))

# Automatic fail
assert(expr_simp(base_expr) == m2_expr.ExprOp("*", a,
                                              m2_expr.ExprInt_from(a, 3)))
