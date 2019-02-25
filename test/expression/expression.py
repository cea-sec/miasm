from __future__ import print_function
#
# Expression regression tests  #
#
from pdb import pm
from miasm2.expression.expression import *
from miasm2.expression.expression_helper import *

# Expression comparison
assert(ExprInt(-1, 64) != ExprInt(-2, 64))
assert(ExprInt(1, 64) != ExprInt(1, 32))

# Expression size
big_cst = ExprInt(1, size=0x1000)
assert big_cst.size == 0x1000

# Possible values
#- Common constants
A = ExprId("A", 32)
cond1 = ExprId("cond1", 1)
cond2 = ExprId("cond2", 16)
cst1 = ExprInt(1, 32)
cst2 = ExprInt(2, 32)
cst3 = ExprInt(3, 32)
cst4 = ExprInt(4, 32)

#- Launch tests
for expr in [
        cst1,
        A,
        ExprMem(cst1, 32),
        ExprCond(cond1, cst1, cst2),
        ExprMem(ExprCond(cond1, cst1, cst2), 16),
        ExprCond(cond1,
                 ExprCond(cond2, cst3, cst4),
                 cst2),
        A + cst1,
        A + ExprCond(cond1, cst1, cst2),
        ExprCond(cond1, cst1, cst2) + ExprCond(cond2, cst3, cst4),
        ExprCompose(A, cst1),
        ExprCompose(ExprCond(cond1, cst1, cst2), A),
        ExprCompose(ExprCond(cond1, cst1, cst2),
                    ExprCond(cond2, cst3, cst4)),
        ExprCond(ExprCond(cond1, cst1, cst2), cst3, cst4),
]:
    print("*" * 80)
    print(expr)
    sol = possible_values(expr)
    print(sol)
    print("Resulting constraints:")
    for consval in sol:
        print("For value %s" % consval.value)
        for constraint in consval.constraints:
            print("\t%s" % constraint.to_constraint())

# Repr
for expr in [
        cst1,
        A,
        ExprMem(cst1, 32),
        ExprCond(cond1, cst1, cst2),
        A + cst1,
        ExprCompose(A, cst1),
        A.msb(),
        ExprAssign(A, cst1),
]:
    print(repr(expr))
    assert expr == eval(repr(expr))


aff = ExprAssign(A[0:32], cst1)

assert aff.dst == A and aff.src == cst1
