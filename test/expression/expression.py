#
# Expression regression tests  #
#
from pdb import pm
from miasm2.expression.expression import *
from miasm2.expression.expression_helper import *

# Expression comparison
assert(ExprInt64(-1) != ExprInt64(-2))
assert(ExprInt64(1) != ExprInt32(1))

# Expression size
big_cst = ExprInt(1, size=0x1000)
assert big_cst.size == 0x1000

# Possible values
#- Common constants
A = ExprId("A")
cond1 = ExprId("cond1", 1)
cond2 = ExprId("cond2", 16)
cst1 = ExprInt32(1)
cst2 = ExprInt32(2)
cst3 = ExprInt32(3)
cst4 = ExprInt32(4)

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
    print "*" * 80
    print expr
    sol = possible_values(expr)
    print sol
    print "Resulting constraints:"
    for consval in sol:
        print "For value %s" % consval.value
        for constraint in consval.constraints:
            print "\t%s" % constraint.to_constraint()

# Repr
for expr in [
        cst1,
        A,
        ExprMem(cst1, 32),
        ExprCond(cond1, cst1, cst2),
        A + cst1,
        ExprCompose(A, cst1),
        A.msb(),
        ExprAff(A, cst1),
]:
    print repr(expr)
    assert expr == eval(repr(expr))
