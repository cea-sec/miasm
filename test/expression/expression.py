from __future__ import print_function
#
# Expression regression tests  #
#
from pdb import pm
from miasm.expression.expression import *
from miasm.expression.expression_helper import *

# Expression comparison
assert(ExprInt(-1, 64) != ExprInt(-2, 64))
assert(ExprInt(1, 64) != ExprInt(1, 32))

# Expression size
big_cst = ExprInt(1, size=0x1000)
assert big_cst.size == 0x1000

# Possible values
#- Common constants
A = ExprId("A", 32)
B = ExprId("B", 32)
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


mem = ExprMem(A, 32)
assert mem.get_r() == set([mem])
assert mem.get_r(mem_read=True) == set([mem, A])

C = A+B
D = C + A

assert A in A
assert A in C
assert B in C
assert C in C

assert A in D
assert B in D
assert C in D
assert D in D

assert C not in A
assert C not in B

assert D not in A
assert D not in B
assert D not in C


assert cst1.get_r(cst_read=True) == set([cst1])
mem1 = ExprMem(A, 32)
mem2 = ExprMem(mem1 + B, 32)
assert mem2.get_r() == set([mem2])

assign1 = ExprAssign(A, cst1)
assert assign1.get_r() == set([])

assign2 = ExprAssign(mem1, D)
assert assign2.get_r() == set([A, B])
assert assign2.get_r(mem_read=True) == set([A, B])
assert assign2.get_w() == set([mem1])

assign3 = ExprAssign(mem1, mem2)
assert assign3.get_r() == set([mem2])
assert assign3.get_r(mem_read=True) == set([mem1, mem2, A, B])
assert assign3.get_w() == set([mem1])
