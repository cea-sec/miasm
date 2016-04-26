from  miasm2.expression.expression import *
from miasm2.expression.expression_helper import ExprDissector

# define expressions
cf = ExprId('cf', size=1)
rbp = ExprId('RBP', size=64)
rdx = ExprId('RDX', size=64)
int1 = ExprInt(0xfffffffffffffffc, 64)
int2 = ExprInt(0xffffffce, 32)
int3 = ExprInt(0x32, 32)
compose1 = ExprCompose([(int2, 0, 32), (int3, 32, 64)])
op1 = rbp + int1 + compose1 + rdx
op2 = int2 + int3
mem1 = ExprMem(op1, 32)
mem2 = ExprMem(op2, 32)
cond1 = ExprCond(mem1, int2, int3)
slice1 = ExprSlice(mem1 + mem2 + cond1, 31, 32)
aff1 = ExprAff(cf, slice1)


dissector = ExprDissector()

assert (dissector.op(cond1) == {op1})
assert (dissector.op(mem2) == {op2})
assert (dissector.slice_(aff1) == {slice1})
assert (dissector.cond(aff1) == {cond1})
assert (dissector.compose(aff1) == {compose1})
assert (dissector.mem(aff1) == {mem1, mem2})
assert (dissector.aff(aff1) == {aff1})
assert (dissector.int_(aff1) == {int1, int2, int3})
assert (dissector.id_(aff1) == {cf, rbp, rdx})
