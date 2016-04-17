from  miasm2.expression.expression import *
from miasm2.expression.expression_dissector import ExprDissector

# define expressions
cf = ExprId('cf', size=1)
rbp = ExprId('RBP', size=64)
rdx = ExprId('RDX', size=64)
int1 = ExprInt(0xfffffffffffffffc, 64)
int2 = ExprInt(0xffffffce, 32)
int3 = ExprInt(0x32, 32)
compose = ExprCompose([(int2, 0, 32), (int3, 32, 64)])
op1 = rbp + int1 + compose + rdx
op2 = int2 + int3
mem1 = ExprMem(op1, 32)
mem2 = ExprMem(op2, 32)
cond = ExprCond(mem1, int2, int3)
slice = ExprSlice(mem1 + mem2 + cond, 31, 32)
aff = ExprAff(cf, slice)


dissector = ExprDissector()

assert (dissector.op(cond) == {op1})
assert (dissector.op(mem2) == {op2})
assert (dissector.slice(aff) == {slice})
assert (dissector.cond(aff) == {cond})
assert (dissector.compose(aff) == {compose})
assert (dissector.mem(aff) == {mem1, mem2})
assert (dissector.aff(aff) == {aff})
assert (dissector.int(aff) == {int1, int2, int3})
assert (dissector.id(aff) == {cf, rbp, rdx})
