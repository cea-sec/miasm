from z3 import Solver, unsat, parse_smt2_string
from miasm2.expression.expression import *
from miasm2.ir.translators.smt2 import TranslatorSMT2
from miasm2.ir.translators.z3_ir import TranslatorZ3

# create nested expression
a = ExprId("a", 64)
b = ExprId('b', 32)
c = ExprId('c', 16)
d = ExprId('d', 8)
e = ExprId('e', 1)

left = ExprCond(e + ExprOp('parity', a),
                ExprMem(a * a, 64),
                ExprMem(a, 64))

cond = ExprSlice(ExprSlice(ExprSlice(a, 0, 32) + b, 0, 16) * c, 0, 8) << ExprOp('>>>', d, ExprInt(0x5L, 8))
right = ExprCond(cond,
                 a + ExprInt(0x64L, 64),
                 ExprInt(0x16L, 64))

e = ExprAff(left, right)

# initialise translators
t_z3 = TranslatorZ3()
t_smt2 = TranslatorSMT2()

# translate to z3
e_z3 = t_z3.from_expr(e)
# translate to smt2
smt2 = t_smt2.to_smt2([t_smt2.from_expr(e)])

# parse smt2 string with z3
smt2_z3 = parse_smt2_string(smt2)
# initialise SMT solver
s = Solver()

# prove equivalence of z3 and smt2 translation
s.add(e_z3 != smt2_z3)
assert (s.check() == unsat)
