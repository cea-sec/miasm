import z3
from miasm.ir.translators import Translator
from miasm.expression.expression import *

translator = Translator.to_language("z3")

values = [
    (42, 10, 4, 2),
    (-42, 10, -4, -2),
    (42, -10, -4, 2),
    (-42, -10, 4, -2)
]

for a, b, c, d in values:
    cst_a = ExprInt(a, 8)
    cst_b = ExprInt(b, 8)

    div_result = ExprInt(c, 8)
    div = ExprOp("sdiv", cst_a, cst_b)
    print("%d / %d == %d" % (a, b, div_result))
    solver = z3.Solver()
    print("%s == %s" %(div, div_result))
    eq1 = translator.from_expr(div) != translator.from_expr(div_result)
    solver.add(eq1)
    result = solver.check()
    assert result == z3.unsat

    mod_result = ExprInt(d, 8)
    print("%d %% %d == %d" % (a, b, mod_result))
    res2 = ExprOp("smod", cst_a, cst_b)
    solver = z3.Solver()
    print("%s == %s" %(res2, mod_result))
    eq2 = translator.from_expr(res2) != translator.from_expr(mod_result)
    solver.add(eq2)
    result = solver.check()
    assert result == z3.unsat

