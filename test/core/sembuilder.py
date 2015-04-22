import inspect

from miasm2.core.sembuilder import SemBuilder
import miasm2.expression.expression as m2_expr

sb = SemBuilder(m2_expr.__dict__)

@sb.parse
def test(Arg1, Arg2, Arg3):
    "Test docstring"
    Arg1 = Arg2
    mem32[Arg1] = Arg2
    mem32[Arg2] = Arg3  + i32(4) - mem32[Arg1]
    Arg3 = Arg3 if Arg2 else i32(0)

a = m2_expr.ExprId('A')
b = m2_expr.ExprId('B')
c = m2_expr.ExprId('C')
ir = None
instr = None
print test(ir, instr, a, b, c)
print test.__doc__
