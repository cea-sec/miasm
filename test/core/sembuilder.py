import inspect
from pdb import pm

from miasm2.core.sembuilder import SemBuilder
import miasm2.expression.expression as m2_expr
from miasm2.core.asmblock import AsmLabel

# Test classes
class IR(object):

    IRDst = m2_expr.ExprId("IRDst", 32)

    def get_next_instr(self, _):
        return AsmLabel(m2_expr.LocKey(0), "NEXT")

    def get_next_label(self, _):
        return AsmLabel(m2_expr.LocKey(0), "NEXT")

    def gen_label(self):
        return AsmLabel(m2_expr.LocKey(1), "GEN")

class Instr(object):
    mode = 32

# Test
sb = SemBuilder(m2_expr.__dict__)

@sb.parse
def test(Arg1, Arg2, Arg3):
    "Test docstring"
    Arg1 = Arg2
    mem32[Arg1] = Arg2
    mem32[Arg2] = Arg3  + i32(4) - mem32[Arg1]
    Arg3 = Arg3 if Arg2 else i32(0)
    tmpvar = 'myop'(i32(2))
    Arg2 = ('myopsize%d' % Arg1.size)(tmpvar, Arg1)
    alias = Arg1[:24]

    if not Arg1:
        Arg2 = Arg3
    else:
        alias = {i16(4), i8(5)}

a = m2_expr.ExprId('A', 32)
b = m2_expr.ExprId('B', 32)
c = m2_expr.ExprId('C', 32)
ir = IR()
instr = Instr()
res = test(ir, instr, a, b, c)

print "[+] Returned:"
print res
print "[+] DocString:", test.__doc__

print "[+] Cur instr:"
for statement in res[0]:
    print statement

print "[+] Blocks:"
for irb in res[1]:
    print irb.label
    for assignblk in irb:
        for expr in assignblk:
            print expr
        print
