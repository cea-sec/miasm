import inspect
from pdb import pm

from miasm2.core.sembuilder import SemBuilder
import miasm2.expression.expression as m2_expr
from miasm2.core.asmbloc import asm_label

# Test classes
class IR(object):

    IRDst = m2_expr.ExprId("IRDst")

    def get_next_instr(self, _):
        return asm_label("NEXT")

    def get_next_label(self, _):
        return asm_label("NEXT")

    def gen_label(self):
        return asm_label("GEN")

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

a = m2_expr.ExprId('A')
b = m2_expr.ExprId('B')
c = m2_expr.ExprId('C')
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
for block in res[1]:
    print block
