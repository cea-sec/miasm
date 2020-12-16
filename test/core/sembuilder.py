from __future__ import print_function
import inspect
from pdb import pm

from miasm.core.sembuilder import SemBuilder
from miasm.core.locationdb import LocationDB
import miasm.expression.expression as m2_expr



# Test classes
class IR(object):
    def __init__(self, loc_db):
        self.loc_db = loc_db

    IRDst = m2_expr.ExprId("IRDst", 32)

    def get_next_instr(self, _):
        return m2_expr.LocKey(0)

    def get_next_loc_key(self, _):
        return m2_expr.LocKey(0)

class Instr(object):
    mode = 32

# Test
sb = SemBuilder(m2_expr.__dict__)

@sb.parse
def test(Arg1, Arg2, Arg3):
    "Test docstring"
    Arg1 = Arg2
    value1 = Arg2
    value2 = Arg3  + i32(4) - ExprMem(Arg1, 32)
    Arg3 = Arg3 if Arg2 + value1 else i32(0) + value2
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
loc_db = LocationDB()
ir = IR(loc_db)
instr = Instr()
res = test(ir, instr, a, b, c)

print("[+] Returned:")
print(res)
print("[+] DocString:", test.__doc__)

print("[+] Cur instr:")
for statement in res[0]:
    print(statement)

print("[+] Blocks:")
for irb in res[1]:
    print(irb.loc_key)
    for assignblk in irb:
        for expr in assignblk:
            print(expr)
        print()
