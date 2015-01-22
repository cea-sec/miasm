import z3

from miasm2.expression.expression import *
from miasm2.ir.translators.translator import Translator
from miasm2.ir.translators.z3_ir import TranslatorZ3, Z3Mem

# Some examples of use/unit tests.

def equiv(z3_expr1, z3_expr2):
    s = z3.Solver()
    s.add(z3.Not(z3_expr1 == z3_expr2))
    return s.check() == z3.unsat

def check_interp(interp, constraints, bits=32, valbits=8):
    """Checks that a list of @constraints (addr, value) (as python ints)
    match a z3 FuncInterp (@interp).
    """
    constraints = dict((addr,
                        z3.BitVecVal(val, valbits))
                       for addr, val in constraints)
    l = interp.as_list()
    for entry in l:
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        addr, value = entry[0], entry[1]
        if addr.as_long() in constraints:
            assert equiv(value, constraints[addr.as_long()])

# equiv short test
# --------------------------------------------------------------------------
assert equiv(z3.BitVec('a', 32) + z3.BitVecVal(3, 32) - z3.BitVecVal(1, 32),
             z3.BitVec('a', 32) + z3.BitVecVal(2, 32))

# Z3Mem short tests
# --------------------------------------------------------------------------
mem = Z3Mem(endianness='<') # little endian  
eax = z3.BitVec('EAX', 32)
assert equiv(
         # @32[EAX]
         mem.get(eax, 32),
         # @16[EAX+2] . @16[EAX]
         z3.Concat(mem.get(eax+2, 16), 
                   mem.get(eax, 16)))

# --------------------------------------------------------------------------
ax = z3.BitVec('AX', 16) 
assert not equiv(
        # @16[EAX] with EAX = ZeroExtend(AX)
        mem.get(z3.ZeroExt(16, ax), 16),
        # @16[AX]
        mem.get(ax, 16))

# TranslatorZ3 tests
# --------------------------------------------------------------------------
e = ExprId('x', 32)
ez3 = Translator.to_language('z3').from_expr(e)

z3_e = z3.BitVec('x', 32)
assert equiv(ez3, z3_e)

# --------------------------------------------------------------------------
four = ExprInt32(4)
five = ExprInt32(5)
e2 = (e + five + four) * five
ez3 = Translator.to_language('z3').from_expr(e2)

z3_four = z3.BitVecVal(4, 32)
z3_five = z3.BitVecVal(5, 32)
z3_e2 = (z3_e + z3_five + z3_four) * z3_five
assert equiv(ez3, z3_e2)

# --------------------------------------------------------------------------
emem = ExprMem(ExprInt32(0xdeadbeef), size=32)
emem2 = ExprMem(ExprInt32(0xfee1dead), size=32)
e3 = (emem + e) * ExprInt32(2) * emem2
ez3 = Translator.to_language('z3').from_expr(e3)

mem = Z3Mem()
z3_emem = mem.get(z3.BitVecVal(0xdeadbeef, 32), 32)
z3_emem2 = mem.get(z3.BitVecVal(0xfee1dead, 32), 32)
z3_e3 = (z3_emem + z3_e) * z3.BitVecVal(2, 32) * z3_emem2
assert equiv(ez3, z3_e3)

# --------------------------------------------------------------------------
e4 = emem * five
ez3 = Translator.to_language('z3').from_expr(e4)

z3_e4 = z3_emem * z3_five
assert equiv(ez3, z3_e4)

# Solve constraint and check endianness
solver = z3.Solver()
solver.add(ez3 == 10)
solver.check()
model = solver.model()
check_interp(model[mem.get_mem_array(32)],
             [(0xdeadbeef, 2), (0xdeadbeef + 3, 0)])

# --------------------------------------------------------------------------
ez3 = TranslatorZ3.from_expr(e4, endianness=">")

memb = Z3Mem(endianness=">")
z3_emem = memb.get(z3.BitVecVal(0xdeadbeef, 32), 32)
z3_e4 = z3_emem * z3_five
assert equiv(ez3, z3_e4)

# Solve constraint and check endianness
solver = z3.Solver()
solver.add(ez3 == 10)
solver.check()
model = solver.model()
check_interp(model[memb.get_mem_array(32)],
             [(0xdeadbeef, 0), (0xdeadbeef + 3, 2)])

# --------------------------------------------------------------------------
e5 = ExprSlice(ExprCompose(((e, 0, 32), (four, 32, 64))), 0, 32) * five
ez3 = Translator.to_language('z3').from_expr(e5)

z3_e5 = z3.Extract(31, 0, z3.Concat(z3_four, z3_e)) * z3_five
assert equiv(ez3, z3_e5)

print "TranslatorZ3 tests are OK."

