from __future__ import print_function
import z3

from miasm.core.locationdb import LocationDB
from miasm.expression.expression import *
from miasm.ir.translators.z3_ir import Z3Mem, TranslatorZ3

# Some examples of use/unit tests.

loc_db = LocationDB()
translator1 = TranslatorZ3(endianness="<", loc_db=loc_db)
translator2 = TranslatorZ3(endianness=">", loc_db=loc_db)


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
    entry = interp.children()
    assert len(entry) == 3
    _, addr, value = entry
    addr = addr.as_long()
    assert addr in constraints
    assert equiv(value, constraints[addr])

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
ez3 = translator1.from_expr(e)

z3_e = z3.BitVec('x', 32)
assert equiv(ez3, z3_e)

# --------------------------------------------------------------------------
four = ExprInt(4, 32)
five = ExprInt(5, 32)
e2 = (e + five + four) * five
ez3 = translator1.from_expr(e2)

z3_four = z3.BitVecVal(4, 32)
z3_five = z3.BitVecVal(5, 32)
z3_e2 = (z3_e + z3_five + z3_four) * z3_five
assert equiv(ez3, z3_e2)

# --------------------------------------------------------------------------
emem = ExprMem(ExprInt(0xdeadbeef, 32), size=32)
emem2 = ExprMem(ExprInt(0xfee1dead, 32), size=32)
e3 = (emem + e) * ExprInt(2, 32) * emem2
ez3 = translator1.from_expr(e3)

mem = Z3Mem()
z3_emem = mem.get(z3.BitVecVal(0xdeadbeef, 32), 32)
z3_emem2 = mem.get(z3.BitVecVal(0xfee1dead, 32), 32)
z3_e3 = (z3_emem + z3_e) * z3.BitVecVal(2, 32) * z3_emem2
assert equiv(ez3, z3_e3)

# --------------------------------------------------------------------------
e4 = emem * five
ez3 = translator1.from_expr(e4)

z3_e4 = z3_emem * z3_five
assert equiv(ez3, z3_e4)

# Solve constraint and check endianness
solver = z3.Solver()
solver.add(ez3 == 10)
solver.check()
model = solver.model()
check_interp(model[mem.get_mem_array(32)],
             [(0xdeadbeef, 2)])

# --------------------------------------------------------------------------
ez3 = translator2.from_expr(e4)

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
             [(0xdeadbeef+3, 2)])

# --------------------------------------------------------------------------
e5 = ExprSlice(ExprCompose(e, four), 0, 32) * five
ez3 = translator1.from_expr(e5)

z3_e5 = z3.Extract(31, 0, z3.Concat(z3_four, z3_e)) * z3_five
assert equiv(ez3, z3_e5)

# --------------------------------------------------------------------------
# Parity
seven = ExprInt(7, 32)
one0seven = ExprInt(0x107, 32)
for miasm_int, res in [(five, 1), (four, 0), (seven, 0), (one0seven, 0)]:
    e6 = ExprOp('parity', miasm_int)
    ez3 = translator1.from_expr(e6)
    z3_e6 = z3.BitVecVal(res, 1)
    assert equiv(ez3, z3_e6)

# --------------------------------------------------------------------------
# '-'
for miasm_int, res in [(five, -5), (four, -4)]:
    e6 = ExprOp('-', miasm_int)
    ez3 = translator1.from_expr(e6)
    z3_e6 = z3.BitVecVal(res, 32)
    assert equiv(ez3, z3_e6)

# --------------------------------------------------------------------------
label_histoire = loc_db.add_location("label_histoire", 0xdeadbeef)
e7 = ExprLoc(label_histoire, 32)
ez3 = translator1.from_expr(e7)
z3_e7 = z3.BitVecVal(0xdeadbeef, 32)
assert equiv(ez3, z3_e7)

# Should just not throw anything to pass
lbl_e8 = loc_db.add_location("label_jambe")

e8 = ExprLoc(lbl_e8, 32)
ez3 = translator1.from_expr(e8)
assert not equiv(ez3, z3_e7)

# --------------------------------------------------------------------------
# cntleadzeros, cnttrailzeros

# cnttrailzeros(0x1138) == 3
cnttrailzeros1 = translator1.from_expr(ExprOp("cnttrailzeros", ExprInt(0x1138, 32)))
cnttrailzeros2 = z3.BitVecVal(3, 32)
assert(equiv(cnttrailzeros1, cnttrailzeros2))

# cntleadzeros(0x11300) == 0xf
cntleadzeros1 = translator1.from_expr(ExprOp("cntleadzeros", ExprInt(0x11300, 32)))
cntleadzeros2 = z3.BitVecVal(0xf, 32)
assert(equiv(cntleadzeros1, cntleadzeros2))

# cnttrailzeros(0x8000) + 1 == cntleadzeros(0x8000)
cnttrailzeros3 = translator1.from_expr(ExprOp("cnttrailzeros", ExprInt(0x8000, 32)) + ExprInt(1, 32))
cntleadzeros3 = translator1.from_expr(ExprOp("cntleadzeros", ExprInt(0x8000, 32)))
assert(equiv(cnttrailzeros3, cntleadzeros3))

print("TranslatorZ3 tests are OK.")

