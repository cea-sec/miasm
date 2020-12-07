""" Test cases for dead code elimination"""
from __future__ import print_function

from future.utils import viewitems

from miasm.expression.expression import ExprId, ExprInt, ExprAssign, ExprMem
from miasm.core.locationdb import LocationDB
from miasm.analysis.data_flow import DeadRemoval, ReachingDefinitions, DiGraphDefUse
from miasm.ir.analysis import LifterModelCall
from miasm.ir.ir import IRBlock, AssignBlock

loc_db = LocationDB()

a = ExprId("a", 32)
b = ExprId("b", 32)
c = ExprId("c", 32)
d = ExprId("d", 32)
r = ExprId("r", 32)

a_init = ExprId("a_init", 32)
b_init = ExprId("b_init", 32)
c_init = ExprId("c_init", 32)
d_init = ExprId("d_init", 32)
r_init = ExprId("r_init", 32) # Return register

pc = ExprId("pc", 32)
sp = ExprId("sp", 32)

CST1 = ExprInt(0x11, 32)
CST2 = ExprInt(0x12, 32)
CST3 = ExprInt(0x13, 32)

LBL0 = loc_db.add_location("lbl0", 0)
LBL1 = loc_db.add_location("lbl1", 1)
LBL2 = loc_db.add_location("lbl2", 2)
LBL3 = loc_db.add_location("lbl3", 3)
LBL4 = loc_db.add_location("lbl4", 4)
LBL5 = loc_db.add_location("lbl5", 5)
LBL6 = loc_db.add_location("lbl6", 6)

IRDst = ExprId('IRDst', 32)
dummy = ExprId('dummy', 32)


def gen_irblock(label, exprs_list):
    irs = []
    for exprs in exprs_list:
        if isinstance(exprs, AssignBlock):
            irs.append(exprs)
        else:
            irs.append(AssignBlock(exprs))

    irs.append(AssignBlock({IRDst:dummy}))
    irbl = IRBlock(loc_db, label, irs)
    return irbl


class Regs(object):
    regs_init = {a: a_init, b: b_init, c: c_init, d: d_init, r: r_init}
    all_regs_ids = [a, b, c, d, r, sp, pc]

class Arch(object):
    regs = Regs()

    def getpc(self, _):
        return pc

    def getsp(self, _):
        return sp

class LifterTest(LifterModelCall):

    """Fake Lifter class for tests"""

    def __init__(self, loc_db):
        arch = Arch()
        super(LifterTest, self).__init__(arch, 32, loc_db)
        self.IRDst = IRDst
        self.ret_reg = r

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

Lifter = LifterTest(loc_db)
deadrm = DeadRemoval(Lifter)

# graph 1 : Simple graph with dead and alive variables

G1_cfg = Lifter.new_ircfg()

G1_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)], [ExprAssign(b, CST2)]])
G1_IRB1 = gen_irblock(LBL1, [[ExprAssign(a, b)]])
G1_IRB2 = gen_irblock(LBL2, [[ExprAssign(r, a)]])

for irb in [G1_IRB0, G1_IRB1, G1_IRB2]:
    G1_cfg.add_irblock(irb)

G1_cfg.add_uniq_edge(G1_IRB0.loc_key, G1_IRB1.loc_key)
G1_cfg.add_uniq_edge(G1_IRB1.loc_key, G1_IRB2.loc_key)

# Expected output for graph 1
G1_EXP_cfg = Lifter.new_ircfg()

G1_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAssign(b, CST2)]])
G1_EXP_IRB1 = gen_irblock(LBL1, [[ExprAssign(a, b)]])
G1_EXP_IRB2 = gen_irblock(LBL2, [[ExprAssign(r, a)]])

for irb in [G1_EXP_IRB0, G1_EXP_IRB1, G1_EXP_IRB2]:
    G1_EXP_cfg.add_irblock(irb)

# graph 2 : Natural loop with dead variable

G2_cfg = Lifter.new_ircfg()

G2_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)], [ExprAssign(r, CST1)]])
G2_IRB1 = gen_irblock(LBL1, [[ExprAssign(a, a+CST1)]])
G2_IRB2 = gen_irblock(LBL2, [[ExprAssign(a, r)]])

for irb in [G2_IRB0, G2_IRB1, G2_IRB2]:
    G2_cfg.add_irblock(irb)

G2_cfg.add_uniq_edge(G2_IRB0.loc_key, G2_IRB1.loc_key)
G2_cfg.add_uniq_edge(G2_IRB1.loc_key, G2_IRB2.loc_key)
G2_cfg.add_uniq_edge(G2_IRB1.loc_key, G2_IRB1.loc_key)

# Expected output for graph 2
G2_EXP_cfg = Lifter.new_ircfg()

G2_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAssign(r, CST1)]])
G2_EXP_IRB1 = gen_irblock(LBL1, [[]])
G2_EXP_IRB2 = gen_irblock(LBL2, [[]])

for irb in [G2_EXP_IRB0, G2_EXP_IRB1, G2_EXP_IRB2]:
    G2_EXP_cfg.add_irblock(irb)

# graph 3 : Natural loop with alive variables

G3_cfg = Lifter.new_ircfg()

G3_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)]])
G3_IRB1 = gen_irblock(LBL1, [[ExprAssign(a, a+CST1)]])
G3_IRB2 = gen_irblock(LBL2, [[ExprAssign(r, a)]])

for irb in [G3_IRB0, G3_IRB1, G3_IRB2]:
    G3_cfg.add_irblock(irb)

G3_cfg.add_uniq_edge(G3_IRB0.loc_key, G3_IRB1.loc_key)
G3_cfg.add_uniq_edge(G3_IRB1.loc_key, G3_IRB2.loc_key)
G3_cfg.add_uniq_edge(G3_IRB1.loc_key, G3_IRB1.loc_key)

# Expected output for graph 3
G3_EXP_cfg = Lifter.new_ircfg()

G3_EXP_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)]])
G3_EXP_IRB1 = gen_irblock(LBL1, [[ExprAssign(a, a+CST1)]])
G3_EXP_IRB2 = gen_irblock(LBL2, [[ExprAssign(r, a)]])

for irb in [G3_EXP_IRB0, G3_EXP_IRB1, G3_EXP_IRB2]:
    G3_EXP_cfg.add_irblock(irb)

# graph 4 : If/else with dead variables

G4_cfg = Lifter.new_ircfg()

G4_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)]])
G4_IRB1 = gen_irblock(LBL1, [[ExprAssign(a, a+CST1)]])
G4_IRB2 = gen_irblock(LBL2, [[ExprAssign(a, a+CST2)]])
G4_IRB3 = gen_irblock(LBL3, [[ExprAssign(a, CST3)], [ExprAssign(r, a)]])

for irb in [G4_IRB0, G4_IRB1, G4_IRB2, G4_IRB3]:
    G4_cfg.add_irblock(irb)

G4_cfg.add_uniq_edge(G4_IRB0.loc_key, G4_IRB1.loc_key)
G4_cfg.add_uniq_edge(G4_IRB0.loc_key, G4_IRB2.loc_key)
G4_cfg.add_uniq_edge(G4_IRB1.loc_key, G4_IRB3.loc_key)
G4_cfg.add_uniq_edge(G4_IRB2.loc_key, G4_IRB3.loc_key)

# Expected output for graph 4
G4_EXP_cfg = Lifter.new_ircfg()

G4_EXP_IRB0 = gen_irblock(LBL0, [[]])
G4_EXP_IRB1 = gen_irblock(LBL1, [[]])
G4_EXP_IRB2 = gen_irblock(LBL2, [[]])
G4_EXP_IRB3 = gen_irblock(LBL3, [[ExprAssign(a, CST3)], [ExprAssign(r, a)]])

for irb in [G4_EXP_IRB0, G4_EXP_IRB1, G4_EXP_IRB2, G4_EXP_IRB3]:
    G4_EXP_cfg.add_irblock(irb)

# graph 5 : Loop and If/else with dead variables

G5_cfg = Lifter.new_ircfg()

G5_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)]])
G5_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, CST2)]])
G5_IRB2 = gen_irblock(LBL2, [[ExprAssign(a, a+CST2)]])
G5_IRB3 = gen_irblock(LBL3, [[ExprAssign(a, a+CST3)]])
G5_IRB4 = gen_irblock(LBL4, [[ExprAssign(a, a+CST1)]])
G5_IRB5 = gen_irblock(LBL5, [[ExprAssign(a, r)]])

for irb in [G5_IRB0, G5_IRB1, G5_IRB2, G5_IRB3, G5_IRB4, G5_IRB5]:
    G5_cfg.add_irblock(irb)

G5_cfg.add_uniq_edge(G5_IRB0.loc_key, G5_IRB1.loc_key)
G5_cfg.add_uniq_edge(G5_IRB1.loc_key, G5_IRB2.loc_key)
G5_cfg.add_uniq_edge(G5_IRB1.loc_key, G5_IRB3.loc_key)
G5_cfg.add_uniq_edge(G5_IRB2.loc_key, G5_IRB4.loc_key)
G5_cfg.add_uniq_edge(G5_IRB3.loc_key, G5_IRB4.loc_key)
G5_cfg.add_uniq_edge(G5_IRB4.loc_key, G5_IRB5.loc_key)
G5_cfg.add_uniq_edge(G5_IRB4.loc_key, G5_IRB1.loc_key)

# Expected output for graph 5
G5_EXP_cfg = Lifter.new_ircfg()

G5_EXP_IRB0 = gen_irblock(LBL0, [[]])
G5_EXP_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, CST2)]])
G5_EXP_IRB2 = gen_irblock(LBL2, [[]])
G5_EXP_IRB3 = gen_irblock(LBL3, [[]])
G5_EXP_IRB4 = gen_irblock(LBL4, [[]])
G5_EXP_IRB5 = gen_irblock(LBL5, [[]])

for irb in [G5_EXP_IRB0, G5_EXP_IRB1, G5_EXP_IRB2,
            G5_EXP_IRB3, G5_EXP_IRB4, G5_EXP_IRB5]:
    G5_EXP_cfg.add_irblock(irb)

# graph 6 : Natural loop with dead variables symmetric assignment
# (a = b <-> b = a )

G6_cfg = Lifter.new_ircfg()

G6_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)]])
G6_IRB1 = gen_irblock(LBL1, [[ExprAssign(b, a)]])
G6_IRB2 = gen_irblock(LBL2, [[ExprAssign(a, b)]])
G6_IRB3 = gen_irblock(LBL3, [[ExprAssign(r, CST2)]])

for irb in [G6_IRB0, G6_IRB1, G6_IRB2, G6_IRB3]:
    G6_cfg.add_irblock(irb)

G6_cfg.add_uniq_edge(G6_IRB0.loc_key, G6_IRB1.loc_key)
G6_cfg.add_uniq_edge(G6_IRB1.loc_key, G6_IRB2.loc_key)
G6_cfg.add_uniq_edge(G6_IRB2.loc_key, G6_IRB1.loc_key)
G6_cfg.add_uniq_edge(G6_IRB2.loc_key, G6_IRB3.loc_key)

# Expected output for graph 6
G6_EXP_cfg = Lifter.new_ircfg()

G6_EXP_IRB0 = gen_irblock(LBL0, [[]])
G6_EXP_IRB1 = gen_irblock(LBL1, [[]])
G6_EXP_IRB2 = gen_irblock(LBL2, [[]])
G6_EXP_IRB3 = gen_irblock(LBL3, [[ExprAssign(r, CST2)]])

for irb in [G6_EXP_IRB0, G6_EXP_IRB1, G6_EXP_IRB2, G6_EXP_IRB3]:
    G6_EXP_cfg.add_irblock(irb)

# graph 7 : Double entry loop with dead variables

G7_cfg = Lifter.new_ircfg()

G7_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)], [ExprAssign(r, CST1)]])
G7_IRB1 = gen_irblock(LBL1, [[ExprAssign(a, a+CST1)]])
G7_IRB2 = gen_irblock(LBL2, [[ExprAssign(a, a+CST2)]])
G7_IRB3 = gen_irblock(LBL3, [[ExprAssign(a, r)]])

for irb in [G7_IRB0, G7_IRB1, G7_IRB2, G7_IRB3]:
    G7_cfg.add_irblock(irb)

G7_cfg.add_uniq_edge(G7_IRB0.loc_key, G7_IRB1.loc_key)
G7_cfg.add_uniq_edge(G7_IRB1.loc_key, G7_IRB2.loc_key)
G7_cfg.add_uniq_edge(G7_IRB2.loc_key, G7_IRB1.loc_key)
G7_cfg.add_uniq_edge(G7_IRB2.loc_key, G7_IRB3.loc_key)
G7_cfg.add_uniq_edge(G7_IRB0.loc_key, G7_IRB2.loc_key)


# Expected output for graph 7
G7_EXP_cfg = Lifter.new_ircfg()

G7_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAssign(r, CST1)]])
G7_EXP_IRB1 = gen_irblock(LBL1, [[]])
G7_EXP_IRB2 = gen_irblock(LBL2, [[]])
G7_EXP_IRB3 = gen_irblock(LBL3, [[]])

for irb in [G7_EXP_IRB0, G7_EXP_IRB1, G7_EXP_IRB2, G7_EXP_IRB3]:
    G7_EXP_cfg.add_irblock(irb)

# graph 8 : Nested loops with dead variables

G8_cfg = Lifter.new_ircfg()

G8_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)], [ExprAssign(b, CST1)]])
G8_IRB1 = gen_irblock(LBL1, [[ExprAssign(a, a+CST1)]])
G8_IRB2 = gen_irblock(LBL2, [[ExprAssign(b, b+CST2)]])
G8_IRB3 = gen_irblock(LBL3, [[ExprAssign(a, b)]])


for irb in [G8_IRB0, G8_IRB1, G8_IRB2, G8_IRB3]:
    G8_cfg.add_irblock(irb)

G8_cfg.add_uniq_edge(G8_IRB0.loc_key, G8_IRB1.loc_key)
G8_cfg.add_uniq_edge(G8_IRB1.loc_key, G8_IRB2.loc_key)
G8_cfg.add_uniq_edge(G8_IRB2.loc_key, G8_IRB1.loc_key)
G8_cfg.add_uniq_edge(G8_IRB2.loc_key, G8_IRB3.loc_key)
G8_cfg.add_uniq_edge(G8_IRB3.loc_key, G8_IRB2.loc_key)


# Expected output for graph 8

G8_EXP_cfg = Lifter.new_ircfg()

G8_EXP_IRB0 = gen_irblock(LBL0, [[], []])
G8_EXP_IRB1 = gen_irblock(LBL1, [[]])
G8_EXP_IRB2 = gen_irblock(LBL2, [[]])
G8_EXP_IRB3 = gen_irblock(LBL3, [[]])

for irb in [G8_EXP_IRB0, G8_EXP_IRB1, G8_EXP_IRB2, G8_EXP_IRB3]:
    G8_EXP_cfg.add_irblock(irb)

# graph 9 : Miultiple-exits loops with dead variables

G9_cfg = Lifter.new_ircfg()

G9_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)], [ExprAssign(b, CST1)]])
G9_IRB1 = gen_irblock(LBL1, [[ExprAssign(a, a+CST1)], [ExprAssign(b, b+CST1)]])
G9_IRB2 = gen_irblock(LBL2, [[ExprAssign(a, a+CST2)], [ExprAssign(b, b+CST2)]])
G9_IRB3 = gen_irblock(LBL3, [[ExprAssign(a, b)]])
G9_IRB4 = gen_irblock(LBL4, [[ExprAssign(r, a)], [ExprAssign(r, b)]])

for irb in [G9_IRB0, G9_IRB1, G9_IRB2, G9_IRB3, G9_IRB4]:
    G9_cfg.add_irblock(irb)

G9_cfg.add_uniq_edge(G9_IRB0.loc_key, G9_IRB4.loc_key)
G9_cfg.add_uniq_edge(G9_IRB0.loc_key, G9_IRB1.loc_key)
G9_cfg.add_uniq_edge(G9_IRB1.loc_key, G9_IRB0.loc_key)
G9_cfg.add_uniq_edge(G9_IRB1.loc_key, G9_IRB4.loc_key)
G9_cfg.add_uniq_edge(G9_IRB1.loc_key, G9_IRB2.loc_key)
G9_cfg.add_uniq_edge(G9_IRB2.loc_key, G9_IRB0.loc_key)
G9_cfg.add_uniq_edge(G9_IRB2.loc_key, G9_IRB3.loc_key)
G9_cfg.add_uniq_edge(G9_IRB3.loc_key, G9_IRB4.loc_key)


# Expected output for graph 9

G9_EXP_cfg = Lifter.new_ircfg()

G9_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAssign(b, CST1)]])
G9_EXP_IRB1 = gen_irblock(LBL1, [[], [ExprAssign(b, b+CST1)]])
G9_EXP_IRB2 = gen_irblock(LBL2, [[], [ExprAssign(b, b+CST2)]])
G9_EXP_IRB3 = gen_irblock(LBL3, [[]])
G9_EXP_IRB4 = gen_irblock(LBL4, [[], [ExprAssign(r, b)]])

for irb in [G9_EXP_IRB0, G9_EXP_IRB1, G9_EXP_IRB2, G9_EXP_IRB3, G9_EXP_IRB4]:
    G9_EXP_cfg.add_irblock(irb)

# graph 10 : Natural loop with alive variables symmetric assignment
# (a = b <-> b = a )

G10_cfg = Lifter.new_ircfg()

G10_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)]])
G10_IRB1 = gen_irblock(LBL1, [[ExprAssign(b, a)]])
G10_IRB2 = gen_irblock(LBL2, [[ExprAssign(a, b)]])
G10_IRB3 = gen_irblock(LBL3, [[ExprAssign(r, CST1)]])

for irb in [G10_IRB0, G10_IRB1, G10_IRB2, G10_IRB3]:
    G10_cfg.add_irblock(irb)


G10_cfg.add_uniq_edge(G10_IRB0.loc_key, G10_IRB1.loc_key)
G10_cfg.add_uniq_edge(G10_IRB1.loc_key, G10_IRB2.loc_key)
G10_cfg.add_uniq_edge(G10_IRB2.loc_key, G10_IRB1.loc_key)
G10_cfg.add_uniq_edge(G10_IRB2.loc_key, G10_IRB3.loc_key)

# Expected output for graph 10
G10_EXP_cfg = Lifter.new_ircfg()

G10_EXP_IRB0 = gen_irblock(LBL0, [[]])
G10_EXP_IRB1 = gen_irblock(LBL1, [[]])
G10_EXP_IRB2 = gen_irblock(LBL2, [[]])
G10_EXP_IRB3 = gen_irblock(LBL3, [[ExprAssign(r, CST1)]])

for irb in [G10_EXP_IRB0, G10_EXP_IRB1, G10_EXP_IRB2, G10_EXP_IRB3]:
    G10_EXP_cfg.add_irblock(irb)

# graph 11 : If/Else conditions with alive variables

G11_cfg = Lifter.new_ircfg()

G11_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, b)]])
G11_IRB1 = gen_irblock(LBL1, [[ExprAssign(b, a)]])
G11_IRB2 = gen_irblock(LBL2, [[ExprAssign(r, a)]])
G11_IRB3 = gen_irblock(LBL3, [[ExprAssign(a, a+CST1)]])
G11_IRB4 = gen_irblock(LBL4, [[ExprAssign(b, b+CST1)]])


for irb in [G11_IRB0, G11_IRB1, G11_IRB2]:
    G11_cfg.add_irblock(irb)

G11_cfg.add_uniq_edge(G11_IRB0.loc_key, G11_IRB1.loc_key)
#G11_cfg.add_uniq_edge(G11_IRB3.loc_key, G11_IRB1.loc_key)
G11_cfg.add_uniq_edge(G11_IRB1.loc_key, G11_IRB0.loc_key)
#G11_cfg.add_uniq_edge(G11_IRB4.loc_key, G11_IRB0.loc_key)
G11_cfg.add_uniq_edge(G11_IRB1.loc_key, G11_IRB2.loc_key)


# Expected output for graph 11
G11_EXP_cfg = Lifter.new_ircfg()

G11_EXP_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, b)]])
G11_EXP_IRB1 = gen_irblock(LBL1, [[ExprAssign(b, a)]])
G11_EXP_IRB2 = gen_irblock(LBL2, [[ExprAssign(r, a)]])
#G11_EXP_IRB3 = gen_irblock(LBL3, [[ExprAssign(a, a+CST1)]])
#G11_EXP_IRB4 = gen_irblock(LBL4, [[ExprAssign(b, b+CST1)]])

for irb in [G11_EXP_IRB0, G11_EXP_IRB1,
            G11_EXP_IRB2]:
    G11_EXP_cfg.add_irblock(irb)

# graph 12 : Graph with multiple out points and useless definitions
# of return register

G12_cfg = Lifter.new_ircfg()

G12_IRB0 = gen_irblock(LBL0, [[ExprAssign(r, CST1)], [ExprAssign(a, CST2)]])
G12_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, CST2)]])
G12_IRB2 = gen_irblock(LBL2, [[ExprAssign(r, a)], [ExprAssign(b, CST3)]])
G12_IRB3 = gen_irblock(LBL3, [[ExprAssign(r, CST3)]])
G12_IRB4 = gen_irblock(LBL4, [[ExprAssign(r, CST2)]])
G12_IRB5 = gen_irblock(LBL5, [[ExprAssign(r, b)]])

for irb in [G12_IRB0, G12_IRB1, G12_IRB2, G12_IRB3, G12_IRB4, G12_IRB5]:
    G12_cfg.add_irblock(irb)

G12_cfg.add_uniq_edge(G12_IRB0.loc_key, G12_IRB1.loc_key)
G12_cfg.add_uniq_edge(G12_IRB0.loc_key, G12_IRB2.loc_key)
G12_cfg.add_uniq_edge(G12_IRB2.loc_key, G12_IRB3.loc_key)
G12_cfg.add_uniq_edge(G12_IRB2.loc_key, G12_IRB4.loc_key)
G12_cfg.add_uniq_edge(G12_IRB4.loc_key, G12_IRB5.loc_key)

# Expected output for graph 12
G12_EXP_cfg = Lifter.new_ircfg()

G12_EXP_IRB0 = gen_irblock(LBL0, [[], []])
G12_EXP_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, CST2)]])
G12_EXP_IRB2 = gen_irblock(LBL2, [[], [ExprAssign(b, CST3)]])
G12_EXP_IRB3 = gen_irblock(LBL3, [[ExprAssign(r, CST3)]])
G12_EXP_IRB4 = gen_irblock(LBL4, [[]])
G12_EXP_IRB5 = gen_irblock(LBL5, [[ExprAssign(r, b)]])


for irb in [G12_EXP_IRB0, G12_EXP_IRB1,
            G12_EXP_IRB2, G12_EXP_IRB3,
            G12_EXP_IRB4, G12_EXP_IRB5]:
    G12_EXP_cfg.add_irblock(irb)

# graph 13 : Graph where a leaf has lost its son

G13_cfg = Lifter.new_ircfg()

G13_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)], [ExprAssign(b, CST2)]])
G13_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, b)]])
G13_IRB2 = gen_irblock(LBL2, [[ExprAssign(d, CST2)], [ExprAssign(a, b+CST1),
                                                   ExprAssign(c, a+b)]])
G13_IRB3 = gen_irblock(LBL3, [[]]) # lost son
G13_IRB4 = gen_irblock(LBL4, [[ExprAssign(b, CST2)]])

for irb in [G13_IRB0, G13_IRB1, G13_IRB2, G13_IRB4]:
    G13_cfg.add_irblock(irb)

G13_cfg.add_uniq_edge(G13_IRB0.loc_key, G13_IRB1.loc_key)
G13_cfg.add_uniq_edge(G13_IRB0.loc_key, G13_IRB4.loc_key)
G13_cfg.add_uniq_edge(G13_IRB2.loc_key, G13_IRB3.loc_key)
G13_cfg.add_uniq_edge(G13_IRB4.loc_key, G13_IRB2.loc_key)

# Expected output for graph 13
G13_EXP_cfg = Lifter.new_ircfg()

G13_EXP_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)], [ExprAssign(b, CST2)]])
G13_EXP_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, b)]])
G13_EXP_IRB2 = gen_irblock(LBL2, [[ExprAssign(d, CST2)], [ExprAssign(a, b+CST1),
                                                       ExprAssign(c, a+b)]])
G13_EXP_IRB3 = gen_irblock(LBL3, [[]])
G13_EXP_IRB4 = gen_irblock(LBL4, [[ExprAssign(b, CST2)]])

for irb in [G13_EXP_IRB0, G13_EXP_IRB1, G13_EXP_IRB2, G13_EXP_IRB4]:
    G13_EXP_cfg.add_irblock(irb)

#G13_EXP_cfg = G13_cfg

# graph 14 : Graph where variable assigned multiple times in a block but still
# useful in the end

G14_cfg = Lifter.new_ircfg()

G14_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)], [ExprAssign(c, a)],
                              [ExprAssign(a, CST2)]])
G14_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, a+c)]])

for irb in [G14_IRB0, G14_IRB1]:
    G14_cfg.add_irblock(irb)

G14_cfg.add_uniq_edge(G14_IRB0.loc_key, G14_IRB1.loc_key)

# Expected output for graph 1
G14_EXP_cfg = Lifter.new_ircfg()

G14_EXP_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1)], [ExprAssign(c, a)],
                                  [ExprAssign(a, CST2)]])
G14_EXP_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, a+c)]])

for irb in [G14_EXP_IRB0, G14_EXP_IRB1]:
    G14_EXP_cfg.add_irblock(irb)

# graph 15 : Graph where variable assigned multiple and read at the same time,
# but useless

G15_cfg = Lifter.new_ircfg()

G15_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST2)], [ExprAssign(a, CST1),
                                                   ExprAssign(b, a+CST2),
                                                   ExprAssign(c, CST1)]])
G15_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, a)]])

for irb in [G15_IRB0, G15_IRB1]:
    G15_cfg.add_irblock(irb)

G15_cfg.add_uniq_edge(G15_IRB0.loc_key, G15_IRB1.loc_key)

# Expected output for graph 1
G15_EXP_cfg = Lifter.new_ircfg()

G15_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAssign(a, CST1)]])
G15_EXP_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, a)]])

for irb in [G15_EXP_IRB0, G15_EXP_IRB1]:
    G15_EXP_cfg.add_irblock(irb)

# graph 16 : Graph where variable assigned multiple times in the same block

G16_cfg = Lifter.new_ircfg()

G16_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, CST1), ExprAssign(b, CST2),
                               ExprAssign(c, CST3)], [ExprAssign(a, c+CST1),
                                                   ExprAssign(b, c+CST2)]])
G16_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, a+b)], [ExprAssign(r, c+r)]])
G16_IRB2 = gen_irblock(LBL2, [[]])

for irb in [G16_IRB0, G16_IRB1]:
    G16_cfg.add_irblock(irb)

G16_cfg.add_uniq_edge(G16_IRB0.loc_key, G16_IRB1.loc_key)
G16_cfg.add_uniq_edge(G16_IRB1.loc_key, G16_IRB2.loc_key)

for irb in [G16_IRB0, G16_IRB1]:
    G16_cfg.add_irblock(irb)

# Expected output for graph 1
G16_EXP_cfg = Lifter.new_ircfg()

G16_EXP_IRB0 = gen_irblock(LBL0, [[ExprAssign(c, CST3)], [ExprAssign(a, c + CST1),
                                                       ExprAssign(b, c + CST2)]])
G16_EXP_IRB1 = gen_irblock(LBL1, [[ExprAssign(r, a+b)], [ExprAssign(r, c+r)]])

for irb in [G16_EXP_IRB0, G16_EXP_IRB1]:
    G16_EXP_cfg.add_irblock(irb)

# graph 17 : parallel ir

G17_cfg = Lifter.new_ircfg()

G17_IRB0 = gen_irblock(LBL0, [[ExprAssign(a, a*b),
                               ExprAssign(b, c),
                               ExprAssign(c, CST1)],

                              [ExprAssign(d, d+ CST2)],

                              [ExprAssign(a, CST1),
                               ExprAssign(b, a),
                               ExprAssign(c, b)],

                              [ExprAssign(ExprMem(d+CST1, 32), a),
                               ExprAssign(a, b),
                               ExprAssign(b, c),
                               ExprAssign(c, CST1)],

                              [ExprAssign(a, CST1),
                               ExprAssign(b, a),
                               ExprAssign(c, b)],

                              [ExprAssign(ExprMem(d+CST2, 32), a),
                               ExprAssign(a, b),
                               ExprAssign(b, c),
                               ExprAssign(c, CST1)],


                              [ExprAssign(a, CST2),
                               ExprAssign(b, a),
                               ExprAssign(c, b)],

                              [ExprAssign(a, a+CST1)],

                              [ExprAssign(d, a),
                               ExprAssign(a, d)],

                              [ExprAssign(d, d+CST1)],

                              [ExprAssign(a, CST2),
                               ExprAssign(b, a),
                               ExprAssign(c, b)],

                              [ExprAssign(a, a+CST2)],

                              [ExprAssign(a, CST2),
                               ExprAssign(b, a),
                               ExprAssign(c, b)],

                              [ExprAssign(a, CST1),
                               ExprAssign(b, a),
                               ExprAssign(c, b)],

                              [ExprAssign(ExprMem(d, 32), a+b+c)],

                         ])

for irb in [G17_IRB0]:
    G17_cfg.add_irblock(irb)

#G17_cfg.graph.add_node(G17_IRB0.loc_key)

# Expected output for graph 17
G17_EXP_cfg = Lifter.new_ircfg()

G17_EXP_IRB0 = gen_irblock(LBL0, [[],

                                  [ExprAssign(d, d+ CST2)],

                                  [ExprAssign(a, CST1)],

                                  [ExprAssign(ExprMem(d+CST1, 32), a)],

                                  [ExprAssign(a, CST1)],

                                  [ExprAssign(ExprMem(d+CST2, 32), a)],

                                  [ExprAssign(a, CST2)],

                                  [ExprAssign(a, a+CST1)],

                                  [ExprAssign(d, a)],

                                  [ExprAssign(d, d+CST1)],

                                  [ExprAssign(a, CST2)],

                                  [ExprAssign(a, a+CST2)],

                                  [ExprAssign(a, CST2),
                                   ExprAssign(b, a)],

                                  [ExprAssign(a, CST1),
                                   ExprAssign(b, a),
                                   ExprAssign(c, b)],

                                  G17_IRB0[14]
                                  # Trick because a+b+c != ((a+b)+c)
                                 ])

for irb in [G17_EXP_IRB0]:
    G17_EXP_cfg.add_irblock(irb)

# Beginning  of tests

for test_nb, test in enumerate([(G1_cfg, G1_EXP_cfg),
                                (G2_cfg, G2_EXP_cfg),
                                (G3_cfg, G3_EXP_cfg),
                                (G4_cfg, G4_EXP_cfg),
                                (G5_cfg, G5_EXP_cfg),
                                (G6_cfg, G6_EXP_cfg),
                                (G7_cfg, G7_EXP_cfg),
                                (G8_cfg, G8_EXP_cfg),
                                (G9_cfg, G9_EXP_cfg),
                                (G10_cfg, G10_EXP_cfg),
                                (G11_cfg, G11_EXP_cfg),
                                (G12_cfg, G12_EXP_cfg),
                                (G13_cfg, G13_EXP_cfg),
                                (G14_cfg, G14_EXP_cfg),
                                (G15_cfg, G15_EXP_cfg),
                                (G16_cfg, G16_EXP_cfg),
                                (G17_cfg, G17_EXP_cfg)
]):
    # Extract test elements
    g_ircfg, g_exp_ircfg = test

    print("[+] Test", test_nb+1)

    # Print initial graph, for debug
    open("graph_%02d.dot" % (test_nb+1), "w").write(g_ircfg.dot())

    reaching_defs = ReachingDefinitions(g_ircfg)
    defuse = DiGraphDefUse(reaching_defs, deref_mem=True)

    # # Simplify graph
    deadrm(g_ircfg)

    # # Print simplified graph, for debug
    open("simp_graph_%02d.dot" % (test_nb+1), "w").write(g_ircfg.dot())

    # Same number of blocks
    assert len(g_ircfg.blocks) == len(g_exp_ircfg.blocks)
    # Check that each expr in the blocks are the same
    for lbl, irb in viewitems(g_ircfg.blocks):
        exp_irb = g_exp_ircfg.blocks[lbl]
        assert exp_irb.assignblks == irb.assignblks
