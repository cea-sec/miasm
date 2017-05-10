""" Test cases for dead code elimination"""
from miasm2.expression.expression import ExprId, ExprInt, ExprAff, ExprMem
from miasm2.core.asmblock import AsmLabel
from miasm2.analysis.data_flow import *
from miasm2.ir.analysis import ira
from miasm2.ir.ir import IRBlock, AssignBlock

a = ExprId("a")
b = ExprId("b")
c = ExprId("c")
d = ExprId("d")
r = ExprId("r")

a_init = ExprId("a_init")
b_init = ExprId("b_init")
c_init = ExprId("c_init")
d_init = ExprId("d_init")
r_init = ExprId("r_init") # Return register

pc = ExprId("pc")
sp = ExprId("sp")

CST1 = ExprInt(0x11, 32)
CST2 = ExprInt(0x12, 32)
CST3 = ExprInt(0x13, 32)

LBL0 = AsmLabel("lbl0")
LBL1 = AsmLabel("lbl1")
LBL2 = AsmLabel("lbl2")
LBL3 = AsmLabel("lbl3")
LBL4 = AsmLabel("lbl4")
LBL5 = AsmLabel("lbl5")
LBL6 = AsmLabel("lbl6")

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
    irbl = IRBlock(label, irs)
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

class IRATest(ira):

    """Fake IRA class for tests"""

    def __init__(self, symbol_pool=None):
        arch = Arch()
        super(IRATest, self).__init__(arch, 32, symbol_pool)
        self.IRDst = IRDst
        self.ret_reg = r

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

# graph 1 : Simple graph with dead and alive variables

G1_IRA = IRATest()

G1_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)], [ExprAff(b, CST2)]])
G1_IRB1 = gen_irblock(LBL1, [[ExprAff(a, b)]])
G1_IRB2 = gen_irblock(LBL2, [[ExprAff(r, a)]])

G1_IRA.blocks = {irb.label : irb for irb in [G1_IRB0, G1_IRB1, G1_IRB2]}

G1_IRA.graph.add_uniq_edge(G1_IRB0.label, G1_IRB1.label)
G1_IRA.graph.add_uniq_edge(G1_IRB1.label, G1_IRB2.label)

# Expected output for graph 1
G1_EXP_IRA = IRATest()

G1_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAff(b, CST2)]])
G1_EXP_IRB1 = gen_irblock(LBL1, [[ExprAff(a, b)]])
G1_EXP_IRB2 = gen_irblock(LBL2, [[ExprAff(r, a)]])

G1_EXP_IRA.blocks = {irb.label : irb for irb in [G1_EXP_IRB0, G1_EXP_IRB1,
                                                 G1_EXP_IRB2]}

# graph 2 : Natural loop with dead variable

G2_IRA = IRATest()

G2_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)], [ExprAff(r, CST1)]])
G2_IRB1 = gen_irblock(LBL1, [[ExprAff(a, a+CST1)]])
G2_IRB2 = gen_irblock(LBL2, [[ExprAff(a, r)]])

G2_IRA.blocks = {irb.label : irb for irb in [G2_IRB0, G2_IRB1, G2_IRB2]}

G2_IRA.graph.add_uniq_edge(G2_IRB0.label, G2_IRB1.label)
G2_IRA.graph.add_uniq_edge(G2_IRB1.label, G2_IRB2.label)
G2_IRA.graph.add_uniq_edge(G2_IRB1.label, G2_IRB1.label)

# Expected output for graph 2
G2_EXP_IRA = IRATest()

G2_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAff(r, CST1)]])
G2_EXP_IRB1 = gen_irblock(LBL1, [[]])
G2_EXP_IRB2 = gen_irblock(LBL2, [[]])

G2_EXP_IRA.blocks = {irb.label : irb for irb in [G2_EXP_IRB0, G2_EXP_IRB1,
                                                 G2_EXP_IRB2]}

# graph 3 : Natural loop with alive variables

G3_IRA = IRATest()

G3_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)]])
G3_IRB1 = gen_irblock(LBL1, [[ExprAff(a, a+CST1)]])
G3_IRB2 = gen_irblock(LBL2, [[ExprAff(r, a)]])

G3_IRA.blocks = {irb.label : irb for irb in [G3_IRB0, G3_IRB1, G3_IRB2]}

G3_IRA.graph.add_uniq_edge(G3_IRB0.label, G3_IRB1.label)
G3_IRA.graph.add_uniq_edge(G3_IRB1.label, G3_IRB2.label)
G3_IRA.graph.add_uniq_edge(G3_IRB1.label, G3_IRB1.label)

# Expected output for graph 3
G3_EXP_IRA = IRATest()

G3_EXP_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)]])
G3_EXP_IRB1 = gen_irblock(LBL1, [[ExprAff(a, a+CST1)]])
G3_EXP_IRB2 = gen_irblock(LBL2, [[ExprAff(r, a)]])

G3_EXP_IRA.blocks = {irb.label : irb for irb in [G3_EXP_IRB0, G3_EXP_IRB1,
                                                 G3_EXP_IRB2]}

# graph 4 : If/else with dead variables

G4_IRA = IRATest()

G4_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)]])
G4_IRB1 = gen_irblock(LBL1, [[ExprAff(a, a+CST1)]])
G4_IRB2 = gen_irblock(LBL2, [[ExprAff(a, a+CST2)]])
G4_IRB3 = gen_irblock(LBL3, [[ExprAff(a, CST3)], [ExprAff(r, a)]])

G4_IRA.blocks = {irb.label : irb for irb in [G4_IRB0, G4_IRB1, G4_IRB2,
                                            G4_IRB3]}

G4_IRA.graph.add_uniq_edge(G4_IRB0.label, G4_IRB1.label)
G4_IRA.graph.add_uniq_edge(G4_IRB0.label, G4_IRB2.label)
G4_IRA.graph.add_uniq_edge(G4_IRB1.label, G4_IRB3.label)
G4_IRA.graph.add_uniq_edge(G4_IRB2.label, G4_IRB3.label)

# Expected output for graph 4
G4_EXP_IRA = IRATest()

G4_EXP_IRB0 = gen_irblock(LBL0, [[]])
G4_EXP_IRB1 = gen_irblock(LBL1, [[]])
G4_EXP_IRB2 = gen_irblock(LBL2, [[]])
G4_EXP_IRB3 = gen_irblock(LBL3, [[ExprAff(a, CST3)], [ExprAff(r, a)]])

G4_EXP_IRA.blocks = {irb.label : irb for irb in [G4_EXP_IRB0, G4_EXP_IRB1,
                                                 G4_EXP_IRB2, G4_EXP_IRB3]}

# graph 5 : Loop and If/else with dead variables

G5_IRA = IRATest()

G5_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)]])
G5_IRB1 = gen_irblock(LBL1, [[ExprAff(r, CST2)]])
G5_IRB2 = gen_irblock(LBL2, [[ExprAff(a, a+CST2)]])
G5_IRB3 = gen_irblock(LBL3, [[ExprAff(a, a+CST3)]])
G5_IRB4 = gen_irblock(LBL4, [[ExprAff(a, a+CST1)]])
G5_IRB5 = gen_irblock(LBL5, [[ExprAff(a, r)]])

G5_IRA.blocks = {irb.label : irb for irb in [G5_IRB0, G5_IRB1, G5_IRB2, G5_IRB3,
                                            G5_IRB4, G5_IRB5]}

G5_IRA.graph.add_uniq_edge(G5_IRB0.label, G5_IRB1.label)
G5_IRA.graph.add_uniq_edge(G5_IRB1.label, G5_IRB2.label)
G5_IRA.graph.add_uniq_edge(G5_IRB1.label, G5_IRB3.label)
G5_IRA.graph.add_uniq_edge(G5_IRB2.label, G5_IRB4.label)
G5_IRA.graph.add_uniq_edge(G5_IRB3.label, G5_IRB4.label)
G5_IRA.graph.add_uniq_edge(G5_IRB4.label, G5_IRB5.label)
G5_IRA.graph.add_uniq_edge(G5_IRB4.label, G5_IRB1.label)

# Expected output for graph 5
G5_EXP_IRA = IRATest()

G5_EXP_IRB0 = gen_irblock(LBL0, [[]])
G5_EXP_IRB1 = gen_irblock(LBL1, [[ExprAff(r, CST2)]])
G5_EXP_IRB2 = gen_irblock(LBL2, [[]])
G5_EXP_IRB3 = gen_irblock(LBL3, [[]])
G5_EXP_IRB4 = gen_irblock(LBL4, [[]])
G5_EXP_IRB5 = gen_irblock(LBL5, [[]])

G5_EXP_IRA.blocks = {irb.label : irb for irb in [G5_EXP_IRB0, G5_EXP_IRB1,
                                                 G5_EXP_IRB2, G5_EXP_IRB3,
                                                 G5_EXP_IRB4, G5_EXP_IRB5]}

# graph 6 : Natural loop with dead variables symetric affectation
# (a = b <-> b = a )

G6_IRA = IRATest()

G6_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)]])
G6_IRB1 = gen_irblock(LBL1, [[ExprAff(b, a)]])
G6_IRB2 = gen_irblock(LBL2, [[ExprAff(a, b)]])
G6_IRB3 = gen_irblock(LBL3, [[ExprAff(r, CST2)]])

G6_IRA.blocks = {irb.label : irb for irb in [G6_IRB0, G6_IRB1, G6_IRB2,
                                            G6_IRB3]}

G6_IRA.graph.add_uniq_edge(G6_IRB0.label, G6_IRB1.label)
G6_IRA.graph.add_uniq_edge(G6_IRB1.label, G6_IRB2.label)
G6_IRA.graph.add_uniq_edge(G6_IRB2.label, G6_IRB1.label)
G6_IRA.graph.add_uniq_edge(G6_IRB2.label, G6_IRB3.label)

# Expected output for graph 6
G6_EXP_IRA = IRATest()

G6_EXP_IRB0 = gen_irblock(LBL0, [[]])
G6_EXP_IRB1 = gen_irblock(LBL1, [[]])
G6_EXP_IRB2 = gen_irblock(LBL2, [[]])
G6_EXP_IRB3 = gen_irblock(LBL3, [[ExprAff(r, CST2)]])

G6_EXP_IRA.blocks = {irb.label : irb for irb in [G6_EXP_IRB0, G6_EXP_IRB1,
                                                 G6_EXP_IRB2, G6_EXP_IRB3]}

# graph 7 : Double entry loop with dead variables

G7_IRA = IRATest()

G7_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)], [ExprAff(r, CST1)]])
G7_IRB1 = gen_irblock(LBL1, [[ExprAff(a, a+CST1)]])
G7_IRB2 = gen_irblock(LBL2, [[ExprAff(a, a+CST2)]])
G7_IRB3 = gen_irblock(LBL3, [[ExprAff(a, r)]])

G7_IRA.blocks = {irb.label : irb for irb in [G7_IRB0, G7_IRB1, G7_IRB2,
                                            G7_IRB3]}

G7_IRA.graph.add_uniq_edge(G7_IRB0.label, G7_IRB1.label)
G7_IRA.graph.add_uniq_edge(G7_IRB1.label, G7_IRB2.label)
G7_IRA.graph.add_uniq_edge(G7_IRB2.label, G7_IRB1.label)
G7_IRA.graph.add_uniq_edge(G7_IRB2.label, G7_IRB3.label)
G7_IRA.graph.add_uniq_edge(G7_IRB0.label, G7_IRB2.label)


# Expected output for graph 7
G7_EXP_IRA = IRATest()

G7_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAff(r, CST1)]])
G7_EXP_IRB1 = gen_irblock(LBL1, [[]])
G7_EXP_IRB2 = gen_irblock(LBL2, [[]])
G7_EXP_IRB3 = gen_irblock(LBL3, [[]])

G7_EXP_IRA.blocks = {irb.label : irb for irb in [G7_EXP_IRB0, G7_EXP_IRB1,
                                                 G7_EXP_IRB2, G7_EXP_IRB3]}

# graph 8 : Nested loops with dead variables

G8_IRA = IRATest()

G8_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)], [ExprAff(b, CST1)]])
G8_IRB1 = gen_irblock(LBL1, [[ExprAff(a, a+CST1)]])
G8_IRB2 = gen_irblock(LBL2, [[ExprAff(b, b+CST2)]])
G8_IRB3 = gen_irblock(LBL3, [[ExprAff(a, b)]])


G8_IRA.blocks = {irb.label : irb for irb in [G8_IRB0, G8_IRB1, G8_IRB2,
                                            G8_IRB3]}

G8_IRA.graph.add_uniq_edge(G8_IRB0.label, G8_IRB1.label)
G8_IRA.graph.add_uniq_edge(G8_IRB1.label, G8_IRB2.label)
G8_IRA.graph.add_uniq_edge(G8_IRB2.label, G8_IRB1.label)
G8_IRA.graph.add_uniq_edge(G8_IRB2.label, G8_IRB3.label)
G8_IRA.graph.add_uniq_edge(G8_IRB3.label, G8_IRB2.label)


# Expected output for graph 8

G8_EXP_IRA = IRATest()

G8_EXP_IRB0 = gen_irblock(LBL0, [[], []])
G8_EXP_IRB1 = gen_irblock(LBL1, [[]])
G8_EXP_IRB2 = gen_irblock(LBL2, [[]])
G8_EXP_IRB3 = gen_irblock(LBL3, [[]])

G8_EXP_IRA.blocks = {irb.label : irb for irb in [G8_EXP_IRB0, G8_EXP_IRB1,
                                                 G8_EXP_IRB2, G8_EXP_IRB3]}

# graph 9 : Miultiple-exits loops with dead variables

G9_IRA = IRATest()

G9_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)], [ExprAff(b, CST1)]])
G9_IRB1 = gen_irblock(LBL1, [[ExprAff(a, a+CST1)], [ExprAff(b, b+CST1)]])
G9_IRB2 = gen_irblock(LBL2, [[ExprAff(a, a+CST2)], [ExprAff(b, b+CST2)]])
G9_IRB3 = gen_irblock(LBL3, [[ExprAff(a, b)]])
G9_IRB4 = gen_irblock(LBL4, [[ExprAff(r, a)], [ExprAff(r, b)]])

G9_IRA.blocks = {irb.label : irb for irb in [G9_IRB0, G9_IRB1, G9_IRB2,
                                            G9_IRB3, G9_IRB4]}

G9_IRA.graph.add_uniq_edge(G9_IRB0.label, G9_IRB4.label)
G9_IRA.graph.add_uniq_edge(G9_IRB0.label, G9_IRB1.label)
G9_IRA.graph.add_uniq_edge(G9_IRB1.label, G9_IRB0.label)
G9_IRA.graph.add_uniq_edge(G9_IRB1.label, G9_IRB4.label)
G9_IRA.graph.add_uniq_edge(G9_IRB1.label, G9_IRB2.label)
G9_IRA.graph.add_uniq_edge(G9_IRB2.label, G9_IRB0.label)
G9_IRA.graph.add_uniq_edge(G9_IRB2.label, G9_IRB3.label)
G9_IRA.graph.add_uniq_edge(G9_IRB3.label, G9_IRB4.label)


# Expected output for graph 9

G9_EXP_IRA = IRATest()

G9_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAff(b, CST1)]])
G9_EXP_IRB1 = gen_irblock(LBL1, [[], [ExprAff(b, b+CST1)]])
G9_EXP_IRB2 = gen_irblock(LBL2, [[], [ExprAff(b, b+CST2)]])
G9_EXP_IRB3 = gen_irblock(LBL3, [[]])
G9_EXP_IRB4 = gen_irblock(LBL4, [[], [ExprAff(r, b)]])

G9_EXP_IRA.blocks = {irb.label : irb for irb in [G9_EXP_IRB0, G9_EXP_IRB1,
                                                 G9_EXP_IRB2, G9_EXP_IRB3,
                                                 G9_EXP_IRB4]}

# graph 10 : Natural loop with alive variables symetric affectation
# (a = b <-> b = a )

G10_IRA = IRATest()

G10_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)]])
G10_IRB1 = gen_irblock(LBL1, [[ExprAff(b, a)]])
G10_IRB2 = gen_irblock(LBL2, [[ExprAff(a, b)]])
G10_IRB3 = gen_irblock(LBL3, [[ExprAff(r, CST1)]])

G10_IRA.blocks = {irb.label : irb for irb in [G10_IRB0, G10_IRB1,
                                             G10_IRB2, G10_IRB3]}

G10_IRA.graph.add_uniq_edge(G10_IRB0.label, G10_IRB1.label)
G10_IRA.graph.add_uniq_edge(G10_IRB1.label, G10_IRB2.label)
G10_IRA.graph.add_uniq_edge(G10_IRB2.label, G10_IRB1.label)
G10_IRA.graph.add_uniq_edge(G10_IRB2.label, G10_IRB3.label)

# Expected output for graph 10
G10_EXP_IRA = IRATest()

G10_EXP_IRB0 = gen_irblock(LBL0, [[]])
G10_EXP_IRB1 = gen_irblock(LBL1, [[]])
G10_EXP_IRB2 = gen_irblock(LBL2, [[]])
G10_EXP_IRB3 = gen_irblock(LBL3, [[ExprAff(r, CST1)]])

G10_EXP_IRA.blocks = {irb.label : irb for irb in [G10_EXP_IRB0, G10_EXP_IRB1,
                                                  G10_EXP_IRB2, G10_EXP_IRB3]}

# graph 11 : If/Else conditions with alive variables

G11_IRA = IRATest()

G11_IRB0 = gen_irblock(LBL0, [[ExprAff(a, b)]])
G11_IRB1 = gen_irblock(LBL1, [[ExprAff(b, a)]])
G11_IRB2 = gen_irblock(LBL2, [[ExprAff(r, a)]])
G11_IRB3 = gen_irblock(LBL3, [[ExprAff(a, a+CST1)]])
G11_IRB4 = gen_irblock(LBL4, [[ExprAff(b, b+CST1)]])


G11_IRA.blocks = {irb.label : irb for irb in [G11_IRB0, G11_IRB1, G11_IRB2]}

G11_IRA.graph.add_uniq_edge(G11_IRB0.label, G11_IRB1.label)
#G11_IRA.graph.add_uniq_edge(G11_IRB3.label, G11_IRB1.label)
G11_IRA.graph.add_uniq_edge(G11_IRB1.label, G11_IRB0.label)
#G11_IRA.graph.add_uniq_edge(G11_IRB4.label, G11_IRB0.label)
G11_IRA.graph.add_uniq_edge(G11_IRB1.label, G11_IRB2.label)


# Expected output for graph 11
G11_EXP_IRA = IRATest()

G11_EXP_IRB0 = gen_irblock(LBL0, [[ExprAff(a, b)]])
G11_EXP_IRB1 = gen_irblock(LBL1, [[ExprAff(b, a)]])
G11_EXP_IRB2 = gen_irblock(LBL2, [[ExprAff(r, a)]])
#G11_EXP_IRB3 = gen_irblock(LBL3, [[ExprAff(a, a+CST1)]])
#G11_EXP_IRB4 = gen_irblock(LBL4, [[ExprAff(b, b+CST1)]])

G11_EXP_IRA.blocks = {irb.label : irb for irb in [G11_EXP_IRB0, G11_EXP_IRB1,
                                                  G11_EXP_IRB2]}

# graph 12 : Graph with multiple out points and useless definitions
# of return register

G12_IRA = IRATest()

G12_IRB0 = gen_irblock(LBL0, [[ExprAff(r, CST1)], [ExprAff(a, CST2)]])
G12_IRB1 = gen_irblock(LBL1, [[ExprAff(r, CST2)]])
G12_IRB2 = gen_irblock(LBL2, [[ExprAff(r, a)], [ExprAff(b, CST3)]])
G12_IRB3 = gen_irblock(LBL3, [[ExprAff(r, CST3)]])
G12_IRB4 = gen_irblock(LBL4, [[ExprAff(r, CST2)]])
G12_IRB5 = gen_irblock(LBL5, [[ExprAff(r, b)]])

G12_IRA.blocks = {irb.label : irb for irb in [G12_IRB0, G12_IRB1, G12_IRB2,
                                             G12_IRB3, G12_IRB4, G12_IRB5]}

G12_IRA.graph.add_uniq_edge(G12_IRB0.label, G12_IRB1.label)
G12_IRA.graph.add_uniq_edge(G12_IRB0.label, G12_IRB2.label)
G12_IRA.graph.add_uniq_edge(G12_IRB2.label, G12_IRB3.label)
G12_IRA.graph.add_uniq_edge(G12_IRB2.label, G12_IRB4.label)
G12_IRA.graph.add_uniq_edge(G12_IRB4.label, G12_IRB5.label)

# Expected output for graph 12
G12_EXP_IRA = IRATest()

G12_EXP_IRB0 = gen_irblock(LBL0, [[], []])
G12_EXP_IRB1 = gen_irblock(LBL1, [[ExprAff(r, CST2)]])
G12_EXP_IRB2 = gen_irblock(LBL2, [[], [ExprAff(b, CST3)]])
G12_EXP_IRB3 = gen_irblock(LBL3, [[ExprAff(r, CST3)]])
G12_EXP_IRB4 = gen_irblock(LBL4, [[]])
G12_EXP_IRB5 = gen_irblock(LBL5, [[ExprAff(r, b)]])


G12_EXP_IRA.blocks = {irb.label : irb for irb in [G12_EXP_IRB0, G12_EXP_IRB1,
                                                  G12_EXP_IRB2, G12_EXP_IRB3,
                                                  G12_EXP_IRB4, G12_EXP_IRB5]}

# graph 13 : Graph where a leaf has lost its son

G13_IRA = IRATest()

G13_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)], [ExprAff(b, CST2)]])
G13_IRB1 = gen_irblock(LBL1, [[ExprAff(r, b)]])
G13_IRB2 = gen_irblock(LBL2, [[ExprAff(d, CST2)], [ExprAff(a, b+CST1),
                                                   ExprAff(c, a+b)]])
G13_IRB3 = gen_irblock(LBL3, [[]]) # lost son
G13_IRB4 = gen_irblock(LBL4, [[ExprAff(b, CST2)]])

G13_IRA.blocks = {irb.label : irb for irb in [G13_IRB0, G13_IRB1, G13_IRB2,
                                             G13_IRB4]}

G13_IRA.graph.add_uniq_edge(G13_IRB0.label, G13_IRB1.label)
G13_IRA.graph.add_uniq_edge(G13_IRB0.label, G13_IRB4.label)
G13_IRA.graph.add_uniq_edge(G13_IRB2.label, G13_IRB3.label)
G13_IRA.graph.add_uniq_edge(G13_IRB4.label, G13_IRB2.label)

# Expected output for graph 13
G13_EXP_IRA = IRATest()

G13_EXP_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)], [ExprAff(b, CST2)]])
G13_EXP_IRB1 = gen_irblock(LBL1, [[ExprAff(r, b)]])
G13_EXP_IRB2 = gen_irblock(LBL2, [[ExprAff(d, CST2)], [ExprAff(a, b+CST1),
                                                       ExprAff(c, a+b)]])
G13_EXP_IRB3 = gen_irblock(LBL3, [[]])
G13_EXP_IRB4 = gen_irblock(LBL4, [[ExprAff(b, CST2)]])

G13_EXP_IRA.blocks = {irb.label: irb for irb in [G13_EXP_IRB0, G13_EXP_IRB1,
                                                 G13_EXP_IRB2, G13_EXP_IRB4]}

#G13_EXP_IRA = G13_IRA

# graph 14 : Graph where variable assigned multiple times in a block but still
# useful in the end

G14_IRA = IRATest()

G14_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)], [ExprAff(c, a)],
                              [ExprAff(a, CST2)]])
G14_IRB1 = gen_irblock(LBL1, [[ExprAff(r, a+c)]])

G14_IRA.blocks = {irb.label : irb for irb in [G14_IRB0, G14_IRB1]}

G14_IRA.graph.add_uniq_edge(G14_IRB0.label, G14_IRB1.label)

# Expected output for graph 1
G14_EXP_IRA = IRATest()

G14_EXP_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1)], [ExprAff(c, a)],
                                  [ExprAff(a, CST2)]])
G14_EXP_IRB1 = gen_irblock(LBL1, [[ExprAff(r, a+c)]])

G14_EXP_IRA.blocks = {irb.label: irb for irb in [G14_EXP_IRB0, G14_EXP_IRB1]}

# graph 15 : Graph where variable assigned multiple and read at the same time,
# but useless

G15_IRA = IRATest()

G15_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST2)], [ExprAff(a, CST1),
                                                   ExprAff(b, a+CST2),
                                                   ExprAff(c, CST1)]])
G15_IRB1 = gen_irblock(LBL1, [[ExprAff(r, a)]])

G15_IRA.blocks = {irb.label : irb for irb in [G15_IRB0, G15_IRB1]}

G15_IRA.graph.add_uniq_edge(G15_IRB0.label, G15_IRB1.label)

# Expected output for graph 1
G15_EXP_IRA = IRATest()

G15_EXP_IRB0 = gen_irblock(LBL0, [[], [ExprAff(a, CST1)]])
G15_EXP_IRB1 = gen_irblock(LBL1, [[ExprAff(r, a)]])

G15_EXP_IRA.blocks = {irb.label: irb for irb in [G15_EXP_IRB0, G15_EXP_IRB1]}

# graph 16 : Graph where variable assigned multiple times in the same bloc

G16_IRA = IRATest()

G16_IRB0 = gen_irblock(LBL0, [[ExprAff(a, CST1), ExprAff(b, CST2),
                               ExprAff(c, CST3)], [ExprAff(a, c+CST1),
                                                   ExprAff(b, c+CST2)]])
G16_IRB1 = gen_irblock(LBL1, [[ExprAff(r, a+b)], [ExprAff(r, c+r)]])
G16_IRB2 = gen_irblock(LBL2, [[]])

G16_IRA.blocks = {irb.label : irb for irb in [G16_IRB0, G16_IRB1]}

G16_IRA.graph.add_uniq_edge(G16_IRB0.label, G16_IRB1.label)
G16_IRA.graph.add_uniq_edge(G16_IRB1.label, G16_IRB2.label)

G16_IRA.blocks = {irb.label : irb for irb in [G16_IRB0, G16_IRB1]}

# Expected output for graph 1
G16_EXP_IRA = IRATest()

G16_EXP_IRB0 = gen_irblock(LBL0, [[ExprAff(c, CST3)], [ExprAff(a, c + CST1),
                                                       ExprAff(b, c + CST2)]])
G16_EXP_IRB1 = gen_irblock(LBL1, [[ExprAff(r, a+b)], [ExprAff(r, c+r)]])

G16_EXP_IRA.blocks = {irb.label: irb for irb in [G16_EXP_IRB0, G16_EXP_IRB1]}

# graph 17 : parallel ir

G17_IRA = IRATest()

G17_IRB0 = gen_irblock(LBL0, [[ExprAff(a, a*b),
                               ExprAff(b, c),
                               ExprAff(c, CST1)],

                              [ExprAff(d, d+ CST2)],

                              [ExprAff(a, CST1),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(ExprMem(d+CST1), a),
                               ExprAff(a, b),
                               ExprAff(b, c),
                               ExprAff(c, CST1)],

                              [ExprAff(a, CST1),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(ExprMem(d+CST2), a),
                               ExprAff(a, b),
                               ExprAff(b, c),
                               ExprAff(c, CST1)],


                              [ExprAff(a, CST2),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(a, a+CST1)],

                              [ExprAff(d, a),
                               ExprAff(a, d)],

                              [ExprAff(d, d+CST1)],

                              [ExprAff(a, CST2),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(a, a+CST2)],

                              [ExprAff(a, CST2),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(a, CST1),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(ExprMem(d), a+b+c)],

                         ])

G17_IRA.blocks = {irb.label : irb for irb in [G17_IRB0]}

G17_IRA.graph.add_node(G17_IRB0.label)

# Expected output for graph 17
G17_EXP_IRA = IRATest()

G17_EXP_IRB0 = gen_irblock(LBL0, [[],

                                  [ExprAff(d, d+ CST2)],

                                  [ExprAff(a, CST1)],

                                  [ExprAff(ExprMem(d+CST1), a)],

                                  [ExprAff(a, CST1)],

                                  [ExprAff(ExprMem(d+CST2), a)],

                                  [ExprAff(a, CST2)],

                                  [ExprAff(a, a+CST1)],

                                  [ExprAff(d, a)],

                                  [ExprAff(d, d+CST1)],

                                  [ExprAff(a, CST2)],

                                  [ExprAff(a, a+CST2)],

                                  [ExprAff(a, CST2),
                                   ExprAff(b, a)],

                                  [ExprAff(a, CST1),
                                   ExprAff(b, a),
                                   ExprAff(c, b)],

                                  G17_IRB0.irs[14]
                                  # Trick because a+b+c != ((a+b)+c)
                                 ])

G17_EXP_IRA.blocks = {irb.label : irb for irb in [G17_EXP_IRB0]}

# Begining  of tests

for test_nb, test in enumerate([(G1_IRA, G1_EXP_IRA),
                                (G2_IRA, G2_EXP_IRA),
                                (G3_IRA, G3_EXP_IRA),
                                (G4_IRA, G4_EXP_IRA),
                                (G5_IRA, G5_EXP_IRA),
                                (G6_IRA, G6_EXP_IRA),
                                (G7_IRA, G7_EXP_IRA),
                                (G8_IRA, G8_EXP_IRA),
                                (G9_IRA, G9_EXP_IRA),
                                (G10_IRA, G10_EXP_IRA),
                                (G11_IRA, G11_EXP_IRA),
                                (G12_IRA, G12_EXP_IRA),
                                (G13_IRA, G13_EXP_IRA),
                                (G14_IRA, G14_EXP_IRA),
                                (G15_IRA, G15_EXP_IRA),
                                (G16_IRA, G16_EXP_IRA),
                                (G17_IRA, G17_EXP_IRA)
]):
    # Extract test elements
    g_ira, g_exp_ira = test

    print "[+] Test", test_nb+1

    # Print initial graph, for debug
    open("graph_%02d.dot" % (test_nb+1), "w").write(g_ira.graph.dot())

    reaching_defs = ReachingDefinitions(g_ira)
    defuse = DiGraphDefUse(reaching_defs, deref_mem=True)
    #open("defuse_%02d.dot" % (test_nb+1), "w").write(defuse.dot())

    # # Simplify graph
    dead_simp(g_ira)

    # # Print simplified graph, for debug
    open("simp_graph_%02d.dot" % (test_nb+1), "w").write(g_ira.graph.dot())

    # Same number of blocks
    assert len(g_ira.blocks) == len(g_exp_ira.blocks)
    # Check that each expr in the blocks are the same
    for lbl, irb in g_ira.blocks.iteritems():
        exp_irb = g_exp_ira.blocks[lbl]
        assert exp_irb.irs == irb.irs
