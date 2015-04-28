from miasm2.expression.expression import ExprId, ExprInt32, ExprAff, ExprMem, ExprOp
from miasm2.core.asmbloc import asm_label
from miasm2.ir.analysis import ira
from miasm2.ir.ir import ir, irbloc
from miasm2.core.graph import DiGraph
from pdb import pm

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

cst1 = ExprInt32(0x11)
cst2 = ExprInt32(0x12)
cst3 = ExprInt32(0x13)

lbl0 = asm_label("lbl0")
lbl1 = asm_label("lbl1")
lbl2 = asm_label("lbl2")
lbl3 = asm_label("lbl3")
lbl4 = asm_label("lbl4")
lbl5 = asm_label("lbl5")
lbl6 = asm_label("lbl6")



def gen_irbloc(lbl, exprs):
    lines = [None for i in xrange(len(exprs))]
    irb = irbloc(lbl, exprs, lines)
    return irb


class Regs(object):
    regs_init = {a: a_init, b: b_init, c: c_init, d: d_init, r: r_init}
    all_regs_ids = [a, b, c, d, r, sp, pc]

class Arch(object):
    regs = Regs()

    def getpc(self, attrib):
        return pc

    def getsp(self, attrib):
        return sp

class IRATest(ir, ira):

    def __init__(self, symbol_pool=None):
        arch = Arch()
        ir.__init__(self, arch, 32, symbol_pool)
        self.IRDst = pc
        self.ret_reg = r

    def get_out_regs(self, b):
        return set([self.ret_reg, self.sp])

# graph 1 : Simple graph with dead and alive variables

g1_ira = IRATest()

g1_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)], [ExprAff(b, cst2)] ])
g1_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, b)] ])
g1_irb2 = gen_irbloc(lbl2, [ [ExprAff(r, a)] ])

g1_ira.gen_graph()

g1_ira.g.add_uniq_edge(g1_irb0.label, g1_irb1.label)
g1_ira.g.add_uniq_edge(g1_irb1.label, g1_irb2.label)

g1_ira.blocs = {irb.label : irb for irb in [g1_irb0, g1_irb1, g1_irb2]}

# Expected output for graph 1
g1_exp_ira = IRATest()

g1_exp_irb0 = gen_irbloc(lbl0, [ [], [ExprAff(b, cst2)] ])
g1_exp_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, b)] ])
g1_exp_irb2 = gen_irbloc(lbl2, [ [ExprAff(r, a)] ])

g1_exp_ira.blocs = {irb.label : irb for irb in [g1_exp_irb0, g1_exp_irb1, g1_exp_irb2]}

# graph 2 : Natural loop with dead variable

g2_ira = IRATest()

g2_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)], [ExprAff(r, cst1)] ])
g2_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, a+cst1)] ])
g2_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, r)] ])

g2_ira.gen_graph()

g2_ira.g.add_uniq_edge(g2_irb0.label, g2_irb1.label)
g2_ira.g.add_uniq_edge(g2_irb1.label, g2_irb2.label)
g2_ira.g.add_uniq_edge(g2_irb1.label, g2_irb1.label)

g2_ira.blocs = {irb.label : irb for irb in [g2_irb0, g2_irb1, g2_irb2]}

# Expected output for graph 2
g2_exp_ira = IRATest()

g2_exp_irb0 = gen_irbloc(lbl0, [ [], [ExprAff(r, cst1)] ])
g2_exp_irb1 = gen_irbloc(lbl1, [ [] ])
g2_exp_irb2 = gen_irbloc(lbl2, [ [] ])

g2_exp_ira.blocs = {irb.label : irb for irb in [g2_exp_irb0, g2_exp_irb1, g2_exp_irb2]}

# graph 3 : Natural loop with alive variables

g3_ira = IRATest()

g3_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)] ])
g3_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, a+cst1)] ])
g3_irb2 = gen_irbloc(lbl2, [ [ExprAff(r, a)] ])

g3_ira.gen_graph()

g3_ira.g.add_uniq_edge(g3_irb0.label, g3_irb1.label)
g3_ira.g.add_uniq_edge(g3_irb1.label, g3_irb2.label)
g3_ira.g.add_uniq_edge(g3_irb1.label, g3_irb1.label)

g3_ira.blocs = {irb.label : irb for irb in [g3_irb0, g3_irb1, g3_irb2]}

# Expected output for graph 3
g3_exp_ira = IRATest()

g3_exp_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)] ])
g3_exp_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, a+cst1)] ])
g3_exp_irb2 = gen_irbloc(lbl2, [ [ExprAff(r, a)] ])

g3_exp_ira.blocs = {irb.label : irb for irb in [g3_exp_irb0, g3_exp_irb1, g3_exp_irb2]}

# graph 4 : If/else with dead variables

g4_ira = IRATest()

g4_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)] ])
g4_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, a+cst1)] ])
g4_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, a+cst2)] ])
g4_irb3 = gen_irbloc(lbl3, [ [ExprAff(a, cst3)], [ExprAff(r, a)] ])

g4_ira.gen_graph()

g4_ira.g.add_uniq_edge(g4_irb0.label, g4_irb1.label)
g4_ira.g.add_uniq_edge(g4_irb0.label, g4_irb2.label)
g4_ira.g.add_uniq_edge(g4_irb1.label, g4_irb3.label)
g4_ira.g.add_uniq_edge(g4_irb2.label, g4_irb3.label)

g4_ira.blocs = {irb.label : irb for irb in [g4_irb0, g4_irb1, g4_irb2, g4_irb3]}

# Expected output for graph 4
g4_exp_ira = IRATest()

g4_exp_irb0 = gen_irbloc(lbl0, [ [] ])
g4_exp_irb1 = gen_irbloc(lbl1, [ [] ])
g4_exp_irb2 = gen_irbloc(lbl2, [ [] ])
g4_exp_irb3 = gen_irbloc(lbl3, [ [ExprAff(a, cst3)], [ExprAff(r, a)] ])

g4_exp_ira.gen_graph()

g4_exp_ira.blocs = {irb.label : irb for irb in [g4_exp_irb0, g4_exp_irb1, g4_exp_irb2, g4_exp_irb3]}

# graph 5 : Loop and If/else with dead variables

g5_ira = IRATest()

g5_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)] ])
g5_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, cst2)] ])
g5_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, a+cst2)] ])
g5_irb3 = gen_irbloc(lbl3, [ [ExprAff(a, a+cst3)] ])
g5_irb4 = gen_irbloc(lbl4, [ [ExprAff(a, a+cst1)] ])
g5_irb5 = gen_irbloc(lbl5, [ [ExprAff(a, r)] ])

g5_ira.gen_graph()

g5_ira.g.add_uniq_edge(g5_irb0.label, g5_irb1.label)
g5_ira.g.add_uniq_edge(g5_irb1.label, g5_irb2.label)
g5_ira.g.add_uniq_edge(g5_irb1.label, g5_irb3.label)
g5_ira.g.add_uniq_edge(g5_irb2.label, g5_irb4.label)
g5_ira.g.add_uniq_edge(g5_irb3.label, g5_irb4.label)
g5_ira.g.add_uniq_edge(g5_irb4.label, g5_irb5.label)
g5_ira.g.add_uniq_edge(g5_irb4.label, g5_irb1.label)

g5_ira.blocs = {irb.label : irb for irb in [g5_irb0, g5_irb1, g5_irb2, g5_irb3, g5_irb4, g5_irb5]}

# Expected output for graph 5
g5_exp_ira = IRATest()

g5_exp_irb0 = gen_irbloc(lbl0, [ [] ])
g5_exp_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, cst2)] ])
g5_exp_irb2 = gen_irbloc(lbl2, [ [] ])
g5_exp_irb3 = gen_irbloc(lbl3, [ [] ])
g5_exp_irb4 = gen_irbloc(lbl4, [ [] ])
g5_exp_irb5 = gen_irbloc(lbl5, [ [] ])

g5_exp_ira.gen_graph()

g5_exp_ira.blocs = {irb.label : irb for irb in [g5_exp_irb0, g5_exp_irb1, g5_exp_irb2, g5_exp_irb3, g5_exp_irb4, g5_exp_irb5]}

# graph 6 : Natural loop with dead variables symetric affectation (a = b <-> b = a )

g6_ira = IRATest()

g6_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)] ])
g6_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, a)] ])
g6_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, b)] ])
g6_irb3 = gen_irbloc(lbl3, [ [ExprAff(r, cst2)] ])


g6_ira.gen_graph()

g6_ira.g.add_uniq_edge(g6_irb0.label, g6_irb1.label)
g6_ira.g.add_uniq_edge(g6_irb1.label, g6_irb2.label)
g6_ira.g.add_uniq_edge(g6_irb2.label, g6_irb1.label)
g6_ira.g.add_uniq_edge(g6_irb2.label, g6_irb3.label)

g6_ira.blocs = {irb.label : irb for irb in [g6_irb0, g6_irb1, g6_irb2, g6_irb3]}

# Expected output for graph 6
g6_exp_ira = IRATest()

g6_exp_irb0 = gen_irbloc(lbl0, [ [] ])
g6_exp_irb1 = gen_irbloc(lbl1, [ [] ])
g6_exp_irb2 = gen_irbloc(lbl2, [ [] ])
g6_exp_irb3 = gen_irbloc(lbl3, [ [ExprAff(r, cst2)] ])

g6_exp_ira.blocs = {irb.label : irb for irb in [g6_exp_irb0, g6_exp_irb1, g6_exp_irb2, g6_exp_irb3]}

# graph 7 : Double entry loop with dead variables

g7_ira = IRATest()

g7_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)], [ExprAff(r, cst1)] ])
g7_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, a+cst1)] ])
g7_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, a+cst2)] ])
g7_irb3 = gen_irbloc(lbl3, [ [ExprAff(a, r)] ])


g7_ira.gen_graph()

g7_ira.g.add_uniq_edge(g7_irb0.label, g7_irb1.label)
g7_ira.g.add_uniq_edge(g7_irb1.label, g7_irb2.label)
g7_ira.g.add_uniq_edge(g7_irb2.label, g7_irb1.label)
g7_ira.g.add_uniq_edge(g7_irb2.label, g7_irb3.label)
g7_ira.g.add_uniq_edge(g7_irb0.label, g7_irb2.label)


g7_ira.blocs = {irb.label : irb for irb in [g7_irb0, g7_irb1, g7_irb2, g7_irb3]}

# Expected output for graph 7
g7_exp_ira = IRATest()

g7_exp_irb0 = gen_irbloc(lbl0, [ [],  [ExprAff(r, cst1)] ])
g7_exp_irb1 = gen_irbloc(lbl1, [ [] ])
g7_exp_irb2 = gen_irbloc(lbl2, [ [] ])
g7_exp_irb3 = gen_irbloc(lbl3, [ [] ])

g7_exp_ira.blocs = {irb.label : irb for irb in [g7_exp_irb0, g7_exp_irb1, g7_exp_irb2, g7_exp_irb3]}

# graph 8 : Nested loops with dead variables

g8_ira = IRATest()

g8_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)], [ExprAff(b, cst1)] ])
g8_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, a+cst1)] ])
g8_irb2 = gen_irbloc(lbl2, [ [ExprAff(b, b+cst2)] ])
g8_irb3 = gen_irbloc(lbl3, [ [ExprAff(a, b)] ])


g8_ira.gen_graph()

g8_ira.g.add_uniq_edge(g8_irb0.label, g8_irb1.label)
g8_ira.g.add_uniq_edge(g8_irb1.label, g8_irb2.label)
g8_ira.g.add_uniq_edge(g8_irb2.label, g8_irb1.label)
g8_ira.g.add_uniq_edge(g8_irb2.label, g8_irb3.label)
g8_ira.g.add_uniq_edge(g8_irb3.label, g8_irb2.label)


g8_ira.blocs = {irb.label : irb for irb in [g8_irb0, g8_irb1, g8_irb2, g8_irb3]}

# Expected output for graph 8

g8_exp_ira = IRATest()

g8_exp_irb0 = gen_irbloc(lbl0, [ [],  [] ])
g8_exp_irb1 = gen_irbloc(lbl1, [ [] ])
g8_exp_irb2 = gen_irbloc(lbl2, [ [] ])
g8_exp_irb3 = gen_irbloc(lbl3, [ [] ])

g8_exp_ira.blocs = {irb.label : irb for irb in [g8_exp_irb0, g8_exp_irb1, g8_exp_irb2, g8_exp_irb3]}

# graph 9 : Miultiple-exits loops with dead variables

g9_ira = IRATest()

g9_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)], [ExprAff(b, cst1)] ])
g9_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, a+cst1)], [ExprAff(b, b+cst1)] ])
g9_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, a+cst2)], [ExprAff(b, b+cst2)] ])
g9_irb3 = gen_irbloc(lbl3, [ [ExprAff(a, b)] ])
g9_irb4 = gen_irbloc(lbl4, [ [ExprAff(r, a)], [ExprAff(r, b)] ])


g9_ira.gen_graph()

g9_ira.g.add_uniq_edge(g9_irb0.label, g9_irb4.label)
g9_ira.g.add_uniq_edge(g9_irb0.label, g9_irb1.label)
g9_ira.g.add_uniq_edge(g9_irb1.label, g9_irb0.label)
g9_ira.g.add_uniq_edge(g9_irb1.label, g9_irb4.label)
g9_ira.g.add_uniq_edge(g9_irb1.label, g9_irb2.label)
g9_ira.g.add_uniq_edge(g9_irb2.label, g9_irb0.label)
g9_ira.g.add_uniq_edge(g9_irb2.label, g9_irb3.label)
g9_ira.g.add_uniq_edge(g9_irb3.label, g9_irb4.label)


g9_ira.blocs = {irb.label : irb for irb in [g9_irb0, g9_irb1, g9_irb2, g9_irb3,  g9_irb4]}

# Expected output for graph 9

g9_exp_ira = IRATest()

g9_exp_irb0 = gen_irbloc(lbl0, [ [], [ExprAff(b, cst1)] ])
g9_exp_irb1 = gen_irbloc(lbl1, [ [], [ExprAff(b, b+cst1)] ])
g9_exp_irb2 = gen_irbloc(lbl2, [ [], [ExprAff(b, b+cst2)] ])
g9_exp_irb3 = gen_irbloc(lbl3, [ [] ])
g9_exp_irb4 = gen_irbloc(lbl4, [ [], [ExprAff(r, b)] ])

g9_exp_ira.blocs = {irb.label : irb for irb in [g9_exp_irb0, g9_exp_irb1, g9_exp_irb2, g9_exp_irb3, g9_exp_irb4]}

# graph 10 : Natural loop with alive variables symetric affectation (a = b <-> b = a )

g10_ira = IRATest()

g10_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)] ])
g10_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, a)] ])
g10_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, b)] ])
g10_irb3 = gen_irbloc(lbl3, [ [ExprAff(r, cst1)] ])


g10_ira.gen_graph()

g10_ira.g.add_uniq_edge(g10_irb0.label, g10_irb1.label)
g10_ira.g.add_uniq_edge(g10_irb1.label, g10_irb2.label)
g10_ira.g.add_uniq_edge(g10_irb2.label, g10_irb1.label)
g10_ira.g.add_uniq_edge(g10_irb2.label, g10_irb3.label)

g10_ira.blocs = {irb.label : irb for irb in [g10_irb0, g10_irb1, g10_irb2, g10_irb3]}

# Expected output for graph 10
g10_exp_ira = IRATest()

g10_exp_irb0 = gen_irbloc(lbl0, [ [] ])
g10_exp_irb1 = gen_irbloc(lbl1, [ [] ])
g10_exp_irb2 = gen_irbloc(lbl2, [ [] ])
g10_exp_irb3 = gen_irbloc(lbl3, [ [ExprAff(r, cst1)] ])

g10_exp_ira.blocs = {irb.label : irb for irb in [g10_exp_irb0, g10_exp_irb1, g10_exp_irb2, g10_exp_irb3]}

# graph 11 : If/Else conditions with alive variables

g11_ira = IRATest()

g11_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, b)] ])
g11_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, a)] ])
g11_irb2 = gen_irbloc(lbl2, [ [ExprAff(r, a)] ])
g11_irb3 = gen_irbloc(lbl3, [ [ExprAff(a, a+cst1)] ])
g11_irb4 = gen_irbloc(lbl4, [ [ExprAff(b, b+cst1)] ])


g11_ira.gen_graph()

g11_ira.g.add_uniq_edge(g11_irb0.label, g11_irb1.label)
#g11_ira.g.add_uniq_edge(g11_irb3.label, g11_irb1.label)
g11_ira.g.add_uniq_edge(g11_irb1.label, g11_irb0.label)
#g11_ira.g.add_uniq_edge(g11_irb4.label, g11_irb0.label)
g11_ira.g.add_uniq_edge(g11_irb1.label, g11_irb2.label)

g11_ira.blocs = {irb.label : irb for irb in [g11_irb0, g11_irb1, g11_irb2]} #, g11_irb3, g11_irb4]}

# Expected output for graph 11
g11_exp_ira = IRATest()

g11_exp_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, b)] ])
g11_exp_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, a)] ])
g11_exp_irb2 = gen_irbloc(lbl2, [ [ExprAff(r, a)] ])
#g11_exp_irb3 = gen_irbloc(lbl3, [ [ExprAff(a, a+cst1)] ])
#g11_exp_irb4 = gen_irbloc(lbl4, [ [ExprAff(b, b+cst1)] ])

g11_exp_ira.blocs = {irb.label : irb for irb in [g11_exp_irb0, g11_exp_irb1, g11_exp_irb2]} #, g11_exp_irb3, g11_exp_irb4]}

# graph 12 : Graph with multiple out points and useless definitions of out register

g12_ira = IRATest()

g12_irb0 = gen_irbloc(lbl0, [ [ExprAff(r, cst1)], [ExprAff(a, cst2)] ])
g12_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, cst2)] ])
g12_irb2 = gen_irbloc(lbl2, [ [ExprAff(r, a)], [ExprAff(b, cst3)] ])
g12_irb3 = gen_irbloc(lbl3, [ [ExprAff(r, cst3)] ])
g12_irb4 = gen_irbloc(lbl4, [ [ExprAff(r, cst2)] ])
g12_irb5 = gen_irbloc(lbl5, [ [ExprAff(r, b)] ])

g12_ira.gen_graph()

g12_ira.g.add_uniq_edge(g12_irb0.label, g12_irb1.label)
g12_ira.g.add_uniq_edge(g12_irb0.label, g12_irb2.label)
g12_ira.g.add_uniq_edge(g12_irb2.label, g12_irb3.label)
g12_ira.g.add_uniq_edge(g12_irb2.label, g12_irb4.label)
g12_ira.g.add_uniq_edge(g12_irb4.label, g12_irb5.label)

g12_ira.blocs = {irb.label : irb for irb in [g12_irb0, g12_irb1, g12_irb2, g12_irb3, g12_irb4, g12_irb5]}

# Expected output for graph 12
g12_exp_ira = IRATest()

g12_exp_irb0 = gen_irbloc(lbl0, [ [], [] ])
g12_exp_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, cst2)] ])
g12_exp_irb2 = gen_irbloc(lbl2, [ [], [ExprAff(b, cst3)] ])
g12_exp_irb3 = gen_irbloc(lbl3, [ [ExprAff(r, cst3)] ])
g12_exp_irb4 = gen_irbloc(lbl4, [ [] ])
g12_exp_irb5 = gen_irbloc(lbl5, [ [ExprAff(r, b)] ])


g12_exp_ira.blocs = {irb.label : irb for irb in [g12_exp_irb0, g12_exp_irb1, g12_exp_irb2, g12_exp_irb3, g12_exp_irb4, g12_exp_irb5]}

# graph 13 : Graph where a leaf has lost its son

g13_ira = IRATest()

g13_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)], [ExprAff(b, cst2)] ])
g13_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, b)] ])
g13_irb2 = gen_irbloc(lbl2, [  [ExprAff(d, cst2)], [ExprAff(a, b+cst1), ExprAff(c, a+b)] ])
g13_irb3 = gen_irbloc(lbl3, [ [] ]) # lost son
g13_irb4 = gen_irbloc(lbl4, [ [ExprAff(b, cst2)] ])

g13_ira.gen_graph()

g13_ira.g.add_uniq_edge(g13_irb0.label, g13_irb1.label)
g13_ira.g.add_uniq_edge(g13_irb0.label, g13_irb4.label)
g13_ira.g.add_uniq_edge(g13_irb2.label, g13_irb3.label)
g13_ira.g.add_uniq_edge(g13_irb4.label, g13_irb2.label)

g13_ira.blocs = {irb.label : irb for irb in [g13_irb0, g13_irb1, g13_irb2, g13_irb4]}

# Expected output for graph 13
g13_exp_ira =  IRATest()

g13_exp_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)], [ExprAff(b, cst2)] ])
g13_exp_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, b)] ])
g13_exp_irb2 = gen_irbloc(lbl2, [ [ExprAff(d, cst2)], [ExprAff(a, b+cst1), ExprAff(c, a+b)] ])
g13_exp_irb3 = gen_irbloc(lbl3, [ [] ])
g13_exp_irb4 = gen_irbloc(lbl4, [ [ExprAff(b, cst2)] ])

g13_exp_ira.blocs = {irb.label: irb for irb in [g13_exp_irb0, g13_exp_irb1, g13_exp_irb2, g13_exp_irb4]}

#g13_exp_ira = g13_ira

# graph 14 : Graph where variable assigned multiple times in a block but still useful in the end

g14_ira = IRATest()

g14_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)], [ExprAff(c, a)], [ExprAff(a, cst2)] ])
g14_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, a+c)] ])

g14_ira.gen_graph()

g14_ira.g.add_uniq_edge(g14_irb0.label, g14_irb1.label)

g14_ira.blocs = {irb.label : irb for irb in [g14_irb0, g14_irb1]}

# Expected output for graph 1
g14_exp_ira = IRATest()

g14_exp_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1)], [ExprAff(c, a)], [ExprAff(a, cst2)] ])
g14_exp_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, a+c)] ])

g14_exp_ira.blocs = {irb.label: irb for irb in [g14_exp_irb0, g14_exp_irb1]}

# graph 15 : Graph where variable assigned multiple and read at the same time, but useless

g15_ira = IRATest()

g15_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst2)], [ExprAff(a, cst1), ExprAff(b, a+cst2), ExprAff(c,cst1)] ])
g15_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, a)] ])

g15_ira.gen_graph()

g15_ira.g.add_uniq_edge(g15_irb0.label, g15_irb1.label)

g15_ira.blocs = {irb.label : irb for irb in [g15_irb0, g15_irb1]}

# Expected output for graph 1
g15_exp_ira = IRATest()

g15_exp_irb0 = gen_irbloc(lbl0, [ [], [ExprAff(a, cst1)] ])
g15_exp_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, a)] ])

g15_exp_ira.blocs = {irb.label: irb for irb in [g15_exp_irb0, g15_exp_irb1]}

# graph 16 : Graph where variable assigned multiple times in the same bloc

g16_ira = IRATest()

g16_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, cst1), ExprAff(b, cst2), ExprAff(c,cst3)], [ExprAff(a, c+cst1), ExprAff(b, c+cst2)] ])
g16_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, a+b)], [ExprAff(r, c+r)] ])
g16_irb2 = gen_irbloc(lbl2, [ [] ])

g16_ira.gen_graph()

g16_ira.g.add_uniq_edge(g16_irb0.label, g16_irb1.label)
g16_ira.g.add_uniq_edge(g16_irb1.label, g16_irb2.label)

g16_ira.blocs = {irb.label : irb for irb in [g16_irb0, g16_irb1]}

# Expected output for graph 1
g16_exp_ira = IRATest()

g16_exp_irb0 = gen_irbloc(lbl0, [ [ExprAff(c, cst3)], [ExprAff(a, c + cst1), ExprAff(b, c + cst2)] ])
g16_exp_irb1 = gen_irbloc(lbl1, [ [ExprAff(r, a+b)], [ExprAff(r, c+r)] ])

g16_exp_ira.blocs = {irb.label: irb for irb in [g16_exp_irb0, g16_exp_irb1]}

# graph 17 : parallel ir

g17_ira = IRATest()

g17_irb0 = gen_irbloc(lbl0, [ [ExprAff(a, a*b),
                               ExprAff(b, c),
                               ExprAff(c, cst1)],

                              [ExprAff(d, d+ cst2)],

                              [ExprAff(a, cst1),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(ExprMem(d+cst1), a),
                               ExprAff(a, b),
                               ExprAff(b, c),
                               ExprAff(c, cst1)],

                              [ExprAff(a, cst1),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(ExprMem(d+cst2), a),
                               ExprAff(a, b),
                               ExprAff(b, c),
                               ExprAff(c, cst1)],


                              [ExprAff(a, cst2),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(a, a+cst1)],

                              [ExprAff(d, a),
                               ExprAff(a, d)],

                              [ExprAff(d, d+cst1)],

                              [ExprAff(a, cst2),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(a, a+cst2)],

                              [ExprAff(a, cst2),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(a, cst1),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              [ExprAff(ExprMem(d), a+b+c)],

                          ])

g17_ira.gen_graph()

g17_ira.blocs = {irb.label : irb for irb in [g17_irb0]}

g17_ira.g.add_node(g17_irb0.label)

# Expected output for graph 17
g17_exp_ira = IRATest()

g17_exp_irb0 = gen_irbloc(lbl0, [[],

                              [ExprAff(d, d+ cst2)],

                              [ExprAff(a, cst1)],

                              [ExprAff(ExprMem(d+cst1), a)],

                              [ExprAff(a, cst1)],

                              [ExprAff(ExprMem(d+cst2), a)],

                              [ExprAff(a, cst2)],

                              [ExprAff(a, a+cst1)],

                              [ExprAff(d, a)],

                              [ExprAff(d, d+cst1)],

                              [ExprAff(a, cst2)],

                              [ExprAff(a, a+cst2)],

                              [ExprAff(a, cst2),
                               ExprAff(b, a)],

                              [ExprAff(a, cst1),
                               ExprAff(b, a),
                               ExprAff(c, b)],

                              g17_irb0.irs[14] # Trick because a+b+c != ((a+b)+c)
                                 #[ExprAff(ExprMem(ExprId('d', 32), 32), ExprOp('+', ExprOp('+', ExprId('a', 32), ExprId('b', 32)), ExprId('c', 32)))]
                          ])

g17_exp_ira.blocs = {irb.label : irb for irb in [g17_exp_irb0]}

# Begining  of tests

for i, test in enumerate([(g1_ira, g1_exp_ira),
                          (g2_ira, g2_exp_ira),
                          (g3_ira, g3_exp_ira),
                          (g4_ira, g4_exp_ira),
                          (g5_ira, g5_exp_ira),
                          (g6_ira, g6_exp_ira),
                          (g7_ira, g7_exp_ira),
                          (g8_ira, g8_exp_ira),
                          (g9_ira, g9_exp_ira),
                          (g10_ira, g10_exp_ira),
                          (g11_ira, g11_exp_ira),
                          (g12_ira, g12_exp_ira),
                          (g13_ira, g13_exp_ira),
                          (g14_ira, g14_exp_ira),
                          (g15_ira, g15_exp_ira),
                          (g16_ira, g16_exp_ira),
                          (g17_ira, g17_exp_ira)
                      ]):
    # Extract test elements
    g_ira, g_exp_ira = test

    print "[+] Test", i+1

    # Print initial graph, for debug
    open("graph_%02d.dot" % (i+1), "w").write(g_ira.graph())

    # Simplify graph
    g_ira.dead_simp()

    # Print simplified graph, for debug
    open("simp_graph_%02d.dot" % (i+1), "w").write(g_ira.graph())

    # Same number of blocks
    assert len(g_ira.blocs) == len(g_exp_ira.blocs)
    # Check that each expr in the blocs are the same
    for lbl , irb in g_ira.blocs.iteritems():
        exp_irb = g_exp_ira.blocs[lbl]
        assert len(irb.irs) == len(exp_irb.irs), "(%s)  %d / %d" %(
            lbl, len(irb.irs), len(exp_irb.irs))
        for i in xrange(0,len(exp_irb.irs)):
            assert len(irb.irs[i]) == len(exp_irb.irs[i]), "(%s:%d)  %d / %d" %(
                lbl, i, len(irb.irs[i]), len(exp_irb.irs[i]))
            for s_instr in xrange(len(irb.irs[i])):
                assert irb.irs[i][s_instr] == exp_irb.irs[i][s_instr],\
                    "(%s:%d)  %s / %s" %(
                        lbl, i, irb.irs[i][s_instr], exp_irb.irs[i][s_instr])
