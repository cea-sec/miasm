"""Regression test module for DependencyGraph"""
from miasm2.expression.expression import ExprId, ExprInt32, ExprAff, ExprCond
from miasm2.core.asmbloc import asm_label
from miasm2.ir.analysis import ira
from miasm2.ir.ir import ir, irbloc
from miasm2.core.graph import DiGraph
from miasm2.analysis.depgraph import DependencyNode, DependencyGraph,\
    DependencyDict
from itertools import count

EMULATION=True
try:
    import z3
except ImportError:
    EMULATION=False

STEP_COUNTER = count()
A = ExprId("a")
B = ExprId("b")
C = ExprId("c")
D = ExprId("d")
R = ExprId("r")

A_INIT = ExprId("a_init")
B_INIT = ExprId("b_init")
C_INIT = ExprId("c_init")
D_INIT = ExprId("d_init")

PC = ExprId("pc")
SP = ExprId("sp")

CST0 = ExprInt32(0x0)
CST1 = ExprInt32(0x11)
CST2 = ExprInt32(0x12)
CST3 = ExprInt32(0x13)
CST22 = ExprInt32(0x22)
CST23 = ExprInt32(0x23)
CST24 = ExprInt32(0x24)
CST33 = ExprInt32(0x33)
CST35 = ExprInt32(0x35)
CST37 = ExprInt32(0x37)

LBL0 = asm_label("lbl0")
LBL1 = asm_label("lbl1")
LBL2 = asm_label("lbl2")
LBL3 = asm_label("lbl3")
LBL4 = asm_label("lbl4")
LBL5 = asm_label("lbl5")
LBL6 = asm_label("lbl6")


def gen_irbloc(lbl, exprs):
    """ Returns an IRBlock with empty lines.
    Used only for tests purpose
    """
    lines = [None for _ in xrange(len(exprs))]
    return irbloc(lbl, exprs, lines)


class Regs(object):

    """Fake registers for tests """
    regs_init = {A: A_INIT, B: B_INIT, C: C_INIT, D: D_INIT}
    all_regs_ids = [A, B, C, D, SP, PC, R]


class Arch(object):

    """Fake architecture for tests """
    regs = Regs()

    def getpc(self, attrib):
        return PC

    def getsp(self, attrib):
        return SP


class IRATest(ira):

    """Fake IRA class for tests"""

    def __init__(self, symbol_pool=None):
        arch = Arch()
        super(IRATest, self).__init__(arch, 32, symbol_pool)
        self.IRDst = PC
        self.ret_reg = R

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])


class GraphTest(DiGraph):

    """Fake graph representation class for test cases"""

    def __init__(self, pira):
        self.ira = pira
        super(GraphTest, self).__init__()

    def __eq__(self, graph):
        if (len(self._nodes) != len(graph.nodes()) or
                len(self._edges) != len(graph.edges())):
            return False

        if (set([n.nostep_repr for n in self._nodes]) !=
                set([n.nostep_repr for n in graph.nodes()])):
            return False
        if (sorted([(src.nostep_repr, dst.nostep_repr)
                    for (src, dst) in self._edges])
        != sorted([(src.nostep_repr, dst.nostep_repr)
                   for (src, dst) in graph.edges()])):
            return False
        return True

    def node2str(self, node):
        if isinstance(node, asm_label):
            if node not in self.ira.blocs:
                return str(node)
            else:
                return str(self.ira.blocs[node])

        assert node.label in self.ira.blocs
        out = "(%s, %s, %s)\\l" % (node.label.name,
                                 node.element,
                                 node.line_nb)
        if not 0 <= node.line_nb < len(self.ira.blocs[node.label].irs):
            return out
        exprs = self.ira.blocs[node.label].irs[node.line_nb]
        exprs_str = '\\l'.join([str(x) for x in exprs])
        return "%s %s" % (out, exprs_str)

# Test structures
print "[+] Test structures"

print "[+] Test DependencyDict"
DD0 = DependencyDict(LBL0, [])
DEPNODES_0 = [DependencyNode(LBL0, A, linenb, next(STEP_COUNTER))
              for linenb in xrange(10)][::-1]

# Heads
assert list(DD0.heads()) == []
assert DD0.is_head(DEPNODES_0[-1]) == True
assert DD0.is_head(DEPNODES_0[0]) == False
DD0.cache[DEPNODES_0[-1]] = set(DEPNODES_0[-1:])
assert list(DD0.heads()) == [DEPNODES_0[-1]]

# Extend
DD1 = DD0.extend(LBL1)

assert DD1.label == LBL1
assert DD1.history == [DD0]
assert DD1.cache == DD0.cache
assert DD1.pending == set()
assert DD1 != DD0

DD1.cache[DEPNODES_0[4]] = set(DEPNODES_0[5:9])
assert DD1.cache != DD0.cache

DD2 = DD0.copy()
assert DD2.label == LBL0
assert DD2.history == []
assert DD2.cache == DD0.cache
assert DD2.pending == DD0.pending
assert DD2 == DD0

DD2.cache[DEPNODES_0[4]] = set(DEPNODES_0[5:9])
assert DD2.cache != DD0.cache


print "   [+] Test dictionary equality"
DNA = DependencyNode(LBL2, A, 0, next(STEP_COUNTER))
DNB = DependencyNode(LBL1, B, 1, next(STEP_COUNTER))
DNC = DependencyNode(LBL1, C, 0, next(STEP_COUNTER), True)
DNB2 = DependencyNode(LBL1, B, 1, next(STEP_COUNTER))
DNC2 = DependencyNode(LBL1, C, 0, next(STEP_COUNTER), True)
DNB3 = DependencyNode(LBL1, B, 1, next(STEP_COUNTER))
DNC3 = DependencyNode(LBL1, C, 0, next(STEP_COUNTER), True)

DDCT1 = DependencyDict(LBL1, [])
DDCT1.cache.update({DNA: set([DNB]), DNB: set([DNC])})

DDCT2 = DDCT1.extend(LBL1)
DDCT2.cache.update({DNA: set([DNB]), DNB: set([DNC]),
                    DNC: set([DNB2]), DNB2: set([DNC2])
                    })

DDCT3 = DDCT2.extend(LBL1)
DDCT3.cache.update(
    {DNA: set([DNB]), DNB: set([DNC]),
     DNC: set([DNB2]), DNB2: set([DNC2]),
     DNC2: set([DNB3]), DNB3: set([DNC3])})

assert not DDCT1.__eq__(DDCT2)
assert DDCT2.__eq__(DDCT3)

print "[+] DependencyDict OK !"
print "[+] Structures OK !"

# graph 1

G1_IRA = IRATest()
G1_IRA.g = GraphTest(G1_IRA)

G1_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G1_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, C)]])
G1_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G1_IRA.graph.add_uniq_edge(G1_IRB0.label, G1_IRB1.label)
G1_IRA.graph.add_uniq_edge(G1_IRB1.label, G1_IRB2.label)

G1_IRA.blocs = dict([(irb.label, irb) for irb in [G1_IRB0, G1_IRB1, G1_IRB2]])

# graph 2

G2_IRA = IRATest()
G2_IRA.g = GraphTest(G2_IRA)

G2_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G2_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, CST2)]])
G2_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B + C)]])

G2_IRA.graph.add_uniq_edge(G2_IRB0.label, G2_IRB1.label)
G2_IRA.graph.add_uniq_edge(G2_IRB1.label, G2_IRB2.label)

G2_IRA.blocs = dict([(irb.label, irb) for irb in [G2_IRB0, G2_IRB1, G2_IRB2]])


# graph 3

G3_IRA = IRATest()
G3_IRA.g = GraphTest(G3_IRA)

G3_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G3_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, CST2)]])
G3_IRB2 = gen_irbloc(LBL2, [[ExprAff(B, CST3)]])
G3_IRB3 = gen_irbloc(LBL3, [[ExprAff(A, B + C)]])

G3_IRA.graph.add_uniq_edge(G3_IRB0.label, G3_IRB1.label)
G3_IRA.graph.add_uniq_edge(G3_IRB0.label, G3_IRB2.label)
G3_IRA.graph.add_uniq_edge(G3_IRB1.label, G3_IRB3.label)
G3_IRA.graph.add_uniq_edge(G3_IRB2.label, G3_IRB3.label)

G3_IRA.blocs = dict([(irb.label, irb) for irb in [G3_IRB0, G3_IRB1,
                                                  G3_IRB2, G3_IRB3]])

# graph 4

G4_IRA = IRATest()
G4_IRA.g = GraphTest(G4_IRA)

G4_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G4_IRB1 = gen_irbloc(LBL1, [[ExprAff(C, C + CST2)],
                            [ExprAff(G4_IRA.IRDst,
                                     ExprCond(C, ExprId(LBL2),
                                              ExprId(LBL1)))]])

G4_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G4_IRA.graph.add_uniq_edge(G4_IRB0.label, G4_IRB1.label)
G4_IRA.graph.add_uniq_edge(G4_IRB1.label, G4_IRB2.label)
G4_IRA.graph.add_uniq_edge(G4_IRB1.label, G4_IRB1.label)

G4_IRA.blocs = dict([(irb.label, irb) for irb in [G4_IRB0, G4_IRB1, G4_IRB2]])


# graph 5

G5_IRA = IRATest()
G5_IRA.g = GraphTest(G5_IRA)

G5_IRB0 = gen_irbloc(LBL0, [[ExprAff(B, CST1)]])
G5_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, B + CST2)],
                            [ExprAff(G5_IRA.IRDst,
                                     ExprCond(B, ExprId(LBL2),
                                              ExprId(LBL1)))]])

G5_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G5_IRA.graph.add_uniq_edge(G5_IRB0.label, G5_IRB1.label)
G5_IRA.graph.add_uniq_edge(G5_IRB1.label, G5_IRB2.label)
G5_IRA.graph.add_uniq_edge(G5_IRB1.label, G5_IRB1.label)

G5_IRA.blocs = dict([(irb.label, irb) for irb in [G5_IRB0, G5_IRB1, G5_IRB2]])

# graph 6

G6_IRA = IRATest()
G6_IRA.g = GraphTest(G6_IRA)

G6_IRB0 = gen_irbloc(LBL0, [[ExprAff(B, CST1)]])
G6_IRB1 = gen_irbloc(LBL1, [[ExprAff(A, B)]])

G6_IRA.graph.add_uniq_edge(G6_IRB0.label, G6_IRB1.label)
G6_IRA.graph.add_uniq_edge(G6_IRB1.label, G6_IRB1.label)

G6_IRA.blocs = dict([(irb.label, irb) for irb in [G6_IRB0, G6_IRB1]])

# graph 7

G7_IRA = IRATest()
G7_IRA.g = GraphTest(G7_IRA)

G7_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G7_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, C)], [ExprAff(A, B)]])
G7_IRB2 = gen_irbloc(LBL2, [[ExprAff(D, A)]])

G7_IRA.graph.add_uniq_edge(G7_IRB0.label, G7_IRB1.label)
G7_IRA.graph.add_uniq_edge(G7_IRB1.label, G7_IRB1.label)
G7_IRA.graph.add_uniq_edge(G7_IRB1.label, G7_IRB2.label)

G7_IRA.blocs = dict([(irb.label, irb) for irb in [G7_IRB0, G7_IRB1, G7_IRB2]])

# graph 8

G8_IRA = IRATest()
G8_IRA.g = GraphTest(G8_IRA)

G8_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G8_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, C)], [ExprAff(C, D)]])
G8_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G8_IRA.graph.add_uniq_edge(G8_IRB0.label, G8_IRB1.label)
G8_IRA.graph.add_uniq_edge(G8_IRB1.label, G8_IRB1.label)
G8_IRA.graph.add_uniq_edge(G8_IRB1.label, G8_IRB2.label)

G8_IRA.blocs = dict([(irb.label, irb) for irb in [G8_IRB0, G8_IRB1, G8_IRB2]])

# graph 9 is graph 8

# graph 10

G10_IRA = IRATest()
G10_IRA.g = GraphTest(G10_IRA)

G10_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, B + CST2)]])
G10_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G10_IRA.graph.add_uniq_edge(G10_IRB1.label, G10_IRB2.label)
G10_IRA.graph.add_uniq_edge(G10_IRB1.label, G10_IRB1.label)

G10_IRA.blocs = dict([(irb.label, irb) for irb in [G10_IRB1, G10_IRB2]])

# graph 11

G11_IRA = IRATest()
G11_IRA.g = GraphTest(G11_IRA)

G11_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST1),
                              ExprAff(B, CST2)]])
G11_IRB1 = gen_irbloc(LBL1, [[ExprAff(A, B),
                              ExprAff(B, A)]])
G11_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, A - B)]])

G11_IRA.graph.add_uniq_edge(G11_IRB0.label, G11_IRB1.label)
G11_IRA.graph.add_uniq_edge(G11_IRB1.label, G11_IRB2.label)

G11_IRA.blocs = dict([(irb.label, irb)
                     for irb in [G11_IRB0, G11_IRB1, G11_IRB2]])

# graph 12

G12_IRA = IRATest()
G12_IRA.g = GraphTest(G12_IRA)

G12_IRB0 = gen_irbloc(LBL0, [[ExprAff(B, CST1)]])
G12_IRB1 = gen_irbloc(LBL1, [[ExprAff(A, B)], [ExprAff(B, B + CST2)]])
G12_IRB2 = gen_irbloc(LBL2, [[ExprAff(B, A)]])

G12_IRA.graph.add_uniq_edge(G12_IRB0.label, G12_IRB1.label)
G12_IRA.graph.add_uniq_edge(G12_IRB1.label, G12_IRB2.label)
G12_IRA.graph.add_uniq_edge(G12_IRB1.label, G12_IRB1.label)

G12_IRA.blocs = dict([(irb.label, irb) for irb in [G12_IRB0, G12_IRB1,
                                                   G12_IRB2]])


# graph 13

G13_IRA = IRATest()
G13_IRA.g = GraphTest(G13_IRA)

G13_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST1)],
                             #[ExprAff(B, A)],
                             [ExprAff(G13_IRA.IRDst,
                                      ExprId(LBL1))]])
G13_IRB1 = gen_irbloc(LBL1, [[ExprAff(C, A)],
                             #[ExprAff(A, A + CST1)],
                             [ExprAff(G13_IRA.IRDst,
                                      ExprCond(R, ExprId(LBL2),
                                               ExprId(LBL1)))]])

G13_IRB2 = gen_irbloc(LBL2, [[ExprAff(B, A + CST3)], [ExprAff(A, B + CST3)],
                             [ExprAff(G13_IRA.IRDst,
                                      ExprId(LBL1))]])

G13_IRB3 = gen_irbloc(LBL3, [[ExprAff(R, C)]])

G13_IRA.graph.add_uniq_edge(G13_IRB0.label, G13_IRB1.label)
G13_IRA.graph.add_uniq_edge(G13_IRB1.label, G13_IRB2.label)
G13_IRA.graph.add_uniq_edge(G13_IRB2.label, G13_IRB1.label)
G13_IRA.graph.add_uniq_edge(G13_IRB1.label, G13_IRB3.label)

G13_IRA.blocs = dict([(irb.label, irb) for irb in [G13_IRB0, G13_IRB1,
                                                   G13_IRB2, G13_IRB3]])

# graph 14

G14_IRA = IRATest()
G14_IRA.g = GraphTest(G14_IRA)

G14_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST1)],
                             [ExprAff(G14_IRA.IRDst,
                                      ExprId(LBL1))]
                             ])
G14_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, A)],
                             [ExprAff(G14_IRA.IRDst,
                                      ExprCond(C, ExprId(LBL2),
                                               ExprId(LBL3)))]
                             ])

G14_IRB2 = gen_irbloc(LBL2, [[ExprAff(D, A)],
                             [ExprAff(A, D + CST1)],
                             [ExprAff(G14_IRA.IRDst,
                                      ExprId(LBL1))]
                             ])

G14_IRB3 = gen_irbloc(LBL3, [[ExprAff(R, D + B)]])

G14_IRA.graph.add_uniq_edge(G14_IRB0.label, G14_IRB1.label)
G14_IRA.graph.add_uniq_edge(G14_IRB1.label, G14_IRB2.label)
G14_IRA.graph.add_uniq_edge(G14_IRB2.label, G14_IRB1.label)
G14_IRA.graph.add_uniq_edge(G14_IRB1.label, G14_IRB3.label)

G14_IRA.blocs = dict([(irb.label, irb) for irb in [G14_IRB0, G14_IRB1,
                                                   G14_IRB2, G14_IRB3]])

# graph 16

G15_IRA = IRATest()
G15_IRA.g = GraphTest(G15_IRA)

G15_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST1)]])
G15_IRB1 = gen_irbloc(LBL1, [[ExprAff(D, A + B)],
                             [ExprAff(C, D)],
                             [ExprAff(B, C)]])
G15_IRB2 = gen_irbloc(LBL2, [[ExprAff(R, B)]])

G15_IRA.graph.add_uniq_edge(G15_IRB0.label, G15_IRB1.label)
G15_IRA.graph.add_uniq_edge(G15_IRB1.label, G15_IRB2.label)
G15_IRA.graph.add_uniq_edge(G15_IRB1.label, G15_IRB1.label)

G15_IRA.blocs = dict([(irb.label, irb) for irb in [G15_IRB0, G15_IRB1,
                                                   G15_IRB2]])

# graph 16

G16_IRA = IRATest()
G16_IRA.g = GraphTest(G16_IRA)

G16_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST1)]])
G16_IRB1 = gen_irbloc(LBL1, [[ExprAff(R, D)]])
G16_IRB2 = gen_irbloc(LBL2, [[ExprAff(D, A)]])
G16_IRB3 = gen_irbloc(LBL3, [[ExprAff(R, D)]])
G16_IRB4 = gen_irbloc(LBL4, [[ExprAff(R, A)]])
G16_IRB5 = gen_irbloc(LBL5, [[ExprAff(R, A)]])

G16_IRA.graph.add_uniq_edge(G16_IRB0.label, G16_IRB1.label)
G16_IRA.graph.add_uniq_edge(G16_IRB1.label, G16_IRB2.label)
G16_IRA.graph.add_uniq_edge(G16_IRB2.label, G16_IRB1.label)
G16_IRA.graph.add_uniq_edge(G16_IRB1.label, G16_IRB3.label)
G16_IRA.graph.add_uniq_edge(G16_IRB3.label, G16_IRB1.label)
G16_IRA.graph.add_uniq_edge(G16_IRB1.label, G16_IRB4.label)
G16_IRA.graph.add_uniq_edge(G16_IRB4.label, G16_IRB1.label)
G16_IRA.graph.add_uniq_edge(G16_IRB1.label, G16_IRB5.label)

G16_IRA.blocs = dict([(irb.label, irb) for irb in [G16_IRB0, G16_IRB1,
                                                   G16_IRB2, G16_IRB3,
                                                   G16_IRB4, G16_IRB5]])

# graph 17

G17_IRA = IRATest()
G17_IRA.g = GraphTest(G17_IRA)

G17_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST1),
                              ExprAff(D, CST2)]])
G17_IRB1 = gen_irbloc(LBL1, [[ExprAff(A, D),
                              ExprAff(B, D)]])
G17_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, A - B)]])

G17_IRA.graph.add_uniq_edge(G17_IRB0.label, G17_IRB1.label)
G17_IRA.graph.add_uniq_edge(G17_IRB1.label, G17_IRB2.label)

G17_IRA.blocs = dict([(irb.label, irb) for irb in [G17_IRB0, G17_IRB1,
                                                   G17_IRB2]])

# Test graph 1

G1_TEST1 = GraphTest(G1_IRA)

G1_TEST1_DN1 = DependencyNode(
    G1_IRB2.label, A, len(G1_IRB2.irs), next(STEP_COUNTER))
G1_TEST1_DN2 = DependencyNode(G1_IRB2.label, B, 0, next(STEP_COUNTER))
G1_TEST1_DN3 = DependencyNode(G1_IRB1.label, C, 0, next(STEP_COUNTER))
G1_TEST1_DN4 = DependencyNode(G1_IRB0.label, CST1, 0, next(STEP_COUNTER))

G1_TEST1.add_uniq_edge(G1_TEST1_DN4, G1_TEST1_DN3)
G1_TEST1.add_uniq_edge(G1_TEST1_DN3, G1_TEST1_DN2)
G1_TEST1.add_uniq_edge(G1_TEST1_DN2, G1_TEST1_DN1)

G1_INPUT = (set([G1_TEST1_DN1]), set([G1_IRB0.label]))

G1_OUTPUT = {"graph": [G1_TEST1],
             "emul": [{A: CST1}],
             "unresolved": [set()],
             "has_loop": [False]}

# Test graph 2

G2_TEST1 = GraphTest(G2_IRA)

G2_TEST1_DN1 = DependencyNode(
    G2_IRB2.label, A, len(G2_IRB2.irs), next(STEP_COUNTER))
G2_TEST1_DN2 = DependencyNode(G2_IRB2.label, B, 0, next(STEP_COUNTER))
G2_TEST1_DN3 = DependencyNode(G2_IRB2.label, C, 0, next(STEP_COUNTER))
G2_TEST1_DN4 = DependencyNode(G2_IRB1.label, CST2, 0, next(STEP_COUNTER))
G2_TEST1_DN5 = DependencyNode(G2_IRB0.label, CST1, 0, next(STEP_COUNTER))

G2_TEST1.add_uniq_edge(G2_TEST1_DN5, G2_TEST1_DN3)
G2_TEST1.add_uniq_edge(G2_TEST1_DN4, G2_TEST1_DN2)
G2_TEST1.add_uniq_edge(G2_TEST1_DN2, G2_TEST1_DN1)
G2_TEST1.add_uniq_edge(G2_TEST1_DN3, G2_TEST1_DN1)

G2_INPUT = (set([G2_TEST1_DN1]), set([G2_IRB0.label]))
G2_OUTPUT = {"graph": [G2_TEST1],
             "emul": [{A: ExprInt32(int(CST1.arg) + int(CST2.arg))}],
             "unresolved": [set()],
             "has_loop": [False]}

# Test graph 3

G3_TEST1_0 = GraphTest(G3_IRA)
G3_TEST1_1 = GraphTest(G3_IRA)

G3_TEST1_0_DN1 = DependencyNode(
    G3_IRB3.label, A, len(G3_IRB3.irs), next(STEP_COUNTER))
G3_TEST1_0_DN2 = DependencyNode(G3_IRB3.label, B, 0, next(STEP_COUNTER))
G3_TEST1_0_DN3 = DependencyNode(G3_IRB3.label, C, 0, next(STEP_COUNTER))
G3_TEST1_0_DN4 = DependencyNode(G3_IRB2.label, CST3, 0, next(STEP_COUNTER))
G3_TEST1_0_DN5 = DependencyNode(G3_IRB0.label, CST1, 0, next(STEP_COUNTER))

G3_TEST1_1_DN2 = DependencyNode(G3_IRB3.label, B, 0, next(STEP_COUNTER))
G3_TEST1_1_DN3 = DependencyNode(G3_IRB3.label, C, 0, next(STEP_COUNTER))
G3_TEST1_1_DN4 = DependencyNode(G3_IRB1.label, CST2, 0, next(STEP_COUNTER))
G3_TEST1_1_DN5 = DependencyNode(G3_IRB0.label, CST1, 0, next(STEP_COUNTER))

G3_TEST1_0.add_uniq_edge(G3_TEST1_0_DN5, G3_TEST1_0_DN3)
G3_TEST1_0.add_uniq_edge(G3_TEST1_0_DN4, G3_TEST1_0_DN2)
G3_TEST1_0.add_uniq_edge(G3_TEST1_0_DN2, G3_TEST1_0_DN1)
G3_TEST1_0.add_uniq_edge(G3_TEST1_0_DN3, G3_TEST1_0_DN1)

G3_TEST1_1.add_uniq_edge(G3_TEST1_1_DN5, G3_TEST1_1_DN3)
G3_TEST1_1.add_uniq_edge(G3_TEST1_1_DN4, G3_TEST1_1_DN2)
G3_TEST1_1.add_uniq_edge(G3_TEST1_1_DN2, G3_TEST1_0_DN1)
G3_TEST1_1.add_uniq_edge(G3_TEST1_1_DN3, G3_TEST1_0_DN1)

G3_INPUT = (set([G3_TEST1_0_DN1]), set([G3_IRB0.label]))

G3_OUTPUT = {"graph": [G3_TEST1_0, G3_TEST1_1],
             "emul": [{A: ExprInt32(int(CST1.arg) + int(CST3.arg))},
                      {A: ExprInt32(int(CST1.arg) + int(CST2.arg))}],
             "unresolved": [set(),
                            set()],
             "has_loop": [False, False]}

# Test graph 4

G4_TEST1 = GraphTest(G4_IRA)

G4_TEST1_DN1 = DependencyNode(
    G4_IRB2.label, A, len(G2_IRB0.irs), next(STEP_COUNTER))
G4_TEST1_DN2 = DependencyNode(G4_IRB2.label, B, 0, next(STEP_COUNTER))
G4_TEST1_DN3 = DependencyNode(G4_IRB0.label, B, 0, 10)
G4_TEST1_DN4 = DependencyNode(G4_IRB0.label, G4_IRA.IRDst, 0, 0)

G4_TEST1.add_uniq_edge(G4_TEST1_DN2, G4_TEST1_DN1)

G4_INPUT = (set([G4_TEST1_DN1]), set([G4_IRB0.label]))

G4_OUTPUT = {"graph": [G4_TEST1],
             "emul": [{A: B_INIT}],
             "unresolved": [set([G4_TEST1_DN3.nostep_repr])],
             "has_loop": [False]}

# Test graph 5

G5_TEST1_0 = GraphTest(G5_IRA)
G5_TEST1_1 = GraphTest(G5_IRA)

G5_TEST1_0_DN1 = DependencyNode(
    G5_IRB2.label, A, len(G5_IRB2.irs), next(STEP_COUNTER))
G5_TEST1_0_DN2 = DependencyNode(G5_IRB2.label, B, 0, next(STEP_COUNTER))
G5_TEST1_0_DN3 = DependencyNode(G5_IRB1.label, B, 0, next(STEP_COUNTER))
G5_TEST1_0_DN4 = DependencyNode(G5_IRB0.label, CST1, 0, next(STEP_COUNTER))
G5_TEST1_0_DN5 = DependencyNode(G5_IRB1.label, CST2, 0, next(STEP_COUNTER))

G5_TEST1_0.add_uniq_edge(G5_TEST1_0_DN4, G5_TEST1_0_DN3)
G5_TEST1_0.add_uniq_edge(G5_TEST1_0_DN3, G5_TEST1_0_DN2)
G5_TEST1_0.add_uniq_edge(G5_TEST1_0_DN5, G5_TEST1_0_DN2)
G5_TEST1_0.add_uniq_edge(G5_TEST1_0_DN2, G5_TEST1_0_DN1)

G5_TEST1_1_DN3 = DependencyNode(G5_IRB1.label, B, 0, next(STEP_COUNTER))
G5_TEST1_1_DN5 = DependencyNode(G5_IRB1.label, CST2, 0, next(STEP_COUNTER))

G5_TEST1_1.add_uniq_edge(G5_TEST1_0_DN4, G5_TEST1_1_DN3)
G5_TEST1_1.add_uniq_edge(G5_TEST1_1_DN3, G5_TEST1_0_DN3)
G5_TEST1_1.add_uniq_edge(G5_TEST1_1_DN5, G5_TEST1_0_DN3)
G5_TEST1_1.add_uniq_edge(G5_TEST1_0_DN3, G5_TEST1_0_DN2)
G5_TEST1_1.add_uniq_edge(G5_TEST1_0_DN5, G5_TEST1_0_DN2)
G5_TEST1_1.add_uniq_edge(G5_TEST1_0_DN2, G5_TEST1_0_DN1)

G5_INPUT = (set([G5_TEST1_0_DN1]), set([G5_IRB0.label]))

G5_OUTPUT = {"graph": [G5_TEST1_0, G5_TEST1_1],
             "emul": [{A: CST35}, {A: CST23}],
             "unresolved": [set(), set()],
             "has_loop": [True, False]}

# Test graph 6

G6_TEST1_0 = GraphTest(G6_IRA)

G6_TEST1_0_DN1 = DependencyNode(
    G6_IRB1.label, A, len(G6_IRB1.irs), next(STEP_COUNTER))
G6_TEST1_0_DN2 = DependencyNode(G6_IRB1.label, B, 0, next(STEP_COUNTER))
G6_TEST1_0_DN3 = DependencyNode(G6_IRB0.label, CST1, 0, next(STEP_COUNTER))


G6_TEST1_0.add_uniq_edge(G6_TEST1_0_DN3, G6_TEST1_0_DN2)
G6_TEST1_0.add_uniq_edge(G6_TEST1_0_DN2, G6_TEST1_0_DN1)

G6_INPUT = (set([G6_TEST1_0_DN1]), set([G6_IRB0.label]))

G6_OUTPUT = {"graph": [G6_TEST1_0],
             "emul": [{A: CST1}],
             "unresolved": [set()],
             "has_loop": [False]}

# Test graph 7

G7_TEST1_0 = GraphTest(G7_IRA)

G7_TEST1_0_DN1 = DependencyNode(
    G7_IRB2.label, A, len(G7_IRB2.irs), next(STEP_COUNTER))
G7_TEST1_0_DN2 = DependencyNode(G7_IRB1.label, B, 1, next(STEP_COUNTER))
G7_TEST1_0_DN3 = DependencyNode(G7_IRB1.label, C, 0, next(STEP_COUNTER))
G7_TEST1_0_DN4 = DependencyNode(G7_IRB0.label, CST1, 0, next(STEP_COUNTER))


G7_TEST1_0.add_uniq_edge(G7_TEST1_0_DN4, G7_TEST1_0_DN3)
G7_TEST1_0.add_uniq_edge(G7_TEST1_0_DN3, G7_TEST1_0_DN2)
G7_TEST1_0.add_uniq_edge(G7_TEST1_0_DN2, G7_TEST1_0_DN1)

G7_INPUT = (set([G7_TEST1_0_DN1]), set([G7_IRB0.label]))

G7_OUTPUT = {"graph": [G7_TEST1_0],
             "emul": [{A: CST1}],
             "unresolved": [set()],
             "has_loop": [False]}

# Test graph 8

G8_TEST1_0 = GraphTest(G8_IRA)
G8_TEST1_1 = GraphTest(G8_IRA)

G8_TEST1_0_DN1 = DependencyNode(
    G8_IRB2.label, A, len(G8_IRB2.irs), next(STEP_COUNTER))
G8_TEST1_0_DN2 = DependencyNode(G8_IRB2.label, B, 0, next(STEP_COUNTER))
G8_TEST1_0_DN3 = DependencyNode(G8_IRB1.label, C, 0, next(STEP_COUNTER))
G8_TEST1_0_DN4 = DependencyNode(G8_IRB0.label, CST1, 0, next(STEP_COUNTER))

G8_TEST1_1_DN1 = DependencyNode(
    G8_IRB2.label, A, len(G8_IRB2.irs), next(STEP_COUNTER))
G8_TEST1_1_DN2 = DependencyNode(G8_IRB2.label, B, 0, next(STEP_COUNTER))
G8_TEST1_1_DN3 = DependencyNode(G8_IRB1.label, C, 0, next(STEP_COUNTER))
G8_TEST1_1_DN4 = DependencyNode(G8_IRB1.label, D, 1, next(STEP_COUNTER))

G8_TEST1_1_DN5 = DependencyNode(G8_IRB0.label, D, 0, next(STEP_COUNTER))


G8_TEST1_0.add_uniq_edge(G8_TEST1_0_DN4, G8_TEST1_0_DN3)
G8_TEST1_0.add_uniq_edge(G8_TEST1_0_DN3, G8_TEST1_0_DN2)
G8_TEST1_0.add_uniq_edge(G8_TEST1_0_DN2, G8_TEST1_0_DN1)

G8_TEST1_1.add_uniq_edge(G8_TEST1_1_DN4, G8_TEST1_1_DN3)
G8_TEST1_1.add_uniq_edge(G8_TEST1_1_DN3, G8_TEST1_1_DN2)
G8_TEST1_1.add_uniq_edge(G8_TEST1_1_DN2, G8_TEST1_1_DN1)

G8_INPUT = (set([G8_TEST1_0_DN1]), set([G3_IRB0.label]))

G8_OUTPUT = {"graph": [G8_TEST1_0, G8_TEST1_1],
             "emul": [{A: D_INIT}, {A: CST1}],
             "unresolved": [set([G8_TEST1_1_DN5.nostep_repr]), set()],
             "has_loop": [True, False]}

# Test 9: Multi elements

G9_TEST1_0 = GraphTest(G8_IRA)
G9_TEST1_1 = GraphTest(G8_IRA)

G9_TEST1_0_DN1 = DependencyNode(
    G8_IRB2.label, A, len(G8_IRB2.irs), next(STEP_COUNTER))
G9_TEST1_0_DN2 = DependencyNode(G8_IRB2.label, B, 0, next(STEP_COUNTER))
G9_TEST1_0_DN3 = DependencyNode(G8_IRB1.label, C, 0, next(STEP_COUNTER))
G9_TEST1_0_DN4 = DependencyNode(G8_IRB0.label, CST1, 0, next(STEP_COUNTER))
G9_TEST1_0_DN5 = DependencyNode(
    G8_IRB2.label, C, len(G8_IRB2.irs), next(STEP_COUNTER))
G9_TEST1_0_DN6 = DependencyNode(G8_IRB1.label, D, 1, next(STEP_COUNTER))

G9_TEST1_1_DN1 = DependencyNode(
    G8_IRB2.label, A, len(G8_IRB2.irs), next(STEP_COUNTER))
G9_TEST1_1_DN2 = DependencyNode(G8_IRB2.label, B, 0, next(STEP_COUNTER))
G9_TEST1_1_DN3 = DependencyNode(G8_IRB1.label, C, 0, next(STEP_COUNTER))
G9_TEST1_1_DN4 = DependencyNode(G8_IRB1.label, D, 1, next(STEP_COUNTER))
G9_TEST1_1_DN5 = DependencyNode(
    G8_IRB2.label, C, len(G8_IRB2.irs), next(STEP_COUNTER))
G9_TEST1_1_DN6 = DependencyNode(G8_IRB1.label, D, 1, next(STEP_COUNTER))


G9_TEST1_0.add_uniq_edge(G9_TEST1_0_DN4, G9_TEST1_0_DN3)
G9_TEST1_0.add_uniq_edge(G9_TEST1_0_DN3, G9_TEST1_0_DN2)
G9_TEST1_0.add_uniq_edge(G9_TEST1_0_DN2, G9_TEST1_0_DN1)
G9_TEST1_0.add_uniq_edge(G9_TEST1_0_DN6, G9_TEST1_0_DN5)

G9_TEST1_1.add_uniq_edge(G9_TEST1_1_DN6, G9_TEST1_1_DN5)
G9_TEST1_1.add_uniq_edge(G9_TEST1_1_DN4, G9_TEST1_1_DN3)
G9_TEST1_1.add_uniq_edge(G9_TEST1_1_DN3, G9_TEST1_1_DN2)
G9_TEST1_1.add_uniq_edge(G9_TEST1_1_DN2, G9_TEST1_1_DN1)

G9_INPUT = (set([G9_TEST1_0_DN1, G9_TEST1_0_DN5]), set([G8_IRB0.label]))

G9_OUTPUT = {"graph": [G9_TEST1_1, G9_TEST1_0],
             "emul": [{A: D_INIT, C: D_INIT},
                      {A: CST1, C: D_INIT}],
             "unresolved": [set([G8_TEST1_1_DN5.nostep_repr]),
                            set([G8_TEST1_1_DN5.nostep_repr])],
             "has_loop": [True, False]}

# Test 10: loop at beginning

G10_TEST1_0 = GraphTest(G10_IRA)
G10_TEST1_1 = GraphTest(G10_IRA)

G10_TEST1_0_DN1 = DependencyNode(
    G10_IRB2.label, A, len(G10_IRB2.irs), next(STEP_COUNTER))
G10_TEST1_0_DN2 = DependencyNode(G10_IRB2.label, B, 0, next(STEP_COUNTER))
G10_TEST1_0_DN3 = DependencyNode(G10_IRB1.label, B, 0, next(STEP_COUNTER))
G10_TEST1_0_DN4 = DependencyNode(G10_IRB1.label, CST2, 0, next(STEP_COUNTER))

G10_TEST1_0.add_uniq_edge(G10_TEST1_0_DN3, G10_TEST1_0_DN2)
G10_TEST1_0.add_uniq_edge(G10_TEST1_0_DN4, G10_TEST1_0_DN2)
G10_TEST1_0.add_uniq_edge(G10_TEST1_0_DN2, G10_TEST1_0_DN1)

G10_TEST1_1_DN3 = DependencyNode(G10_IRB1.label, B, 0, next(STEP_COUNTER))
G10_TEST1_1_DN4 = DependencyNode(G10_IRB1.label, CST2, 0, next(STEP_COUNTER))

G10_TEST1_1.add_uniq_edge(G10_TEST1_1_DN3, G10_TEST1_0_DN3)
G10_TEST1_1.add_uniq_edge(G10_TEST1_1_DN4, G10_TEST1_0_DN3)
G10_TEST1_1.add_uniq_edge(G10_TEST1_0_DN3, G10_TEST1_0_DN2)
G10_TEST1_1.add_uniq_edge(G10_TEST1_0_DN4, G10_TEST1_0_DN2)
G10_TEST1_1.add_uniq_edge(G10_TEST1_0_DN2, G10_TEST1_0_DN1)

G10_INPUT = (set([G10_TEST1_0_DN1]), set([G10_IRB1.label]))

G10_OUTPUT = {"graph": [G10_TEST1_0, G10_TEST1_1],
              "emul": [{A: B_INIT + CST24}, {A: B_INIT + CST2}],
              "unresolved": [set([G10_TEST1_0_DN3.nostep_repr]),
                             set([G10_TEST1_0_DN3.nostep_repr])],
              "has_loop": [True, False]}


# Test 11: no dual bloc emulation
G11_TEST1 = GraphTest(G11_IRA)

G11_TEST1_DN1 = DependencyNode(
    G11_IRB2.label, A, len(G11_IRB2.irs), next(STEP_COUNTER))
G11_TEST1_DN2 = DependencyNode(G11_IRB2.label, A, 0, next(STEP_COUNTER))
G11_TEST1_DN3 = DependencyNode(G11_IRB2.label, B, 0, next(STEP_COUNTER))
G11_TEST1_DN4 = DependencyNode(G11_IRB1.label, A, 0, next(STEP_COUNTER))
G11_TEST1_DN5 = DependencyNode(G11_IRB1.label, B, 0, next(STEP_COUNTER))
G11_TEST1_DN6 = DependencyNode(G11_IRB0.label, CST1, 0, next(STEP_COUNTER))
G11_TEST1_DN7 = DependencyNode(G11_IRB0.label, CST2, 0, next(STEP_COUNTER))

G11_TEST1.add_uniq_edge(G11_TEST1_DN7, G11_TEST1_DN5)
G11_TEST1.add_uniq_edge(G11_TEST1_DN6, G11_TEST1_DN4)
G11_TEST1.add_uniq_edge(G11_TEST1_DN5, G11_TEST1_DN2)
G11_TEST1.add_uniq_edge(G11_TEST1_DN4, G11_TEST1_DN3)
G11_TEST1.add_uniq_edge(G11_TEST1_DN3, G11_TEST1_DN1)
G11_TEST1.add_uniq_edge(G11_TEST1_DN2, G11_TEST1_DN1)

G11_INPUT = (set([G11_TEST1_DN1]), set([G11_IRB0.label]))

G11_OUTPUT = {"graph": [G11_TEST1],
              "emul": [{A: ExprInt32(0x1)}],
              "unresolved": [set()],
              "has_loop": [False]}
# Test graph 12

G12_TEST1_0 = GraphTest(G12_IRA)
G12_TEST1_1 = GraphTest(G12_IRA)

G12_TEST1_0_DN1 = DependencyNode(G12_IRB2.label, B, 1, next(STEP_COUNTER))
G12_TEST1_0_DN2 = DependencyNode(G12_IRB2.label, A, 0, next(STEP_COUNTER))
G12_TEST1_0_DN3 = DependencyNode(G12_IRB1.label, B, 0, next(STEP_COUNTER))
G12_TEST1_0_DN4 = DependencyNode(G12_IRB0.label, CST1, 0, next(STEP_COUNTER))


G12_TEST1_0.add_uniq_edge(G12_TEST1_0_DN2, G12_TEST1_0_DN1)
G12_TEST1_0.add_uniq_edge(G12_TEST1_0_DN3, G12_TEST1_0_DN2)
G12_TEST1_0.add_uniq_edge(G12_TEST1_0_DN4, G12_TEST1_0_DN3)

G12_TEST1_1_DN3 = DependencyNode(G12_IRB1.label, B, 1, next(STEP_COUNTER))
G12_TEST1_1_DN5 = DependencyNode(G12_IRB1.label, CST2, 1, next(STEP_COUNTER))

G12_TEST1_1.add_uniq_edge(G12_TEST1_0_DN4, G12_TEST1_1_DN3)
G12_TEST1_1.add_uniq_edge(G12_TEST1_1_DN5, G12_TEST1_0_DN3)
G12_TEST1_1.add_uniq_edge(G12_TEST1_1_DN3, G12_TEST1_0_DN3)
G12_TEST1_1.add_uniq_edge(G12_TEST1_0_DN3, G12_TEST1_0_DN2)
G12_TEST1_1.add_uniq_edge(G12_TEST1_0_DN2, G12_TEST1_0_DN1)


G12_INPUT = (set([G12_TEST1_0_DN1]), set([]))

G12_OUTPUT = {"graph": [G12_TEST1_0, G12_TEST1_1],
              "emul": [{B: CST23}, {B: CST1}],
              "unresolved": [set(), set()],
              "has_loop": [True, False]}

# Test graph 13:

# All filters
G13_TEST1_0 = GraphTest(G13_IRA)
G13_TEST1_1 = GraphTest(G13_IRA)

G13_TEST1_0_DN1 = DependencyNode(G13_IRB0.label, CST1, 0, next(STEP_COUNTER))
G13_TEST1_0_DN2 = DependencyNode(G13_IRB1.label, A, 0, next(STEP_COUNTER))
G13_TEST1_0_DN3 = DependencyNode(G13_IRB3.label, C, 0, next(STEP_COUNTER))
G13_TEST1_0_DN4 = DependencyNode(G13_IRB3.label, R, 1, next(STEP_COUNTER))

G13_TEST1_0.add_uniq_edge(G13_TEST1_0_DN3, G13_TEST1_0_DN4)
G13_TEST1_0.add_uniq_edge(G13_TEST1_0_DN2, G13_TEST1_0_DN3)
G13_TEST1_0.add_uniq_edge(G13_TEST1_0_DN1, G13_TEST1_0_DN2)

G13_TEST1_1_DN5 = DependencyNode(G13_IRB2.label, A, 0, next(STEP_COUNTER))
G13_TEST1_1_DN6 = DependencyNode(G13_IRB2.label, CST3, 0, next(STEP_COUNTER))
G13_TEST1_1_DN7 = DependencyNode(G13_IRB2.label, B, 1, next(STEP_COUNTER))
G13_TEST1_1_DN8 = DependencyNode(G13_IRB2.label, CST3, 1, next(STEP_COUNTER))

G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN3, G13_TEST1_0_DN4)
G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN2, G13_TEST1_0_DN3)

G13_TEST1_1.add_uniq_edge(G13_TEST1_1_DN7, G13_TEST1_0_DN2)
G13_TEST1_1.add_uniq_edge(G13_TEST1_1_DN8, G13_TEST1_0_DN2)
G13_TEST1_1.add_uniq_edge(G13_TEST1_1_DN5, G13_TEST1_1_DN7)
G13_TEST1_1.add_uniq_edge(G13_TEST1_1_DN6, G13_TEST1_1_DN7)

G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN1, G13_TEST1_1_DN5)

# Implicit dependencies

G13_TEST2_0 = GraphTest(G13_IRA)
G13_TEST2_1 = GraphTest(G13_IRA)

G13_TEST2_0_DN1 = DependencyNode(G13_IRB0.label, CST1, 0, next(STEP_COUNTER))
G13_TEST2_0_DN2 = DependencyNode(G13_IRB1.label, A, 0, next(STEP_COUNTER))
G13_TEST2_0_DN3 = DependencyNode(G13_IRB3.label, C, 0, next(STEP_COUNTER))
G13_TEST2_0_DN4 = DependencyNode(G13_IRB3.label, R, 1, next(STEP_COUNTER))
G13_TEST2_0_DN5 = DependencyNode(G13_IRB1.label, R, 1, next(STEP_COUNTER))

G13_TEST2_0.add_uniq_edge(G13_TEST2_0_DN3, G13_TEST2_0_DN4)
G13_TEST2_0.add_uniq_edge(G13_TEST2_0_DN2, G13_TEST2_0_DN3)
G13_TEST2_0.add_uniq_edge(G13_TEST2_0_DN1, G13_TEST2_0_DN2)
G13_TEST2_0.add_uniq_edge(G13_TEST2_0_DN5, G13_TEST2_0_DN3)

G13_TEST2_1_DN5 = DependencyNode(G13_IRB2.label, A, 0, next(STEP_COUNTER))
G13_TEST2_1_DN6 = DependencyNode(G13_IRB2.label, CST3, 0, next(STEP_COUNTER))
G13_TEST2_1_DN7 = DependencyNode(G13_IRB2.label, B, 1, next(STEP_COUNTER))
G13_TEST2_1_DN8 = DependencyNode(G13_IRB2.label, CST3, 1, next(STEP_COUNTER))
G13_TEST2_1_DN9 = DependencyNode(G13_IRB1.label, R, 1, next(STEP_COUNTER))

G13_TEST2_1.add_uniq_edge(G13_TEST2_0_DN3, G13_TEST2_0_DN4)
G13_TEST2_1.add_uniq_edge(G13_TEST2_0_DN2, G13_TEST2_0_DN3)
G13_TEST2_1.add_uniq_edge(G13_TEST2_0_DN5, G13_TEST2_0_DN3)

G13_TEST2_1.add_uniq_edge(G13_TEST2_1_DN7, G13_TEST2_0_DN2)
G13_TEST2_1.add_uniq_edge(G13_TEST2_1_DN8, G13_TEST2_0_DN2)
G13_TEST2_1.add_uniq_edge(G13_TEST2_1_DN5, G13_TEST2_1_DN7)
G13_TEST2_1.add_uniq_edge(G13_TEST2_1_DN6, G13_TEST2_1_DN7)

G13_TEST2_1.add_uniq_edge(G13_TEST2_0_DN1, G13_TEST2_1_DN5)
G13_TEST2_1.add_uniq_edge(G13_TEST2_1_DN9, G13_TEST2_0_DN5)
G13_TEST2_1.add_uniq_edge(G13_TEST2_1_DN9, G13_TEST2_1_DN5)


DN13_UR_R = DependencyNode(G13_IRB0.label, R, 0, 0).nostep_repr

G13_INPUT = (set([G13_TEST1_0_DN4]), set([]))

G13_OUTPUT = {"graph": [G13_TEST1_0, G13_TEST1_1],
              "graph_implicit": [G13_TEST2_0, G13_TEST2_1],
              "emul": [{R: CST37}, {R: CST1}],
              "unresolved": [set(), set()],
              "unresolved_implicit": [set([DN13_UR_R]), set([DN13_UR_R])],
              "has_loop": [True, False]}

# Test graph 14

# All filters
G14_TEST1_0 = GraphTest(G14_IRA)
G14_TEST1_1 = GraphTest(G14_IRA)

G14_TEST1_0_DN1 = DependencyNode(G14_IRB3.label, R, 1, next(STEP_COUNTER))
G14_TEST1_0_DN2 = DependencyNode(G14_IRB3.label, D, 0, next(STEP_COUNTER))
G14_TEST1_0_DN3 = DependencyNode(G14_IRB3.label, B, 0, next(STEP_COUNTER))
G14_TEST1_0_DN4 = DependencyNode(G14_IRB1.label, A, 0, next(STEP_COUNTER))
G14_TEST1_0_DN5 = DependencyNode(G14_IRB0.label, CST1, 0, next(STEP_COUNTER))

G14_TEST1_0.add_uniq_edge(G14_TEST1_0_DN2, G14_TEST1_0_DN1)
G14_TEST1_0.add_uniq_edge(G14_TEST1_0_DN3, G14_TEST1_0_DN1)

G14_TEST1_0.add_uniq_edge(G14_TEST1_0_DN4, G14_TEST1_0_DN3)
G14_TEST1_0.add_uniq_edge(G14_TEST1_0_DN5, G14_TEST1_0_DN4)

G14_TEST1_1_DN5 = DependencyNode(G14_IRB2.label, D, 1, next(STEP_COUNTER))
G14_TEST1_1_DN6 = DependencyNode(G14_IRB2.label, CST1, 1, next(STEP_COUNTER))
G14_TEST1_1_DN7 = DependencyNode(G14_IRB2.label, A, 0, next(STEP_COUNTER))
#G14_TEST1_1_DN8 = DependencyNode(
#    G14_IRB2.label, A, 0, next(STEP_COUNTER) + 1)
#G14_TEST1_1_DN9 = DependencyNode(
#    G14_IRB0.label, CST1, 0, next(STEP_COUNTER) + 1)

# 1 loop
G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN2, G14_TEST1_0_DN1)
G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN3, G14_TEST1_0_DN1)

G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN4, G14_TEST1_0_DN3)
G14_TEST1_1.add_uniq_edge(G14_TEST1_1_DN5, G14_TEST1_0_DN4)
G14_TEST1_1.add_uniq_edge(G14_TEST1_1_DN6, G14_TEST1_0_DN4)
G14_TEST1_1.add_uniq_edge(G14_TEST1_1_DN7, G14_TEST1_1_DN5)
G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN5, G14_TEST1_1_DN7)

G14_TEST1_1.add_uniq_edge(G14_TEST1_1_DN7, G14_TEST1_0_DN2)
# G14_TEST1_1.add_uniq_edge(G14_TEST1_1_DN5, G14_TEST1_1_DN8)

# Implicit dependencies
G14_TEST2_0 = GraphTest(G14_IRA)
G14_TEST2_1 = GraphTest(G14_IRA)

G14_TEST2_0_DN6 = DependencyNode(G14_IRB1.label, C, 1, next(STEP_COUNTER))

G14_TEST2_0.add_uniq_edge(G14_TEST1_0_DN2, G14_TEST1_0_DN1)
G14_TEST2_0.add_uniq_edge(G14_TEST1_0_DN3, G14_TEST1_0_DN1)

G14_TEST2_0.add_uniq_edge(G14_TEST1_0_DN4, G14_TEST1_0_DN3)
G14_TEST2_0.add_uniq_edge(G14_TEST1_0_DN5, G14_TEST1_0_DN4)

G14_TEST2_0.add_uniq_edge(G14_TEST2_0_DN6, G14_TEST1_0_DN3)
G14_TEST2_0.add_uniq_edge(G14_TEST2_0_DN6, G14_TEST1_0_DN2)

# 1 loop
G14_TEST2_0_DN7 = DependencyNode(G14_IRB1.label, C, 1, next(STEP_COUNTER))

G14_TEST2_1.add_uniq_edge(G14_TEST1_0_DN2, G14_TEST1_0_DN1)
G14_TEST2_1.add_uniq_edge(G14_TEST1_0_DN3, G14_TEST1_0_DN1)

G14_TEST2_1.add_uniq_edge(G14_TEST1_0_DN4, G14_TEST1_0_DN3)
G14_TEST2_1.add_uniq_edge(G14_TEST1_1_DN5, G14_TEST1_0_DN4)
G14_TEST2_1.add_uniq_edge(G14_TEST1_1_DN6, G14_TEST1_0_DN4)
G14_TEST2_1.add_uniq_edge(G14_TEST1_1_DN7, G14_TEST1_1_DN5)
G14_TEST2_1.add_uniq_edge(G14_TEST1_0_DN5, G14_TEST1_1_DN7)

G14_TEST2_1.add_uniq_edge(G14_TEST1_1_DN7, G14_TEST1_0_DN2)

G14_TEST2_1.add_uniq_edge(G14_TEST2_0_DN6, G14_TEST1_0_DN3)
G14_TEST2_1.add_uniq_edge(G14_TEST2_0_DN6, G14_TEST1_0_DN2)

DN14_UR_D = DependencyNode(G14_IRB0.label, D, 0, 0).nostep_repr
DN14_UR_C = DependencyNode(G14_IRB0.label, C, 0, 0).nostep_repr

G14_INPUT = (set([G14_TEST1_0_DN1]), set([]))

G14_OUTPUT = {"graph": [G14_TEST1_0, G14_TEST1_1],
              "graph_implicit": [G14_TEST2_0, G14_TEST2_1],
              "emul": [{R: CST33}, {R: D_INIT + CST1}],
              "unresolved": [set(), set([DN14_UR_D])],
              "unresolved_implicit": [set([DN14_UR_C]),
                                      set([DN14_UR_D, DN14_UR_C])],
              "has_loop": [True, False]}

# Test graph 15

G15_TEST1_0 = GraphTest(G15_IRA)
G15_TEST1_1 = GraphTest(G15_IRA)

G15_TEST1_0_DN1 = DependencyNode(G15_IRB2.label, R, 1, next(STEP_COUNTER))
G15_TEST1_0_DN2 = DependencyNode(G15_IRB2.label, B, 0, next(STEP_COUNTER))
G15_TEST1_0_DN3 = DependencyNode(G15_IRB1.label, C, 2, next(STEP_COUNTER))
G15_TEST1_0_DN4 = DependencyNode(G15_IRB1.label, D, 1, next(STEP_COUNTER))
G15_TEST1_0_DN5 = DependencyNode(G15_IRB1.label, B, 0, next(STEP_COUNTER))
G15_TEST1_0_DN6 = DependencyNode(G15_IRB1.label, A, 0, next(STEP_COUNTER))
G15_TEST1_0_DN7 = DependencyNode(G15_IRB0.label, CST1, 0, next(STEP_COUNTER))
G15_TEST1_0_DN8 = DependencyNode(G15_IRB1.label, C, 2, next(STEP_COUNTER))
G15_TEST1_0_DN9 = DependencyNode(G15_IRB1.label, D, 1, next(STEP_COUNTER))
G15_TEST1_0_DN10 = DependencyNode(G15_IRB1.label, B, 0, next(STEP_COUNTER))


# 1 loop
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN2, G15_TEST1_0_DN1)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN3, G15_TEST1_0_DN2)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN4, G15_TEST1_0_DN3)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN5, G15_TEST1_0_DN4)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN6, G15_TEST1_0_DN4)

G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN7, G15_TEST1_0_DN6)

G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN8, G15_TEST1_0_DN5)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN9, G15_TEST1_0_DN8)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN6, G15_TEST1_0_DN9)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN10, G15_TEST1_0_DN9)

# 0 loop

G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN2, G15_TEST1_0_DN1)
G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN3, G15_TEST1_0_DN2)
G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN4, G15_TEST1_0_DN3)
G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN5, G15_TEST1_0_DN4)
G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN6, G15_TEST1_0_DN4)
G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN7, G15_TEST1_0_DN6)

G15_INPUT = (set([G15_TEST1_0_DN1]), set([]))

DN15_UNRESOLVED = DependencyNode(G15_IRB0.label, B, 0, 0).nostep_repr
G15_OUTPUT = {"graph": [G15_TEST1_0, G15_TEST1_1],
              "emul": [{R: B_INIT + CST22}, {R: B_INIT + CST1}],
              "unresolved": [set([DN15_UNRESOLVED]), set([DN15_UNRESOLVED])],
              "has_loop": [True, False]}

# Test graph 16
G16_TEST1_0_DN1 = DependencyNode(G16_IRB5.label, R, 1, next(STEP_COUNTER))
G16_TEST1_0_DN2 = DependencyNode(G16_IRB5.label, A, 0, next(STEP_COUNTER))
G16_TEST1_0_DN3 = DependencyNode(G16_IRB0.label, CST1, 0, next(STEP_COUNTER))

G16_TEST1_0 = GraphTest(G16_IRA)

G16_TEST1_0.add_uniq_edge(G16_TEST1_0_DN3, G16_TEST1_0_DN2)
G16_TEST1_0.add_uniq_edge(G16_TEST1_0_DN2, G16_TEST1_0_DN1)

G16_INPUT = (set([G16_TEST1_0_DN1]), set([]))

G16_OUTPUT = {"graph": [G16_TEST1_0],
              "emul": [{R: CST1}],
              "unresolved": [set()],
              "has_loop": [False]}

# Test graph 17

G17_TEST1 = GraphTest(G17_IRA)

G17_TEST1_DN1 = DependencyNode(G17_IRB2.label, A, 1, next(STEP_COUNTER))
G17_TEST1_DN2 = DependencyNode(G17_IRB2.label, B, 0, next(STEP_COUNTER))
G17_TEST1_DN3 = DependencyNode(G17_IRB2.label, A, 0, next(STEP_COUNTER))
G17_TEST1_DN4 = DependencyNode(G17_IRB1.label, D, 0, next(STEP_COUNTER))
G17_TEST1_DN5 = DependencyNode(G17_IRB0.label, CST2, 0, next(STEP_COUNTER))

G17_TEST1.add_uniq_edge(G17_TEST1_DN2, G17_TEST1_DN1)
G17_TEST1.add_uniq_edge(G17_TEST1_DN3, G17_TEST1_DN1)
G17_TEST1.add_uniq_edge(G17_TEST1_DN4, G17_TEST1_DN2)
G17_TEST1.add_uniq_edge(G17_TEST1_DN4, G17_TEST1_DN3)
G17_TEST1.add_uniq_edge(G17_TEST1_DN5, G17_TEST1_DN4)

G17_INPUT = (set([G17_TEST1_DN1]), set([]))

G17_OUTPUT = {"graph": [G17_TEST1],
              "emul": [{A: CST0}],
              "unresolved": [set()],
              "has_loop": [False]}



FAILED = set()



# Launch tests
for test_nb, test in enumerate([(G1_IRA, G1_INPUT, G1_OUTPUT),
                                (G2_IRA, G2_INPUT, G2_OUTPUT),
                                (G3_IRA, G3_INPUT, G3_OUTPUT),
                                (G4_IRA, G4_INPUT, G4_OUTPUT),
                                (G5_IRA, G5_INPUT, G5_OUTPUT),
                                (G6_IRA, G6_INPUT, G6_OUTPUT),
                                (G7_IRA, G7_INPUT, G7_OUTPUT),
                                (G8_IRA, G8_INPUT, G8_OUTPUT),
                                (G8_IRA, G9_INPUT, G9_OUTPUT),
                                (G10_IRA, G10_INPUT, G10_OUTPUT),
                                (G11_IRA, G11_INPUT, G11_OUTPUT),
                                (G12_IRA, G12_INPUT, G12_OUTPUT),
                                (G13_IRA, G13_INPUT, G13_OUTPUT),
                                (G14_IRA, G14_INPUT, G14_OUTPUT),
                                (G15_IRA, G15_INPUT, G15_OUTPUT),
                                (G16_IRA, G16_INPUT, G16_OUTPUT),
                                (G17_IRA, G17_INPUT, G17_OUTPUT),
                                ]):

    # Extract test elements
    print "[+] Test", test_nb + 1
    g_ira, (depnodes, heads), g_test_output = test

    open("graph_%02d.dot" % (test_nb + 1), "w").write(g_ira.graph.dot())

    # Different options
    suffix_key_list = ["", "_nosimp", "_nomem", "_nocall",
                       "_implicit"]
    # Test classes
    for g_ind, g_dep in enumerate([DependencyGraph(g_ira),
                                   DependencyGraph(g_ira, apply_simp=False),
                                   DependencyGraph(g_ira, follow_mem=False),
                                   DependencyGraph(g_ira, follow_mem=False,
                                                   follow_call=False),
                                   DependencyGraph(g_ira, implicit=True),
                                   ]):
        if g_ind == 4:
            # TODO: Implicit specifications
            continue
        print " - Class %s - %s" % (g_dep.__class__.__name__,
                                    suffix_key_list[g_ind])
        # Select the correct result key
        mode_suffix = suffix_key_list[g_ind]
        graph_test_key = "graph" + mode_suffix
        if not g_test_output.has_key(graph_test_key):
            graph_test_key = "graph"

        expected_results = g_test_output[graph_test_key]

        # Test public APIs
        for api_i, g_list in enumerate(
            [g_dep.get_from_depnodes(depnodes, heads),
             g_dep.get(list(depnodes)[0].label,
                       [depnode.element for
                        depnode in depnodes],
                       list(depnodes)[0].line_nb,
                       heads)
             ]):
            print " - - API %s" % ("get_from_depnodes"
                                   if api_i == 0 else "get")

            # Expand result iterator
            g_list = list(g_list)

            # Dump outputs graphs for debug means
            for result_nb, result_graph in enumerate(g_list):
                open("graph_test_%02d_%02d.dot" % (test_nb + 1, result_nb),
                     "w").write(result_graph.graph.dot())

            for result_nb, result_graph in enumerate(expected_results):
                open("exp_graph_test_%02d_%02d.dot" % (test_nb + 1, result_nb),
                     "w").write(result_graph.dot())

            try:
                # The number of results should be the same
                print " - - - number of results %d/%d" % (len(g_list),
                                                          len(expected_results))

                error = 'len:' + \
                        str(len(g_list)) + '/' + str(len(expected_results))
                assert len(g_list) == len(expected_results)

                # Check that every result appears in expected_results
                for j, result in enumerate(g_list):
                    print " - - - result %d" % j
                    found = False
                    for expected in expected_results:
                        if expected.__eq__(result.graph):
                            found = True
                error = "found1"
                assert found

                # Check that every expected result appears in real results
                for j, expected in enumerate(expected_results):
                    print " - - - expected %d" % j
                    found = False
                    for result in g_list:
                        if expected.__eq__(result.graph):
                            found = True
                error = "found2"
                assert found

                if not EMULATION:
                    continue
                # Test emulation results and other properties
                unresolved_test_key = "unresolved" + mode_suffix
                if not g_test_output.has_key(unresolved_test_key):
                    unresolved_test_key = "unresolved"

                # Check that every computed result was expected
                for emul_nb, result in enumerate(g_list):
                    print " - - - - emul %d" % emul_nb
                    emul_result = result.emul()

                    error = "emul"
                    found = False
                    for exp_nb in xrange(len(g_list)):
                        if (emul_result == g_test_output["emul"][exp_nb] and
                            getattr(result, "unresolved") ==
                            g_test_output[unresolved_test_key][exp_nb] and
                            g_test_output["has_loop"][exp_nb] ==
                            getattr(result, "has_loop")
                                ):
                            found = True
                            break
                    assert found

                # Check that every expected result has been computed
                for exp_nb in xrange(len(g_list)):
                    print " - - - - emul %d" % exp_nb

                    error = "emul2"
                    found = False
                    for emul_nb, result in enumerate(g_list):
                        emul_result = result.emul()
                        if (emul_result == g_test_output["emul"][exp_nb] and
                            getattr(result, "unresolved") ==
                            g_test_output[unresolved_test_key][exp_nb] and
                            g_test_output["has_loop"][exp_nb] ==
                            getattr(result, "has_loop")
                            ):
                            found = True
                            break
                    assert found

            except AssertionError:
                FAILED.add((test_nb + 1, error))
                continue

if FAILED:
    print "FAILED :", len(FAILED)
    for i in sorted(FAILED, key=lambda (u, _): u):
        print i,
else:
    print "SUCCESS"

# Return an error status on error
assert not FAILED
