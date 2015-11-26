import itertools

from miasm2.expression.expression import ExprId, ExprInt32, ExprAff, ExprMem, ExprCond
from miasm2.core.asmbloc import asm_label
from miasm2.ir.analysis import ira
from miasm2.ir.ir import ir, irbloc
from miasm2.core.graph import DiGraph
from miasm2.analysis.influencegraph import DependencyNode, InfluenceGraph,\
    DependencyDict

A = ExprId("a")
B = ExprId("b")
C = ExprId("c")
D = ExprId("d")
R = ExprId("r")

a_init = ExprId("a_init")
b_init = ExprId("b_init")
c_init = ExprId("c_init")
d_init = ExprId("d_init")

pc = ExprId("pc")
sp = ExprId("sp")

CST1 = ExprInt32(0x11)
CST2 = ExprInt32(0x12)
CST3 = ExprInt32(0x13)

LBL0 = asm_label("lbl0")
LBL1 = asm_label("lbl1")
LBL2 = asm_label("lbl2")
LBL3 = asm_label("lbl3")
LBL4 = asm_label("lbl4")
LBL5 = asm_label("lbl5")
LBL6 = asm_label("lbl6")


class InfluencyNode(DependencyNode):
    counter = itertools.count()

    def __init__(self, label, element, line_nb, modifier=False):
        DependencyNode.__init__(self, label, element, line_nb, next(self.counter),
                                modifier=modifier)


def gen_irbloc(lbl, exprs):
    lines = [None] * len(exprs)
    return irbloc(lbl, exprs, lines)


class Regs(object):
    regs_init = {A: a_init, B: b_init, C: c_init, D: d_init}

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

class GraphTest(DiGraph):
    """Fake graph representation class for test cases"""

    def __init__(self, pira):
        self.ira = pira
        super(GraphTest, self).__init__()

    def __eq__(self, graph):
        if (sorted([node.nostep_repr for node in self._nodes])
                != sorted([node.nostep_repr for node in graph.nodes])):
            return False
        if (sorted([(src.nostep_repr, dst.nostep_repr)
                    for (src, dst) in self._edges])
            != sorted([(src.nostep_repr, dst.nostep_repr)
                       for (src, dst) in graph.edges()])):
            return False
        return True

    def node2str(self, node):
        if not node in self.ira.blocs:
            return str(node)
        else:
            return str(self.ira.blocs[node])


class DepNodeTest(DiGraph):

    """Fake graph class to represent expected test results"""

    def __init__(self, pira):
        self.ira = pira
        super(DepNodeTest, self).__init__()

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
dd0 = DependencyDict(LBL0, [])
depnodes_0 = [InfluencyNode(LBL0, A, j) for j in xrange(10)][::-1]

## Heads
assert list(dd0.heads()) == []
assert dd0.is_head(depnodes_0[-1]) == True
assert dd0.is_head(depnodes_0[0]) == False
dd0.cache[depnodes_0[-1]] = set(depnodes_0[-1:])
assert list(dd0.heads()) == [depnodes_0[-1]]

## Extend
dd1 = dd0.extend(LBL1)

assert dd1.label == LBL1
assert dd1.history == [dd0]
assert dd1.cache == dd0.cache
assert dd1.pending == set()
assert dd1 != dd0

dd1.cache[depnodes_0[4]] = set(depnodes_0[5:9])
assert dd1.cache != dd0.cache

dd2 = dd0.copy()
assert dd2.label == LBL0
assert dd2.history == []
assert dd2.cache == dd0.cache
assert dd2.pending == dd0.pending
assert dd2 == dd0

dd2.cache[depnodes_0[4]] = set(depnodes_0[5:9])
assert dd2.cache != dd0.cache

print "[+] DependencyDict OK !"
print "[+] Structures OK !"

# graph 1

G1_IRA = IRATest()
G1_IRA.g = GraphTest(G1_IRA)

G1_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)],
                             [ExprAff(B, C)], [ExprAff(D, C)],
                            [ExprAff(D, CST1)],
                             [ExprAff(A, B)], [ExprAff(A, D)]])
G1_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, C)], [ExprAff(D, A)]])


G1_IRA.g.add_uniq_edge(G1_IRB0.label, G1_IRB1.label)

G1_IRA.blocs = dict([(irb.label, irb) for irb in [G1_IRB0, G1_IRB1]])

# graph 2

G2_IRA = IRATest()
G2_IRA.g = GraphTest(G2_IRA)

G2_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G2_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, CST2)]])
G2_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B+C)]])

G2_IRA.g.add_uniq_edge(G2_IRB0.label, G2_IRB1.label)
G2_IRA.g.add_uniq_edge(G2_IRB1.label, G2_IRB2.label)

G2_IRA.blocs = dict([(irb.label, irb) for irb in [G2_IRB0, G2_IRB1, G2_IRB2]])


# graph 3

G3_IRA = IRATest()
G3_IRA.g = GraphTest(G3_IRA)

G3_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G3_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, CST2)]])
G3_IRB2 = gen_irbloc(LBL2, [[ExprAff(B, CST3)]])
G3_IRB3 = gen_irbloc(LBL3, [[ExprAff(A, B+C)]])

G3_IRA.g.add_uniq_edge(G3_IRB0.label, G3_IRB1.label)
G3_IRA.g.add_uniq_edge(G3_IRB0.label, G3_IRB2.label)
G3_IRA.g.add_uniq_edge(G3_IRB1.label, G3_IRB3.label)
G3_IRA.g.add_uniq_edge(G3_IRB2.label, G3_IRB3.label)

G3_IRA.blocs = dict([(irb.label, irb) for irb in [G3_IRB0, G3_IRB1,
                                                  G3_IRB2, G3_IRB3]])

# graph 4

G4_IRA = IRATest()
G4_IRA.g = GraphTest(G4_IRA)

G4_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G4_IRB1 = gen_irbloc(LBL1, [[ExprAff(C, C+CST2)]])
G4_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G4_IRA.g.add_uniq_edge(G4_IRB0.label, G4_IRB1.label)
G4_IRA.g.add_uniq_edge(G4_IRB1.label, G4_IRB2.label)
G4_IRA.g.add_uniq_edge(G4_IRB1.label, G4_IRB1.label)

G4_IRA.blocs = dict([(irb.label, irb) for irb in [G4_IRB0, G4_IRB1, G4_IRB2]])


# graph 5

G5_IRA = IRATest()
G5_IRA.g = GraphTest(G5_IRA)

G5_IRB0 = gen_irbloc(LBL0, [[ExprAff(B, CST1)]])
G5_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, B+CST2)]])
G5_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G5_IRA.g.add_uniq_edge(G5_IRB0.label, G5_IRB1.label)
G5_IRA.g.add_uniq_edge(G5_IRB1.label, G5_IRB2.label)
G5_IRA.g.add_uniq_edge(G5_IRB1.label, G5_IRB1.label)

G5_IRA.blocs = dict([(irb.label, irb) for irb in [G5_IRB0, G5_IRB1, G5_IRB2]])

# graph 6

G6_IRA = IRATest()
G6_IRA.g = GraphTest(G6_IRA)

G6_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, D)], [ExprAff(D, C)]])

G6_IRA.g.add_uniq_edge(G6_IRB1.label, G6_IRB1.label)

G6_IRA.blocs = dict([(irb.label, irb) for irb in [G6_IRB1]])

# graph 7

G7_IRA = IRATest()
G7_IRA.g = GraphTest(G7_IRA)

G7_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G7_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, C)], [ExprAff(A, B)]])
G7_IRB2 = gen_irbloc(LBL2, [[ExprAff(D, A)]])

G7_IRA.g.add_uniq_edge(G7_IRB0.label, G7_IRB1.label)
G7_IRA.g.add_uniq_edge(G7_IRB1.label, G7_IRB1.label)
G7_IRA.g.add_uniq_edge(G7_IRB1.label, G7_IRB2.label)

G7_IRA.blocs = dict([(irb.label, irb) for irb in [G7_IRB0, G7_IRB1, G7_IRB2]])

# graph 8

G8_IRA = IRATest()
G8_IRA.g = GraphTest(G8_IRA)

G8_IRB0 = gen_irbloc(LBL0, [[ExprAff(C, CST1)]])
G8_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, D)], [ExprAff(D, C)]])
G8_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G8_IRA.g.add_uniq_edge(G8_IRB0.label, G8_IRB1.label)
G8_IRA.g.add_uniq_edge(G8_IRB1.label, G8_IRB1.label)
G8_IRA.g.add_uniq_edge(G8_IRB1.label, G8_IRB2.label)

G8_IRA.blocs = dict([(irb.label, irb) for irb in [G8_IRB0,
                                                  G8_IRB1, G8_IRB2]])

# graph 9 is graph 8

# graph 10

G10_IRA = IRATest()
G10_IRA.g = GraphTest(G10_IRA)

G10_IRB1 = gen_irbloc(LBL1, [#[ExprAff(C, B)],
                             [ExprAff(B, B+CST2)]])
G10_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G10_IRA.g.add_uniq_edge(G10_IRB1.label, G10_IRB2.label)
G10_IRA.g.add_uniq_edge(G10_IRB1.label, G10_IRB1.label)

G10_IRA.blocs = dict([(irb.label, irb) for irb in [G10_IRB1, G10_IRB2]])

# graph 11

G11_IRA = IRATest()
G11_IRA.g = GraphTest(G11_IRA)

G11_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST1),
                               ExprAff(B, CST2)]])
G11_IRB1 = gen_irbloc(LBL1, [[ExprAff(A, B),
                               ExprAff(B, A)]])
G11_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, A - B)]])

G11_IRA.g.add_uniq_edge(G11_IRB0.label, G11_IRB1.label)
G11_IRA.g.add_uniq_edge(G11_IRB1.label, G11_IRB2.label)

G11_IRA.blocs = dict([(irb.label, irb) for irb in [G11_IRB0, G11_IRB1,
                                                   G11_IRB2]])

# Test graph 12 : ExprMem

G12_IRA = IRATest()
G12_IRA.g = GraphTest(G12_IRA)

G12_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST2), ExprAff(C, CST3)]])
G12_IRB1 = gen_irbloc(LBL1, [[ExprAff(ExprMem(CST1), A),
                               ExprAff(ExprMem(C), A)],
                              [ExprAff(C, CST1)],
                              [ExprAff(B, ExprMem(CST1)),
                               ExprAff(D, ExprMem(C))]])
G12_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B), ExprAff(C, D)]])

G12_IRA.g.add_uniq_edge(G12_IRB0.label, G12_IRB1.label)
G12_IRA.g.add_uniq_edge(G12_IRB1.label, G12_IRB2.label)

G12_IRA.blocs = dict([(irb.label, irb)
                      for irb in [G12_IRB0, G12_IRB1, G12_IRB2]])

# graph 13

G13_IRA = IRATest()
G13_IRA.g = GraphTest(G13_IRA)

G13_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST1)],
                             [ExprAff(D, A)],
                             [ExprAff(B, D)],
                             [ExprAff(G13_IRA.IRDst,
                                      ExprId(LBL1))]])
G13_IRB1 = gen_irbloc(LBL1, [[ExprAff(C, B)],
                             [ExprAff(A, A + CST1)],
                             [ExprAff(G13_IRA.IRDst,
                                      ExprCond(R, ExprId(LBL2),
                                               ExprId(LBL1)))]])

G13_IRB2 = gen_irbloc(LBL2, [[ExprAff(B, A + CST3)], [ExprAff(G13_IRA.IRDst,
                                                              ExprId(LBL1))]])

G13_IRB3 = gen_irbloc(LBL3, [[ExprAff(R, CST1)]])

G13_IRA.g.add_uniq_edge(G13_IRB0.label, G13_IRB1.label)
G13_IRA.g.add_uniq_edge(G13_IRB1.label, G13_IRB2.label)
G13_IRA.g.add_uniq_edge(G13_IRB2.label, G13_IRB1.label)
G13_IRA.g.add_uniq_edge(G13_IRB1.label, G13_IRB3.label)

G13_IRA.blocs = dict([(irb.label, irb) for irb in [G13_IRB0, G13_IRB1,
                                                   G13_IRB2, G13_IRB3]])

# graph 14

G14_IRA = IRATest()
G14_IRA.g = GraphTest(G14_IRA)

G14_IRB0 = gen_irbloc(LBL0, [[ExprAff(A, CST1)],
                             [ExprAff(G14_IRA.IRDst,
                                      ExprId(LBL1))]])
G14_IRB1 = gen_irbloc(LBL1, [[ExprAff(B, A)],
                             [ExprAff(R, D)],
                             [ExprAff(G14_IRA.IRDst,
                                      ExprCond(C, ExprId(LBL2),
                                               ExprId(LBL1)))]])

G14_IRB2 = gen_irbloc(LBL2, [[ExprAff(D, A)],
                             [ExprAff(A, D+CST1)],
                             [ExprAff(G14_IRA.IRDst,
                                      ExprId(LBL1))]])

G14_IRB3 = gen_irbloc(LBL3, [[ExprAff(R, A+B)]])

G14_IRA.g.add_uniq_edge(G14_IRB0.label, G14_IRB1.label)
G14_IRA.g.add_uniq_edge(G14_IRB1.label, G14_IRB2.label)
G14_IRA.g.add_uniq_edge(G14_IRB2.label, G14_IRB1.label)
G14_IRA.g.add_uniq_edge(G14_IRB1.label, G14_IRB3.label)

G14_IRA.blocs = dict([(irb.label, irb) for irb in [G14_IRB0, G14_IRB1,
                                                   G14_IRB2, G14_IRB3]])

# graph 15

G15_IRA = IRATest()
G15_IRA.g = GraphTest(G15_IRA)

G15_IRB0 = gen_irbloc(LBL0, [[ExprAff(B, CST1)]])
G15_IRB1 = gen_irbloc(LBL1, [[ExprAff(A, B)], [ExprAff(C, B)], [ExprAff(B, C+CST2)]])
G15_IRB2 = gen_irbloc(LBL2, [[ExprAff(A, B)]])

G15_IRA.g.add_uniq_edge(G15_IRB0.label, G15_IRB1.label)
G15_IRA.g.add_uniq_edge(G15_IRB1.label, G15_IRB2.label)
G15_IRA.g.add_uniq_edge(G15_IRB1.label, G15_IRB1.label)

G15_IRA.blocs = dict([(irb.label, irb) for irb in [G15_IRB0, G15_IRB1,
                                                   G15_IRB2]])


# Test graph 1

G1_TEST1 = DepNodeTest(G1_IRA)

G1_TEST1_DN1 = InfluencyNode(G1_IRB0.label, A, 5)
G1_TEST1_DN2 = InfluencyNode(G1_IRB0.label, B, 2)
G1_TEST1_DN3 = InfluencyNode(G1_IRB0.label, C, 1)
G1_TEST1_DN4 = InfluencyNode(G1_IRB0.label, D, 3)

G1_TEST1_DN5 = InfluencyNode(G1_IRB1.label, B, 1)

G1_TEST1.add_uniq_edge(G1_TEST1_DN3, G1_TEST1_DN5)
G1_TEST1.add_uniq_edge(G1_TEST1_DN3, G1_TEST1_DN2)
G1_TEST1.add_uniq_edge(G1_TEST1_DN3, G1_TEST1_DN4)
G1_TEST1.add_uniq_edge(G1_TEST1_DN2, G1_TEST1_DN1)


G1_INPUT = (set([G1_TEST1_DN3]), set())
G1_OUTPUT = {"graph": [G1_TEST1],
             "emul": {A: CST1},
             "unresolved": set(),
             "has_loop": False}

# Test graph 2

G2_TEST1 = DepNodeTest(G2_IRA)

G2_TEST1_DN1 = InfluencyNode(G2_IRB2.label, A, len(G2_IRB2.irs))
G2_TEST1_DN3 = InfluencyNode(G2_IRB0.label, C, 1)
G2_TEST1_DN5 = InfluencyNode(G2_IRB0.label, CST1, 0)

G2_TEST1.add_uniq_edge(G2_TEST1_DN5, G2_TEST1_DN3)
G2_TEST1.add_uniq_edge(G2_TEST1_DN3, G2_TEST1_DN1)

G2_INPUT = (set([G2_TEST1_DN5]), set([]))

G2_OUTPUT = {"graph": [G2_TEST1],
              "emul": {A: ExprInt32(int(CST1.arg) + int(CST2.arg))},
              "unresolved": set(),
              "has_loop": False}

# Test graph 3

G3_TEST1 = DepNodeTest(G3_IRA)

G3_TEST1_DN1 = InfluencyNode(G3_IRB0.label, C, 1)
G3_TEST1_DN2 = InfluencyNode(G3_IRB3.label, A, 1)


G3_TEST1.add_uniq_edge(G3_TEST1_DN1, G3_TEST1_DN2)

G3_INPUT = (set([G3_TEST1_DN1]), set([]))

G3_OUTPUT = {"graph": [G3_TEST1],
              "emul": {A: ExprInt32(int(CST1.arg) + int(CST3.arg))},
              "unresolved": set(),
              "has_loop": False}


# Test graph 4

G4_TEST1_0 = DepNodeTest(G4_IRA)
G4_TEST1_1 = DepNodeTest(G4_IRA)

G4_TEST1_DN1 = InfluencyNode(G4_IRB0.label, C, 1)
G4_TEST1_DN2 = InfluencyNode(G4_IRB1.label, C, 1)
G4_TEST1_DN3 = InfluencyNode(G4_IRB1.label, C, 1)

G4_TEST1_0.add_uniq_edge(G4_TEST1_DN1, G4_TEST1_DN2)

G4_TEST1_1.add_uniq_edge(G4_TEST1_DN2, G4_TEST1_DN3)
G4_TEST1_1.add_uniq_edge(G4_TEST1_DN1, G4_TEST1_DN2)


G4_INPUT = (set([G4_TEST1_DN1]), set([]))

G4_OUTPUT = {"graph": [G4_TEST1_0, G4_TEST1_1],
              "emul": {A: b_init},
              "unresolved": set([G4_TEST1_DN1]),
              "has_loop": False}

# Test graph 5

G5_TEST1_0 = DepNodeTest(G5_IRA)
G5_TEST1_1 = DepNodeTest(G5_IRA)

G5_TEST1_DN1 = InfluencyNode(G5_IRB0.label, B, 1)
G5_TEST1_DN2 = InfluencyNode(G5_IRB1.label, B, 1)
G5_TEST1_DN3 = InfluencyNode(G5_IRB2.label, A, len(G5_IRB2.irs))

G5_TEST1_DN4 = InfluencyNode(G5_IRB1.label, B, 1)

G5_TEST1_0.add_uniq_edge(G5_TEST1_DN1, G5_TEST1_DN2)
G5_TEST1_0.add_uniq_edge(G5_TEST1_DN2, G5_TEST1_DN3)

G5_TEST1_1.add_uniq_edge(G5_TEST1_DN1, G5_TEST1_DN2)
G5_TEST1_1.add_uniq_edge(G5_TEST1_DN2, G5_TEST1_DN4)
G5_TEST1_1.add_uniq_edge(G5_TEST1_DN4, G5_TEST1_DN3)

G5_INPUT = (set([G5_TEST1_DN1]), set([]))

G5_OUTPUT = {"graph": [G5_TEST1_0, G5_TEST1_1],
              "emul": {},
              "unresolved": set(),
              "has_loop": True}

# Test graph 6

G6_TEST1_0 = DepNodeTest(G6_IRA)
G6_TEST1_1 = DepNodeTest(G6_IRA)

G6_TEST1_DN1 = InfluencyNode(G6_IRB1.label, D, 2)
G6_TEST1_DN2 = InfluencyNode(G6_IRB1.label, C, 0)

G6_TEST1_DN3 = InfluencyNode(G6_IRB1.label, B, 1)
G6_TEST1_DN4 = InfluencyNode(G6_IRB1.label, D, 2)

G6_TEST1_0.add_uniq_edge(G6_TEST1_DN2, G6_TEST1_DN1)

G6_TEST1_1.add_uniq_edge(G6_TEST1_DN2, G6_TEST1_DN1)
G6_TEST1_1.add_uniq_edge(G6_TEST1_DN2, G6_TEST1_DN4)
G6_TEST1_1.add_uniq_edge(G6_TEST1_DN1, G6_TEST1_DN3)


G6_INPUT = (set([G6_TEST1_DN2]), set([G6_IRB1.label]))

G6_OUTPUT = {"graph": [G6_TEST1_0, G6_TEST1_1],
              "emul": {A: CST1},
              "unresolved": set(),
              "has_loop": False}

# Test graph 7

G7_TEST1_0 = DepNodeTest(G7_IRA)

G7_TEST1_DN0 = InfluencyNode(G7_IRB2.label, D, 1)
G7_TEST1_DN1 = InfluencyNode(G7_IRB1.label, A, 2)
G7_TEST1_DN2 = InfluencyNode(G7_IRB1.label, B, 1)
G7_TEST1_DN3 = InfluencyNode(G7_IRB0.label, C, 1)
G7_TEST1_DN4 = InfluencyNode(G7_IRB0.label, CST1, 0)


G7_TEST1_0.add_uniq_edge(G7_TEST1_DN3, G7_TEST1_DN2)
G7_TEST1_0.add_uniq_edge(G7_TEST1_DN2, G7_TEST1_DN1)
G7_TEST1_0.add_uniq_edge(G7_TEST1_DN1, G7_TEST1_DN0)
G7_TEST1_0.add_uniq_edge(G7_TEST1_DN4, G7_TEST1_DN3)


G7_INPUT = (set([G7_TEST1_DN4]), set([]))

G7_OUTPUT = {"graph": [G7_TEST1_0],
              "emul": {A: CST1},
              "unresolved": set(),
              "has_loop": True}

# Test graph 8

G8_TEST1_0 = DepNodeTest(G8_IRA)
G8_TEST1_1 = DepNodeTest(G8_IRA)

G8_TEST1_DN1 = InfluencyNode(G8_IRB1.label, D, 2)
G8_TEST1_DN2 = InfluencyNode(G8_IRB0.label, C, 1)

G8_TEST1_DN3 = InfluencyNode(G8_IRB1.label, B, 1)
G8_TEST1_DN4 = InfluencyNode(G8_IRB2.label, A, 1)
G8_TEST1_DN5 = InfluencyNode(G8_IRB1.label, D, 2)

G8_TEST1_0.add_uniq_edge(G8_TEST1_DN2, G8_TEST1_DN1)

G8_TEST1_1.add_uniq_edge(G8_TEST1_DN2, G8_TEST1_DN1)
G8_TEST1_1.add_uniq_edge(G8_TEST1_DN2, G8_TEST1_DN5)
G8_TEST1_1.add_uniq_edge(G8_TEST1_DN1, G8_TEST1_DN3)
G8_TEST1_1.add_uniq_edge(G8_TEST1_DN3, G8_TEST1_DN4)


G8_INPUT = (set([G8_TEST1_DN2]), set([]))

G8_OUTPUT = {"graph": [G8_TEST1_0, G8_TEST1_1]}


# Test 9: Multi elements

G9_TEST1_0 = DepNodeTest(G8_IRA)
G9_TEST1_1 = DepNodeTest(G8_IRA)

G9_TEST1_DN1 = InfluencyNode(G8_IRB0.label, D, 1)
G9_TEST1_DN2 = InfluencyNode(G8_IRB1.label, B, 1)
G9_TEST1_DN3 = InfluencyNode(G8_IRB2.label, A, len(G8_IRB2.irs))

G9_TEST1_DN4 = InfluencyNode(G8_IRB0.label, C, 1)
G9_TEST1_DN5 = InfluencyNode(G8_IRB1.label, D, len(G8_IRB1.irs))
G9_TEST1_DN6 = InfluencyNode(G8_IRB1.label, D, len(G8_IRB1.irs))
G9_TEST1_DN7 = InfluencyNode(G8_IRB1.label, B, 1)

G9_TEST1_0.add_uniq_edge(G9_TEST1_DN1, G9_TEST1_DN2)
G9_TEST1_0.add_uniq_edge(G9_TEST1_DN2, G9_TEST1_DN3)

G9_TEST1_0.add_uniq_edge(G9_TEST1_DN4, G9_TEST1_DN5)

# 1 loop

G9_TEST1_1.add_uniq_edge(G9_TEST1_DN1, G9_TEST1_DN2)


G9_TEST1_1.add_uniq_edge(G9_TEST1_DN4, G9_TEST1_DN5)
G9_TEST1_1.add_uniq_edge(G9_TEST1_DN4, G9_TEST1_DN6)
G9_TEST1_1.add_uniq_edge(G9_TEST1_DN6, G9_TEST1_DN7)
G9_TEST1_1.add_uniq_edge(G9_TEST1_DN7, G9_TEST1_DN3)


G9_INPUT = (set([G9_TEST1_DN1, G9_TEST1_DN4]), set([]))

G9_OUTPUT = {"graph": [G9_TEST1_0, G9_TEST1_1],
              "emul": {A: CST1,
                       C: d_init},
              "has_loop": False}

# Test 10: loop at beginning

G10_TEST1_0 = DepNodeTest(G10_IRA)
G10_TEST1_1 = DepNodeTest(G10_IRA)

G10_TEST1_DN1 = InfluencyNode(G10_IRB2.label, A, 1)
G10_TEST1_DN2 = InfluencyNode(G10_IRB1.label, B, 1)
G10_TEST1_DN3 = InfluencyNode(G10_IRB1.label, B, 0)
G10_TEST1_DN4 = InfluencyNode(G10_IRB1.label, B, 1)

G10_TEST1_0.add_uniq_edge(G10_TEST1_DN2, G10_TEST1_DN1)
G10_TEST1_0.add_uniq_edge(G10_TEST1_DN3, G10_TEST1_DN2)

G10_TEST1_1.add_uniq_edge(G10_TEST1_DN4, G10_TEST1_DN1)
G10_TEST1_1.add_uniq_edge(G10_TEST1_DN2, G10_TEST1_DN4)
G10_TEST1_1.add_uniq_edge(G10_TEST1_DN3, G10_TEST1_DN2)

G10_INPUT = (set([G10_TEST1_DN3]), set())

G10_OUTPUT = {"graph": [G10_TEST1_0, G10_TEST1_1],
               "emul": {},
               "unresolved": set([G10_TEST1_DN3]),
               "has_loop": True}


# Test 11: no dual bloc emulation
G11_TEST1 = DepNodeTest(G11_IRA)

G11_TEST1_DN1 = InfluencyNode(G11_IRB2.label, A, 1)
G11_TEST1_DN2 = InfluencyNode(G11_IRB1.label, A, 1)
G11_TEST1_DN3 = InfluencyNode(G11_IRB1.label, B, 1)
G11_TEST1_DN4 = InfluencyNode(G11_IRB0.label, A, 1)
G11_TEST1_DN5 = InfluencyNode(G11_IRB0.label, B, 1)
G11_TEST1_DN6 = InfluencyNode(G11_IRB0.label, CST1, 0)
G11_TEST1_DN7 = InfluencyNode(G11_IRB0.label, CST2, 0)

G11_TEST1.add_uniq_edge(G11_TEST1_DN7, G11_TEST1_DN5)
G11_TEST1.add_uniq_edge(G11_TEST1_DN5, G11_TEST1_DN2)
G11_TEST1.add_uniq_edge(G11_TEST1_DN6, G11_TEST1_DN4)
G11_TEST1.add_uniq_edge(G11_TEST1_DN4, G11_TEST1_DN3)
G11_TEST1.add_uniq_edge(G11_TEST1_DN3, G11_TEST1_DN1)
G11_TEST1.add_uniq_edge(G11_TEST1_DN2, G11_TEST1_DN1)

G11_INPUT = (set([G11_TEST1_DN6, G11_TEST1_DN7]), set([]))

G11_OUTPUT = {"graph": [G11_TEST1],
               "emul": {A: ExprInt32(0x1)},
               "unresolved": set(),
               "has_loop": False}

# Test 12: no dual bloc emulation
G12_TEST1 = DepNodeTest(G12_IRA)

G12_TEST1_DN1 = InfluencyNode(G12_IRB0.label, A, 1)
G12_TEST1_DN2 = InfluencyNode(G12_IRB1.label, B, 3)
G12_TEST1_DN3 = InfluencyNode(G12_IRB1.label, ExprMem(CST1), 1)
G12_TEST1_DN4 = InfluencyNode(G12_IRB1.label, ExprMem(C), 1)
G12_TEST1_DN5 = InfluencyNode(G12_IRB1.label, D, 3)
G12_TEST1_DN6 = InfluencyNode(G12_IRB2.label, A, 1)
G12_TEST1_DN7 = InfluencyNode(G12_IRB2.label, C, 1)


G12_TEST1.add_uniq_edge(G12_TEST1_DN1, G12_TEST1_DN3)
G12_TEST1.add_uniq_edge(G12_TEST1_DN1, G12_TEST1_DN4)
G12_TEST1.add_uniq_edge(G12_TEST1_DN3, G12_TEST1_DN2)
G12_TEST1.add_uniq_edge(G12_TEST1_DN4, G12_TEST1_DN5)
G12_TEST1.add_uniq_edge(G12_TEST1_DN5, G12_TEST1_DN7)
G12_TEST1.add_uniq_edge(G12_TEST1_DN2, G12_TEST1_DN6)

# no ExprMem
G12_TEST2 = DepNodeTest(G12_IRA)
G12_TEST2.add_node(InfluencyNode(G12_IRB0.label, A, 1))


G12_INPUT = (set([G12_TEST1_DN1]), set([]))

G12_OUTPUT = {"graph": [G12_TEST1],
              "graph_nomem": [G12_TEST2],
              "graph_nocall": [G12_TEST2],
               "emul": {A: ExprInt32(0x1)},
               "unresolved": set(),
               "has_loop": False}

# Test graph 13:

G13_TEST1_0 = DepNodeTest(G13_IRA)
G13_TEST1_1 = DepNodeTest(G13_IRA)

G13_TEST1_0_DN1 = InfluencyNode(G13_IRB0.label, A, 1, True)
G13_TEST1_0_DN2 = InfluencyNode(G13_IRB0.label, D, 2, True)
G13_TEST1_0_DN6 = InfluencyNode(G13_IRB0.label, B, 3, True)
G13_TEST1_0_DN3 = InfluencyNode(G13_IRB1.label, C, 1, True)
G13_TEST1_0_DN4 = InfluencyNode(G13_IRB1.label, A, 2, True)
G13_TEST1_0_DN5 = InfluencyNode(G13_IRB2.label, B, 1, True)
G13_TEST1_0_DN7 = InfluencyNode(G13_IRB1.label, A, 2, True)
G13_TEST1_0_DN8 = InfluencyNode(G13_IRB1.label, C, 1, True)


G13_TEST1_0.add_uniq_edge(G13_TEST1_0_DN1, G13_TEST1_0_DN2)
G13_TEST1_0.add_uniq_edge(G13_TEST1_0_DN1, G13_TEST1_0_DN4)
G13_TEST1_0.add_uniq_edge(G13_TEST1_0_DN2, G13_TEST1_0_DN6)
G13_TEST1_0.add_uniq_edge(G13_TEST1_0_DN6, G13_TEST1_0_DN3)

G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN1, G13_TEST1_0_DN2)
G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN2, G13_TEST1_0_DN6)
G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN1, G13_TEST1_0_DN4)
G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN4, G13_TEST1_0_DN5)
G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN5, G13_TEST1_0_DN3)
G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN4, G13_TEST1_0_DN7)
G13_TEST1_1.add_uniq_edge(G13_TEST1_0_DN6, G13_TEST1_0_DN8)

G13_INPUT = (set([G13_TEST1_0_DN1]), set([]))

G13_OUTPUT = {"graph": [G13_TEST1_0, G13_TEST1_1]}

# Test graph 14:

G14_TEST1_0 = DepNodeTest(G14_IRA)
G14_TEST1_1 = DepNodeTest(G14_IRA)
G14_TEST1_2 = DepNodeTest(G14_IRA)

G14_TEST1_0_DN1 = InfluencyNode(G14_IRB0.label, A, 1)
G14_TEST1_0_DN2 = InfluencyNode(G14_IRB1.label, B, 1)
G14_TEST1_0_DN3 = InfluencyNode(G14_IRB3.label, R, 1)
G14_TEST1_0_DN4 = InfluencyNode(G14_IRB1.label, R, 2)

G14_TEST1_0_DN5 = InfluencyNode(G14_IRB2.label, A, 2)
G14_TEST1_0_DN6 = InfluencyNode(G14_IRB2.label, D, 1)
G14_TEST1_0_DN7 = InfluencyNode(G14_IRB1.label, B, 1)
G14_TEST1_0_DN8 = InfluencyNode(G14_IRB2.label, D, 1)
G14_TEST1_0_DN9 = InfluencyNode(G14_IRB2.label, A, 2)
G14_TEST1_0_DN10 = InfluencyNode(G14_IRB1.label, R, 2)
G14_TEST1_0_DN11 = InfluencyNode(G14_IRB1.label, B, 1)

G14_TEST1_0.add_uniq_edge(G14_TEST1_0_DN1, G14_TEST1_0_DN2)
G14_TEST1_0.add_uniq_edge(G14_TEST1_0_DN1, G14_TEST1_0_DN3)
G14_TEST1_0.add_uniq_edge(G14_TEST1_0_DN2, G14_TEST1_0_DN3)

## 1 loop
G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN1, G14_TEST1_0_DN6)
G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN1, G14_TEST1_0_DN2)

G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN6, G14_TEST1_0_DN5)
G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN6, G14_TEST1_0_DN4)

G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN5, G14_TEST1_0_DN7)
G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN5, G14_TEST1_0_DN3)

G14_TEST1_1.add_uniq_edge(G14_TEST1_0_DN7, G14_TEST1_0_DN3)

## 2 loops
G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN1, G14_TEST1_0_DN6)
G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN1, G14_TEST1_0_DN2)

G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN6, G14_TEST1_0_DN5)
G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN6, G14_TEST1_0_DN4)

G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN5, G14_TEST1_0_DN7)
G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN5, G14_TEST1_0_DN8)

G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN8, G14_TEST1_0_DN9)
G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN8, G14_TEST1_0_DN10)

G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN9, G14_TEST1_0_DN11)

G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN9, G14_TEST1_0_DN3)
G14_TEST1_2.add_uniq_edge(G14_TEST1_0_DN11, G14_TEST1_0_DN3)

G14_INPUT = (set([G14_TEST1_0_DN1]), set([]))

G14_OUTPUT = {"graph": [G14_TEST1_0, G14_TEST1_1, G14_TEST1_2]}

# Test graph 15

G15_TEST1_0 = DepNodeTest(G15_IRA)
G15_TEST1_1 = DepNodeTest(G15_IRA)

G15_TEST1_0_DN1 = InfluencyNode(G15_IRB0.label, B, 1)
G15_TEST1_0_DN2 = InfluencyNode(G15_IRB1.label, A, 1)
G15_TEST1_0_DN3 = InfluencyNode(G15_IRB1.label, C, 2)
G15_TEST1_0_DN4 = InfluencyNode(G15_IRB1.label, B, 3)
G15_TEST1_0_DN5 = InfluencyNode(G15_IRB2.label, A, 1)
G15_TEST1_0_DN6 = InfluencyNode(G15_IRB1.label, A, 1)
G15_TEST1_0_DN7 = InfluencyNode(G15_IRB1.label, C, 2)
G15_TEST1_0_DN8 = InfluencyNode(G15_IRB1.label, B, 3)


G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN1, G15_TEST1_0_DN2)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN1, G15_TEST1_0_DN3)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN3, G15_TEST1_0_DN4)
G15_TEST1_0.add_uniq_edge(G15_TEST1_0_DN4, G15_TEST1_0_DN5)

G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN1, G15_TEST1_0_DN2)
G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN1, G15_TEST1_0_DN3)
G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN3, G15_TEST1_0_DN4)

G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN4, G15_TEST1_0_DN6)
G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN4, G15_TEST1_0_DN7)
G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN7, G15_TEST1_0_DN8)

G15_TEST1_1.add_uniq_edge(G15_TEST1_0_DN8, G15_TEST1_0_DN5)


G15_INPUT = (set([G15_TEST1_0_DN1]), set([]))

G15_OUTPUT = {"graph": [G15_TEST1_0, G15_TEST1_1]
}
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
                            ]):

    # if test_nb + 1 != 12:
    #     continue
    # Extract test elements
    print "[+] Test", test_nb + 1
    g_ira, (depnodes, heads), g_test_output = test

    open("graph_influence_%02d.dot" % (test_nb + 1), "w").write(g_ira.g.dot())

    # Different options
    suffix_key_list = ["", "_nosimp", "_nomem", "_nocall",
                       "_implicit"]
    # Test classes
    for g_ind, g_dep in enumerate([InfluenceGraph(g_ira),
                                   InfluenceGraph(g_ira, apply_simp=False),
                                   InfluenceGraph(g_ira, follow_mem=False),
                                   InfluenceGraph(g_ira, follow_mem=False,
                                                  follow_call=False),
                                   InfluenceGraph(g_ira, implicit=True),
                                   ]):
        if g_ind > 0: continue
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
                open("graph_influence_test_%02d_%02d.dot" % (test_nb + 1, result_nb),
                     "w").write(result_graph.graph.dot())

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

            except AssertionError:
                FAILED.add((test_nb + 1, error))
                continue

if FAILED:
    print "FAILED :", len(FAILED)
    for i in sorted(FAILED, key=lambda (u, _): u):
        print i,
else:
    print "SUCCESS"
