from miasm2.expression.expression import ExprId, ExprInt32, ExprAff
from miasm2.core.asmbloc import asm_label
from miasm2.ir.analysis import ira
from miasm2.ir.ir import ir, irbloc
from miasm2.core.graph import DiGraph
from miasm2.analysis.depgraph import DependencyNode, DependencyGraph, DependencyDict, DependencyGraph_NoMemory
from pdb import pm

a = ExprId("a")
b = ExprId("b")
c = ExprId("c")
d = ExprId("d")

a_init = ExprId("a_init")
b_init = ExprId("b_init")
c_init = ExprId("c_init")
d_init = ExprId("d_init")

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
    regs_init = {a: a_init, b: b_init, c: c_init, d: d_init}

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

    def gen_graph(self):
        return

class GraphTest(DiGraph):
    def __init__(self, ira):
        self.ira = ira
        super(GraphTest, self).__init__()

    def __eq__(self, graph):
        if self._nodes != graph._nodes:
            return False
        if sorted(self._edges) != sorted(graph._edges):
            return False
        return True

    def gen_graph(self):
        return

    def node2str(self, node):
        if not node in self.ira.blocs:
            return str(node)
        else:
            return str(self.ira.blocs[node])

class DepNodeTest(DiGraph):
    def __init__(self, ira):
        self.ira = ira
        super(DepNodeTest, self).__init__()

    def __eq__(self, graph):
        if self._nodes != graph._nodes:
            return False
        if sorted(self._edges) != sorted(graph._edges):
            return False
        return True

    def node2str(self, node):
        assert(node.label in self.ira.blocs)
        out = "(%s, %s, %s)\\l"%(node.label.name,
                                 node.element,
                                 node.line_nb)
        if not (0 <= node.line_nb < len(self.ira.blocs[node.label].irs)):
            return out
        exprs = self.ira.blocs[node.label].irs[node.line_nb]
        exprs_str = '\\l'.join([str(x) for x in exprs])
        return "%s %s"%(out, exprs_str)

# Test structures
print "[+] Test structures"

print "[+] Test DependencyDict"
dd0 = DependencyDict(lbl0, [])
depnodes_0 = [DependencyNode(lbl0, a, i) for i in xrange(10)][::-1]

## Heads
assert(list(dd0.heads()) == [])
assert(dd0.is_head(depnodes_0[-1]) == True)
assert(dd0.is_head(depnodes_0[0]) == False)
dd0.cache[depnodes_0[-1]] = set(depnodes_0[-1:])
assert(list(dd0.heads()) == [depnodes_0[-1]])

## Extend
dd1 = dd0.extend(lbl1)

assert(dd1.label == lbl1)
assert(dd1.history == [dd0])
assert(dd1.cache == dd0.cache)
assert(dd1.pending == set())
assert(dd1 != dd0)

dd1.cache[depnodes_0[4]] = set(depnodes_0[5:9])
assert(dd1.cache != dd0.cache)

dd2 = dd0.copy()
assert(dd2.label == lbl0)
assert(dd2.history == [])
assert(dd2.cache == dd0.cache)
assert(dd2.pending == dd0.pending)
assert(dd2 == dd0)

dd2.cache[depnodes_0[4]] = set(depnodes_0[5:9])
assert(dd2.cache != dd0.cache)

print "[+] DependencyDict OK !"
print "[+] Structures OK !"

# graph 1

g1_ira = IRATest()
g1_ira.g = GraphTest(g1_ira)

g1_irb0 = gen_irbloc(lbl0, [ [ExprAff(c, cst1)] ])
g1_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, c)] ])
g1_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, b)] ])

g1_ira.g.add_uniq_edge(g1_irb0.label, g1_irb1.label)
g1_ira.g.add_uniq_edge(g1_irb1.label, g1_irb2.label)

g1_ira.blocs = dict([(irb.label, irb) for irb in [g1_irb0, g1_irb1, g1_irb2]])

# graph 2

g2_ira = IRATest()
g2_ira.g = GraphTest(g2_ira)

g2_irb0 = gen_irbloc(lbl0, [ [ExprAff(c, cst1)] ])
g2_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, cst2)] ])
g2_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, b+c)] ])

g2_ira.g.add_uniq_edge(g2_irb0.label, g2_irb1.label)
g2_ira.g.add_uniq_edge(g2_irb1.label, g2_irb2.label)

g2_ira.blocs = dict([(irb.label, irb) for irb in [g2_irb0, g2_irb1, g2_irb2]])


# graph 3

g3_ira = IRATest()
g3_ira.g = GraphTest(g3_ira)

g3_irb0 = gen_irbloc(lbl0, [ [ExprAff(c, cst1)] ])
g3_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, cst2)] ])
g3_irb2 = gen_irbloc(lbl2, [ [ExprAff(b, cst3)] ])
g3_irb3 = gen_irbloc(lbl3, [ [ExprAff(a, b+c)] ])

g3_ira.g.add_uniq_edge(g3_irb0.label, g3_irb1.label)
g3_ira.g.add_uniq_edge(g3_irb0.label, g3_irb2.label)
g3_ira.g.add_uniq_edge(g3_irb1.label, g3_irb3.label)
g3_ira.g.add_uniq_edge(g3_irb2.label, g3_irb3.label)

g3_ira.blocs = dict([(irb.label, irb) for irb in [g3_irb0, g3_irb1,
                                                  g3_irb2, g3_irb3]])

# graph 4

g4_ira = IRATest()
g4_ira.g = GraphTest(g4_ira)

g4_irb0 = gen_irbloc(lbl0, [ [ExprAff(c, cst1)] ])
g4_irb1 = gen_irbloc(lbl1, [ [ExprAff(c, c+cst2)] ])
g4_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, b)] ])

g4_ira.g.add_uniq_edge(g4_irb0.label, g4_irb1.label)
g4_ira.g.add_uniq_edge(g4_irb1.label, g4_irb2.label)
g4_ira.g.add_uniq_edge(g4_irb1.label, g4_irb1.label)

g4_ira.blocs = dict([(irb.label, irb) for irb in [g4_irb0, g4_irb1, g4_irb2]])


# graph 5

g5_ira = IRATest()
g5_ira.g = GraphTest(g5_ira)

g5_irb0 = gen_irbloc(lbl0, [ [ExprAff(b, cst1)] ])
g5_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, b+cst2)] ])
g5_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, b)] ])

g5_ira.g.add_uniq_edge(g5_irb0.label, g5_irb1.label)
g5_ira.g.add_uniq_edge(g5_irb1.label, g5_irb2.label)
g5_ira.g.add_uniq_edge(g5_irb1.label, g5_irb1.label)

g5_ira.blocs = dict([(irb.label, irb) for irb in [g5_irb0, g5_irb1, g5_irb2]])

# graph 6

g6_ira = IRATest()
g6_ira.g = GraphTest(g6_ira)

g6_irb0 = gen_irbloc(lbl0, [ [ExprAff(b, cst1)] ])
g6_irb1 = gen_irbloc(lbl1, [ [ExprAff(a, b)] ])

g6_ira.g.add_uniq_edge(g6_irb0.label, g6_irb1.label)
g6_ira.g.add_uniq_edge(g6_irb1.label, g6_irb1.label)

g6_ira.blocs = dict([(irb.label, irb) for irb in [g6_irb0, g6_irb1]])

# graph 7

g7_ira = IRATest()
g7_ira.g = GraphTest(g7_ira)

g7_irb0 = gen_irbloc(lbl0, [ [ExprAff(c, cst1)] ])
g7_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, c)], [ExprAff(a, b)]  ])
g7_irb2 = gen_irbloc(lbl2, [ [ExprAff(d, a)]  ])

g7_ira.g.add_uniq_edge(g7_irb0.label, g7_irb1.label)
g7_ira.g.add_uniq_edge(g7_irb1.label, g7_irb1.label)
g7_ira.g.add_uniq_edge(g7_irb1.label, g7_irb2.label)

g7_ira.blocs = dict([(irb.label, irb) for irb in [g7_irb0, g7_irb1, g7_irb2]])

# graph 8

g8_ira = IRATest()
g8_ira.g = GraphTest(g8_ira)

g8_irb0 = gen_irbloc(lbl0, [ [ExprAff(c, cst1)] ])
g8_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, c)], [ExprAff(c, d)]  ])
g8_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, b)]  ])

g8_ira.g.add_uniq_edge(g8_irb0.label, g8_irb1.label)
g8_ira.g.add_uniq_edge(g8_irb1.label, g8_irb1.label)
g8_ira.g.add_uniq_edge(g8_irb1.label, g8_irb2.label)

g8_ira.blocs = dict([(irb.label, irb) for irb in [g8_irb0, g8_irb1, g8_irb2]])

# graph 9 is graph 8

# graph 10

g10_ira = IRATest()
g10_ira.g = GraphTest(g10_ira)

g10_irb1 = gen_irbloc(lbl1, [ [ExprAff(b, b+cst2)] ])
g10_irb2 = gen_irbloc(lbl2, [ [ExprAff(a, b)] ])

g10_ira.g.add_uniq_edge(g10_irb1.label, g10_irb2.label)
g10_ira.g.add_uniq_edge(g10_irb1.label, g10_irb1.label)

g10_ira.blocs = dict([(irb.label, irb) for irb in [g10_irb1, g10_irb2]])


# Test graph 1

g1_test1 = DepNodeTest(g1_ira)

g1_test1_dn1 = DependencyNode(g1_irb2.label, a, len(g1_irb2.irs))
g1_test1_dn2 = DependencyNode(g1_irb2.label, b, 0)
g1_test1_dn3 = DependencyNode(g1_irb1.label, c, 0)
g1_test1_dn4 = DependencyNode(g1_irb0.label, cst1, 0)

g1_test1.add_uniq_edge(g1_test1_dn4, g1_test1_dn3)
g1_test1.add_uniq_edge(g1_test1_dn3, g1_test1_dn2)
g1_test1.add_uniq_edge(g1_test1_dn2, g1_test1_dn1)

g1_input = (set([g1_test1_dn1]), set([g1_irb0.label]))
g1_output1 = {"graph": g1_test1,
              "emul": {a: cst1},
              "unresolved": set(),
              "has_loop": False}

# Test graph 2

g2_test1 = DepNodeTest(g2_ira)

g2_test1_dn1 = DependencyNode(g2_irb2.label, a, len(g2_irb2.irs))
g2_test1_dn2 = DependencyNode(g2_irb2.label, b, 0)
g2_test1_dn3 = DependencyNode(g2_irb2.label, c, 0)
g2_test1_dn4 = DependencyNode(g2_irb1.label, cst2, 0)
g2_test1_dn5 = DependencyNode(g2_irb0.label, cst1, 0)

g2_test1.add_uniq_edge(g2_test1_dn5, g2_test1_dn3)
g2_test1.add_uniq_edge(g2_test1_dn4, g2_test1_dn2)
g2_test1.add_uniq_edge(g2_test1_dn2, g2_test1_dn1)
g2_test1.add_uniq_edge(g2_test1_dn3, g2_test1_dn1)

g2_input = (set([g2_test1_dn1]), set([g2_irb0.label]))
g2_output1 = {"graph": g2_test1,
              "emul": {a: ExprInt32(int(cst1.arg) + int(cst2.arg))},
              "unresolved": set(),
              "has_loop": False}

# Test graph 3

g3_test1_0 = DepNodeTest(g3_ira)
g3_test1_1 = DepNodeTest(g3_ira)

g3_test1_0_dn1 = DependencyNode(g3_irb3.label, a, len(g3_irb3.irs))
g3_test1_0_dn2 = DependencyNode(g3_irb3.label, b, 0)
g3_test1_0_dn3 = DependencyNode(g3_irb3.label, c, 0)
g3_test1_0_dn4 = DependencyNode(g3_irb2.label, cst3, 0)
g3_test1_0_dn5 = DependencyNode(g3_irb0.label, cst1, 0)

g3_test1_1_dn1 = DependencyNode(g3_irb3.label, a, len(g3_irb3.irs))
g3_test1_1_dn2 = DependencyNode(g3_irb3.label, b, 0)
g3_test1_1_dn3 = DependencyNode(g3_irb3.label, c, 0)
g3_test1_1_dn4 = DependencyNode(g3_irb1.label, cst2, 0)
g3_test1_1_dn5 = DependencyNode(g3_irb0.label, cst1, 0)

g3_test1_0.add_uniq_edge(g3_test1_0_dn5, g3_test1_0_dn3)
g3_test1_0.add_uniq_edge(g3_test1_0_dn4, g3_test1_0_dn2)
g3_test1_0.add_uniq_edge(g3_test1_0_dn2, g3_test1_0_dn1)
g3_test1_0.add_uniq_edge(g3_test1_0_dn3, g3_test1_0_dn1)

g3_test1_1.add_uniq_edge(g3_test1_1_dn5, g3_test1_1_dn3)
g3_test1_1.add_uniq_edge(g3_test1_1_dn4, g3_test1_1_dn2)
g3_test1_1.add_uniq_edge(g3_test1_1_dn2, g3_test1_1_dn1)
g3_test1_1.add_uniq_edge(g3_test1_1_dn3, g3_test1_0_dn1)

g3_input = (set([g3_test1_0_dn1]), set([g3_irb0.label]))

g3_output1 = {"graph": g3_test1_0,
              "emul": {a: ExprInt32(int(cst1.arg) + int(cst3.arg))},
              "unresolved": set(),
              "has_loop": False}

g3_output2 = {"graph": g3_test1_1,
              "emul": {a: ExprInt32(int(cst1.arg) + int(cst2.arg))},
              "unresolved": set(),
              "has_loop": False}

# Test graph 4

g4_test1 = DepNodeTest(g4_ira)

g4_test1_dn1 = DependencyNode(g4_irb2.label, a, len(g2_irb0.irs))
g4_test1_dn2 = DependencyNode(g4_irb2.label, b, 0)
g4_test1_dn3 = DependencyNode(g4_irb0.label, b, 0)

g4_test1.add_uniq_edge(g4_test1_dn2, g4_test1_dn1)

g4_input = (set([g4_test1_dn1]), set([g4_irb0.label]))

g4_output1 = {"graph": g4_test1,
              "emul": {a: b_init},
              "unresolved": set([g4_test1_dn3]),
              "has_loop": False}

# Test graph 5

g5_test1 = DepNodeTest(g5_ira)

g5_test1_dn1 = DependencyNode(g5_irb2.label, a, len(g5_irb2.irs))
g5_test1_dn2 = DependencyNode(g5_irb2.label, b, 0)
g5_test1_dn3 = DependencyNode(g5_irb1.label, b, 0)
g5_test1_dn4 = DependencyNode(g5_irb0.label, cst1, 0)
g5_test1_dn5 = DependencyNode(g5_irb1.label, cst2, 0)

g5_test1.add_uniq_edge(g5_test1_dn4, g5_test1_dn3)
g5_test1.add_uniq_edge(g5_test1_dn3, g5_test1_dn2)
g5_test1.add_uniq_edge(g5_test1_dn5, g5_test1_dn2)
g5_test1.add_uniq_edge(g5_test1_dn2, g5_test1_dn1)

g5_input = (set([g5_test1_dn1]), set([g5_irb0.label]))

g5_output1 = {"graph": g5_test1,
              "emul": {},
              "unresolved": set(),
              "has_loop": True}

# Test graph 6

g6_test1_0 = DepNodeTest(g6_ira)

g6_test1_0_dn1 = DependencyNode(g6_irb1.label, a, len(g6_irb1.irs))
g6_test1_0_dn2 = DependencyNode(g6_irb1.label, b, 0)
g6_test1_0_dn3 = DependencyNode(g6_irb0.label, cst1, 0)


g6_test1_0.add_uniq_edge(g6_test1_0_dn3, g6_test1_0_dn2)
g6_test1_0.add_uniq_edge(g6_test1_0_dn2, g6_test1_0_dn1)

g6_input = (set([g6_test1_0_dn1]), set([g6_irb0.label]))

g6_output1 = {"graph": g6_test1_0,
              "emul": {a: cst1},
              "unresolved": set(),
              "has_loop": True}

# Test graph 7

g7_test1_0 = DepNodeTest(g7_ira)

g7_test1_0_dn1 = DependencyNode(g7_irb2.label, a, len(g7_irb2.irs))
g7_test1_0_dn2 = DependencyNode(g7_irb1.label, b, 1)
g7_test1_0_dn3 = DependencyNode(g7_irb1.label, c, 0)
g7_test1_0_dn4 = DependencyNode(g7_irb0.label, cst1, 0)


g7_test1_0.add_uniq_edge(g7_test1_0_dn4, g7_test1_0_dn3)
g7_test1_0.add_uniq_edge(g7_test1_0_dn3, g7_test1_0_dn2)
g7_test1_0.add_uniq_edge(g7_test1_0_dn2, g7_test1_0_dn1)

g7_input = (set([g7_test1_0_dn1]), set([g7_irb0.label]))

g7_output1 = {"graph": g7_test1_0,
              "emul": {a: cst1},
              "unresolved": set(),
              "has_loop": True}

# Test graph 8

g8_test1_0 = DepNodeTest(g8_ira)
g8_test1_1 = DepNodeTest(g8_ira)

g8_test1_0_dn1 = DependencyNode(g8_irb2.label, a, len(g8_irb2.irs))
g8_test1_0_dn2 = DependencyNode(g8_irb2.label, b, 0)
g8_test1_0_dn3 = DependencyNode(g8_irb1.label, c, 0)
g8_test1_0_dn4 = DependencyNode(g8_irb0.label, cst1, 0)

g8_test1_1_dn1 = DependencyNode(g8_irb2.label, a, len(g8_irb2.irs))
g8_test1_1_dn2 = DependencyNode(g8_irb2.label, b, 0)
g8_test1_1_dn3 = DependencyNode(g8_irb1.label, c, 0)
g8_test1_1_dn4 = DependencyNode(g8_irb1.label, d, 1)

g8_test1_1_dn5 = DependencyNode(g8_irb0.label, d, 0)


g8_test1_0.add_uniq_edge(g8_test1_0_dn4, g8_test1_0_dn3)
g8_test1_0.add_uniq_edge(g8_test1_0_dn3, g8_test1_0_dn2)
g8_test1_0.add_uniq_edge(g8_test1_0_dn2, g8_test1_0_dn1)

g8_test1_1.add_uniq_edge(g8_test1_1_dn4, g8_test1_1_dn3)
g8_test1_1.add_uniq_edge(g8_test1_1_dn3, g8_test1_1_dn2)
g8_test1_1.add_uniq_edge(g8_test1_1_dn2, g8_test1_1_dn1)

g8_input = (set([g8_test1_0_dn1]), set([g3_irb0.label]))

g8_output1 = {"graph": g8_test1_0,
              "emul": {a: cst1},
              "unresolved": set(),
              "has_loop": False}

g8_output2 = {"graph": g8_test1_1,
              "emul": {a: d_init},
              "unresolved": set([g8_test1_1_dn5]),
              "has_loop": True}


# Test 9: Multi elements

g9_test1_0 = DepNodeTest(g8_ira)
g9_test1_1 = DepNodeTest(g8_ira)

g9_test1_0_dn1 = DependencyNode(g8_irb2.label, a, len(g8_irb2.irs))
g9_test1_0_dn2 = DependencyNode(g8_irb2.label, b, 0)
g9_test1_0_dn3 = DependencyNode(g8_irb1.label, c, 0)
g9_test1_0_dn4 = DependencyNode(g8_irb0.label, cst1, 0)
g9_test1_0_dn5 = DependencyNode(g8_irb2.label, c, len(g8_irb2.irs))
g9_test1_0_dn6 = DependencyNode(g8_irb1.label, d, 1)

g9_test1_1_dn1 = DependencyNode(g8_irb2.label, a, len(g8_irb2.irs))
g9_test1_1_dn2 = DependencyNode(g8_irb2.label, b, 0)
g9_test1_1_dn3 = DependencyNode(g8_irb1.label, c, 0)
g9_test1_1_dn4 = DependencyNode(g8_irb1.label, d, 1)
g9_test1_1_dn5 = DependencyNode(g8_irb2.label, c, len(g8_irb2.irs))


g9_test1_0.add_uniq_edge(g9_test1_0_dn4, g9_test1_0_dn3)
g9_test1_0.add_uniq_edge(g9_test1_0_dn3, g9_test1_0_dn2)
g9_test1_0.add_uniq_edge(g9_test1_0_dn2, g9_test1_0_dn1)
g9_test1_0.add_uniq_edge(g9_test1_0_dn6, g9_test1_0_dn5)

g9_test1_1.add_uniq_edge(g9_test1_1_dn4, g9_test1_1_dn5)
g9_test1_1.add_uniq_edge(g9_test1_1_dn4, g9_test1_1_dn3)
g9_test1_1.add_uniq_edge(g9_test1_1_dn3, g9_test1_1_dn2)
g9_test1_1.add_uniq_edge(g9_test1_1_dn2, g9_test1_1_dn1)

g9_input = (set([g9_test1_0_dn1, g9_test1_0_dn5]), set([g8_irb0.label]))

g9_output1 = {"graph": g9_test1_0,
              "emul": {a: cst1,
                       c: d_init},
              "unresolved": set([g8_test1_1_dn5]),
              "has_loop": False}

g9_output2 = {"graph": g9_test1_1,
              "emul": {a: d_init,
                       c: d_init},
              "unresolved": set([g8_test1_1_dn5]),
              "has_loop": True}


# Test 10: loop at beginning

g10_test1 = DepNodeTest(g10_ira)

g10_test1_dn1 = DependencyNode(g10_irb2.label, a, len(g10_irb2.irs))
g10_test1_dn2 = DependencyNode(g10_irb2.label, b, 0)
g10_test1_dn3 = DependencyNode(g10_irb1.label, b, 0)
g10_test1_dn4 = DependencyNode(g10_irb1.label, cst2, 0)

g10_test1.add_uniq_edge(g10_test1_dn3, g10_test1_dn2)
g10_test1.add_uniq_edge(g10_test1_dn4, g10_test1_dn2)
g10_test1.add_uniq_edge(g10_test1_dn2, g10_test1_dn1)

g10_input = (set([g10_test1_dn1]), set([g10_irb1.label]))

g10_output1 = {"graph": g10_test1,
               "emul": {},
               "unresolved": set([g10_test1_dn3]),
               "has_loop": True}


# Launch tests
for i, test in enumerate([(g1_ira, g1_input, [g1_output1]),
                          (g2_ira, g2_input, [g2_output1]),
                          (g3_ira, g3_input, [g3_output1, g3_output2]),
                          (g4_ira, g4_input, [g4_output1]),
                          (g5_ira, g5_input, [g5_output1]),
                          (g6_ira, g6_input, [g6_output1]),
                          (g7_ira, g7_input, [g7_output1]),
                          (g8_ira, g8_input, [g8_output1, g8_output2]),
                          (g8_ira, g9_input, [g9_output1, g9_output2]),
                          (g10_ira, g10_input, [g10_output1]),
                      ]):
    # Extract test elements
    print "[+] Test", i+1
    g_ira, (depnodes, heads), g_test_list = test
    open("graph_%02d.dot" % (i+1), "w").write(g_ira.g.dot())
    # Test classes
    for g_dep in [DependencyGraph(g_ira),
                  DependencyGraph_NoMemory(g_ira)]:
        print " - Class %s" % g_dep.__class__.__name__

        ## Test public APIs
        for api_i, g_list in enumerate([g_dep.get_fromDepNodes(depnodes, heads),
                                        g_dep.get(list(depnodes)[0].label,
                                                  [depnode.element for
                                                   depnode in depnodes],
                                                  list(depnodes)[0].line_nb,
                                                  heads)]):
            print " - - API %s" % ("get_fromDepNodes" if api_i == 0 else "get")

            ### Expand result iterator
            g_list = list(g_list)
            ### Dump outputs graphs for debug means
            for j, result in enumerate(g_list):
                open("graph_test_%02d_%02d.dot" % (i+1, j), "w").write(result.graph.dot())

            ### The number of results should be the same
            print " - - - number of results"
            assert(len(g_list) == len(g_test_list))

            ### Match the right result (unordered)
            for i, result in enumerate(g_list):
                print " - - - result %d" % i
                found = False
                for expected in g_test_list:
                    if expected["graph"].__eq__(result.graph):
                        found = True
                        break
                assert(found)

                #### @expected is the corresponding result, test for properties
                print " - - - - emul"
                if not expected["has_loop"]:
                    assert(expected["emul"] == result.emul())
                for element in ["unresolved"]: # TODO: has_loop
                    print " - - - - %s" % element
                    assert(expected[element] == getattr(result, element))
