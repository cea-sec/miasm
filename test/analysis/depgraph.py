"""Regression test module for DependencyGraph"""
from miasm2.expression.expression import ExprId, ExprInt, ExprAff, ExprCond
from miasm2.core.asmblock import AsmLabel
from miasm2.ir.analysis import ira
from miasm2.ir.ir import IRBlock, AssignBlock
from miasm2.core.graph import DiGraph
from miasm2.analysis.depgraph import DependencyNode, DependencyGraph
from itertools import count
from pdb import pm
import re

EMULATION = True
try:
    import z3
except ImportError:
    EMULATION = False

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

CST0 = ExprInt(0x0, 32)
CST1 = ExprInt(0x1, 32)
CST2 = ExprInt(0x2, 32)
CST3 = ExprInt(0x3, 32)
CST22 = ExprInt(0x22, 32)
CST23 = ExprInt(0x23, 32)
CST24 = ExprInt(0x24, 32)
CST33 = ExprInt(0x33, 32)
CST35 = ExprInt(0x35, 32)
CST37 = ExprInt(0x37, 32)

LBL0 = AsmLabel("lbl0")
LBL1 = AsmLabel("lbl1")
LBL2 = AsmLabel("lbl2")
LBL3 = AsmLabel("lbl3")
LBL4 = AsmLabel("lbl4")
LBL5 = AsmLabel("lbl5")
LBL6 = AsmLabel("lbl6")

def gen_irblock(label, exprs_list):
    """ Returns an IRBlock.
    Used only for tests purpose
    """
    irs = []
    for exprs in exprs_list:
        if isinstance(exprs, AssignBlock):
            irs.append(exprs)
        else:
            irs.append(AssignBlock(exprs))

    irbl = IRBlock(label, irs)
    return irbl


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


def bloc2graph(irgraph, label=False, lines=True):
    """Render dot graph of @blocks"""

    escape_chars = re.compile('[' + re.escape('{}') + ']')
    label_attr = 'colspan="2" align="center" bgcolor="grey"'
    edge_attr = 'label = "%s" color="%s" style="bold"'
    td_attr = 'align="left"'
    block_attr = 'shape="Mrecord" fontname="Courier New"'

    out = ["digraph asm_graph {"]
    fix_chars = lambda x: '\\' + x.group()

    # Generate basic blocks
    out_blocks = []
    for label in irgraph.graph.nodes():
        if isinstance(label, AsmLabel):
            label_name = label.name
        else:
            label_name = str(label)

        if hasattr(irgraph, 'blocks'):
            irblock = irgraph.blocks[label]
        else:
            irblock = None
        if isinstance(label, AsmLabel):
            out_block = '%s [\n' % label.name
        else:
            out_block = '%s [\n' % label
        out_block += "%s " % block_attr
        out_block += 'label =<<table border="0" cellborder="0" cellpadding="3">'

        block_label = '<tr><td %s>%s</td></tr>' % (
            label_attr, label_name)
        block_html_lines = []
        if lines and irblock is not None:
            for assignblk in irblock.irs:
                for dst, src in assignblk.iteritems():
                    if False:
                        out_render = "%.8X</td><td %s> " % (0, td_attr)
                    else:
                        out_render = ""
                    out_render += escape_chars.sub(fix_chars, "%s = %s" % (dst, src))
                    block_html_lines.append(out_render)
                block_html_lines.append(" ")
            block_html_lines.pop()
        block_html_lines = ('<tr><td %s>' % td_attr +
                            ('</td></tr><tr><td %s>' % td_attr).join(block_html_lines) +
                            '</td></tr>')
        out_block += "%s " % block_label
        out_block += block_html_lines + "</table>> ];"
        out_blocks.append(out_block)

    out += out_blocks
    # Generate links
    for src, dst in irgraph.graph.edges():
            if isinstance(src, AsmLabel):
                src_name = src.name
            else:
                src_name = str(src)
            if isinstance(dst, AsmLabel):
                dst_name = dst.name
            else:
                dst_name = str(dst)

            edge_color = "black"
            out.append('%s -> %s' % (src_name,
                                     dst_name) +
                       '[' + edge_attr % ("", edge_color) + '];')

    out.append("}")
    return '\n'.join(out)


def dg2graph(graph, label=False, lines=True):
    """Render dot graph of @blocks"""

    escape_chars = re.compile('[' + re.escape('{}') + ']')
    label_attr = 'colspan="2" align="center" bgcolor="grey"'
    edge_attr = 'label = "%s" color="%s" style="bold"'
    td_attr = 'align="left"'
    block_attr = 'shape="Mrecord" fontname="Courier New"'

    out = ["digraph asm_graph {"]
    fix_chars = lambda x: '\\' + x.group()

    # Generate basic blocks
    out_blocks = []
    for label in graph.nodes():
        if isinstance(label, DependencyNode):
            label_name = "%s %s %s" % (label.label.name,
                                       label.element,
                                       label.line_nb)
        else:
            label_name = str(label)
        out_block = '%s [\n' % hash(label)
        out_block += "%s " % block_attr
        out_block += 'label =<<table border="0" cellborder="0" cellpadding="3">'

        block_label = '<tr><td %s>%s</td></tr>' % (
            label_attr, label_name)
        block_html_lines = []
        block_html_lines = ('<tr><td %s>' % td_attr +
                            ('</td></tr><tr><td %s>' % td_attr).join(block_html_lines) +
                            '</td></tr>')
        out_block += "%s " % block_label
        out_block += block_html_lines + "</table>> ];"
        out_blocks.append(out_block)

    out += out_blocks
    # Generate links
    for src, dst in graph.edges():
            edge_color = "black"
            out.append('%s -> %s ' % (hash(src),
                                      hash(dst)) +
                       '[' + edge_attr % ("", edge_color) + '];')

    out.append("}")
    return '\n'.join(out)


print "   [+] Test dictionnary equality"
DNA = DependencyNode(LBL2, A, 0)
DNB = DependencyNode(LBL1, B, 1)
DNC = DependencyNode(LBL1, C, 0)
DNB2 = DependencyNode(LBL1, B, 1)
DNC2 = DependencyNode(LBL1, C, 0)
DNB3 = DependencyNode(LBL1, B, 1)
DNC3 = DependencyNode(LBL1, C, 0)

# graph 1

G1_IRA = IRATest()

G1_IRB0 = gen_irblock(LBL0, [[ExprAff(C, CST1)]])
G1_IRB1 = gen_irblock(LBL1, [[ExprAff(B, C)]])
G1_IRB2 = gen_irblock(LBL2, [[ExprAff(A, B)]])

G1_IRA.graph.add_uniq_edge(G1_IRB0.label, G1_IRB1.label)
G1_IRA.graph.add_uniq_edge(G1_IRB1.label, G1_IRB2.label)

G1_IRA.blocks = dict([(irb.label, irb) for irb in [G1_IRB0, G1_IRB1, G1_IRB2]])

# graph 2

G2_IRA = IRATest()

G2_IRB0 = gen_irblock(LBL0, [[ExprAff(C, CST1)]])
G2_IRB1 = gen_irblock(LBL1, [[ExprAff(B, CST2)]])
G2_IRB2 = gen_irblock(LBL2, [[ExprAff(A, B + C)]])

G2_IRA.graph.add_uniq_edge(G2_IRB0.label, G2_IRB1.label)
G2_IRA.graph.add_uniq_edge(G2_IRB1.label, G2_IRB2.label)

G2_IRA.blocks = dict([(irb.label, irb) for irb in [G2_IRB0, G2_IRB1, G2_IRB2]])


# graph 3

G3_IRA = IRATest()

G3_IRB0 = gen_irblock(LBL0, [[ExprAff(C, CST1)]])
G3_IRB1 = gen_irblock(LBL1, [[ExprAff(B, CST2)]])
G3_IRB2 = gen_irblock(LBL2, [[ExprAff(B, CST3)]])
G3_IRB3 = gen_irblock(LBL3, [[ExprAff(A, B + C)]])

G3_IRA.graph.add_uniq_edge(G3_IRB0.label, G3_IRB1.label)
G3_IRA.graph.add_uniq_edge(G3_IRB0.label, G3_IRB2.label)
G3_IRA.graph.add_uniq_edge(G3_IRB1.label, G3_IRB3.label)
G3_IRA.graph.add_uniq_edge(G3_IRB2.label, G3_IRB3.label)

G3_IRA.blocks = dict([(irb.label, irb) for irb in [G3_IRB0, G3_IRB1,
                                                   G3_IRB2, G3_IRB3]])

# graph 4

G4_IRA = IRATest()

G4_IRB0 = gen_irblock(LBL0, [[ExprAff(C, CST1)]])
G4_IRB1 = gen_irblock(LBL1, [[ExprAff(C, C + CST2)],
                             [ExprAff(G4_IRA.IRDst,
                                      ExprCond(C, ExprId(LBL2),
                                               ExprId(LBL1)))]])

G4_IRB2 = gen_irblock(LBL2, [[ExprAff(A, B)]])

G4_IRA.graph.add_uniq_edge(G4_IRB0.label, G4_IRB1.label)
G4_IRA.graph.add_uniq_edge(G4_IRB1.label, G4_IRB2.label)
G4_IRA.graph.add_uniq_edge(G4_IRB1.label, G4_IRB1.label)

G4_IRA.blocks = dict([(irb.label, irb) for irb in [G4_IRB0, G4_IRB1, G4_IRB2]])


# graph 5

G5_IRA = IRATest()

G5_IRB0 = gen_irblock(LBL0, [[ExprAff(B, CST1)]])
G5_IRB1 = gen_irblock(LBL1, [[ExprAff(B, B + CST2)],
                             [ExprAff(G5_IRA.IRDst,
                                      ExprCond(B, ExprId(LBL2),
                                               ExprId(LBL1)))]])

G5_IRB2 = gen_irblock(LBL2, [[ExprAff(A, B)]])

G5_IRA.graph.add_uniq_edge(G5_IRB0.label, G5_IRB1.label)
G5_IRA.graph.add_uniq_edge(G5_IRB1.label, G5_IRB2.label)
G5_IRA.graph.add_uniq_edge(G5_IRB1.label, G5_IRB1.label)

G5_IRA.blocks = dict([(irb.label, irb) for irb in [G5_IRB0, G5_IRB1, G5_IRB2]])

# graph 6

G6_IRA = IRATest()

G6_IRB0 = gen_irblock(LBL0, [[ExprAff(B, CST1)]])
G6_IRB1 = gen_irblock(LBL1, [[ExprAff(A, B)]])

G6_IRA.graph.add_uniq_edge(G6_IRB0.label, G6_IRB1.label)
G6_IRA.graph.add_uniq_edge(G6_IRB1.label, G6_IRB1.label)

G6_IRA.blocks = dict([(irb.label, irb) for irb in [G6_IRB0, G6_IRB1]])

# graph 7

G7_IRA = IRATest()

G7_IRB0 = gen_irblock(LBL0, [[ExprAff(C, CST1)]])
G7_IRB1 = gen_irblock(LBL1, [[ExprAff(B, C)], [ExprAff(A, B)]])
G7_IRB2 = gen_irblock(LBL2, [[ExprAff(D, A)]])

G7_IRA.graph.add_uniq_edge(G7_IRB0.label, G7_IRB1.label)
G7_IRA.graph.add_uniq_edge(G7_IRB1.label, G7_IRB1.label)
G7_IRA.graph.add_uniq_edge(G7_IRB1.label, G7_IRB2.label)

G7_IRA.blocks = dict([(irb.label, irb) for irb in [G7_IRB0, G7_IRB1, G7_IRB2]])

# graph 8

G8_IRA = IRATest()

G8_IRB0 = gen_irblock(LBL0, [[ExprAff(C, CST1)]])
G8_IRB1 = gen_irblock(LBL1, [[ExprAff(B, C)], [ExprAff(C, D)]])
G8_IRB2 = gen_irblock(LBL2, [[ExprAff(A, B)]])

G8_IRA.graph.add_uniq_edge(G8_IRB0.label, G8_IRB1.label)
G8_IRA.graph.add_uniq_edge(G8_IRB1.label, G8_IRB1.label)
G8_IRA.graph.add_uniq_edge(G8_IRB1.label, G8_IRB2.label)

G8_IRA.blocks = dict([(irb.label, irb) for irb in [G8_IRB0, G8_IRB1, G8_IRB2]])

# graph 9 is graph 8

# graph 10

G10_IRA = IRATest()

G10_IRB1 = gen_irblock(LBL1, [[ExprAff(B, B + CST2)]])
G10_IRB2 = gen_irblock(LBL2, [[ExprAff(A, B)]])

G10_IRA.graph.add_uniq_edge(G10_IRB1.label, G10_IRB2.label)
G10_IRA.graph.add_uniq_edge(G10_IRB1.label, G10_IRB1.label)

G10_IRA.blocks = dict([(irb.label, irb) for irb in [G10_IRB1, G10_IRB2]])

# graph 11

G11_IRA = IRATest()

G11_IRB0 = gen_irblock(LBL0, [[ExprAff(A, CST1),
                               ExprAff(B, CST2)]])
G11_IRB1 = gen_irblock(LBL1, [[ExprAff(A, B),
                               ExprAff(B, A)]])
G11_IRB2 = gen_irblock(LBL2, [[ExprAff(A, A - B)]])

G11_IRA.graph.add_uniq_edge(G11_IRB0.label, G11_IRB1.label)
G11_IRA.graph.add_uniq_edge(G11_IRB1.label, G11_IRB2.label)

G11_IRA.blocks = dict([(irb.label, irb)
                       for irb in [G11_IRB0, G11_IRB1, G11_IRB2]])

# graph 12

G12_IRA = IRATest()

G12_IRB0 = gen_irblock(LBL0, [[ExprAff(B, CST1)]])
G12_IRB1 = gen_irblock(LBL1, [[ExprAff(A, B)], [ExprAff(B, B + CST2)]])
G12_IRB2 = gen_irblock(LBL2, [[ExprAff(B, A)]])

G12_IRA.graph.add_uniq_edge(G12_IRB0.label, G12_IRB1.label)
G12_IRA.graph.add_uniq_edge(G12_IRB1.label, G12_IRB2.label)
G12_IRA.graph.add_uniq_edge(G12_IRB1.label, G12_IRB1.label)

G12_IRA.blocks = dict([(irb.label, irb) for irb in [G12_IRB0, G12_IRB1,
                                                    G12_IRB2]])


# graph 13

G13_IRA = IRATest()

G13_IRB0 = gen_irblock(LBL0, [[ExprAff(A, CST1)],
                              #[ExprAff(B, A)],
                              [ExprAff(G13_IRA.IRDst,
                                       ExprId(LBL1))]])
G13_IRB1 = gen_irblock(LBL1, [[ExprAff(C, A)],
                              #[ExprAff(A, A + CST1)],
                              [ExprAff(G13_IRA.IRDst,
                                       ExprCond(R, ExprId(LBL2),
                                                ExprId(LBL1)))]])

G13_IRB2 = gen_irblock(LBL2, [[ExprAff(B, A + CST3)], [ExprAff(A, B + CST3)],
                              [ExprAff(G13_IRA.IRDst,
                                       ExprId(LBL1))]])

G13_IRB3 = gen_irblock(LBL3, [[ExprAff(R, C)]])

G13_IRA.graph.add_uniq_edge(G13_IRB0.label, G13_IRB1.label)
G13_IRA.graph.add_uniq_edge(G13_IRB1.label, G13_IRB2.label)
G13_IRA.graph.add_uniq_edge(G13_IRB2.label, G13_IRB1.label)
G13_IRA.graph.add_uniq_edge(G13_IRB1.label, G13_IRB3.label)

G13_IRA.blocks = dict([(irb.label, irb) for irb in [G13_IRB0, G13_IRB1,
                                                    G13_IRB2, G13_IRB3]])

# graph 14

G14_IRA = IRATest()

G14_IRB0 = gen_irblock(LBL0, [[ExprAff(A, CST1)],
                              [ExprAff(G14_IRA.IRDst,
                                       ExprId(LBL1))]
                             ])
G14_IRB1 = gen_irblock(LBL1, [[ExprAff(B, A)],
                              [ExprAff(G14_IRA.IRDst,
                                       ExprCond(C, ExprId(LBL2),
                                                ExprId(LBL3)))]
                             ])

G14_IRB2 = gen_irblock(LBL2, [[ExprAff(D, A)],
                              [ExprAff(A, D + CST1)],
                              [ExprAff(G14_IRA.IRDst,
                                       ExprId(LBL1))]
                             ])

G14_IRB3 = gen_irblock(LBL3, [[ExprAff(R, D + B)]])

G14_IRA.graph.add_uniq_edge(G14_IRB0.label, G14_IRB1.label)
G14_IRA.graph.add_uniq_edge(G14_IRB1.label, G14_IRB2.label)
G14_IRA.graph.add_uniq_edge(G14_IRB2.label, G14_IRB1.label)
G14_IRA.graph.add_uniq_edge(G14_IRB1.label, G14_IRB3.label)

G14_IRA.blocks = dict([(irb.label, irb) for irb in [G14_IRB0, G14_IRB1,
                                                    G14_IRB2, G14_IRB3]])

# graph 16

G15_IRA = IRATest()

G15_IRB0 = gen_irblock(LBL0, [[ExprAff(A, CST1)]])
G15_IRB1 = gen_irblock(LBL1, [[ExprAff(D, A + B)],
                              [ExprAff(C, D)],
                              [ExprAff(B, C)]])
G15_IRB2 = gen_irblock(LBL2, [[ExprAff(R, B)]])

G15_IRA.graph.add_uniq_edge(G15_IRB0.label, G15_IRB1.label)
G15_IRA.graph.add_uniq_edge(G15_IRB1.label, G15_IRB2.label)
G15_IRA.graph.add_uniq_edge(G15_IRB1.label, G15_IRB1.label)

G15_IRA.blocks = dict([(irb.label, irb) for irb in [G15_IRB0, G15_IRB1,
                                                    G15_IRB2]])

# graph 16

G16_IRA = IRATest()

G16_IRB0 = gen_irblock(LBL0, [[ExprAff(A, CST1)]])
G16_IRB1 = gen_irblock(LBL1, [[ExprAff(R, D)]])
G16_IRB2 = gen_irblock(LBL2, [[ExprAff(D, A)]])
G16_IRB3 = gen_irblock(LBL3, [[ExprAff(R, D)]])
G16_IRB4 = gen_irblock(LBL4, [[ExprAff(R, A)]])
G16_IRB5 = gen_irblock(LBL5, [[ExprAff(R, A)]])

G16_IRA.graph.add_uniq_edge(G16_IRB0.label, G16_IRB1.label)
G16_IRA.graph.add_uniq_edge(G16_IRB1.label, G16_IRB2.label)
G16_IRA.graph.add_uniq_edge(G16_IRB2.label, G16_IRB1.label)
G16_IRA.graph.add_uniq_edge(G16_IRB1.label, G16_IRB3.label)
G16_IRA.graph.add_uniq_edge(G16_IRB3.label, G16_IRB1.label)
G16_IRA.graph.add_uniq_edge(G16_IRB1.label, G16_IRB4.label)
G16_IRA.graph.add_uniq_edge(G16_IRB4.label, G16_IRB1.label)
G16_IRA.graph.add_uniq_edge(G16_IRB1.label, G16_IRB5.label)

G16_IRA.blocks = dict([(irb.label, irb) for irb in [G16_IRB0, G16_IRB1,
                                                    G16_IRB2, G16_IRB3,
                                                    G16_IRB4, G16_IRB5]])

# graph 17

G17_IRA = IRATest()

G17_IRB0 = gen_irblock(LBL0, [[ExprAff(A, CST1),
                               ExprAff(D, CST2)]])
G17_IRB1 = gen_irblock(LBL1, [[ExprAff(A, D),
                               ExprAff(B, D)]])
G17_IRB2 = gen_irblock(LBL2, [[ExprAff(A, A - B)]])

G17_IRA.graph.add_uniq_edge(G17_IRB0.label, G17_IRB1.label)
G17_IRA.graph.add_uniq_edge(G17_IRB1.label, G17_IRB2.label)

G17_IRA.blocks = dict([(irb.label, irb) for irb in [G17_IRB0, G17_IRB1,
                                                    G17_IRB2]])

# Test graph 1
G1_TEST1_DN1 = DependencyNode(
    G1_IRB2.label, A, len(G1_IRB2.irs))

G1_INPUT = (set([G1_TEST1_DN1]), set([G1_IRB0.label]))

# Test graph 2

G2_TEST1_DN1 = DependencyNode(
    G2_IRB2.label, A, len(G2_IRB2.irs))

G2_INPUT = (set([G2_TEST1_DN1]), set([G2_IRB0.label]))

# Test graph 3

G3_TEST1_0_DN1 = DependencyNode(
    G3_IRB3.label, A, len(G3_IRB3.irs))

G3_INPUT = (set([G3_TEST1_0_DN1]), set([G3_IRB0.label]))

# Test graph 4

G4_TEST1_DN1 = DependencyNode(
    G4_IRB2.label, A, len(G2_IRB0.irs))

G4_INPUT = (set([G4_TEST1_DN1]), set([G4_IRB0.label]))

# Test graph 5

G5_TEST1_0_DN1 = DependencyNode(
    G5_IRB2.label, A, len(G5_IRB2.irs))

G5_INPUT = (set([G5_TEST1_0_DN1]), set([G5_IRB0.label]))

# Test graph 6

G6_TEST1_0_DN1 = DependencyNode(
    G6_IRB1.label, A, len(G6_IRB1.irs))

G6_INPUT = (set([G6_TEST1_0_DN1]), set([G6_IRB0.label]))

# Test graph 7

G7_TEST1_0_DN1 = DependencyNode(
    G7_IRB2.label, D, len(G7_IRB2.irs))

G7_INPUT = (set([G7_TEST1_0_DN1]), set([G7_IRB0.label]))

# Test graph 8

G8_TEST1_0_DN1 = DependencyNode(
    G8_IRB2.label, A, len(G8_IRB2.irs))

G8_INPUT = (set([G8_TEST1_0_DN1]), set([G3_IRB0.label]))

# Test 9: Multi elements

G9_TEST1_0_DN1 = DependencyNode(
    G8_IRB2.label, A, len(G8_IRB2.irs))
G9_TEST1_0_DN5 = DependencyNode(
    G8_IRB2.label, C, len(G8_IRB2.irs))

G9_INPUT = (set([G9_TEST1_0_DN1, G9_TEST1_0_DN5]), set([G8_IRB0.label]))

# Test 10: loop at beginning

G10_TEST1_0_DN1 = DependencyNode(
    G10_IRB2.label, A, len(G10_IRB2.irs))

G10_INPUT = (set([G10_TEST1_0_DN1]), set([G10_IRB1.label]))


# Test 11: no dual bloc emulation

G11_TEST1_DN1 = DependencyNode(
    G11_IRB2.label, A, len(G11_IRB2.irs))

G11_INPUT = (set([G11_TEST1_DN1]), set([G11_IRB0.label]))

# Test graph 12

G12_TEST1_0_DN1 = DependencyNode(G12_IRB2.label, B, 1)

G12_INPUT = (set([G12_TEST1_0_DN1]), set([]))

# Test graph 13:

# All filters

G13_TEST1_0_DN4 = DependencyNode(G13_IRB3.label, R, 1)

G13_INPUT = (set([G13_TEST1_0_DN4]), set([]))

# Test graph 14

# All filters

G14_TEST1_0_DN1 = DependencyNode(G14_IRB3.label, R, 1)

G14_INPUT = (set([G14_TEST1_0_DN1]), set([]))

# Test graph 15

G15_TEST1_0_DN1 = DependencyNode(G15_IRB2.label, R, 1)

G15_INPUT = (set([G15_TEST1_0_DN1]), set([]))

# Test graph 16
G16_TEST1_0_DN1 = DependencyNode(G16_IRB5.label, R, 1)

G16_INPUT = (set([G16_TEST1_0_DN1]), set([]))

# Test graph 17

G17_TEST1_DN1 = DependencyNode(G17_IRB2.label, A, 1)

G17_INPUT = (set([G17_TEST1_DN1]), set([]))


FAILED = set()


def flatNode(node):
    if isinstance(node, DependencyNode):
        if isinstance(node.element, ExprId):
            element = node.element.name
        elif isinstance(node.element, ExprInt):
            element = int(node.element.arg)
        else:
            RuntimeError("Unsupported type '%s'" % type(enode.element))
        return (node.label.name,
                element,
                node.line_nb)
    else:
        return str(node)


def flatGraph(graph):
    out_nodes, out_edges = set(), set()
    for node in graph.nodes():
        out_nodes.add(flatNode(node))
    for nodeA, nodeB in graph.edges():
        out_edges.add((flatNode(nodeA), flatNode(nodeB)))
    out = (tuple(sorted(list(out_nodes))),
           tuple(sorted(list(out_edges))))
    return out


def unflatGraph(flat_graph):
    graph = DiGraph()
    nodes, edges = flat_graph
    for node in nodes:
        graph.add_node(node)
    for nodeA, nodeB in edges:
        graph.add_edge(nodeA, nodeB)
    return graph


def get_node_noidx(node):
    if isinstance(node, tuple):
        return (node[0], node[1], node[2])
    else:
        return node


def test_result(graphA, graphB, leaves):
    """
    Test graph equality without using node index
    """

    todo = set((leaf, leaf) for leaf in leaves)
    done = set()
    while todo:
        nodeA, nodeB = todo.pop()
        if (nodeA, nodeB) in done:
            continue
        done.add((nodeA, nodeB))

        if get_node_noidx(nodeA) != get_node_noidx(nodeB):
            return False
        if nodeA not in graphA.nodes():
            return False
        if nodeB not in graphB.nodes():
            return False

        parentsA = graphA.predecessors(nodeA)
        parentsB = graphB.predecessors(nodeB)
        if len(parentsA) != len(parentsB):
            return False

        parentsA_noidx, parentsB_noidx = {}, {}
        for parents, parents_noidx in ((parentsA, parentsA_noidx),
                                       (parentsB, parentsB_noidx)):
            for node in parents:
                node_noidx = get_node_noidx(node)
                assert(node_noidx not in parents_noidx)
                parents_noidx[node_noidx] = node

        if set(parentsA_noidx.keys()) != set(parentsB_noidx.keys()):
            return False

        for node_noidx, nodeA in parentsA_noidx.iteritems():
            nodeB = parentsB_noidx[node_noidx]
            todo.add((nodeA, nodeB))

    return True


def match_results(resultsA, resultsB, nodes):
    """
    Match computed list of graph against test cases
    """
    out = []

    if len(resultsA) != len(resultsB):
        return False

    for resultA in resultsA:
        nodes = resultA.leaves()
        for resultB in resultsB:
            if test_result(resultA, resultB, nodes):
                out.append((resultA, resultB))
    return len(out) == len(resultsB)


def get_flat_init_depnodes(depnodes):
    out = []
    for node in depnodes:
        out.append((node.label.name,
                    node.element.name,
                    node.line_nb,
                    0))
    return out

# TESTS
flat_test_results = [[((('lbl0', 1, 0), ('lbl0', 'c', 0), ('lbl1', 'b', 0), ('lbl2', 'a', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'c', 0)),
                        (('lbl0', 'c', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0))))],
                     [((('lbl0', 1, 0),
                        ('lbl0', 'c', 0),
                        ('lbl1', 2, 0),
                        ('lbl1', 'b', 0),
                        ('lbl2', 'a', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'c', 0)),
                        (('lbl0', 'c', 0), ('lbl2', 'a', 0)),
                        (('lbl1', 2, 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0))))],
                     [((('lbl0', 1, 0),
                        ('lbl0', 'c', 0),
                        ('lbl1', 2, 0),
                        ('lbl1', 'b', 0),
                        ('lbl3', 'a', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'c', 0)),
                        (('lbl0', 'c', 0), ('lbl3', 'a', 0)),
                        (('lbl1', 2, 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl3', 'a', 0)))),
                      ((('lbl0', 1, 0),
                        ('lbl0', 'c', 0),
                        ('lbl2', 3, 0),
                        ('lbl2', 'b', 0),
                        ('lbl3', 'a', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'c', 0)),
                        (('lbl0', 'c', 0), ('lbl3', 'a', 0)),
                        (('lbl2', 3, 0), ('lbl2', 'b', 0)),
                        (('lbl2', 'b', 0), ('lbl3', 'a', 0))))],
                     [(('b', ('lbl2', 'a', 0)), (('b', ('lbl2', 'a', 0)),))],
                     [((('lbl0', 1, 0),
                        ('lbl0', 'b', 0),
                        ('lbl1', 2, 0),
                        ('lbl1', 'b', 0),
                        ('lbl2', 'a', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'b', 0)),
                        (('lbl0', 'b', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 2, 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0)))),
                      ((('lbl0', 1, 0),
                        ('lbl0', 'b', 0),
                        ('lbl1', 2, 0),
                        ('lbl1', 'b', 0),
                        ('lbl2', 'a', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'b', 0)),
                        (('lbl0', 'b', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 2, 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0))))],
                     [((('lbl0', 1, 0), ('lbl0', 'b', 0), ('lbl1', 'a', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'b', 0)),
                        (('lbl0', 'b', 0), ('lbl1', 'a', 0))))],
                     [((('lbl0', 1, 0),
                        ('lbl0', 'c', 0),
                        ('lbl1', 'a', 1),
                        ('lbl1', 'b', 0),
                        ('lbl2', 'd', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'c', 0)),
                        (('lbl0', 'c', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'a', 1), ('lbl2', 'd', 0)),
                        (('lbl1', 'b', 0), ('lbl1', 'a', 1))))],
                     [(('d', ('lbl1', 'b', 0), ('lbl1', 'c', 1), ('lbl2', 'a', 0)),
                       (('d', ('lbl1', 'c', 1)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0)),
                        (('lbl1', 'c', 1), ('lbl1', 'b', 0)))),
                      ((('lbl0', 1, 0), ('lbl0', 'c', 0), ('lbl1', 'b', 0), ('lbl2', 'a', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'c', 0)),
                        (('lbl0', 'c', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0))))],
                     [(('d',
                        ('lbl0', 1, 0),
                        ('lbl0', 'c', 0),
                        ('lbl1', 'b', 0),
                        ('lbl1', 'c', 1),
                        ('lbl2', 'a', 0)),
                       (('d', ('lbl1', 'c', 1)),
                        (('lbl0', 1, 0), ('lbl0', 'c', 0)),
                        (('lbl0', 'c', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0)))),
                      (('d', ('lbl1', 'b', 0), ('lbl1', 'c', 1), ('lbl2', 'a', 0)),
                       (('d', ('lbl1', 'c', 1)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0)),
                        (('lbl1', 'c', 1), ('lbl1', 'b', 0))))],
                     [(('b', ('lbl1', 2, 0), ('lbl1', 'b', 0), ('lbl2', 'a', 0)),
                       (('b', ('lbl1', 'b', 0)),
                        (('lbl1', 2, 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0)))),
                      (('b', ('lbl1', 2, 0), ('lbl1', 'b', 0), ('lbl2', 'a', 0)),
                       (('b', ('lbl1', 'b', 0)),
                        (('lbl1', 2, 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0))))],
                     [((('lbl0', 1, 0),
                        ('lbl0', 2, 0),
                        ('lbl0', 'a', 0),
                        ('lbl0', 'b', 0),
                        ('lbl1', 'a', 0),
                        ('lbl1', 'b', 0),
                        ('lbl2', 'a', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 2, 0), ('lbl0', 'b', 0)),
                        (('lbl0', 'a', 0), ('lbl1', 'b', 0)),
                        (('lbl0', 'b', 0), ('lbl1', 'a', 0)),
                        (('lbl1', 'a', 0), ('lbl2', 'a', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0))))],
                     [((('lbl0', 1, 0),
                        ('lbl0', 'b', 0),
                        ('lbl1', 2, 1),
                        ('lbl1', 'a', 0),
                        ('lbl1', 'b', 1),
                        ('lbl2', 'b', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'b', 0)),
                        (('lbl0', 'b', 0), ('lbl1', 'b', 1)),
                        (('lbl1', 2, 1), ('lbl1', 'b', 1)),
                        (('lbl1', 'a', 0), ('lbl2', 'b', 0)),
                        (('lbl1', 'b', 1), ('lbl1', 'a', 0)))),
                      ((('lbl0', 1, 0),
                        ('lbl0', 'b', 0),
                        ('lbl1', 2, 1),
                        ('lbl1', 'a', 0),
                        ('lbl1', 'b', 1),
                        ('lbl2', 'b', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'b', 0)),
                        (('lbl0', 'b', 0), ('lbl1', 'b', 1)),
                        (('lbl1', 2, 1), ('lbl1', 'b', 1)),
                        (('lbl1', 'a', 0), ('lbl2', 'b', 0)),
                        (('lbl1', 'b', 1), ('lbl1', 'a', 0)),
                        (('lbl1', 'b', 1), ('lbl1', 'b', 1)))),
                      ((('lbl0', 1, 0), ('lbl0', 'b', 0), ('lbl1', 'a', 0), ('lbl2', 'b', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'b', 0)),
                        (('lbl0', 'b', 0), ('lbl1', 'a', 0)),
                        (('lbl1', 'a', 0), ('lbl2', 'b', 0))))],
                     [((('lbl0', 1, 0),
                        ('lbl0', 'a', 0),
                        ('lbl1', 'c', 0),
                        ('lbl2', 3, 0),
                        ('lbl2', 3, 1),
                        ('lbl2', 'a', 1),
                        ('lbl2', 'b', 0),
                        ('lbl3', 'r', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 'a', 0), ('lbl2', 'b', 0)),
                        (('lbl1', 'c', 0), ('lbl3', 'r', 0)),
                        (('lbl2', 3, 0), ('lbl2', 'b', 0)),
                        (('lbl2', 3, 1), ('lbl2', 'a', 1)),
                        (('lbl2', 'a', 1), ('lbl1', 'c', 0)),
                        (('lbl2', 'a', 1), ('lbl2', 'b', 0)),
                        (('lbl2', 'b', 0), ('lbl2', 'a', 1)))),
                      ((('lbl0', 1, 0),
                        ('lbl0', 'a', 0),
                        ('lbl1', 'c', 0),
                        ('lbl2', 3, 0),
                        ('lbl2', 3, 1),
                        ('lbl2', 'a', 1),
                        ('lbl2', 'b', 0),
                        ('lbl3', 'r', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 'a', 0), ('lbl2', 'b', 0)),
                        (('lbl1', 'c', 0), ('lbl3', 'r', 0)),
                        (('lbl2', 3, 0), ('lbl2', 'b', 0)),
                        (('lbl2', 3, 1), ('lbl2', 'a', 1)),
                        (('lbl2', 'a', 1), ('lbl1', 'c', 0)),
                        (('lbl2', 'b', 0), ('lbl2', 'a', 1)))),
                      ((('lbl0', 1, 0), ('lbl0', 'a', 0), ('lbl1', 'c', 0), ('lbl3', 'r', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 'a', 0), ('lbl1', 'c', 0)),
                        (('lbl1', 'c', 0), ('lbl3', 'r', 0))))],
                     [(('d',
                        ('lbl0', 1, 0),
                        ('lbl0', 'a', 0),
                        ('lbl1', 'b', 0),
                        ('lbl3', 'r', 0)),
                       (('d', ('lbl3', 'r', 0)),
                        (('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 'a', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'b', 0), ('lbl3', 'r', 0)))),
                      ((('lbl0', 1, 0),
                        ('lbl0', 'a', 0),
                        ('lbl1', 'b', 0),
                        ('lbl2', 1, 1),
                        ('lbl2', 'a', 1),
                        ('lbl2', 'd', 0),
                        ('lbl3', 'r', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 'a', 0), ('lbl2', 'd', 0)),
                        (('lbl1', 'b', 0), ('lbl3', 'r', 0)),
                        (('lbl2', 1, 1), ('lbl2', 'a', 1)),
                        (('lbl2', 'a', 1), ('lbl1', 'b', 0)),
                        (('lbl2', 'a', 1), ('lbl2', 'd', 0)),
                        (('lbl2', 'd', 0), ('lbl2', 'a', 1)),
                        (('lbl2', 'd', 0), ('lbl3', 'r', 0)))),
                      ((('lbl0', 1, 0),
                        ('lbl0', 'a', 0),
                        ('lbl1', 'b', 0),
                        ('lbl2', 1, 1),
                        ('lbl2', 'a', 1),
                        ('lbl2', 'd', 0),
                        ('lbl3', 'r', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 'a', 0), ('lbl2', 'd', 0)),
                        (('lbl1', 'b', 0), ('lbl3', 'r', 0)),
                        (('lbl2', 1, 1), ('lbl2', 'a', 1)),
                        (('lbl2', 'a', 1), ('lbl1', 'b', 0)),
                        (('lbl2', 'd', 0), ('lbl2', 'a', 1)),
                        (('lbl2', 'd', 0), ('lbl3', 'r', 0))))],
                     [(('b',
                        ('lbl0', 1, 0),
                        ('lbl0', 'a', 0),
                        ('lbl1', 'b', 2),
                        ('lbl1', 'c', 1),
                        ('lbl1', 'd', 0),
                        ('lbl2', 'r', 0)),
                       (('b', ('lbl1', 'd', 0)),
                        (('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 'a', 0), ('lbl1', 'd', 0)),
                        (('lbl1', 'b', 2), ('lbl1', 'd', 0)),
                        (('lbl1', 'b', 2), ('lbl2', 'r', 0)),
                        (('lbl1', 'c', 1), ('lbl1', 'b', 2)),
                        (('lbl1', 'd', 0), ('lbl1', 'c', 1)))),
                      (('b',
                        ('lbl0', 1, 0),
                        ('lbl0', 'a', 0),
                        ('lbl1', 'b', 2),
                        ('lbl1', 'c', 1),
                        ('lbl1', 'd', 0),
                        ('lbl2', 'r', 0)),
                       (('b', ('lbl1', 'd', 0)),
                        (('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 'a', 0), ('lbl1', 'd', 0)),
                        (('lbl1', 'b', 2), ('lbl2', 'r', 0)),
                        (('lbl1', 'c', 1), ('lbl1', 'b', 2)),
                        (('lbl1', 'd', 0), ('lbl1', 'c', 1))))],
                     [((('lbl0', 1, 0), ('lbl0', 'a', 0), ('lbl5', 'r', 0)),
                       ((('lbl0', 1, 0), ('lbl0', 'a', 0)),
                        (('lbl0', 'a', 0), ('lbl5', 'r', 0))))],
                     [((('lbl0', 2, 0),
                        ('lbl0', 'd', 0),
                        ('lbl1', 'a', 0),
                        ('lbl1', 'b', 0),
                        ('lbl2', 'a', 0)),
                       ((('lbl0', 2, 0), ('lbl0', 'd', 0)),
                        (('lbl0', 'd', 0), ('lbl1', 'a', 0)),
                        (('lbl0', 'd', 0), ('lbl1', 'b', 0)),
                        (('lbl1', 'a', 0), ('lbl2', 'a', 0)),
                        (('lbl1', 'b', 0), ('lbl2', 'a', 0))))]]

test_results = [[unflatGraph(flat_result) for flat_result in flat_results]
                for flat_results in flat_test_results]

all_flats = []
# Launch tests
for test_nb, test in enumerate([(G1_IRA, G1_INPUT),
                                (G2_IRA, G2_INPUT),
                                (G3_IRA, G3_INPUT),
                                (G4_IRA, G4_INPUT),
                                (G5_IRA, G5_INPUT),
                                (G6_IRA, G6_INPUT),
                                (G7_IRA, G7_INPUT),
                                (G8_IRA, G8_INPUT),
                                (G8_IRA, G9_INPUT),
                                (G10_IRA, G10_INPUT),
                                (G11_IRA, G11_INPUT),
                                (G12_IRA, G12_INPUT),
                                (G13_IRA, G13_INPUT),
                                (G14_IRA, G14_INPUT),
                                (G15_IRA, G15_INPUT),
                                (G16_IRA, G16_INPUT),
                                (G17_IRA, G17_INPUT),
                                ]):

    # Extract test elements
    print "[+] Test", test_nb + 1
    g_ira, (depnodes, heads) = test

    open("graph_%02d.dot" % (test_nb + 1), "w").write(g_ira.graph.dot())
    open("graph_%02d.dot" % (test_nb + 1), "w").write(bloc2graph(g_ira))

    # Different options
    suffix_key_list = ["", "_nosimp", "_nomem", "_nocall",
                       "_implicit"]
    # Test classes
    for g_ind, g_dep in enumerate([DependencyGraph(g_ira),
                                   DependencyGraph(g_ira, apply_simp=False),
                                   DependencyGraph(g_ira, follow_mem=False),
                                   DependencyGraph(g_ira, follow_mem=False,
                                                   follow_call=False),
                                   # DependencyGraph(g_ira, implicit=True),
                                   ]):
        # if g_ind == 4:
        # TODO: Implicit specifications
        #    continue
        print " - Class %s - %s" % (g_dep.__class__.__name__,
                                    suffix_key_list[g_ind])
        # Select the correct result key
        mode_suffix = suffix_key_list[g_ind]
        graph_test_key = "graph" + mode_suffix

        # Test public APIs
        results = g_dep.get_from_depnodes(depnodes, heads)
        print "RESULTS"
        all_results = set()
        all_flat = set()
        for i, result in enumerate(results):
            all_flat.add(flatGraph(result.graph))
            all_results.add(unflatGraph(flatGraph(result.graph)))
            open("graph_test_%02d_%02d.dot" % (test_nb + 1, i),
                 "w").write(dg2graph(result.graph))
        # print all_flat
        if g_ind == 0:
            all_flat = sorted(all_flat)
            all_flats.append(all_flat)
        flat_depnodes = get_flat_init_depnodes(depnodes)
        if not match_results(all_results, test_results[test_nb], flat_depnodes):
            FAILED.add(test_nb)
            # fds
        continue

if FAILED:
    print "FAILED :", len(FAILED)
    for test_num in sorted(FAILED):
        print test_num,
else:
    print "SUCCESS"

# Return an error status on error
assert not FAILED
