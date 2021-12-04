"""Regression test module for DependencyGraph"""
from __future__ import print_function

from future.utils import viewitems

from miasm.expression.expression import ExprId, ExprInt, ExprAssign, \
    ExprCond, ExprLoc, LocKey
from miasm.core.locationdb import LocationDB
from miasm.ir.analysis import LifterModelCall
from miasm.ir.ir import IRBlock, AssignBlock
from miasm.core.graph import DiGraph
from miasm.analysis.depgraph import DependencyNode, DependencyGraph
from itertools import count
from pdb import pm
import re

loc_db = LocationDB()

EMULATION = True
try:
    import z3
except ImportError:
    EMULATION = False

STEP_COUNTER = count()
A = ExprId("a", 32)
B = ExprId("b", 32)
C = ExprId("c", 32)
D = ExprId("d", 32)
R = ExprId("r", 32)
COND = ExprId("cond", 32)

A_INIT = ExprId("a_init", 32)
B_INIT = ExprId("b_init", 32)
C_INIT = ExprId("c_init", 32)
D_INIT = ExprId("d_init", 32)

PC = ExprId("pc", 32)
SP = ExprId("sp", 32)

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

LBL0 = loc_db.add_location("lbl0", 0)
LBL1 = loc_db.add_location("lbl1", 1)
LBL2 = loc_db.add_location("lbl2", 2)
LBL3 = loc_db.add_location("lbl3", 3)
LBL4 = loc_db.add_location("lbl4", 4)
LBL5 = loc_db.add_location("lbl5", 5)
LBL6 = loc_db.add_location("lbl6", 6)

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

    irbl = IRBlock(loc_db, label, irs)
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


class IRATest(LifterModelCall):

    """Fake IRA class for tests"""

    def __init__(self, loc_db):
        arch = Arch()
        super(IRATest, self).__init__(arch, 32, loc_db)
        self.IRDst = ExprId("IRDst", 32)
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
    for label in irgraph.nodes():
        assert isinstance(label, LocKey)
        label_names = irgraph.loc_db.get_location_names(label)
        label_name = list(label_names)[0]

        if hasattr(irgraph, 'blocks'):
            irblock = irgraph.blocks[label]
        else:
            irblock = None
        if isinstance(label, LocKey):
            out_block = '%s [\n' % label_name
        else:
            out_block = '%s [\n' % label
        out_block += "%s " % block_attr
        out_block += 'label =<<table border="0" cellborder="0" cellpadding="3">'

        block_label = '<tr><td %s>%s</td></tr>' % (
            label_attr, label_name)
        block_html_lines = []
        if lines and irblock is not None:
            for assignblk in irblock:
                for dst, src in viewitems(assignblk):
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
    for src, dst in irgraph.edges():
        assert isinstance(src, LocKey)
        src_names = irgraph.loc_db.get_location_names(src)
        assert isinstance(dst, LocKey)
        dst_names = irgraph.loc_db.get_location_names(dst)

        src_name = list(src_names)[0]
        dst_name = list(dst_names)[0]

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
    for node in graph.nodes():
        if isinstance(node, DependencyNode):
            name = loc_db.pretty_str(node.loc_key)
            node_name = "%s %s %s" % (name,
                                       node.element,
                                       node.line_nb)
        else:
            node_name = str(node)
        out_block = '%s [\n' % hash(node)
        out_block += "%s " % block_attr
        out_block += 'label =<<table border="0" cellborder="0" cellpadding="3">'

        block_label = '<tr><td %s>%s</td></tr>' % (
            label_attr, node_name)
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


print("   [+] Test dictionary equality")
DNA = DependencyNode(LBL2, A, 0)
DNB = DependencyNode(LBL1, B, 1)
DNC = DependencyNode(LBL1, C, 0)
DNB2 = DependencyNode(LBL1, B, 1)
DNC2 = DependencyNode(LBL1, C, 0)
DNB3 = DependencyNode(LBL1, B, 1)
DNC3 = DependencyNode(LBL1, C, 0)

IRA = IRATest(loc_db)
IRDst = IRA.IRDst
END = ExprId("END", IRDst.size)
# graph 1

G1_IRA = IRA.new_ircfg()

G1_IRB0 = gen_irblock(LBL0, [[ExprAssign(C, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G1_IRB1 = gen_irblock(LBL1, [[ExprAssign(B, C), ExprAssign(IRDst, ExprLoc(LBL2, 32))]])
G1_IRB2 = gen_irblock(LBL2, [[ExprAssign(A, B), ExprAssign(IRDst, END)]])

for irb in [G1_IRB0, G1_IRB1, G1_IRB2]:
    G1_IRA.add_irblock(irb)

# graph 2

G2_IRA = IRA.new_ircfg()

G2_IRB0 = gen_irblock(LBL0, [[ExprAssign(C, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G2_IRB1 = gen_irblock(LBL1, [[ExprAssign(B, CST2), ExprAssign(IRDst, ExprLoc(LBL2, 32))]])
G2_IRB2 = gen_irblock(LBL2, [[ExprAssign(A, B + C), ExprAssign(IRDst, END)]])

for irb in [G2_IRB0, G2_IRB1, G2_IRB2]:
    G2_IRA.add_irblock(irb)


# graph 3

G3_IRA = IRA.new_ircfg()

G3_IRB0 = gen_irblock(
    LBL0,
    [
        [ExprAssign(C, CST1), ExprAssign(
            IRDst, ExprCond(
                COND,
                ExprLoc(LBL1, 32),
                ExprLoc(LBL2, 32)
            )
        )
        ]
    ]
)

G3_IRB1 = gen_irblock(LBL1, [[ExprAssign(B, CST2), ExprAssign(IRDst, ExprLoc(LBL3, 32))]])
G3_IRB2 = gen_irblock(LBL2, [[ExprAssign(B, CST3), ExprAssign(IRDst, ExprLoc(LBL3, 32))]])
G3_IRB3 = gen_irblock(LBL3, [[ExprAssign(A, B + C), ExprAssign(IRDst, END)]])

for irb in [G3_IRB0, G3_IRB1, G3_IRB2, G3_IRB3]:
    G3_IRA.add_irblock(irb)

# graph 4

G4_IRA = IRA.new_ircfg()

G4_IRB0 = gen_irblock(LBL0, [[ExprAssign(C, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G4_IRB1 = gen_irblock(
    LBL1,
    [
        [ExprAssign(C, C + CST2)],
        [ExprAssign(IRDst,
                 ExprCond(
                     C,
                     ExprLoc(LBL2, 32),
                     ExprLoc(LBL1, 32))
        )
        ]]
)

G4_IRB2 = gen_irblock(LBL2, [[ExprAssign(A, B), ExprAssign(IRDst, END)]])

for irb in [G4_IRB0, G4_IRB1, G4_IRB2]:
    G4_IRA.add_irblock(irb)


# graph 5

G5_IRA = IRA.new_ircfg()

G5_IRB0 = gen_irblock(LBL0, [[ExprAssign(B, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G5_IRB1 = gen_irblock(
    LBL1,
    [
        [ExprAssign(B, B + CST2)],
        [ExprAssign(
            IRDst,
            ExprCond(
                B,
                ExprLoc(LBL2, 32),
                ExprLoc(LBL1, 32)
            )
        )
        ]
    ]
)

G5_IRB2 = gen_irblock(LBL2, [[ExprAssign(A, B), ExprAssign(IRDst, END)]])

for irb in [G5_IRB0, G5_IRB1, G5_IRB2]:
    G5_IRA.add_irblock(irb)

# graph 6

G6_IRA = IRA.new_ircfg()

G6_IRB0 = gen_irblock(LBL0, [[ExprAssign(B, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G6_IRB1 = gen_irblock(LBL1, [[ExprAssign(A, B), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])

for irb in [G6_IRB0, G6_IRB1]:
    G6_IRA.add_irblock(irb)

# graph 7

G7_IRA = IRA.new_ircfg()

G7_IRB0 = gen_irblock(LBL0, [[ExprAssign(C, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G7_IRB1 = gen_irblock(
    LBL1,
    [
        [ExprAssign(B, C)],
        [ExprAssign(A, B)],
        [ExprAssign(
            IRDst,
            ExprCond(
                COND,
                ExprLoc(LBL1, 32),
                ExprLoc(LBL2, 32)
            )
        )
        ]
    ]
)

G7_IRB2 = gen_irblock(LBL2, [[ExprAssign(D, A), ExprAssign(IRDst, END)]])

for irb in [G7_IRB0, G7_IRB1, G7_IRB2]:
    G7_IRA.add_irblock(irb)

# graph 8

G8_IRA = IRA.new_ircfg()

G8_IRB0 = gen_irblock(LBL0, [[ExprAssign(C, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G8_IRB1 = gen_irblock(
    LBL1,
    [
        [ExprAssign(B, C)],
        [ExprAssign(C, D),
         ExprAssign(
             IRDst,
             ExprCond(
                 COND,
                 ExprLoc(LBL1, 32),
                 ExprLoc(LBL2, 32)
             )
         )
        ]
    ]
)
G8_IRB2 = gen_irblock(LBL2, [[ExprAssign(A, B), ExprAssign(IRDst, END)]])

for irb in [G8_IRB0, G8_IRB1, G8_IRB2]:
    G8_IRA.add_irblock(irb)

# graph 9 is graph 8

# graph 10

G10_IRA = IRA.new_ircfg()

G10_IRB1 = gen_irblock(
    LBL1,
    [
        [ExprAssign(B, B + CST2),
         ExprAssign(
             IRDst,
             ExprCond(
                 COND,
                 ExprLoc(LBL1, 32),
                 ExprLoc(LBL2, 32)
             )
         )
        ]
    ]
)

G10_IRB2 = gen_irblock(LBL2, [[ExprAssign(A, B), ExprAssign(IRDst, END)]])

for irb in [G10_IRB1, G10_IRB2]:
    G10_IRA.add_irblock(irb)

# graph 11

G11_IRA = IRA.new_ircfg()

G11_IRB0 = gen_irblock(
    LBL0,
    [
        [ExprAssign(A, CST1),
         ExprAssign(B, CST2),
         ExprAssign(IRDst, ExprLoc(LBL1, 32))
        ]
    ]
)

G11_IRB1 = gen_irblock(
    LBL1,
    [
        [ExprAssign(A, B),
         ExprAssign(B, A),
         ExprAssign(IRDst, ExprLoc(LBL2, 32))
        ]
    ]
)

G11_IRB2 = gen_irblock(LBL2, [[ExprAssign(A, A - B), ExprAssign(IRDst, END)]])

for irb in [G11_IRB0, G11_IRB1, G11_IRB2]:
    G11_IRA.add_irblock(irb)

# graph 12

G12_IRA = IRA.new_ircfg()

G12_IRB0 = gen_irblock(LBL0, [[ExprAssign(B, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G12_IRB1 = gen_irblock(
    LBL1,
    [
        [ExprAssign(A, B)],
        [ExprAssign(B, B + CST2),
         ExprAssign(
             IRDst,
             ExprCond(
                 COND,
                 ExprLoc(LBL1, 32),
                 ExprLoc(LBL2, 32)
             )
         )
        ]
    ]
)

G12_IRB2 = gen_irblock(LBL2, [[ExprAssign(B, A), ExprAssign(IRDst, END)]])

for irb in [G12_IRB0, G12_IRB1, G12_IRB2]:
    G12_IRA.add_irblock(irb)


# graph 13

G13_IRA = IRA.new_ircfg()

G13_IRB0 = gen_irblock(LBL0, [[ExprAssign(A, CST1)],
                              #[ExprAssign(B, A)],
                              [ExprAssign(IRDst,
                                       ExprLoc(LBL1, 32))]])
G13_IRB1 = gen_irblock(LBL1, [[ExprAssign(C, A)],
                              #[ExprAssign(A, A + CST1)],
                              [ExprAssign(IRDst,
                                       ExprCond(
                                           R,
                                           ExprLoc(LBL2, 32),
                                           ExprLoc(LBL3, 32)
                                       )
                              )]])

G13_IRB2 = gen_irblock(LBL2, [[ExprAssign(B, A + CST3)], [ExprAssign(A, B + CST3)],
                              [ExprAssign(IRDst,
                                       ExprLoc(LBL1, 32))]])

G13_IRB3 = gen_irblock(LBL3, [[ExprAssign(R, C), ExprAssign(IRDst, END)]])

for irb in [G13_IRB0, G13_IRB1, G13_IRB2, G13_IRB3]:
    G13_IRA.add_irblock(irb)

# graph 14

G14_IRA = IRA.new_ircfg()

G14_IRB0 = gen_irblock(LBL0, [[ExprAssign(A, CST1)],
                              [ExprAssign(IRDst,
                                       ExprLoc(LBL1, 32))]
                             ])
G14_IRB1 = gen_irblock(LBL1, [[ExprAssign(B, A)],
                              [ExprAssign(IRDst,
                                       ExprCond(
                                           C,
                                           ExprLoc(LBL2, 32),
                                           ExprLoc(LBL3, 32)
                                       )
                              )
                              ]
                             ])

G14_IRB2 = gen_irblock(LBL2, [[ExprAssign(D, A)],
                              [ExprAssign(A, D + CST1)],
                              [ExprAssign(IRDst,
                                       ExprLoc(LBL1, 32))]
                             ])

G14_IRB3 = gen_irblock(LBL3, [[ExprAssign(R, D + B), ExprAssign(IRDst, END)]])

for irb in [G14_IRB0, G14_IRB1, G14_IRB2, G14_IRB3]:
    G14_IRA.add_irblock(irb)

# graph 16

G15_IRA = IRA.new_ircfg()

G15_IRB0 = gen_irblock(LBL0, [[ExprAssign(A, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G15_IRB1 = gen_irblock(LBL1, [[ExprAssign(D, A + B)],
                              [ExprAssign(C, D)],
                              [ExprAssign(B, C),
                               ExprAssign(IRDst,
                                       ExprCond(
                                           C,
                                           ExprLoc(LBL1, 32),
                                           ExprLoc(LBL2, 32)
                                       )
                               )]])
G15_IRB2 = gen_irblock(LBL2, [[ExprAssign(R, B), ExprAssign(IRDst, END)]])

for irb in [G15_IRB0, G15_IRB1, G15_IRB2]:
    G15_IRA.add_irblock(irb)

# graph 16

G16_IRA = IRA.new_ircfg()

G16_IRB0 = gen_irblock(
    LBL0, [
        [ExprAssign(A, CST1), ExprAssign(IRDst, ExprLoc(LBL1, 32))]
    ]
)

G16_IRB1 = gen_irblock(
    LBL1,
    [
        [ExprAssign(R, D),
         ExprAssign(
             IRDst,
             ExprCond(
                 C,
                 ExprCond(
                     C,
                     ExprCond(
                         C,
                         ExprLoc(LBL2, 32),
                         ExprLoc(LBL3, 32)
                     ),
                     ExprLoc(LBL4, 32)
                 ),
                 ExprLoc(LBL5, 32)
             )
         )
        ]
    ]
)



G16_IRB2 = gen_irblock(LBL2, [[ExprAssign(D, A), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G16_IRB3 = gen_irblock(LBL3, [[ExprAssign(R, D), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G16_IRB4 = gen_irblock(LBL4, [[ExprAssign(R, A), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G16_IRB5 = gen_irblock(LBL5, [[ExprAssign(R, A), ExprAssign(IRDst, ExprLoc(LBL1, 32))]])

for irb in [G16_IRB0, G16_IRB1, G16_IRB2, G16_IRB3, G16_IRB4, G16_IRB5]:
    G16_IRA.add_irblock(irb)

# graph 17

G17_IRA = IRA.new_ircfg()

G17_IRB0 = gen_irblock(LBL0, [[ExprAssign(A, CST1),
                               ExprAssign(D, CST2),
                               ExprAssign(IRDst, ExprLoc(LBL1, 32))]])
G17_IRB1 = gen_irblock(LBL1, [[ExprAssign(A, D),
                               ExprAssign(B, D),
                               ExprAssign(IRDst, ExprLoc(LBL2, 32))]])
G17_IRB2 = gen_irblock(LBL2, [[ExprAssign(A, A - B),
                               ExprAssign(IRDst, END)]])

G17_IRA.add_uniq_edge(G17_IRB0.loc_key, G17_IRB1.loc_key)
G17_IRA.add_uniq_edge(G17_IRB1.loc_key, G17_IRB2.loc_key)

for irb in [G17_IRB0, G17_IRB1, G17_IRB2]:
    G17_IRA.add_irblock(irb)

# Test graph 1
G1_TEST1_DN1 = DependencyNode(
    G1_IRB2.loc_key, A, len(G1_IRB2))

G1_INPUT = (set([G1_TEST1_DN1]), set([G1_IRB0.loc_key]))

# Test graph 2

G2_TEST1_DN1 = DependencyNode(
    G2_IRB2.loc_key, A, len(G2_IRB2))

G2_INPUT = (set([G2_TEST1_DN1]), set([G2_IRB0.loc_key]))

# Test graph 3

G3_TEST1_0_DN1 = DependencyNode(
    G3_IRB3.loc_key, A, len(G3_IRB3))

G3_INPUT = (set([G3_TEST1_0_DN1]), set([G3_IRB0.loc_key]))

# Test graph 4

G4_TEST1_DN1 = DependencyNode(
    G4_IRB2.loc_key, A, len(G2_IRB0))

G4_INPUT = (set([G4_TEST1_DN1]), set([G4_IRB0.loc_key]))

# Test graph 5

G5_TEST1_0_DN1 = DependencyNode(
    G5_IRB2.loc_key, A, len(G5_IRB2))

G5_INPUT = (set([G5_TEST1_0_DN1]), set([G5_IRB0.loc_key]))

# Test graph 6

G6_TEST1_0_DN1 = DependencyNode(
    G6_IRB1.loc_key, A, len(G6_IRB1))

G6_INPUT = (set([G6_TEST1_0_DN1]), set([G6_IRB0.loc_key]))

# Test graph 7

G7_TEST1_0_DN1 = DependencyNode(
    G7_IRB2.loc_key, D, len(G7_IRB2))

G7_INPUT = (set([G7_TEST1_0_DN1]), set([G7_IRB0.loc_key]))

# Test graph 8

G8_TEST1_0_DN1 = DependencyNode(
    G8_IRB2.loc_key, A, len(G8_IRB2))

G8_INPUT = (set([G8_TEST1_0_DN1]), set([G3_IRB0.loc_key]))

# Test 9: Multi elements

G9_TEST1_0_DN1 = DependencyNode(
    G8_IRB2.loc_key, A, len(G8_IRB2))
G9_TEST1_0_DN5 = DependencyNode(
    G8_IRB2.loc_key, C, len(G8_IRB2))

G9_INPUT = (set([G9_TEST1_0_DN1, G9_TEST1_0_DN5]), set([G8_IRB0.loc_key]))

# Test 10: loop at beginning

G10_TEST1_0_DN1 = DependencyNode(
    G10_IRB2.loc_key, A, len(G10_IRB2))

G10_INPUT = (set([G10_TEST1_0_DN1]), set([G10_IRB1.loc_key]))


# Test 11: no dual block emulation

G11_TEST1_DN1 = DependencyNode(
    G11_IRB2.loc_key, A, len(G11_IRB2))

G11_INPUT = (set([G11_TEST1_DN1]), set([G11_IRB0.loc_key]))

# Test graph 12

G12_TEST1_0_DN1 = DependencyNode(G12_IRB2.loc_key, B, 1)

G12_INPUT = (set([G12_TEST1_0_DN1]), set([]))

# Test graph 13:

# All filters

G13_TEST1_0_DN4 = DependencyNode(G13_IRB3.loc_key, R, 1)

G13_INPUT = (set([G13_TEST1_0_DN4]), set([]))

# Test graph 14

# All filters

G14_TEST1_0_DN1 = DependencyNode(G14_IRB3.loc_key, R, 1)

G14_INPUT = (set([G14_TEST1_0_DN1]), set([]))

# Test graph 15

G15_TEST1_0_DN1 = DependencyNode(G15_IRB2.loc_key, R, 1)

G15_INPUT = (set([G15_TEST1_0_DN1]), set([]))

# Test graph 16
G16_TEST1_0_DN1 = DependencyNode(G16_IRB5.loc_key, R, 1)

G16_INPUT = (set([G16_TEST1_0_DN1]), set([]))

# Test graph 17

G17_TEST1_DN1 = DependencyNode(G17_IRB2.loc_key, A, 1)

G17_INPUT = (set([G17_TEST1_DN1]), set([]))


FAILED = set()


def flatNode(node):
    if isinstance(node, DependencyNode):
        if isinstance(node.element, ExprId):
            element = node.element.name
        elif isinstance(node.element, ExprInt):
            element = int(node.element)
        else:
            RuntimeError("Unsupported type '%s'" % type(enode.element))
        names = loc_db.get_location_names(node.loc_key)
        assert len(names) == 1
        name = next(iter(names))
        return (
            name,
            element,
            node.line_nb
        )
    else:
        return str(node)


def flatGraph(graph):
    out_nodes, out_edges = set(), set()
    for node in graph.nodes():
        out_nodes.add(flatNode(node))
    for nodeA, nodeB in graph.edges():
        out_edges.add((flatNode(nodeA), flatNode(nodeB)))
    out = (
        tuple(sorted(list(out_nodes), key=str)),
        tuple(sorted(list(out_edges), key=str))
    )
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

        for node_noidx, nodeA in viewitems(parentsA_noidx):
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

    for flatA in resultsA:
        resultA = unflatGraph(flatA)
        nodes = resultA.leaves()
        for resultB in resultsB:
            if test_result(resultA, resultB, nodes):
                out.append((resultA, resultB))
    return len(out) == len(resultsB)


def get_flat_init_depnodes(depnodes):
    out = []
    for node in depnodes:
        name = loc_db.pretty_str(node.loc_key)
        out.append((name,
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
    print("[+] Test", test_nb + 1)
    ircfg, (depnodes, heads) = test

    open("graph_%02d.dot" % (test_nb + 1), "w").write(ircfg.dot())
    open("graph_%02d.dot" % (test_nb + 1), "w").write(bloc2graph(ircfg))

    # Different options
    suffix_key_list = ["", "_nosimp", "_nomem", "_nocall",
                       "_implicit"]
    # Test classes
    for g_ind, g_dep in enumerate([DependencyGraph(ircfg),
                                   DependencyGraph(ircfg, apply_simp=False),
                                   DependencyGraph(ircfg, follow_mem=False),
                                   DependencyGraph(
                                       ircfg, follow_mem=False,
                                       follow_call=False
                                   ),
                                   # DependencyGraph(ircfg, implicit=True),
                                   ]):
        # if g_ind == 4:
        # TODO: Implicit specifications
        #    continue
        print(" - Class %s - %s" % (g_dep.__class__.__name__,
                                    suffix_key_list[g_ind]))
        # Select the correct result key
        mode_suffix = suffix_key_list[g_ind]
        graph_test_key = "graph" + mode_suffix

        # Test public APIs
        results = g_dep.get_from_depnodes(depnodes, heads)
        print("RESULTS")
        all_results = set()
        all_flat = set()
        for i, result in enumerate(results):
            all_flat.add(flatGraph(result.graph))
            all_results.add(flatGraph(result.graph))
            open("graph_test_%02d_%02d.dot" % (test_nb + 1, i),
                 "w").write(dg2graph(result.graph))

        if g_ind == 0:
            all_flat = sorted(all_flat, key=str)
            all_flats.append(all_flat)
        flat_depnodes = get_flat_init_depnodes(depnodes)
        if not match_results(all_results, test_results[test_nb], flat_depnodes):
            FAILED.add(test_nb)
        continue

if FAILED:
    print("FAILED :", len(FAILED))
    for test_num in sorted(FAILED):
        print(test_num, end=' ')
else:
    print("SUCCESS")

# Return an error status on error
assert not FAILED
