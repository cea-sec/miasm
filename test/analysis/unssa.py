""" Test cases for dead code elimination"""
from future.utils import viewvalues

from miasm.expression.expression import ExprId, ExprInt, ExprAssign, ExprMem, \
    ExprCond, ExprLoc
from miasm.core.locationdb import LocationDB
from miasm.analysis.simplifier import IRCFGSimplifierSSA
from miasm.ir.analysis import LifterModelCall
from miasm.ir.ir import IRCFG, IRBlock, AssignBlock

loc_db = LocationDB()

a = ExprId("a", 32)
b = ExprId("b", 32)
c = ExprId("c", 32)
d = ExprId("d", 32)
r = ExprId("r", 32)
x = ExprId("x", 32)
y = ExprId("y", 32)
u8 = ExprId("u8", 8)
zf = ExprId('zf', 1)

a_init = ExprId("a_init", 32)
b_init = ExprId("b_init", 32)
c_init = ExprId("c_init", 32)
d_init = ExprId("d_init", 32)
r_init = ExprId("r_init", 32) # Return register

pc = ExprId("pc", 32)
sp = ExprId("sp", 32)

CST0 = ExprInt(0x0, 32)
CST1 = ExprInt(0x1, 32)
CST2 = ExprInt(0x2, 32)
CST3 = ExprInt(0x3, 32)
CSTX_8 = ExprInt(12, 8)

LBL0 = loc_db.add_location("lbl0", 0)
LBL1 = loc_db.add_location("lbl1", 1)
LBL2 = loc_db.add_location("lbl2", 2)
LBL3 = loc_db.add_location("lbl3", 3)
LBL4 = loc_db.add_location("lbl4", 4)
LBL5 = loc_db.add_location("lbl5", 5)
LBL6 = loc_db.add_location("lbl6", 6)
LBL7 = loc_db.add_location("lbl7", 7)

IRDst = ExprId('IRDst', 32)
dummy = ExprId('dummy', 32)


def gen_irblock(label, exprs_list):
    irs = []
    for exprs in exprs_list:
        if isinstance(exprs, AssignBlock):
            irs.append(exprs)
        else:
            irs.append(AssignBlock(exprs))

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

class IRATest(LifterModelCall):

    """Fake IRA class for tests"""

    def __init__(self, loc_db=None):
        arch = Arch()
        super(IRATest, self).__init__(arch, 32, loc_db)
        self.IRDst = IRDst
        self.ret_reg = r
        self.addrsize = 32

    def get_out_regs(self, xx):
        out = set()
        """
        for assignblk in xx:
            for dst in assignblk:
                if str(dst).startswith("r"):
                    out.add(dst)
        """
        out.add(r)
        return out

IRA = IRATest(loc_db)
END = ExprId("END", IRDst.size)

G0_IRA = IRA.new_ircfg()

G0_IRB0 = gen_irblock(LBL0, [
    [ExprAssign(a, CST1)],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])
G0_IRB1 = gen_irblock(LBL1, [
    [ExprAssign(a, a+CST1)],
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL1, 32),
                                ExprLoc(LBL2, 32)
                                )
    )]
])
G0_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(r, a)],
    [ExprAssign(IRDst, END)]
])

for irb in [G0_IRB0, G0_IRB1, G0_IRB2]:
    G0_IRA.add_irblock(irb)



G1_IRA = IRA.new_ircfg()

G1_IRB0 = gen_irblock(LBL0, [
    [ExprAssign(a, CST1)],
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL1, 32),
                                ExprLoc(LBL2, 32)
                                )
    )]
])
G1_IRB1 = gen_irblock(LBL1, [
    [ExprAssign(a, a+CST1)],
    [ExprAssign(IRDst, ExprLoc(LBL3, 32))]
])
G1_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(a, a+CST2)],
    [ExprAssign(IRDst, ExprLoc(LBL3, 32))]
])
G1_IRB3 = gen_irblock(LBL3, [
    [ExprAssign(r, a)],
    [ExprAssign(IRDst, END)]
])

for irb in [G1_IRB0, G1_IRB1, G1_IRB2, G1_IRB3]:
    G1_IRA.add_irblock(irb)





G2_IRA = IRA.new_ircfg()

G2_IRB0 = gen_irblock(LBL0, [
    [ExprAssign(a, CST1)],
    [ExprAssign(b, CST2)],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])
G2_IRB1 = gen_irblock(LBL1, [
    [
        ExprAssign(a, b),
        ExprAssign(b, a),
    ],
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL1, 32),
                                ExprLoc(LBL2, 32)
                                )
    )]
])
G2_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(r, a)],
    [ExprAssign(IRDst, END)]
])

for irb in [G2_IRB0, G2_IRB1, G2_IRB2]:
    G2_IRA.add_irblock(irb)




G3_IRA = IRA.new_ircfg()

G3_IRB0 = gen_irblock(LBL0, [
    [ExprAssign(a, CST1)],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])
G3_IRB1 = gen_irblock(LBL1, [
    [
        ExprAssign(a, a + CST1),
    ],
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL2, 32),
                                ExprCond(y,
                                         ExprLoc(LBL3, 32),
                                         ExprLoc(LBL5, 32)
                                )
    ))]
])

G3_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(a, a + CST1)],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])


G3_IRB3 = gen_irblock(LBL3, [
    [ExprAssign(a, a + CST2)],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])


G3_IRB4 = gen_irblock(LBL4, [
    [ExprAssign(r, a + CST3)],
    [
        ExprAssign(IRDst,
                   ExprCond(y,
                            ExprLoc(LBL1, 32),
                            ExprLoc(LBL5, 32)
                   )
        )
    ]
])


G3_IRB5 = gen_irblock(LBL5, [
    [ExprAssign(r, a)],
    [ExprAssign(IRDst, END)]
])

for irb in [G3_IRB0, G3_IRB1, G3_IRB2, G3_IRB3, G3_IRB5]:
    G3_IRA.add_irblock(irb)






G4_IRA = IRA.new_ircfg()

G4_IRB0 = gen_irblock(LBL0, [
    [ExprAssign(a, CST1)],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])
G4_IRB1 = gen_irblock(LBL1, [
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL2, 32),
                                ExprLoc(LBL3, 32)
                                )
    )]
])
G4_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(a, a+CST2)],
    [ExprAssign(IRDst, ExprLoc(LBL4, 32))]
])
G4_IRB3 = gen_irblock(LBL3, [
    [ExprAssign(a, a+CST3)],
    [ExprAssign(IRDst, ExprLoc(LBL4, 32))]
])
G4_IRB4 = gen_irblock(LBL4, [
    [ExprAssign(a, a+CST1)],
    [
        ExprAssign(
            IRDst,
            ExprCond(
                x,
                ExprLoc(LBL5, 32),
                ExprLoc(LBL1, 32)
            )
        )
    ]
])

G4_IRB5 = gen_irblock(LBL5, [
    [ExprAssign(r, a)],
    [ExprAssign(IRDst, END)]
])

for irb in [G4_IRB0, G4_IRB1, G4_IRB2, G4_IRB3, G4_IRB4, G4_IRB5]:
    G4_IRA.add_irblock(irb)





G5_IRA = IRA.new_ircfg()

G5_IRB0 = gen_irblock(LBL0, [
    [
        ExprAssign(a, CST1),
        ExprAssign(b, CST1),
    ],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])

G5_IRB1 = gen_irblock(LBL1, [
    [
        ExprAssign(b, a),
        ExprAssign(a, a+CST1)
    ],
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL1, 32),
                                ExprLoc(LBL2, 32)
                                )
    )]
])
G5_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(r, b)],
    [ExprAssign(IRDst, END)]
])

for irb in [G5_IRB0, G5_IRB1, G5_IRB2]:
    G5_IRA.add_irblock(irb)



G6_IRA = IRA.new_ircfg()

G6_IRB0 = gen_irblock(LBL0, [
    [
        ExprAssign(a, CST1),
        ExprAssign(b, CST1),
    ],
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL1, 32),
                                ExprLoc(LBL2, 32)
                                )
    )]
])


G6_IRB1 = gen_irblock(LBL1, [
    [ExprAssign(a, a + CST1)],
    [ExprAssign(IRDst, ExprLoc(LBL5, 32))]
])


G6_IRB2 = gen_irblock(LBL2, [
    [
        ExprAssign(a, a + CST1),
    ],
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL3, 32),
                                ExprLoc(LBL4, 32)
                                )
    )]
])

G6_IRB3 = gen_irblock(LBL3, [
    [
        ExprAssign(b, a + CST1),
    ],
    [ExprAssign(IRDst, ExprLoc(LBL5, 32))],
])


G6_IRB4 = gen_irblock(LBL4, [
    [
        ExprAssign(b, a + CST1),
    ],
    [ExprAssign(IRDst, ExprLoc(LBL5, 32))],
])

G6_IRB5 = gen_irblock(LBL5, [
    [ExprAssign(r, a)],
    [ExprAssign(IRDst, END)]
])

for irb in [G6_IRB0, G6_IRB1, G6_IRB2, G6_IRB3, G6_IRB4, G6_IRB5]:
    G6_IRA.add_irblock(irb)





G7_IRA = IRA.new_ircfg()

G7_IRB0 = gen_irblock(LBL0, [
    [ExprAssign(a, a + CST1)],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])
G7_IRB1 = gen_irblock(LBL1, [
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL2, 32),
                                ExprLoc(LBL3, 32)
                                )
    )]
])
G7_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(IRDst, ExprLoc(LBL4, 32))]
])
G7_IRB3 = gen_irblock(LBL3, [
    [ExprAssign(a, a+CST3)],
    [ExprAssign(IRDst, ExprLoc(LBL4, 32))]
])
G7_IRB4 = gen_irblock(LBL4, [
    [
        ExprAssign(
            IRDst,
            ExprCond(
                x,
                ExprLoc(LBL5, 32),
                ExprLoc(LBL1, 32)
            )
        )
    ]
])

G7_IRB5 = gen_irblock(LBL5, [
    [ExprAssign(r, a)],
    [ExprAssign(IRDst, END)]
])

for irb in [G7_IRB0, G7_IRB1, G7_IRB2, G7_IRB3, G7_IRB4, G7_IRB5]:
    G7_IRA.add_irblock(irb)






G8_IRA = IRA.new_ircfg()

G8_IRB0 = gen_irblock(LBL0, [
    [ExprAssign(a, CST0)],
    [ExprAssign(b, c)],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])


G8_IRB1 = gen_irblock(LBL1, [
    [ExprAssign(u8, ExprMem(b, 8))],
    [
        ExprAssign(
            IRDst,
            ExprCond(
                u8,
                ExprLoc(LBL2, 32),
                ExprLoc(LBL7, 32)
            )
        )
    ]
])


G8_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(b, b + CST1)],
    [
        ExprAssign(
            IRDst,
            ExprCond(
                u8 + CSTX_8,
                ExprLoc(LBL1, 32),
                ExprLoc(LBL3, 32)
            )
        )
    ]
])



G8_IRB3 = gen_irblock(LBL3, [
    [
        ExprAssign(a, (ExprMem(b, 8) + u8).zeroExtend(32))
    ],
    [
        ExprAssign(
            IRDst,
            ExprLoc(LBL1, 32)
        )
    ]
])



G8_IRB4 = gen_irblock(LBL4, [
    [ExprAssign(b, b + CST1)],
    [ExprAssign(d, CST0)],
    [ExprAssign(IRDst, ExprLoc(LBL6, 32))]
])


G8_IRB5 = gen_irblock(LBL5, [
    [ExprAssign(d, CST1)],
    [ExprAssign(IRDst, ExprLoc(LBL6, 32))]
])


G8_IRB6 = gen_irblock(LBL6, [
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])

G8_IRB7 = gen_irblock(LBL7, [
    [ExprAssign(b, CST2)],
    [ExprAssign(r, a)],
    [ExprAssign(IRDst, END)]
])


for irb in [G8_IRB0, G8_IRB1, G8_IRB2, G8_IRB3, G8_IRB7]:
    G8_IRA.add_irblock(irb)



G9_IRA = IRA.new_ircfg()

G9_IRB0 = gen_irblock(LBL0, [
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])
G9_IRB1 = gen_irblock(LBL1, [
    [ExprAssign(b, CST1)],
    [ExprAssign(IRDst, ExprCond(x,
                                ExprLoc(LBL1, 32),
                                ExprLoc(LBL2, 32)
                                )
    )]
])
G9_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(r, b)],
    [ExprAssign(IRDst, END)]
])

for irb in [G9_IRB0, G9_IRB1, G9_IRB2]:
    G9_IRA.add_irblock(irb)





G10_IRA = IRA.new_ircfg()

G10_IRB0 = gen_irblock(LBL0, [
    [ExprAssign(a, CST0)],
    [ExprAssign(IRDst, ExprLoc(LBL1, 32))]
])

G10_IRB1 = gen_irblock(LBL1, [
    [ExprAssign(a, a+CST1)],
    [ExprAssign(IRDst, ExprCond(a,
                                ExprLoc(LBL1, 32),
                                ExprLoc(LBL2, 32)
                                )
    )]
])

G10_IRB2 = gen_irblock(LBL2, [
    [ExprAssign(r, CST1)],
    [ExprAssign(IRDst, END)]
])

for irb in [G10_IRB0, G10_IRB1, G10_IRB2]:
    G10_IRA.add_irblock(irb)




ExprId.__repr__ = ExprId.__str__



class IRAOutRegs(IRATest):
    def get_out_regs(self, block):
        regs_todo = super(self.__class__, self).get_out_regs(block)
        out = {}
        for assignblk in block:
            for dst in assignblk:
                reg = self.ssa_var.get(dst, None)
                if reg is None:
                    continue
                if reg in regs_todo:
                    out[reg] = dst
        return set(viewvalues(out))


lifter = IRAOutRegs(loc_db)


class CustomIRCFGSimplifierSSA(IRCFGSimplifierSSA):
    def get_forbidden_regs(self):
        """
        Return a set of immutable register during SSA transformation
        """
        regs = set(
            [
                self.lifter.pc,
                self.lifter.IRDst,
            ]
        )
        return regs

for test_nb, ircfg in enumerate(
        [
            G0_IRA,
            G1_IRA,
            G2_IRA,
            G3_IRA,
            G4_IRA,
            G5_IRA,
            G6_IRA,
            G7_IRA,
            G8_IRA,
            G9_IRA,
            G10_IRA,
        ]):

    open('graph_%d.dot' % test_nb, 'w').write(ircfg.dot())

    # Save a copy of ircfg
    ircfg_orig = IRCFG(IRDst, loc_db)
    for irblock in viewvalues(ircfg.blocks):
        ircfg_orig.add_irblock(irblock)

    # SSA
    head = LBL0
    simplifier = CustomIRCFGSimplifierSSA(lifter)
    ircfg = simplifier(ircfg, head)
    open('final_%d.dot' % test_nb, 'w').write(ircfg.dot())

    # XXX TODO: add real regression test
