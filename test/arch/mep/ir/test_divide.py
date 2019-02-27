# Toshiba MeP-c4 - Divide instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprCond, ExprOp
from miasm.jitter.csts import EXCEPT_DIV_BY_ZERO


class TestDivide(object):

    def test_div(self):
        """Test DIV execution"""

        # DIV Rn,Rm
        exec_instruction("DIV R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80, 32)),
                          (ExprId("R1", 32), ExprInt(0x0, 32)),
                          (ExprId("HI", 32), ExprInt(0, 32)),
                          (ExprId("LO", 32), ExprInt(0, 32))],
                         [(ExprId("HI", 32), ExprInt(0, 32)),
                          (ExprId("LO", 32), ExprInt(0, 32)),
                          (ExprId("exception_flags", 32), ExprInt(EXCEPT_DIV_BY_ZERO, 32))])

        # Negative numbers
        exec_instruction("DIV R0, R1",
                         [(ExprId("R0", 32), ExprInt(-4, 32)),
                          (ExprId("R1", 32), ExprInt(-2, 32))],
                         [(ExprId("HI", 32), ExprInt(0, 32)),
                          (ExprId("LO", 32), ExprInt(2, 32))])

        exec_instruction("DIV R0, R1",
                         [(ExprId("R0", 32), ExprInt(-5, 32)),
                          (ExprId("R1", 32), ExprInt(-2, 32))],
                         [(ExprId("HI", 32), ExprInt(1, 32)),
                          (ExprId("LO", 32), ExprInt(2, 32))])

        # Positive numbers
        exec_instruction("DIV R0, R1",
                         [(ExprId("R0", 32), ExprInt(4, 32)),
                          (ExprId("R1", 32), ExprInt(2, 32))],
                         [(ExprId("HI", 32), ExprInt(0xFFFFFFFC, 32)),
                          (ExprId("LO", 32), ExprInt(0, 32))])

        # Negative & positive numbers
        exec_instruction("DIV R0, R1",
                         [(ExprId("R0", 32), ExprInt(-5, 32)),
                          (ExprId("R1", 32), ExprInt(2, 32))],
                         [(ExprId("HI", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFFFE, 32))])

        exec_instruction("DIV R0, R1",
                         [(ExprId("R0", 32), ExprInt(5, 32)),
                          (ExprId("R1", 32), ExprInt(-2, 32))],
                         [(ExprId("HI", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFFFE, 32))])

    def test_divu(self):
        """Test DIVU execution"""

        # DIVU Rn,Rm
        exec_instruction("DIVU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80, 32)),
                          (ExprId("R1", 32), ExprInt(0x0, 32)),
                          (ExprId("HI", 32), ExprInt(0, 32)),
                          (ExprId("LO", 32), ExprInt(0, 32))],
                         [(ExprId("HI", 32), ExprInt(0, 32)),
                          (ExprId("LO", 32), ExprInt(0, 32)),
                          (ExprId("exception_flags", 32), ExprInt(EXCEPT_DIV_BY_ZERO, 32))])

        exec_instruction("DIVU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80, 32)),
                          (ExprId("R1", 32), ExprInt(0x2, 32))],
                         [(ExprId("HI", 32), ExprInt(0x0, 32)),
                          (ExprId("LO", 32), ExprInt(0x40, 32))])

        exec_instruction("DIVU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x83, 32)),
                          (ExprId("R1", 32), ExprInt(0x2, 32))],
                         [(ExprId("HI", 32), ExprInt(0x1, 32)),
                          (ExprId("LO", 32), ExprInt(0x41, 32))])

        exec_instruction("DIVU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80000000, 32)),
                          (ExprId("R1", 32), ExprInt(-1, 32))],
                         [(ExprId("HI", 32), ExprInt(0x80000000, 32)),
                          (ExprId("LO", 32), ExprInt(0x0, 32))])
