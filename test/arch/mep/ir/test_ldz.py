# Toshiba MeP-c4 - Leading zero instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprCond, ExprOp


class TestLdz(object):

    def test_ldz(self):
        """Test LDZ execution"""

        # LDZ Rn,Rm
        exec_instruction("LDZ R0, R1",
                         [(ExprId("R1", 32), ExprInt(0x80000000, 32))],
                         [(ExprId("R0", 32), ExprInt(0, 32))])

        exec_instruction("LDZ R0, R1",
                         [(ExprId("R1", 32), ExprInt(0x40000000, 32))],
                         [(ExprId("R0", 32), ExprInt(1, 32))])

        exec_instruction("LDZ R0, R1",
                         [(ExprId("R1", 32), ExprInt(0b1111, 32))],
                         [(ExprId("R0", 32), ExprInt(28, 32))])

        exec_instruction("LDZ R0, R1",
                         [(ExprId("R1", 32), ExprInt(0b0100, 32))],
                         [(ExprId("R0", 32), ExprInt(29, 32))])

        exec_instruction("LDZ R0, R1",
                         [(ExprId("R1", 32), ExprInt(0b0010, 32))],
                         [(ExprId("R0", 32), ExprInt(30, 32))])

        exec_instruction("LDZ R0, R1",
                         [(ExprId("R1", 32), ExprInt(0b0001, 32))],
                         [(ExprId("R0", 32), ExprInt(31, 32))])

        exec_instruction("LDZ R0, R1",
                         [(ExprId("R1", 32), ExprInt(0b0000, 32))],
                         [(ExprId("R0", 32), ExprInt(32, 32))])
