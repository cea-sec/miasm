# Toshiba MeP-c4 - Logical instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprCond, ExprOp


class TestLogical(object):

    def test_or(self):
        """Test OR execution"""

        # OR Rn, Rm
        exec_instruction("OR R1, R2",
                         [(ExprId("R1", 32), ExprInt(1, 32)), (ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(1, 32))])

    def test_or3(self):
        """Test OR3 execution"""

        # OR3 Rn,Rm,imm16
        exec_instruction("OR3 R1, R2, 1",
                         [(ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(1, 32))])

    def test_and(self):
        """Test AND  execution"""

        # AND Rn, Rm
        exec_instruction("AND R1, R2",
                         [(ExprId("R1", 32), ExprInt(1, 32)), (ExprId("R2", 32), ExprInt(0, 32))],
                         [(ExprId("R1", 32), ExprInt(0, 32))])

    def test_and3(self):
        """Test AND3 execution"""

        # AND3 Rn,Rm,imm16
        exec_instruction("AND3 R1, R2, 0",
                         [(ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(0, 32))])

    def test_xor(self):
        """Test XOR execution"""

        # XOR Rn, Rm
        exec_instruction("XOR R1, R2",
                         [(ExprId("R1", 32), ExprInt(1, 32)), (ExprId("R2", 32), ExprInt(0, 32))],
                         [(ExprId("R1", 32), ExprInt(1, 32))])

    def test_xor3(self):
        """Test XOR3 execution"""

        # XOR3 Rn,Rm,imm16
        exec_instruction("XOR3 R1, R2, 1",
                         [(ExprId("R2", 32), ExprInt(0, 32))],
                         [(ExprId("R1", 32), ExprInt(1, 32))])

    def test_nor(self):
        """Test NOR execution"""

        # NOR Rn, Rm
        exec_instruction("NOR R1, R2",
                         [(ExprId("R1", 32), ExprInt(1, 32)), (ExprId("R2", 32), ExprInt(0, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFFE, 32))])
