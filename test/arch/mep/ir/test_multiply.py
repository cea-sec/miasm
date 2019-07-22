# Toshiba MeP-c4 - Multiply instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprCond, ExprOp


class TestMultiply(object):

    def test_mul(self):
        """Test MUL execution"""

        # MUL Rn,Rm
        exec_instruction("MUL R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32))],
                         [(ExprId("HI", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFF80, 32))])

        exec_instruction("MUL R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80000000, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32))],
                         [(ExprId("HI", 32), ExprInt(0x00000000, 32)),
                          (ExprId("LO", 32), ExprInt(0x80000000, 32))])

    def test_mulu(self):
        """Test MULU execution"""

        # MULU Rn,Rm
        exec_instruction("MULU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x2, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32))],
                         [(ExprId("HI", 32), ExprInt(0x1, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFFFE, 32))])

        exec_instruction("MULU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80000000, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32))],
                         [(ExprId("HI", 32), ExprInt(0x7FFFFFFF, 32)),
                          (ExprId("LO", 32), ExprInt(0x80000000, 32))])

    def test_mulr(self):
        """Test MULR execution"""

        # MULR Rn,Rm
        exec_instruction("MULR R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32))],
                         [(ExprId("HI", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFF80, 32)),
                          (ExprId("R0", 32), ExprInt(0xFFFFFF80, 32))])

    def test_mulru(self):
        """Test MULRU execution"""

        # MULRU Rn,Rm
        exec_instruction("MULRU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x2, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32))],
                         [(ExprId("HI", 32), ExprInt(0x1, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFFFE, 32)),
                          (ExprId("R0", 32), ExprInt(0xFFFFFFFE, 32))])

    def test_madd(self):
        """Test MADD execution"""

        # MADD Rn,Rm
        exec_instruction("MADD R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("HI", 32), ExprInt(0, 32)),
                          (ExprId("LO", 32), ExprInt(0, 32))],
                         [(ExprId("HI", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFF80, 32))])

        exec_instruction("MADD R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("HI", 32), ExprInt(1, 32)),
                          (ExprId("LO", 32), ExprInt(1, 32))],
                         [(ExprId("HI", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFF81, 32))])

    def test_maddu(self):
        """Test MADDU execution"""

        # MADDU Rn,Rm
        exec_instruction("MADDU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x2, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("HI", 32), ExprInt(0, 32)),
                          (ExprId("LO", 32), ExprInt(0, 32))],
                         [(ExprId("HI", 32), ExprInt(0x1, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFFFE, 32))])

        exec_instruction("MADDU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x2, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("HI", 32), ExprInt(1, 32)),
                          (ExprId("LO", 32), ExprInt(1, 32))],
                         [(ExprId("HI", 32), ExprInt(0x1, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFFFF, 32))])

    def test_maddr(self):
        """Test MADDR execution"""

        # MADDR Rn,Rm
        exec_instruction("MADDR R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("HI", 32), ExprInt(0, 32)),
                          (ExprId("LO", 32), ExprInt(0, 32))],
                         [(ExprId("HI", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFF80, 32)),
                          (ExprId("R0", 32), ExprInt(0xFFFFFF80, 32))])

        exec_instruction("MADDR R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x80, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("HI", 32), ExprInt(1, 32)),
                          (ExprId("LO", 32), ExprInt(1, 32))],
                         [(ExprId("HI", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFF81, 32)),
                          (ExprId("R0", 32), ExprInt(0xFFFFFF81, 32))])

    def test_maddru(self):
        """Test MADDRU execution"""

        # MADDRU Rn,Rm
        exec_instruction("MADDRU R0, R1",
                         [(ExprId("R0", 32), ExprInt(0x2, 32)),
                          (ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("HI", 32), ExprInt(0, 32)),
                          (ExprId("LO", 32), ExprInt(0, 32))],
                         [(ExprId("HI", 32), ExprInt(0x1, 32)),
                          (ExprId("LO", 32), ExprInt(0xFFFFFFFE, 32)),
                          (ExprId("R0", 32), ExprInt(0xFFFFFFFE, 32))])
