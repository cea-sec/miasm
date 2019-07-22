# Toshiba MeP-c4 - Bit manipulation instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprMem


class TestBitManipulation(object):

    def test_bsetm(self):
        """Test BSETM execution"""

        # BSETM (Rm),imm3
        exec_instruction("BSETM (R1), 1",
                         [(ExprId("R1", 32), ExprInt(0x28, 32)),
                          (ExprMem(ExprInt(0x28, 32), 8), ExprInt(0x1, 8))],
                         [(ExprMem(ExprInt(0x28, 32), 8), ExprInt(0x3, 8))])

    def test_bclrm(self):
        """Test BCLRM execution"""

        # BCLRM (Rm),imm3
        exec_instruction("BCLRM (R1), 1",
                         [(ExprId("R1", 32), ExprInt(0x28, 32)),
                          (ExprMem(ExprInt(0x28, 32), 8), ExprInt(0x3, 8))],
                         [(ExprMem(ExprInt(0x28, 32), 8), ExprInt(0x1, 8))])

    def test_bnotm(self):
        """Test BNOTM execution"""

        # BNOTM (Rm),imm3
        exec_instruction("BNOTM (R1), 1",
                         [(ExprId("R1", 32), ExprInt(0x28, 32)),
                          (ExprMem(ExprInt(0x28, 32), 8), ExprInt(0x1, 8))],
                         [(ExprMem(ExprInt(0x28, 32), 8), ExprInt(0x3, 8))])

    def test_btstm(self):
        """Test BTSTM execution"""

        # BTSTM R0,(Rm),imm3
        exec_instruction("BTSTM R0, (R1), 1",
                         [(ExprId("R1", 32), ExprInt(0x28, 32)),
                          (ExprMem(ExprInt(0x28, 32), 8), ExprInt(0x2, 8))],
                         [(ExprId("R0", 32), ExprInt(0x2, 32))])

    def test_tas(self):
        """Test TAS execution"""

        # TAS Rn,(Rm)
        exec_instruction("TAS R0, (R1)",
                         [(ExprId("R1", 32), ExprInt(0x28, 32)),
                          (ExprMem(ExprInt(0x28, 32), 8), ExprInt(0x2, 8))],
                         [(ExprId("R0", 32), ExprInt(0x2, 32)),
                          (ExprMem(ExprInt(0x28, 32), 8), ExprInt(0x1, 8))])
