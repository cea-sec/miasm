# Toshiba MeP-c4 - Arithmetic instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprCond, ExprOp


class TestArithmetic(object):

    def test_add3(self):
        """Test ADD3 execution"""

        # ADD3 Rl,Rn,Rm
        exec_instruction("ADD3 R1, R2, R3",
                         [(ExprId("R2", 32), ExprInt(0x40, 32)), (ExprId("R3", 32), ExprInt(0x2, 32))],
                         [(ExprId("R1", 32), ExprInt(0x42, 32))])

        # ADD3 Rn,SP,imm7.align4
        exec_instruction("ADD3 R1, SP, 0x8",
                         [(ExprId("SP", 32), ExprInt(0x20, 32))],
                         [(ExprId("R1", 32), ExprInt(0x28, 32))])

        # ADD3 Rn,Rm,imm16
        exec_instruction("ADD3 R7, R5, -31912",
                         [(ExprId("R5", 32), ExprInt(0x20, 32))],
                         [(ExprId("R7", 32), ExprInt(-31880, 32))])

    def test_add(self):
        """Test ADD execution"""

        # ADD Rn,imm6
        exec_instruction("ADD R1, 0x10",
                         [(ExprId("R1", 32), ExprInt(0x32, 32))],
                         [(ExprId("R1", 32), ExprInt(0x42, 32))])

        exec_instruction("ADD R1, -5",
                         [(ExprId("R1", 32), ExprInt(0x32, 32))],
                         [(ExprId("R1", 32), ExprInt(45, 32))])

        exec_instruction("ADD R1, -16",
                         [(ExprId("R1", 32), ExprInt(0xFFFF, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFFEF, 32))])

        exec_instruction("ADD R1, -28",
                         [(ExprId("R1", 32), ExprInt(0, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFE4, 32))])

    def test_advck3(self):
        """Test ADVCK3 execution"""

        # ADVCK3 R0,Rn,Rm
        exec_instruction("ADVCK3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(1, 32)),
                          (ExprId("R2", 32), ExprInt(2, 32))],
                         [(ExprId("R0", 32), ExprInt(0, 32))])

        exec_instruction("ADVCK3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(1, 32)),
                          (ExprId("R2", 32), ExprInt(0xFFFFFFFF, 32))],
                         [(ExprId("R0", 32), ExprInt(1, 32))])

    def test_sub(self):
        """Test SUB execution"""

        # SUB Rn,Rm
        exec_instruction("SUB R1, R2",
                         [(ExprId("R1", 32), ExprInt(0x28, 32)),
                          (ExprId("R2", 32), ExprInt(0x7, 32))],
                         [(ExprId("R1", 32), ExprInt(0x21, 32))])

    def test_sbvck3(self):
        """Test SBVCK3 execution"""

        # SBVCK3 R0,Rn,Rm
        exec_instruction("SBVCK3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(2, 32)),
                          (ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R0", 32), ExprCond(ExprOp(">",
                                                             ExprInt(3, 32),
                                                             ExprCond(ExprOp(">", ExprInt(0x2, 32), ExprInt(0x1, 32)),
                                                                      ExprInt(0x2, 32),
                                                                      ExprInt(0x1, 32))),
                                                      ExprInt(1, 32),
                                                      ExprInt(0, 32)))])

        exec_instruction("SBVCK3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(0, 32)),
                          (ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R0", 32), ExprCond(ExprOp(">",
                                                             ExprInt(1, 32),
                                                             ExprCond(ExprOp(">", ExprInt(0, 32), ExprInt(1, 32)),
                                                                      ExprInt(0, 32),
                                                                      ExprInt(1, 32))),
                                                      ExprInt(1, 32),
                                                      ExprInt(0, 32)))])

    def test_neg(self):
        """Test NEG execution"""

        # NEG Rn,Rm
        exec_instruction("NEG R1, R2",
                         [(ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFFF, 32))])

        exec_instruction("NEG R1, R2",
                         [(ExprId("R2", 32), ExprInt(0x42, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFBE, 32))])

    def test_slt3(self):
        """Test SLT3 execution"""

        # SLT3 R0,Rn,Rm
        exec_instruction("SLT3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(0x2, 32)),
                          (ExprId("R2", 32), ExprInt(0x1, 32))],
                         [(ExprId("R0", 32), ExprInt(0, 32))])

        r1 = 0x80000000
        r2 = 0x80000001
        exec_instruction("SLT3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(r1, 32)),
                          (ExprId("R2", 32), ExprInt(r2, 32))],
                         [(ExprId("R0", 32), ExprInt(1, 32))])

        r1 = 0x80000000
        r2 = 0x00000001
        exec_instruction("SLT3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(r1, 32)),
                          (ExprId("R2", 32), ExprInt(r2, 32))],
                         [(ExprId("R0", 32), ExprInt(1, 32))])

        r1 = 0x00000001
        r2 = 0x80000000
        exec_instruction("SLT3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(r1, 32)),
                          (ExprId("R2", 32), ExprInt(r2, 32))],
                         [(ExprId("R0", 32), ExprInt(0, 32))])

        # SLT3 R0,Rn,imm5
        exec_instruction("SLT3 R0, R1, 12",
                         [(ExprId("R1", 32), ExprInt(0x1, 32))],
                         [(ExprId("R0", 32), ExprInt(1, 32))])

        r1 = 0x80000000
        exec_instruction("SLT3 R0, R1, 12",
                         [(ExprId("R1", 32), ExprInt(0x80000000, 32))],
                         [(ExprId("R0", 32), ExprInt(1, 32))])

    def test_sltu3(self):
        """Test SLTU3 execution"""

        # SLTU3 R0,Rn,Rm
        exec_instruction("SLTU3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(0x1, 32)),
                          (ExprId("R2", 32), ExprInt(0x2, 32))],
                         [(ExprId("R0", 32), ExprInt(1, 32))])

        exec_instruction("SLTU3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(0x2, 32)),
                          (ExprId("R2", 32), ExprInt(0x1, 32))],
                         [(ExprId("R0", 32), ExprInt(0, 32))])

        # SLTU3 R0,Rn,imm5
        exec_instruction("SLTU3 R0, R1, 12",
                         [(ExprId("R1", 32), ExprInt(0x1, 32))],
                         [(ExprId("R0", 32), ExprInt(1, 32))])

    def test_sl1ad3(self):
        """Test SL2AD3 execution"""

        # SL1AD3 R0,Rn,Rm
        exec_instruction("SL1AD3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(0x2, 32)),
                          (ExprId("R2", 32), ExprInt(0x20, 32))],
                         [(ExprId("R0", 32), ExprInt(0x24, 32))])

    def test_sl2ad3(self):
        """Test SL2AD3 execution"""

        # SL2AD3 R0,Rn,Rm
        exec_instruction("SL2AD3 R0, R1, R2",
                         [(ExprId("R1", 32), ExprInt(0x2, 32)),
                          (ExprId("R2", 32), ExprInt(0x20, 32))],
                         [(ExprId("R0", 32), ExprInt(0x28, 32))])
