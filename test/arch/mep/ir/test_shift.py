# Toshiba MeP-c4 - Shift instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprCond, ExprOp
from miasm.core.cpu import sign_ext


class TestShift(object):

    def test_sra(self):
        """Test SRA execution"""

        # SRA Rn, Rm
        exec_instruction("SRA R1, R2",
                         [(ExprId("R1", 32), ExprInt(4, 32)), (ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(2, 32))])

        exec_instruction("SRA R1, R2",
                         [(ExprId("R1", 32), ExprInt(sign_ext(4, 3, 32), 32)), (ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFFE, 32))])

        exec_instruction("SRA R1, R2",
                         [(ExprId("R1", 32), ExprInt(0xF0000000, 32)), (ExprId("R2", 32), ExprInt(4, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFF000000, 32))])

        # SRA Rn,imm5
        exec_instruction("SRA R1, 1",
                         [(ExprId("R1", 32), ExprInt(4, 32))],
                         [(ExprId("R1", 32), ExprInt(2, 32))])

        # SRA Rn,imm5
        exec_instruction("SRA R1, 1",
                         [(ExprId("R1", 32), ExprInt(0x80000000, 32))],
                         [(ExprId("R1", 32), ExprInt(0xC0000000, 32))])

        exec_instruction("SRA R1, 1",
                         [(ExprId("R1", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(0, 32))])

    def test_srl(self):
        """Test SRL execution"""

        # SRL Rn, Rm
        exec_instruction("SRL R1, R2",
                         [(ExprId("R1", 32), ExprInt(4, 32)), (ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(2, 32))])

        # SRL Rn,imm5
        exec_instruction("SRL R1, 1",
                         [(ExprId("R1", 32), ExprInt(4, 32))],
                         [(ExprId("R1", 32), ExprInt(2, 32))])

        exec_instruction("SRL R1, 1",
                         [(ExprId("R1", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(0, 32))])

    def test_sll(self):
        """Test SLL execution"""

        # SLL Rn, Rm
        exec_instruction("SLL R1, R2",
                         [(ExprId("R1", 32), ExprInt(4, 32)), (ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(8, 32))])

        exec_instruction("SLL R1, R2",
                         [(ExprId("R1", 32), ExprInt(0x80000000, 32)), (ExprId("R2", 32), ExprInt(1, 32))],
                         [(ExprId("R1", 32), ExprInt(0, 32))])

        # SLL Rn,imm5
        exec_instruction("SLL R1, 1",
                         [(ExprId("R1", 32), ExprInt(4, 32))],
                         [(ExprId("R1", 32), ExprInt(8, 32))])

    def test_sll3(self):
        """Test SLL3 execution"""

        # SLL3 R0,Rn,imm5
        exec_instruction("SLL3 R0, R1, 2",
                         [(ExprId("R1", 32), ExprInt(4, 32))],
                         [(ExprId("R0", 32), ExprInt(16, 32))])

        exec_instruction("SLL3 R0, R1, 2",
                         [(ExprId("R1", 32), ExprInt(0xC0000000, 32))],
                         [(ExprId("R0", 32), ExprInt(0, 32))])

    def test_fsft(self):
        """Test FSFT execution"""

        # FSFT Rn,Rm
        exec_instruction("FSFT R0, R1",
                         [(ExprId("SAR", 32), ExprInt(0x00000001, 32)),
                          (ExprId("R0", 32), ExprInt(0x00000001, 32)),
                          (ExprId("R1", 32), ExprInt(0x80000000, 32))],
                         [(ExprId("R0", 32), ExprInt(0x00000003, 32))])

        exec_instruction("FSFT R0, R1",
                         [(ExprId("SAR", 32), ExprInt(0x00000004, 32)),
                          (ExprId("R0", 32), ExprInt(0xFFFFFFFF, 32)),
                          (ExprId("R1", 32), ExprInt(0xF0000000, 32))],
                         [(ExprId("R0", 32), ExprInt(0xFFFFFFFF, 32))])

        exec_instruction("FSFT R0, R1",
                         [(ExprId("SAR", 32), ExprInt(0x00000004, 32)),
                          (ExprId("R0", 32), ExprInt(0xF0000000, 32)),
                          (ExprId("R1", 32), ExprInt(0x0F000000, 32))],
                         [(ExprId("R0", 32), ExprInt(0, 32))])
