# Toshiba MeP-c4 - Move instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprMem, ExprInt


class TestMove(object):

    def test_mov(self):
        """Test MOV execution"""

        # MOV Rn,Rm
        exec_instruction("MOV R1, R2",
                         [(ExprId("R2", 32), ExprInt(0x2807, 32))],
                         [(ExprId("R1", 32), ExprInt(0x2807, 32))])

        # MOV Rn,imm8
        exec_instruction("MOV R1, 0x28",
                         [],
                         [(ExprId("R1", 32), ExprInt(0x28, 32))])

        exec_instruction("MOV R1, 0x80",
                         [],
                         [(ExprId("R1", 32), ExprInt(0xFFFFFF80, 32))])

        # MOV Rn,imm16
        exec_instruction("MOV R1, 0x2807",
                         [],
                         [(ExprId("R1", 32), ExprInt(0x2807, 32))],
                         index=1)

    def test_movu(self):
        """Test MOVU execution"""

        # MOVU Rn[0-7],imm24
        exec_instruction("MOVU R1, 0xFF2807",
                         [],
                         [(ExprId("R1", 32), ExprInt(0xFF2807, 32))],
                         index=1)

        # MOVU Rn,imm16
        exec_instruction("MOVU R10, 0x2807",
                         [],
                         [(ExprId("R10", 32), ExprInt(0x2807, 32))])

    def test_movh(self):
        """Test MOVH execution"""

        # MOVH Rn,imm16
        exec_instruction("MOVH R1, 1",
                         [],
                         [(ExprId("R1", 32), ExprInt(0x10000, 32))])

        exec_instruction("MOVH R1, 0xFFFF",
                         [],
                         [(ExprId("R1", 32), ExprInt(0xFFFF0000, 32))])
