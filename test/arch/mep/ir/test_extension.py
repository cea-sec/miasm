# Toshiba MeP-c4 - Byte/Halfword extension instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprMem, ExprInt


class TestExtension(object):

    def test_extb(self):
        """Test EXTB execution"""

        # EXTB Rn
        exec_instruction("EXTB R1",
                         [(ExprId("R1", 32), ExprInt(0xFE, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFFE, 32))])

        exec_instruction("EXTB R2",
                         [(ExprId("R2", 32), ExprInt(0x80, 32))],
                         [(ExprId("R2", 32), ExprInt(0xFFFFFF80, 32))])

    def test_exth(self):
        """Test EXTH execution"""

        # EXTH Rn
        exec_instruction("EXTH R1",
                         [(ExprId("R1", 32), ExprInt(0xFFFE, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFFE, 32))])

        exec_instruction("EXTH R2",
                         [(ExprId("R2", 32), ExprInt(0x8000, 32))],
                         [(ExprId("R2", 32), ExprInt(0xFFFF8000, 32))])

    def test_extub(self):
        """Test EXTUB execution"""

        # EXTUB Rn
        exec_instruction("EXTUB R1",
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFFE, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFE, 32))])

        exec_instruction("EXTUB R2",
                         [(ExprId("R2", 32), ExprInt(0xFFFFFF80, 32))],
                         [(ExprId("R2", 32), ExprInt(0x80, 32))])

    def test_extuh(self):
        """Test EXTUH execution"""

        # EXTUH Rn
        exec_instruction("EXTUH R1",
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFFE, 32))],
                         [(ExprId("R1", 32), ExprInt(0xFFFE, 32))])

        exec_instruction("EXTUH R2",
                         [(ExprId("R2", 32), ExprInt(0xFFFF8000, 32))],
                         [(ExprId("R2", 32), ExprInt(0x8000, 32))])
