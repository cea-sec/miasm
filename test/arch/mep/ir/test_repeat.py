# Toshiba MeP-c4 - Repeat instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprCond, ExprOp


class TestRepeat(object):

    def test_repeat(self):
        """Test REPEAT execution"""

        # REPEAT Rn, disp17.align2
        exec_instruction("REPEAT R0, 0x42",
                         [(ExprId("PC", 32), ExprInt(2, 32)),
                          (ExprId("R0", 32), ExprInt(0x28, 32))],
                         [(ExprId("RPB", 32), ExprInt(6, 32)),
                          (ExprId("RPE", 32), ExprInt(0x44, 32)),
                          (ExprId("RPC", 32), ExprInt(0x28, 32))])

    def test_erepeat(self):
        """Test EREPEAT execution"""

        # EREPEAT disp17.align2
        exec_instruction("EREPEAT 0x42",
                         [(ExprId("PC", 32), ExprInt(0, 32))],
                         [(ExprId("RPB", 32), ExprInt(4, 32)),
                          (ExprId("RPE", 32), ExprInt(0x43, 32))])
