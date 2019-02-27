# Toshiba MeP-c4 - Debug instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprCond, ExprOp


class TestDebug(object):

    def test_dret(self):
        """Test DRET execution"""

        # DRET
        exec_instruction("DRET",
                         [(ExprId("DEPC", 32), ExprInt(2, 32)),
                          (ExprId("DBG", 32), ExprInt(0xFFFFFFFF, 32))],
                         [(ExprId("PC", 32), ExprInt(2, 32)),
                          (ExprId("DBG", 32), ExprInt(0xFFFFBFFF, 32))])

        exec_instruction("DRET",
                         [(ExprId("DEPC", 32), ExprInt(2, 32)),
                          (ExprId("DBG", 32), ExprInt(2**15, 32))],
                         [(ExprId("PC", 32), ExprInt(2, 32)),
                          (ExprId("DBG", 32), ExprInt(2**15, 32))])

    def test_dbreak(self):
        """Test DBREAK execution"""

        # DBREAK
        exec_instruction("DBREAK",
                         [(ExprId("DBG", 32), ExprInt(0, 32))],
                         [(ExprId("DBG", 32), ExprInt(0b10, 32))])
