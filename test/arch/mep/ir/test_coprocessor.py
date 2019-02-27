# Toshiba MeP-c4 - Coprocessor instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprMem, ExprInt


class TestCoprocessor(object):

    def test_swcp(self):
        """Test SWCP execution"""

        # SWCP CRn,(Rm)
        exec_instruction("SWCP C1, (R2)",
                         [(ExprId("C1", 32), ExprInt(0x28071010, 32)),
                          (ExprId("R2", 32), ExprInt(0x11, 32))],
                         [(ExprMem(ExprInt(0x10, 32), 32), ExprInt(0x28071010, 32))])

        # SWCP CRn,disp16(Rm)
        exec_instruction("SWCP C10, 0xF800(R2)",
                         [(ExprId("C10", 32), ExprInt(0xABC7, 32)),
                          (ExprId("R2", 32), ExprInt(0x11, 32))],
                         [(ExprMem(ExprInt(0xFFFFF810, 32), 32), ExprInt(0xABC7, 32))])

    def test_lwcp(self):
        """Test LWCP execution"""

        # LWCP CRn[0-15],(Rm)
        exec_instruction("LWCP C1, (R2)",
                         [(ExprId("R2", 32), ExprInt(0x11, 32)),
                          (ExprMem(ExprInt(0x10, 32), 32), ExprInt(0xABCD, 32))],
                         [(ExprId("C1", 32), ExprInt(0xABCD, 32))])

        # LWCP CRn[0-15],disp16(Rm)
        exec_instruction("LWCP C9, 0xF000(R2)",
                         [(ExprId("R2", 32), ExprInt(0x42, 32)),
                          (ExprMem(ExprInt(0xFFFFF040, 32), 32), ExprInt(0x10, 32))],
                         [(ExprId("C9", 32), ExprInt(0x10, 32))])

    def test_smcp(self):
        """Test SMCP execution"""

        # SMCP CRn,(Rm)
        exec_instruction("SMCP C1, (R2)",
                         [(ExprId("C1", 32), ExprInt(0x28071010, 32)),
                          (ExprId("R2", 32), ExprInt(0x17, 32))],
                         [(ExprMem(ExprInt(0x10, 32), 32), ExprInt(0x28071010, 32))])

        # SMCP CRn,disp16(Rm)
        exec_instruction("SMCP C10, 0xF800(R2)",
                         [(ExprId("C10", 32), ExprInt(0xABC7, 32)),
                          (ExprId("R2", 32), ExprInt(0x17, 32))],
                         [(ExprMem(ExprInt(0xFFFFF810, 32), 32), ExprInt(0xABC7, 32))])

    def test_lmcp(self):
        """Test LMCP execution"""

        # LMCP CRn[0-15],(Rm)
        exec_instruction("LMCP C1, (R2)",
                         [(ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x10, 32), 32), ExprInt(0xABCD, 32))],
                         [(ExprId("C1", 32), ExprInt(0xABCD, 32))])

        # LMCP CRn[0-15],disp16(Rm)
        exec_instruction("LMCP C9, 0xF000(R2)",
                         [(ExprId("R2", 32), ExprInt(0x17, 32)),
                          (ExprMem(ExprInt(0xFFFFF010, 32), 32), ExprInt(0x10, 32))],
                         [(ExprId("C9", 32), ExprInt(0x10, 32))])

    def test_swcpi(self):
        """Test SWCPI execution"""

        # SWCPI CRn[0-15],(Rm+)
        exec_instruction("SWCPI C1, (R2+)",
                         [(ExprId("C1", 32), ExprInt(0x28071010, 32)),
                          (ExprId("R2", 32), ExprInt(0x11, 32))],
                         [(ExprMem(ExprInt(0x10, 32), 32), ExprInt(0x28071010, 32)),
                          (ExprId("R2", 32), ExprInt(0x15, 32))])

    def test_lwcpi(self):
        """Test LWCPI execution"""

        # LWCPI CRn[0-15],(Rm+)
        exec_instruction("LWCPI C1, (R2+)",
                         [(ExprId("R2", 32), ExprInt(0x11, 32)),
                          (ExprMem(ExprInt(0x10, 32), 32), ExprInt(0xABCD, 32))],
                         [(ExprId("C1", 32), ExprInt(0xABCD, 32)),
                          (ExprId("R2", 32), ExprInt(0x15, 32))])

    def test_smcpi(self):
        """Test SMCPI execution"""

        # SMCPI CRn[0-15],(Rm+)
        exec_instruction("SMCPI C1, (R2+)",
                         [(ExprId("C1", 32), ExprInt(0x28071010, 32)),
                          (ExprId("R2", 32), ExprInt(0x17, 32))],
                         [(ExprMem(ExprInt(0x10, 32), 32), ExprInt(0x28071010, 32)),
                          (ExprId("R2", 32), ExprInt(0x1F, 32))])

    def test_lmcpi(self):
        """Test LMCPI execution"""

        # LMCPI CRn[0-15],(Rm+)
        exec_instruction("LMCPI C1, (R2+)",
                         [(ExprId("R2", 32), ExprInt(0x11, 32)),
                          (ExprMem(ExprInt(0x10, 32), 32), ExprInt(0xABCD, 32))],
                         [(ExprId("C1", 32), ExprInt(0xABCD, 32)),
                          (ExprId("R2", 32), ExprInt(0x19, 32))])
