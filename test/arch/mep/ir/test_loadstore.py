# Toshiba MeP-c4 - Load/Store instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprMem, ExprInt


class TestLoadStore(object):

    def test_sb(self):
        """Test SB execution"""

        # SB Rn,(Rm)
        exec_instruction("SB R1, (R2)",
                         [(ExprId("R1", 32), ExprInt(0x28, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0x10, 32), 8), ExprInt(0x28, 8))])

        # SB Rn[0-7], disp7(TP)
        exec_instruction("SB R1, 0x18(R2)",
                         [(ExprId("R1", 32), ExprInt(0xABC7, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0x28, 32), 8), ExprInt(0xC7, 8))])

        # SB Rn,disp16(Rm)
        exec_instruction("SB R10, 0xF800(R2)",
                         [(ExprId("R10", 32), ExprInt(0xABC7, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0xFFFFF810, 32), 8), ExprInt(0xC7, 8))])

    def test_sh(self):
        """Test SH execution"""

        # SH Rn,(Rm)
        exec_instruction("SH R1, (R2)",
                         [(ExprId("R1", 32), ExprInt(0x2807, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0x10, 32), 16), ExprInt(0x2807, 16))])

        # SH Rn[0-7],disp7.align2(TP)
        exec_instruction("SH R1, 0x18(R2)",
                         [(ExprId("R1", 32), ExprInt(0xABC7, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0x28, 32), 16), ExprInt(0xABC7, 16))])

        # SH Rn,disp16(Rm)
        exec_instruction("SH R10, 0xF800(R2)",
                         [(ExprId("R10", 32), ExprInt(0xABC7, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0xFFFFF810, 32), 16), ExprInt(0xABC7, 16))])

    def test_sw(self):
        """Test SW execution"""

        # SW Rn,(Rm)
        exec_instruction("SW R1, (R2)",
                         [(ExprId("R1", 32), ExprInt(0x28071010, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0x10, 32), 32), ExprInt(0x28071010, 32))])

        # SW Rn,disp7.align4(SP)
        exec_instruction("SW R1, 4(SP)",
                         [(ExprId("R1", 32), ExprInt(0x28071010, 32)),
                          (ExprId("SP", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0x14, 32), 32), ExprInt(0x28071010, 32))])

        # SW Rn,disp7.align4(TP)
        exec_instruction("SW R1, 12(TP)",
                         [(ExprId("R1", 32), ExprInt(0x28071010, 32)),
                          (ExprId("TP", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0x1c, 32), 32), ExprInt(0x28071010, 32))])

        # SW Rn,disp16(Rm)
        exec_instruction("SW R10, 0xF800(R2)",
                         [(ExprId("R10", 32), ExprInt(0xABC7, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprMem(ExprInt(0xFFFFF810, 32), 32), ExprInt(0xABC7, 32))])

        # SW Rn,(abs24.align4)
        exec_instruction("SW R10, (0x1010)",
                         [(ExprId("R10", 32), ExprInt(0xABC7, 32))],
                         [(ExprMem(ExprInt(0x1010, 32), 32), ExprInt(0xABC7, 32))])

    def test_lb(self):
        """Test LB executon"""

        # LB Rn,(Rm)
        exec_instruction("LB R1, (R2)",
                         [(ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x10, 32), 8), ExprInt(0xF0, 8))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFFFF0, 32))])

        # LB Rn[0-7],disp7(TP)
        exec_instruction("LB R7, 0x3(TP)",
                         [(ExprId("TP", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x13, 32), 8), ExprInt(0xF0, 8))],
                         [(ExprId("R7", 32), ExprInt(0xFFFFFFF0, 32))])

        # LB Rn,disp16(Rm)
        exec_instruction("LB R10, 0xF800(R2)",
                         [(ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0xFFFFF810, 32), 8), ExprInt(0x4, 8))],
                         [(ExprId("R10", 32), ExprInt(0x4, 32))])

        exec_instruction("LB R10, 0xF800(R2)",
                         [(ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0xFFFFF810, 32), 8), ExprInt(0xFE, 8))],
                         [(ExprId("R10", 32), ExprInt(0xFFFFFFFE, 32))])

    def test_lh(self):
        """Test lh execution"""

        # LH Rn,(Rm)
        exec_instruction("LH R1, (R2)",
                         [(ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x10, 32), 16), ExprInt(0xF517, 16))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFF517, 32))])

        # LH Rn[0-7],disp7.align2(TP)
        exec_instruction("LH R1, 0x18(R2)",
                         [(ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x28, 32), 16), ExprInt(0xF517, 16))],
                         [(ExprId("R1", 32), ExprInt(0xFFFFF517, 32))])

        # LH Rn,disp16(Rm)
        exec_instruction("LH R9, 0xF000(R2)",
                         [(ExprId("R2", 32), ExprInt(0x42, 32)),
                          (ExprMem(ExprInt(0xFFFFF042, 32), 16), ExprInt(0x10, 16))],
                         [(ExprId("R9", 32), ExprInt(0x10, 32))])

        exec_instruction("LH R9, 0xF000(R2)",
                         [(ExprId("R2", 32), ExprInt(0x42, 32)),
                          (ExprMem(ExprInt(0xFFFFF042, 32), 16), ExprInt(0xABCD, 16))],
                         [(ExprId("R9", 32), ExprInt(0xFFFFABCD, 32))])

    def test_lw(self):
        """Test SW execution"""

        # LW Rn,(Rm)
        exec_instruction("LW R1, (R2)",
                         [(ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x10, 32), 32), ExprInt(0xABCD, 32))],
                         [(ExprId("R1", 32), ExprInt(0xABCD, 32))])

        #  LW Rn,disp7.align4(SP)
        exec_instruction("LW R1, 0x18(SP)",
                         [(ExprId("SP", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x28, 32), 32), ExprInt(0x01234567, 32))],
                         [(ExprId("R1", 32), ExprInt(0x01234567, 32))])

        # LW Rn[0-7],disp7.align4(TP)
        exec_instruction("LW R1, 0x18(TP)",
                         [(ExprId("TP", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x28, 32), 32), ExprInt(0x1010, 32))],
                         [(ExprId("R1", 32), ExprInt(0x1010, 32))])

        # LW Rn,disp16(Rm)
        exec_instruction("LW R9, 0xF000(R2)",
                         [(ExprId("R2", 32), ExprInt(0x42, 32)),
                          (ExprMem(ExprInt(0xFFFFF040, 32), 32), ExprInt(0x10, 32))],
                         [(ExprId("R9", 32), ExprInt(0x10, 32))])

        # LW Rn,(abs24.align4)
        exec_instruction("LW R10, (0x1010)",
                         [(ExprMem(ExprInt(0x1010, 32), 32), ExprInt(0xABC7, 32))],
                         [(ExprId("R10", 32), ExprInt(0xABC7, 32))])

    def test_lbu(self):
        """Test LBU execution"""

        # LBU Rn,(Rm)
        exec_instruction("LBU R1, (R2)",
                         [(ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x10, 32), 8), ExprInt(0xA, 8))],
                         [(ExprId("R1", 32), ExprInt(0xA, 32))])

        # LBU Rn[0-7],disp7(TP)
        exec_instruction("LBU R1, 0x22(R3)",
                         [(ExprId("R3", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x32, 32), 8), ExprInt(0xA, 8))],
                         [(ExprId("R1", 32), ExprInt(0xA, 32))])

        # LBU Rn,disp16(Rm)
        exec_instruction("LBU R10, 0xF000(R2)",
                         [(ExprId("R2", 32), ExprInt(0x42, 32)),
                          (ExprMem(ExprInt(0xFFFFF042, 32), 32), ExprInt(0x10, 32))],
                         [(ExprId("R10", 32), ExprInt(0x10, 32))])

    def test_lhu(self):
        """Test LHU execution"""

        # LHU Rn,(Rm)
        exec_instruction("LHU R1, (R2)",
                         [(ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x10, 32), 16), ExprInt(0xEF, 16))],
                         [(ExprId("R1", 32), ExprInt(0xEF, 32))])

        # LHU Rn[0-7],disp7.align2(TP)
        exec_instruction("LHU R1, 0x22(R3)",
                         [(ExprId("R3", 32), ExprInt(0x10, 32)),
                          (ExprMem(ExprInt(0x32, 32), 16), ExprInt(0xFEDC, 16))],
                         [(ExprId("R1", 32), ExprInt(0xFEDC, 32))])

        # LHU Rn,disp16(Rm)
        exec_instruction("LHU R10, 0xF000(R2)",
                         [(ExprId("R2", 32), ExprInt(0x42, 32)),
                          (ExprMem(ExprInt(0xFFFFF042, 32), 16), ExprInt(0x1234, 16))],
                         [(ExprId("R10", 32), ExprInt(0x1234, 32))])
