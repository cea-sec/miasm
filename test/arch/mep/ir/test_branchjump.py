# Toshiba MeP-c4 - Branch/Jump instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt


class TestBranchJump(object):

    def test_bra(self):
        """Test BRA execution"""

        # BRA disp12.align2
        exec_instruction("BRA 0x28",
                         [],
                         [(ExprId("PC", 32), ExprInt(0x28, 32))])

        exec_instruction("BRA 0x800",
                         [],
                         [(ExprId("PC", 32), ExprInt(0xFFFFF800, 32))])

        exec_instruction("BRA 0x28",
                         [],
                         [(ExprId("PC", 32), ExprInt(0x1028, 32))], offset=0x1000)

    def test_beqz(self):
        """Test BEQZ execution"""

        # BEQZ Rn,disp8.align2
        exec_instruction("BEQZ R1, 0x10",
                         [(ExprId("R1", 32), ExprInt(0, 32))],
                         [(ExprId("PC", 32), ExprInt(0x20, 32))], offset=0x10)

        exec_instruction("BEQZ R1, 0x10",
                         [(ExprId("R1", 32), ExprInt(1, 32))],
                         [(ExprId("PC", 32), ExprInt(0x2, 32))])

        exec_instruction("BEQZ R1, 0x80",
                         [(ExprId("R1", 32), ExprInt(0, 32))],
                         [(ExprId("PC", 32), ExprInt(0xFFFFFF90, 32))], offset=0x10)

    def test_bnez(self):
        """Test BNEZ execution"""

        # BNEZ Rn,disp8.align2
        exec_instruction("BNEZ R1, 0x10",
                         [(ExprId("R1", 32), ExprInt(0, 32))],
                         [(ExprId("PC", 32), ExprInt(0x2, 32))])

        exec_instruction("BNEZ R1, 0x10",
                         [(ExprId("R1", 32), ExprInt(1, 32))],
                         [(ExprId("PC", 32), ExprInt(0x20, 32))], offset=0x10)

        exec_instruction("BNEZ R1, 0x80",
                         [(ExprId("R1", 32), ExprInt(0, 32))],
                         [(ExprId("PC", 32), ExprInt(0x2, 32))])

    def test_beqi(self):
        """Test BEQI execution"""

        # BEQI Rn,imm4,disp17.align2
        exec_instruction("BEQI R1, 0x8, 0x28",
                         [(ExprId("R1", 32), ExprInt(0, 32))],
                         [(ExprId("PC", 32), ExprInt(0x4, 32))])

        exec_instruction("BEQI R1, 0x1, 0x28",
                         [(ExprId("R1", 32), ExprInt(1, 32))],
                         [(ExprId("PC", 32), ExprInt(0x38, 32))], offset=0x10)

        exec_instruction("BEQI R1, 0x6, 0x10000",
                         [(ExprId("R1", 32), ExprInt(6, 32))],
                         [(ExprId("PC", 32), ExprInt(0xFFFF0010, 32))], offset=0x10)

    def test_bnei(self):
        """Test BNEI execution"""

        # BNEI Rn,imm4,disp17.align2
        exec_instruction("BNEI R1, 0x5, 0x28",
                         [(ExprId("R1", 32), ExprInt(0, 32))],
                         [(ExprId("PC", 32), ExprInt(0x38, 32))], offset=0x10)

        exec_instruction("BNEI R1, 0x7, 0xFF00",
                         [(ExprId("R1", 32), ExprInt(7, 32)),
                          (ExprId("PC", 32), ExprInt(0x1, 32))],
                         [(ExprId("PC", 32), ExprInt(0x4, 32))])

    def test_blti(self):
        """Test BLTI execution"""

        # BLTI Rn,imm4,disp17.align2
        exec_instruction("BLTI R1, 0x5, 0x10000",
                         [(ExprId("R1", 32), ExprInt(0x10, 32))],
                         [(ExprId("PC", 32), ExprInt(0x14, 32))],
                         offset=0x10)

        exec_instruction("BLTI R1, 0x5, 0x10000",
                         [(ExprId("R1", 32), ExprInt(0x1, 32))],
                         [(ExprId("PC", 32), ExprInt(0xFFFF0010, 32))],
                         offset=0x10)

    def test_bgei(self):
        """Test BGEI execution"""

        # BGEI Rn,imm4,disp17.align2
        exec_instruction("BGEI R1, 0x5, 0x10000",
                         [(ExprId("R1", 32), ExprInt(0x10, 32))],
                         [(ExprId("PC", 32), ExprInt(0xFFFF0010, 32))],
                         offset=0x10)

        exec_instruction("BGEI R1, 0x5, 0x10000",
                         [(ExprId("R1", 32), ExprInt(0x01, 32))],
                         [(ExprId("PC", 32), ExprInt(0x14, 32))],
                         offset=0x10)

        exec_instruction("BGEI R1, 0x5, 0x10000",
                         [(ExprId("R1", 32), ExprInt(0x05, 32))],
                         [(ExprId("PC", 32), ExprInt(0xFFFF0010, 32))],
                         offset=0x10)

    def test_beq(self):
        """Test BEQ execution"""

        # BEQ Rn,Rm,disp17.align2
        exec_instruction("BEQ R1, R2, 0x10000",
                         [(ExprId("R1", 32), ExprInt(0x10, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprId("PC", 32), ExprInt(0xFFFF0010, 32))], offset=0x10)

        exec_instruction("BEQ R1, R2, 0x8000",
                         [(ExprId("R1", 32), ExprInt(0x09, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32)),
                          (ExprId("PC", 32), ExprInt(0x10, 32))],
                         [(ExprId("PC", 32), ExprInt(0x4, 32))])

    def test_bne(self):
        """Test BNE execution"""

        # BNE Rn,Rm,disp17.align2
        exec_instruction("BNE R1, R2, 0x8000",
                         [(ExprId("R1", 32), ExprInt(0x10, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprId("PC", 32), ExprInt(0x4, 32))])

        exec_instruction("BNE R1, R2, 0x8000",
                         [(ExprId("R1", 32), ExprInt(0x09, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprId("PC", 32), ExprInt(0x8010, 32))], offset=0x10)

        exec_instruction("BNE R1, R2, 0x10000",
                         [(ExprId("R1", 32), ExprInt(0x09, 32)),
                          (ExprId("R2", 32), ExprInt(0x10, 32))],
                         [(ExprId("PC", 32), ExprInt(0xFFFF0010, 32))], offset=0x10)

    def test_bsr(self):
        """Test BSR execution"""

        # BSR disp12.align2
        exec_instruction("BSR 0x800",
                         [(ExprId("PC", 32), ExprInt(2, 32))],
                         [(ExprId("PC", 32), ExprInt(0xFFFFF800, 32)),
                          (ExprId("LP", 32), ExprInt(2, 32))], index=0)

        # BSR disp24.align2
        exec_instruction("BSR 0x101015",
                         [(ExprId("PC", 32), ExprInt(4, 32))],
                         [(ExprId("PC", 32), ExprInt(0x101014, 32)),
                          (ExprId("LP", 32), ExprInt(4, 32))], index=1)

    def test_jmp(self):
        """Test JMP execution"""

        # JMP Rm
        exec_instruction("JMP R1",
                         [(ExprId("R1", 32), ExprInt(0x101015, 32))],
                         [(ExprId("PC", 32), ExprInt(0x101015, 32))])

        # JMP target24.align2
        exec_instruction("JMP 0x2807",
                         [(ExprId("PC", 32), ExprInt(0, 32))],
                         [(ExprId("PC", 32), ExprInt(0x2806, 32))], offset=0x42)
        exec_instruction("JMP 0x2807",
                         [(ExprId("PC", 32), ExprInt(0xB0000000, 32))],
                         [(ExprId("PC", 32), ExprInt(0xB0002806, 32))], offset=0xB0000000)

    def test_jsr(self):
        """Test JSR execution"""

        # JSR Rm
        exec_instruction("JSR R1",
                         [(ExprId("R1", 32), ExprInt(0x2807, 32))],
                         [(ExprId("PC", 32), ExprInt(0x2807, 32)),
                          (ExprId("LP", 32), ExprInt(0x2, 32))])

    def test_ret(self):
        """Test RET execution"""

        # RET
        exec_instruction("RET",
                         [(ExprId("LP", 32), ExprInt(0x28, 32))],
                         [(ExprId("PC", 32), ExprInt(0x28, 32))])
