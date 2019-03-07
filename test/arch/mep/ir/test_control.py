# Toshiba MeP-c4 - Control instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction

from miasm.expression.expression import ExprId, ExprInt, ExprCond, ExprOp


class TestControl(object):

    def test_stc(self):
        """Test STC execution"""

        # STC Rn,imm5
        exec_instruction("STC R1, SAR",
                         [(ExprId("R1", 32), ExprInt(0x28, 32))],
                         [(ExprId("SAR", 32), ExprInt(0x28, 32))])

    def test_ldc(self):
        """Test LDC execution"""

        # LDC Rn,imm5
        exec_instruction("LDC R1, SAR",
                         [(ExprId("SAR", 32), ExprInt(0x28, 32))],
                         [(ExprId("R1", 32), ExprInt(0x28, 32))])

    def test_di(self):
        """Test DI execution"""

        # DI
        exec_instruction("DI",
                         [(ExprId("PSW", 32), ExprInt(1, 32))],
                         [(ExprId("PSW", 32), ExprInt(0, 32))])

    def test_ei(self):
        """Test EI execution"""

        # EI
        exec_instruction("EI",
                         [(ExprId("PSW", 32), ExprInt(0, 32))],
                         [(ExprId("PSW", 32), ExprInt(1, 32))])

    def test_reti(self):
        """Test RETI execution"""

        # RETI
        exec_instruction("RETI",
                         [(ExprId("PSW", 32), ExprInt(0xF0000201, 32)),  # PSW_NMI = 1
                          (ExprId("NPC", 32), ExprInt(0x43, 32))],
                         [(ExprId("PSW", 32), ExprInt(0xF0000001, 32)),
                          (ExprId("PC", 32), ExprInt(0x42, 32))])

        exec_instruction("RETI",
                         [(ExprId("PSW", 32), ExprInt(0b1010, 32)),  # PSW_UMP = 1 & PSW_IEP = 1
                          (ExprId("EPC", 32), ExprInt(0x29, 32))],
                         [(ExprId("PSW", 32), ExprInt(0b1111, 32)),  # PSW_UMC = 1 & PSW_IEC = 1
                          (ExprId("PC", 32), ExprInt(0x28, 32))])

    def test_swi(self):
        """Test SWI execution"""

        # SWI
        exec_instruction("SWI 0",
                         [(ExprId("EXC", 32), ExprInt(0xF0000001, 32))],
                         [(ExprId("EXC", 32), ExprInt(0xF0000001 + (1 << 4), 32))])

        exec_instruction("SWI 1",
                         [(ExprId("EXC", 32), ExprInt(0xF0000001, 32))],
                         [(ExprId("EXC", 32), ExprInt(0xF0000001 + (1 << 5), 32))])

    def test_halt(self):
        """Test HALT execution"""

        # HALT
        exec_instruction("HALT", [], [])

    def test_sleep(self):
        """Test SLEEP execution"""

        # SLEEP
        exec_instruction("SLEEP", [], [])

    def test_break(self):
        """Test BREAK execution"""

        # BREAK
        exec_instruction("BREAK", [], [])

    def test_syncm(self):
        """Test SYNCM execution"""

        # SYNCM
        exec_instruction("SYNCM", [], [])

    def test_stcb(self):
        """Test STCB execution"""

        # STCB Rn,abs16
        exec_instruction("STCB R0, 0x0", [], [])

    def test_ldcb(self):
        """Test LDCB execution"""

        # LDCB Rn,abs16
        exec_instruction("LDCB R0, 0x0", [], [])
