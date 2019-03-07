# Toshiba MeP-c4 - Major Opcode #7 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor7(object):

    def test_DI(self):
        """Test the DI instruction"""

        # Top instructions
        check_instruction("DI", "7000")

    def test_EI(self):
        """Test the EI instruction"""

        # Top instructions
        check_instruction("EI", "7010")

    def test_SYNCM(self):
        """Test the SYNCM instruction"""

        # Top instructions
        check_instruction("SYNCM", "7011")

    def test_SYNCCP(self):
        """Test the SYNCCP instruction"""

        # Top instructions
        check_instruction("SYNCCP", "7021")

    def test_RET(self):
        """Test the RET instruction"""

        # Top instructions
        check_instruction("RET", "7002")

    def test_RETI(self):
        """Test the RETI instruction"""

        # Top instructions
        check_instruction("RETI", "7012")

    def test_HALT(self):
        """Test the HALT instruction"""

        # Top instructions
        check_instruction("HALT", "7022")

    def test_BREAK(self):
        """Test the BREAK instruction"""

        # Top instructions
        check_instruction("BREAK", "7032")

    def test_SLEEP(self):
        """Test the SLEEP instruction"""

        # Top instructions
        check_instruction("SLEEP", "7062")

    def test_DRET(self):
        """Test the DRET instruction"""

        # Top instructions
        check_instruction("DRET", "7013")

    def test_DBREAK(self):
        """Test the DBREAK instruction"""

        # Top instructions
        check_instruction("DBREAK", "7033")

    def test_CACHE(self):
        """Test the CACHE instruction"""

        # Top instructions
        check_instruction("CACHE 0x0, ($11)", "70b4")
        check_instruction("CACHE 0x2, ($7)", "7274")
        check_instruction("CACHE 0x4, ($7)", "7474")
        check_instruction("CACHE 0x9, ($7)", "7974")
        check_instruction("CACHE 0x2, ($6)", "7264")

        # Randomly chosen instructions
        check_instruction("CACHE 0x5, ($8)", "7584")
        check_instruction("CACHE 0xC, ($6)", "7c64")
        check_instruction("CACHE 0x2, ($1)", "7214")
        check_instruction("CACHE 0x3, ($1)", "7314")
        check_instruction("CACHE 0x1, ($8)", "7184")

    def test_SWI(self):
        """Test the SWI instruction"""

        # Top instructions
        check_instruction("SWI 0x0", "7006")
        check_instruction("SWI 0x2", "7026")
        check_instruction("SWI 0x1", "7016")
        check_instruction("SWI 0x3", "7036")

    def test_STC(self):
        """Test the STC instruction"""

        # Top instructions
        check_instruction("STC $4, $S22", "7469")  # the documentation & objsdump disagree
        check_instruction("STC $3, $S22", "7369")  # the documentation & objsdump disagree
        check_instruction("STC $1, $CFG", "7159")
        check_instruction("STC $8, $LO", "7888")
        check_instruction("STC $0, $LP", "7018")

        # Randomly chosen instructions
        check_instruction("STC $9, $DBG", "7989")
        check_instruction("STC $2, $DBG", "7289")
        check_instruction("STC $9, $LO", "7988")
        check_instruction("STC $11, $DEPC", "7b99")
        check_instruction("STC $1, $S29", "71d9")

    def test_LDC(self):
        """Test the LDC instruction"""

        # Top instructions
        check_instruction("LDC $1, $CFG", "715b")
        check_instruction("LDC $9, $HI", "797a")
        check_instruction("LDC $11, $LO", "7b8a")
        check_instruction("LDC $12, $LO", "7c8a")
        check_instruction("LDC $0, $LP", "701a")

        # Randomly chosen instructions
        check_instruction("LDC $11, $RPC", "7b6a")
        check_instruction("LDC $10, $CFG", "7a5b")
        check_instruction("LDC $2, $NPC", "727b")
        check_instruction("LDC $6, $MB1", "76ea")
        check_instruction("LDC $TP, $RPC", "7d6a")
