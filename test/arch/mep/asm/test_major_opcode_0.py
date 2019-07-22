# Toshiba MeP-c4 - Major Opcode #0 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor0(object):

    def test_MOV(self):
        """Test the MOV instruction"""

        # Top instructions
        check_instruction("MOV $0, $4", "0040")
        check_instruction("MOV $TP, $1", "0d10")
        check_instruction("MOV $1, $7", "0170")
        check_instruction("MOV $1, $8", "0180")
        check_instruction("MOV $1, $TP", "01d0")

        # Randomly chosen instructions
        check_instruction("MOV $3, $7", "0370")
        check_instruction("MOV $0, $SP", "00f0")
        check_instruction("MOV $5, $SP", "05f0")
        check_instruction("MOV $2, $10", "02a0")
        check_instruction("MOV $GP, $12", "0ec0")

    def test_NEG(self):
        """Test the NEG instruction"""

        # Top instructions
        check_instruction("NEG $0, $12", "00c1")
        check_instruction("NEG $1, $0", "0101")
        check_instruction("NEG $0, $1", "0011")
        check_instruction("NEG $0, $0", "0001")
        check_instruction("NEG $0, $8", "0081")

        # Randomly chosen instructions
        check_instruction("NEG $6, $6", "0661")
        check_instruction("NEG $9, $5", "0951")
        check_instruction("NEG $11, $12", "0bc1")
        check_instruction("NEG $2, $6", "0261")
        check_instruction("NEG $4, $9", "0491")

    def test_SLT3(self):
        """Test the SLT3 instruction"""

        # Top instructions
        check_instruction("SLT3 $0, $1, $0", "0102")
        check_instruction("SLT3 $0, $4, $12", "04c2")
        check_instruction("SLT3 $0, $0, $12", "00c2")
        check_instruction("SLT3 $0, $0, $0", "0002")
        check_instruction("SLT3 $0, $0, $8", "0082")

        # Randomly chosen instructions
        check_instruction("SLT3 $0, $2, $4", "0242")
        check_instruction("SLT3 $0, $SP, $2", "0f22")
        check_instruction("SLT3 $0, $5, $9", "0592")
        check_instruction("SLT3 $0, $6, $4", "0642")
        check_instruction("SLT3 $0, $12, $6", "0c62")

    def test_SLTU3(self):
        """Test the SLTU3 instruction"""

        # Top instructions
        check_instruction("SLTU3 $0, $6, $8", "0683")
        check_instruction("SLTU3 $0, $0, $0", "0003")
        check_instruction("SLTU3 $0, $10, $11", "0ab3")
        check_instruction("SLTU3 $0, $12, $0", "0c03")
        check_instruction("SLTU3 $0, $4, $3", "0433")

        # Randomly chosen instructions
        check_instruction("SLTU3 $0, $5, $TP", "05d3")
        check_instruction("SLTU3 $0, $2, $5", "0253")
        check_instruction("SLTU3 $0, $SP, $TP", "0fd3")
        check_instruction("SLTU3 $0, $11, $10", "0ba3")
        check_instruction("SLTU3 $0, $4, $7", "0473")

    def test_SUB(self):
        """Test the SUB instruction"""

        # Top instructions
        check_instruction("SUB $0, $6", "0064")
        check_instruction("SUB $0, $0", "0004")
        check_instruction("SUB $12, $4", "0c44")
        check_instruction("SUB $4, $3", "0434")
        check_instruction("SUB $0, $8", "0084")

        # Randomly chosen instructions
        check_instruction("SUB $11, $9", "0b94")
        check_instruction("SUB $9, $9", "0994")
        check_instruction("SUB $TP, $2", "0d24")
        check_instruction("SUB $1, $9", "0194")
        check_instruction("SUB $SP, $11", "0fb4")

    def test_SBVCK3(self):
        """Test the SBVCK3 instruction"""

        # Top instructions
        check_instruction("SBVCK3 $0, $0, $4", "0045")
        check_instruction("SBVCK3 $0, $5, $0", "0505")
        check_instruction("SBVCK3 $0, $0, $0", "0005")
        check_instruction("SBVCK3 $0, $0, $6", "0065")
        check_instruction("SBVCK3 $0, $0, $12", "00c5")

        # Randomly chosen instructions
        check_instruction("SBVCK3 $0, $0, $5", "0055")
        check_instruction("SBVCK3 $0, $4, $8", "0485")
        check_instruction("SBVCK3 $0, $4, $1", "0415")
        check_instruction("SBVCK3 $0, $TP, $4", "0d45")
        check_instruction("SBVCK3 $0, $1, $7", "0175")

    def test_RI(self):
        """Test the (RI) instruction"""

        # No samples were found
        assert(True)

    def test_ADVCK3(self):
        """Test the ADVCK3 instruction"""

        # Top instructions
        check_instruction("ADVCK3 $0, $0, $6", "0067")
        check_instruction("ADVCK3 $0, $0, $4", "0047")
        check_instruction("ADVCK3 $0, $8, $9", "0897")
        check_instruction("ADVCK3 $0, $0, $0", "0007")
        check_instruction("ADVCK3 $0, $0, $12", "00c7")

        # Randomly chosen instructions
        check_instruction("ADVCK3 $0, $3, $9", "0397")
        check_instruction("ADVCK3 $0, $10, $7", "0a77")
        check_instruction("ADVCK3 $0, $1, $5", "0157")
        check_instruction("ADVCK3 $0, $0, $9", "0097")
        check_instruction("ADVCK3 $0, $0, $2", "0027")

    def test_SB(self):
        """Test the SB instruction"""

        # Top instructions
        check_instruction("SB $10, ($12)", "0ac8")
        check_instruction("SB $8, ($0)", "0808")
        check_instruction("SB $12, ($10)", "0ca8")
        check_instruction("SB $12, ($4)", "0c48")
        check_instruction("SB $12, ($11)", "0cb8")

        # Randomly chosen instructions
        check_instruction("SB $4, ($4)", "0448")
        check_instruction("SB $10, ($8)", "0a88")
        check_instruction("SB $7, ($6)", "0768")
        check_instruction("SB $8, ($11)", "08b8")
        check_instruction("SB $2, ($GP)", "02e8")

    def test_SH(self):
        """Test the SH instruction"""

        # Top instructions
        check_instruction("SH $12, ($11)", "0cb9")
        check_instruction("SH $12, ($0)", "0c09")
        check_instruction("SH $12, ($4)", "0c49")
        check_instruction("SH $0, ($2)", "0029")
        check_instruction("SH $0, ($12)", "00c9")

        # Randomly chosen instructions
        check_instruction("SH $GP, ($12)", "0ec9")
        check_instruction("SH $6, ($10)", "06a9")
        check_instruction("SH $10, ($11)", "0ab9")
        check_instruction("SH $9, ($4)", "0949")
        check_instruction("SH $1, ($5)", "0159")

    def test_SW(self):
        """Test the SW instruction"""

        # Top instructions
        check_instruction("SW $10, ($12)", "0aca")
        check_instruction("SW $0, ($12)", "00ca")
        check_instruction("SW $0, ($0)", "000a")
        check_instruction("SW $12, ($SP)", "0cfa")
        check_instruction("SW $0, ($SP)", "00fa")

        # Randomly chosen instructions
        check_instruction("SW $0, ($7)", "007a")
        check_instruction("SW $4, ($12)", "04ca")
        check_instruction("SW $12, ($7)", "0c7a")
        check_instruction("SW $9, ($12)", "09ca")
        check_instruction("SW $TP, ($1)", "0d1a")

    def test_LBU(self):
        """Test the LBU instruction"""

        # Top instructions
        check_instruction("LBU $12, ($TP)", "0cdb")
        check_instruction("LBU $12, ($10)", "0cab")
        check_instruction("LBU $12, ($11)", "0cbb")
        check_instruction("LBU $12, ($4)", "0c4b")
        check_instruction("LBU $0, ($4)", "004b")

        # Randomly chosen instructions
        check_instruction("LBU $6, ($TP)", "06db")
        check_instruction("LBU $11, ($SP)", "0bfb")
        check_instruction("LBU $10, ($10)", "0aab")
        check_instruction("LBU $1, ($9)", "019b")
        check_instruction("LBU $12, ($1)", "0c1b")

    def test_LB(self):
        """Test the LB instruction"""

        # Top instructions
        check_instruction("LB $11, ($TP)", "0bdc")
        check_instruction("LB $11, ($12)", "0bcc")
        check_instruction("LB $11, ($4)", "0b4c")
        check_instruction("LB $10, ($4)", "0a4c")
        check_instruction("LB $12, ($TP)", "0cdc")

        # Randomly chosen instructions
        check_instruction("LB $0, ($12)", "00cc")
        check_instruction("LB $2, ($7)", "027c")
        check_instruction("LB $5, ($7)", "057c")
        check_instruction("LB $10, ($1)", "0a1c")
        check_instruction("LB $12, ($12)", "0ccc")

    def test_LH(self):
        """Test the LH instruction"""

        # Top instructions
        check_instruction("LH $0, ($4)", "004d")
        check_instruction("LH $0, ($0)", "000d")
        check_instruction("LH $12, ($4)", "0c4d")
        check_instruction("LH $0, ($12)", "00cd")
        check_instruction("LH $10, ($0)", "0a0d")

        # Randomly chosen instructions
        check_instruction("LH $0, ($GP)", "00ed")
        check_instruction("LH $12, ($5)", "0c5d")
        check_instruction("LH $0, ($3)", "003d")
        check_instruction("LH $10, ($SP)", "0afd")
        check_instruction("LH $3, ($6)", "036d")

    def test_LW(self):
        """Test the LW instruction"""

        # Top instructions
        check_instruction("LW $0, ($SP)", "00fe")
        check_instruction("LW $12, ($4)", "0c4e")
        check_instruction("LW $12, ($SP)", "0cfe")
        check_instruction("LW $0, ($12)", "00ce")
        check_instruction("LW $1, ($SP)", "01fe")

        # Randomly chosen instructions
        check_instruction("LW $1, ($0)", "010e")
        check_instruction("LW $7, ($12)", "07ce")
        check_instruction("LW $TP, ($2)", "0d2e")
        check_instruction("LW $5, ($2)", "052e")
        check_instruction("LW $10, ($2)", "0a2e")

    def test_LHU(self):
        """Test the LHU instruction"""

        # Top instructions
        check_instruction("LHU $12, ($1)", "0c1f")
        check_instruction("LHU $11, ($4)", "0b4f")
        check_instruction("LHU $11, ($3)", "0b3f")
        check_instruction("LHU $12, ($8)", "0c8f")
        check_instruction("LHU $12, ($4)", "0c4f")

        # Randomly chosen instructions
        check_instruction("LHU $5, ($11)", "05bf")
        check_instruction("LHU $12, ($3)", "0c3f")
        check_instruction("LHU $9, ($8)", "098f")
        check_instruction("LHU $10, ($3)", "0a3f")
        check_instruction("LHU $5, ($8)", "058f")
