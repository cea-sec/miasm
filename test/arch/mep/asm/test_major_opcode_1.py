# Toshiba MeP-c4 - Major Opcode #1 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor1(object):

    def test_OR(self):
        """Test the OR instruction"""

        # Top instructions
        check_instruction("OR $0, $4", "1040")
        check_instruction("OR $12, $10", "1ca0")
        check_instruction("OR $11, $12", "1bc0")
        check_instruction("OR $0, $11", "10b0")
        check_instruction("OR $0, $12", "10c0")

        # Randomly chosen instructions
        check_instruction("OR $1, $12", "11c0")
        check_instruction("OR $6, $11", "16b0")
        check_instruction("OR $10, $9", "1a90")
        check_instruction("OR $2, $10", "12a0")
        check_instruction("OR $11, $4", "1b40")

    def test_AND(self):
        """Test the AND instruction"""

        # Top instructions
        check_instruction("AND $11, $12", "1bc1")
        check_instruction("AND $12, $10", "1ca1")
        check_instruction("AND $4, $12", "14c1")
        check_instruction("AND $12, $11", "1cb1")
        check_instruction("AND $0, $0", "1001")

        # Randomly chosen instructions
        check_instruction("AND $6, $12", "16c1")
        check_instruction("AND $8, $6", "1861")
        check_instruction("AND $1, $12", "11c1")
        check_instruction("AND $11, $2", "1b21")
        check_instruction("AND $2, $4", "1241")

    def test_XOR(self):
        """Test the XOR instruction"""

        # Top instructions
        check_instruction("XOR $0, $2", "1022")
        check_instruction("XOR $6, $10", "16a2")
        check_instruction("XOR $2, $2", "1222")
        check_instruction("XOR $4, $0", "1402")
        check_instruction("XOR $11, $12", "1bc2")

        # Randomly chosen instructions
        check_instruction("XOR $0, $12", "10c2")
        check_instruction("XOR $12, $1", "1c12")
        check_instruction("XOR $SP, $10", "1fa2")
        check_instruction("XOR $3, $11", "13b2")
        check_instruction("XOR $1, $8", "1182")

    def test_NOR(self):
        """Test the NOR instruction"""

        # Top instructions
        check_instruction("NOR $9, $2", "1923")
        check_instruction("NOR $12, $12", "1cc3")
        check_instruction("NOR $4, $4", "1443")
        check_instruction("NOR $11, $0", "1b03")
        check_instruction("NOR $0, $0", "1003")

        # Randomly chosen instructions
        check_instruction("NOR $4, $1", "1413")
        check_instruction("NOR $11, $11", "1bb3")
        check_instruction("NOR $9, $9", "1993")
        check_instruction("NOR $11, $2", "1b23")
        check_instruction("NOR $0, $5", "1053")

    def test_MUL(self):
        """Test the MUL instruction"""

        # Top instructions
        check_instruction("MUL $9, $SP", "19f4")
        check_instruction("MUL $0, $8", "1084")
        check_instruction("MUL $8, $12", "18c4")
        check_instruction("MUL $10, $9", "1a94")
        check_instruction("MUL $10, $3", "1a34")

        # Randomly chosen instructions
        check_instruction("MUL $2, $2", "1224")
        check_instruction("MUL $4, $12", "14c4")
        check_instruction("MUL $9, $3", "1934")
        check_instruction("MUL $4, $11", "14b4")
        check_instruction("MUL $6, $0", "1604")

    def test_MULU(self):
        """Test the MULU instruction"""

        # Top instructions
        check_instruction("MULU $4, $2", "1425")
        check_instruction("MULU $8, $9", "1895")
        check_instruction("MULU $7, $12", "17c5")
        check_instruction("MULU $5, $12", "15c5")
        check_instruction("MULU $1, $8", "1185")

        # Randomly chosen instructions
        check_instruction("MULU $9, $6", "1965")
        check_instruction("MULU $5, $1", "1515")
        check_instruction("MULU $5, $11", "15b5")
        check_instruction("MULU $1, $10", "11a5")
        check_instruction("MULU $0, $4", "1045")

    def test_MULR(self):
        """Test the MULR instruction"""

        # Top instructions
        check_instruction("MULR $SP, $0", "1f06")
        check_instruction("MULR $8, $3", "1836")
        check_instruction("MULR $SP, $6", "1f66")
        check_instruction("MULR $12, $1", "1c16")
        check_instruction("MULR $6, $1", "1616")

        # Randomly chosen instructions
        check_instruction("MULR $7, $1", "1716")
        check_instruction("MULR $10, $8", "1a86")
        check_instruction("MULR $4, $1", "1416")
        check_instruction("MULR $12, $11", "1cb6")
        check_instruction("MULR $12, $4", "1c46")

    def test_MULRU(self):
        """Test the MULRU instruction"""

        # Top instructions
        check_instruction("MULRU $12, $2", "1c27")
        check_instruction("MULRU $0, $4", "1047")
        check_instruction("MULRU $2, $1", "1217")
        check_instruction("MULRU $7, $1", "1717")
        check_instruction("MULRU $GP, $6", "1e67")

        # Randomly chosen instructions
        check_instruction("MULRU $3, $12", "13c7")
        check_instruction("MULRU $2, $TP", "12d7")
        check_instruction("MULRU $3, $TP", "13d7")
        check_instruction("MULRU $2, $12", "12c7")
        check_instruction("MULRU $TP, $2", "1d27")

    def test_DIV(self):
        """Test the DIV instruction"""

        # Top instructions
        check_instruction("DIV $1, $12", "11c8")
        check_instruction("DIV $8, $1", "1818")
        check_instruction("DIV $GP, $0", "1e08")
        check_instruction("DIV $9, $12", "19c8")
        check_instruction("DIV $12, $11", "1cb8")

        # Randomly chosen instructions
        check_instruction("DIV $6, $1", "1618")
        check_instruction("DIV $5, $11", "15b8")
        check_instruction("DIV $1, $9", "1198")
        check_instruction("DIV $GP, $GP", "1ee8")
        check_instruction("DIV $0, $1", "1018")

    def test_DIVU(self):
        """Test the DIVU instruction"""

        # Top instructions
        check_instruction("DIVU $1, $TP", "11d9")
        check_instruction("DIVU $4, $12", "14c9")
        check_instruction("DIVU $9, $1", "1919")
        check_instruction("DIVU $0, $10", "10a9")
        check_instruction("DIVU $11, $10", "1ba9")

        # Randomly chosen instructions
        check_instruction("DIVU $3, $9", "1399")
        check_instruction("DIVU $SP, $4", "1f49")
        check_instruction("DIVU $12, $5", "1c59")
        check_instruction("DIVU $8, $4", "1849")
        check_instruction("DIVU $8, $11", "18b9")

    def test_RI(self):
        """Test the (RI) instruction"""

        # No samples were found
        assert(True)

    def test_SSARB(self):
        """Test the SSARB instruction"""

        # Top instructions
        check_instruction("SSARB 0($8)", "108c")
        check_instruction("SSARB 3($GP)", "13ec")
        check_instruction("SSARB 0($3)", "103c")
        check_instruction("SSARB 0($TP)", "10dc")
        check_instruction("SSARB 3($0)", "130c")

    def test_EXTB(self):
        """Test the EXTB instruction"""

        # Top instructions
        check_instruction("EXTB $8", "180d")
        check_instruction("EXTB $0", "100d")
        check_instruction("EXTB $4", "140d")
        check_instruction("EXTB $11", "1b0d")
        check_instruction("EXTB $12", "1c0d")

        # Randomly chosen instructions
        check_instruction("EXTB $6", "160d")
        check_instruction("EXTB $10", "1a0d")
        check_instruction("EXTB $9", "190d")
        check_instruction("EXTB $7", "170d")
        check_instruction("EXTB $3", "130d")

    def test_EXTH(self):
        """Test the EXTH instruction"""

        # Top instructions
        check_instruction("EXTH $0", "102d")
        check_instruction("EXTH $11", "1b2d")
        check_instruction("EXTH $2", "122d")
        check_instruction("EXTH $6", "162d")
        check_instruction("EXTH $12", "1c2d")

    def test_EXTUB(self):
        """Test the EXTUB instruction"""

        # Top instructions
        check_instruction("EXTUB $2", "128d")
        check_instruction("EXTUB $11", "1b8d")
        check_instruction("EXTUB $12", "1c8d")
        check_instruction("EXTUB $0", "108d")
        check_instruction("EXTUB $4", "148d")

        # Randomly chosen instructions
        check_instruction("EXTUB $7", "178d")
        check_instruction("EXTUB $1", "118d")
        check_instruction("EXTUB $6", "168d")
        check_instruction("EXTUB $9", "198d")
        check_instruction("EXTUB $10", "1a8d")

    def test_EXTUH(self):
        """Test the EXTUH instruction"""

        # Top instructions
        check_instruction("EXTUH $4", "14ad")
        check_instruction("EXTUH $1", "11ad")
        check_instruction("EXTUH $12", "1cad")
        check_instruction("EXTUH $3", "13ad")
        check_instruction("EXTUH $0", "10ad")

        # Randomly chosen instructions
        check_instruction("EXTUH $7", "17ad")
        check_instruction("EXTUH $5", "15ad")
        check_instruction("EXTUH $2", "12ad")
        check_instruction("EXTUH $GP", "1ead")
        check_instruction("EXTUH $8", "18ad")

    def test_JMP(self):
        """Test the JMP instruction"""

        # Top instructions
        check_instruction("JMP $11", "10be")
        check_instruction("JMP $2", "102e")
        check_instruction("JMP $4", "104e")
        check_instruction("JMP $12", "10ce")
        check_instruction("JMP $1", "101e")

        # Randomly chosen instructions
        check_instruction("JMP $7", "107e")
        check_instruction("JMP $8", "108e")
        check_instruction("JMP $10", "10ae")
        check_instruction("JMP $9", "109e")
        check_instruction("JMP $3", "103e")

    def test_JSR(self):
        """Test the JSR instruction"""

        # Top instructions
        check_instruction("JSR $11", "10bf")
        check_instruction("JSR $0", "100f")
        check_instruction("JSR $3", "103f")
        check_instruction("JSR $12", "10cf")
        check_instruction("JSR $4", "104f")

        # Randomly chosen instructions
        check_instruction("JSR $9", "109f")
        check_instruction("JSR $10", "10af")
        check_instruction("JSR $6", "106f")
        check_instruction("JSR $5", "105f")
        check_instruction("JSR $7", "107f")

    def test_JSRV(self):
        """Test the JSRV instruction"""

        # Top instructions
        check_instruction("JSRV $GP", "18ef")
