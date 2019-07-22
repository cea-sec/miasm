# Toshiba MeP-c4 - Major Opcode #2 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor2(object):

    def test_BSETM(self):
        """Test the BSETM instruction"""

        # Top instructions
        check_instruction("BSETM ($0), 0x0", "2000")
        check_instruction("BSETM ($0), 0x5", "2500")
        check_instruction("BSETM ($3), 0x0", "2030")
        check_instruction("BSETM ($2), 0x5", "2520")
        check_instruction("BSETM ($2), 0x0", "2020")

        # Randomly chosen instructions
        check_instruction("BSETM ($8), 0x4", "2480")
        check_instruction("BSETM ($5), 0x5", "2550")
        check_instruction("BSETM ($5), 0x0", "2050")
        check_instruction("BSETM ($0), 0x7", "2700")
        check_instruction("BSETM ($TP), 0x0", "20d0")

    def test_BCLRM(self):
        """Test the BCLRM instruction"""

        # Top instructions
        check_instruction("BCLRM ($3), 0x0", "2031")
        check_instruction("BCLRM ($2), 0x0", "2021")
        check_instruction("BCLRM ($1), 0x2", "2211")
        check_instruction("BCLRM ($2), 0x1", "2121")
        check_instruction("BCLRM ($0), 0x0", "2001")

        # Randomly chosen instructions
        check_instruction("BCLRM ($6), 0x4", "2461")
        check_instruction("BCLRM ($7), 0x4", "2471")
        check_instruction("BCLRM ($6), 0x5", "2561")
        check_instruction("BCLRM ($0), 0x2", "2201")
        check_instruction("BCLRM ($0), 0x1", "2101")

    def test_BNOTM(self):
        """Test the BNOTM instruction"""

        # Top instructions
        check_instruction("BNOTM ($7), 0x1", "2172")
        check_instruction("BNOTM ($2), 0x1", "2122")
        check_instruction("BNOTM ($SP), 0x0", "20f2")
        check_instruction("BNOTM ($3), 0x0", "2032")
        check_instruction("BNOTM ($7), 0x0", "2072")

        # Randomly chosen instructions
        check_instruction("BNOTM ($6), 0x4", "2462")
        check_instruction("BNOTM ($2), 0x2", "2222")
        check_instruction("BNOTM ($0), 0x1", "2102")
        check_instruction("BNOTM ($2), 0x0", "2022")
        check_instruction("BNOTM ($1), 0x2", "2212")

    def test_BTSTM(self):
        """Test the BTSTM instruction"""

        # Top instructions
        check_instruction("BTSTM $0, ($12), 0x3", "23c3")
        check_instruction("BTSTM $0, ($6), 0x0", "2063")
        check_instruction("BTSTM $0, ($3), 0x0", "2033")
        check_instruction("BTSTM $0, ($0), 0x0", "2003")
        check_instruction("BTSTM $0, ($7), 0x0", "2073")

        # Randomly chosen instructions
        check_instruction("BTSTM $0, ($2), 0x4", "2423")
        check_instruction("BTSTM $0, ($12), 0x6", "26c3")
        check_instruction("BTSTM $0, ($4), 0x5", "2543")
        check_instruction("BTSTM $0, ($9), 0x1", "2193")
        check_instruction("BTSTM $0, ($0), 0x4", "2403")

    def test_TAS(self):
        """Test the TAS instruction"""

        # Top instructions
        check_instruction("TAS $GP, ($6)", "2e64")
        check_instruction("TAS $12, ($TP)", "2cd4")
        check_instruction("TAS $9, ($6)", "2964")
        check_instruction("TAS $0, ($7)", "2074")
        check_instruction("TAS $0, ($6)", "2064")

        # Randomly chosen instructions
        check_instruction("TAS $1, ($6)", "2164")
        check_instruction("TAS $11, ($3)", "2b34")
        check_instruction("TAS $1, ($0)", "2104")
        check_instruction("TAS $8, ($7)", "2874")
        check_instruction("TAS $8, ($4)", "2844")

    def test_SL1AD3(self):
        """Test the SL1AD3 instruction"""

        # Top instructions
        check_instruction("SL1AD3 $0, $1, $4", "2146")
        check_instruction("SL1AD3 $0, $11, $11", "2bb6")
        check_instruction("SL1AD3 $0, $4, $4", "2446")
        check_instruction("SL1AD3 $0, $3, $3", "2336")
        check_instruction("SL1AD3 $0, $12, $12", "2cc6")

        # Randomly chosen instructions
        check_instruction("SL1AD3 $0, $5, $4", "2546")
        check_instruction("SL1AD3 $0, $11, $4", "2b46")
        check_instruction("SL1AD3 $0, $GP, $3", "2e36")
        check_instruction("SL1AD3 $0, $6, $3", "2636")
        check_instruction("SL1AD3 $0, $3, $4", "2346")

    def test_SL2AD3(self):
        """Test the SL2AD3 instruction"""

        # Top instructions
        check_instruction("SL2AD3 $0, $0, $4", "2047")
        check_instruction("SL2AD3 $0, $12, $7", "2c77")
        check_instruction("SL2AD3 $0, $7, $4", "2747")
        check_instruction("SL2AD3 $0, $12, $0", "2c07")
        check_instruction("SL2AD3 $0, $11, $4", "2b47")

        # Randomly chosen instructions
        check_instruction("SL2AD3 $0, $10, $SP", "2af7")
        check_instruction("SL2AD3 $0, $4, $8", "2487")
        check_instruction("SL2AD3 $0, $10, $12", "2ac7")
        check_instruction("SL2AD3 $0, $9, $TP", "29d7")
        check_instruction("SL2AD3 $0, $5, $10", "25a7")

    def test_SRL(self):
        """Test the SRL instruction"""

        # Top instructions
        check_instruction("SRL $0, $4", "204c")
        check_instruction("SRL $3, $7", "237c")
        check_instruction("SRL $0, $2", "202c")
        check_instruction("SRL $0, $6", "206c")
        check_instruction("SRL $SP, $3", "2f3c")

        # Randomly chosen instructions
        check_instruction("SRL $9, $6", "296c")
        check_instruction("SRL $2, $7", "227c")
        check_instruction("SRL $9, $12", "29cc")
        check_instruction("SRL $12, $9", "2c9c")
        check_instruction("SRL $12, $2", "2c2c")

    def test_SRA(self):
        """Test the SRA instruction"""

        # Top instructions
        check_instruction("SRA $0, $6", "206d")
        check_instruction("SRA $TP, $1", "2d1d")
        check_instruction("SRA $5, $3", "253d")
        check_instruction("SRA $0, $3", "203d")
        check_instruction("SRA $0, $5", "205d")

        # Randomly chosen instructions
        check_instruction("SRA $11, $2", "2b2d")
        check_instruction("SRA $9, $6", "296d")
        check_instruction("SRA $4, $8", "248d")
        check_instruction("SRA $8, $3", "283d")
        check_instruction("SRA $3, $0", "230d")

    def test_SLL(self):
        """Test the SLL instruction"""

        # Top instructions
        check_instruction("SLL $10, $1", "2a1e")
        check_instruction("SLL $12, $9", "2c9e")
        check_instruction("SLL $0, $3", "203e")
        check_instruction("SLL $5, $2", "252e")
        check_instruction("SLL $0, $6", "206e")

        # Randomly chosen instructions
        check_instruction("SLL $4, $0", "240e")
        check_instruction("SLL $SP, $10", "2fae")
        check_instruction("SLL $0, $4", "204e")
        check_instruction("SLL $7, $2", "272e")
        check_instruction("SLL $3, $2", "232e")

    def test_FSFT(self):
        """Test the FSFT instruction"""

        # Top instructions
        check_instruction("FSFT $0, $2", "202f")
        check_instruction("FSFT $0, $1", "201f")
        check_instruction("FSFT $9, $SP", "29ff")
        check_instruction("FSFT $SP, $2", "2f2f")
        check_instruction("FSFT $0, $6", "206f")

        # Randomly chosen instructions
        check_instruction("FSFT $SP, $6", "2f6f")
        check_instruction("FSFT $0, $9", "209f")
        check_instruction("FSFT $5, $9", "259f")
        check_instruction("FSFT $0, $TP", "20df")
        check_instruction("FSFT $0, $GP", "20ef")
