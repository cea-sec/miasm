# Toshiba MeP-c4 - Major Opcode #11 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor11(object):

    def test_BRA(self):
        """Test the BRA instruction"""

        # Top instructions
        check_instruction("BRA 0xFFFFF9B4", "b9b4")
        check_instruction("BRA 0x34", "b034")
        check_instruction("BRA 0x16", "b016")
        check_instruction("BRA 0x46", "b046")
        check_instruction("BRA 0xFFFFFF98", "bf98")

        # Randomly chosen instructions
        check_instruction("BRA 0x2AA", "b2aa")
        check_instruction("BRA 0x22", "b022")
        check_instruction("BRA 0x12", "b012")
        check_instruction("BRA 0x7FE", "b7fe")
        check_instruction("BRA 0x34", "b034")

    def test_BSR(self):
        """Test the BSR instruction"""

        # Top instructions
        check_instruction("BSR 0xFFFFFF22", "bf23", multi=2)
        check_instruction("BSR 0x716", "b717", multi=2)
        check_instruction("BSR 0xFFFFFE36", "be37", multi=2)
        check_instruction("BSR 0xFFFFFBB2", "bbb3", multi=2)
        check_instruction("BSR 0xFFFFFCCE", "bccf", multi=2)

        # Randomly chosen instructions
        check_instruction("BSR 0xFFFFFED4", "bed5", multi=2)
        check_instruction("BSR 0xFFFFFF62", "bf63", multi=2)
        check_instruction("BSR 0xFFFFFF36", "bf37", multi=2)
        check_instruction("BSR 0xFFFFFBD0", "bbd1", multi=2)
        check_instruction("BSR 0x5AA", "b5ab", multi=2)

        # Manually crafted
        check_instruction("BSR 0xC67BFA", "bfa3", offset=0xc67c58)
