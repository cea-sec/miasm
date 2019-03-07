# Toshiba MeP-c4 - Major Opcode #8 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor8(object):

    def test_SB(self):
        """Test the SB instruction"""

        # Top instructions
        check_instruction("SB $4, 0x2($TP)", "8402", multi=2)
        check_instruction("SB $4, 0x4B($TP)", "844b", multi=2)
        check_instruction("SB $4, 0x3($TP)", "8403", multi=2)
        check_instruction("SB $4, 0x1($TP)", "8401", multi=2)
        check_instruction("SB $0, 0x3($TP)", "8003", multi=2)

        # Randomly chosen instructions
        check_instruction("SB $2, 0x65($TP)", "8265", multi=2)
        check_instruction("SB $5, 0x48($TP)", "8548", multi=2)
        check_instruction("SB $7, 0x77($TP)", "8777", multi=2)
        check_instruction("SB $1, 0x49($TP)", "8149", multi=2)
        check_instruction("SB $4, 0x20($TP)", "8420", multi=2)

    def test_SH(self):
        """Test the SH instruction"""

        # Top instructions
        check_instruction("SH $0, 0x18($TP)", "8098", multi=2)
        check_instruction("SH $4, 0x10($TP)", "8490", multi=2)
        check_instruction("SH $4, 0xE($TP)", "848e", multi=2)
        check_instruction("SH $4, 0x4($TP)", "8484", multi=2)
        check_instruction("SH $4, 0xC($TP)", "848c", multi=2)

        # Randomly chosen instructions
        check_instruction("SH $7, 0x3A($TP)", "87ba", multi=2)
        check_instruction("SH $2, 0x36($TP)", "82b6", multi=2)
        check_instruction("SH $1, 0x76($TP)", "81f6", multi=2)
        check_instruction("SH $7, 0x74($TP)", "87f4", multi=2)
        check_instruction("SH $7, 0x7E($TP)", "87fe", multi=2)

    def test_LB(self):
        """Test the LB instruction"""

        # Top instructions
        check_instruction("LB $4, 0x1($TP)", "8c01", multi=2)
        check_instruction("LB $4, 0x27($TP)", "8c27", multi=2)
        check_instruction("LB $4, 0x4($TP)", "8c04", multi=2)
        check_instruction("LB $4, 0x1A($TP)", "8c1a", multi=2)
        check_instruction("LB $4, 0x6($TP)", "8c06", multi=2)

        # Randomly chosen instructions
        check_instruction("LB $4, 0x59($TP)", "8c59", multi=2)
        check_instruction("LB $7, 0x53($TP)", "8f53", multi=2)
        check_instruction("LB $6, 0x62($TP)", "8e62", multi=2)
        check_instruction("LB $6, 0x53($TP)", "8e53", multi=2)
        check_instruction("LB $0, 0x34($TP)", "8834", multi=2)

    def test_LH(self):
        """Test the LH instruction"""

        # Top instructions
        check_instruction("LH $4, 0x18($TP)", "8c98", multi=2)
        check_instruction("LH $4, 0x10($TP)", "8c90", multi=2)
        check_instruction("LH $4, 0x28($TP)", "8ca8", multi=2)
        check_instruction("LH $4, 0x6($TP)", "8c86", multi=2)
        check_instruction("LH $4, 0x4($TP)", "8c84", multi=2)

        # Randomly chosen instructions
        check_instruction("LH $7, 0x28($TP)", "8fa8", multi=2)
        check_instruction("LH $4, 0x16($TP)", "8c96", multi=2)
        check_instruction("LH $0, 0x56($TP)", "88d6", multi=2)
        check_instruction("LH $4, 0x40($TP)", "8cc0", multi=2)
        check_instruction("LH $7, 0x2A($TP)", "8faa", multi=2)

    def test_LHU(self):
        """Test the LHU instruction"""

        # Top instructions
        check_instruction("LHU $4, 0x4($TP)", "8c85", multi=2)
        check_instruction("LHU $4, 0x28($TP)", "8ca9", multi=2)
        check_instruction("LHU $4, 0xC($TP)", "8c8d", multi=2)
        check_instruction("LHU $4, 0x10($TP)", "8c91", multi=2)
        check_instruction("LHU $3, 0xC($TP)", "8b8d", multi=2)

        # Randomly chosen instructions
        check_instruction("LHU $3, 0x54($TP)", "8bd5", multi=2)
        check_instruction("LHU $7, 0x66($TP)", "8fe7", multi=2)
        check_instruction("LHU $2, 0x6E($TP)", "8aef", multi=2)
        check_instruction("LHU $2, 0x36($TP)", "8ab7", multi=2)
        check_instruction("LHU $3, 0x78($TP)", "8bf9", multi=2)
