# Toshiba MeP-c4 - Major Opcode #14 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor14(object):

    def test_BEQI(self):
        """Test the BEQI instruction"""

        # Top instructions
        check_instruction("BEQI $0, 0x5, 0x32", "e0500019")
        check_instruction("BEQI $4, 0x3, 0x3C", "e430001e")
        check_instruction("BEQI $4, 0x3, 0x20", "e4300010")
        check_instruction("BEQI $0, 0xA, 0x8", "e0a00004")
        check_instruction("BEQI $0, 0x0, 0xC4", "e0000062")

        # Randomly chosen instructions
        check_instruction("BEQI $0, 0x1, 0xFFFFFF6A", "e010ffb5")
        check_instruction("BEQI $1, 0x2, 0x20", "e1200010")
        check_instruction("BEQI $9, 0x0, 0xE0", "e9000070")
        check_instruction("BEQI $5, 0x8, 0xFFFF2696", "e580934b")
        check_instruction("BEQI $4, 0xA, 0x0", "e4a00000")

    def test_BEQ(self):
        """Test the BEQ instruction"""

        # Top instructions
        check_instruction("BEQ $12, $9, 0x3A", "ec91001d")
        check_instruction("BEQ $11, $10, 0x34", "eba1001a")
        check_instruction("BEQ $11, $12, 0x1E", "ebc1000f")
        check_instruction("BEQ $0, $0, 0x102", "e0010081")
        check_instruction("BEQ $7, $11, 0x56", "e7b1002b")

        # Randomly chosen instructions
        check_instruction("BEQ $11, $9, 0x26", "eb910013")
        check_instruction("BEQ $12, $11, 0x28", "ecb10014")
        check_instruction("BEQ $0, $0, 0xA12", "e0010509")
        check_instruction("BEQ $12, $3, 0x24", "ec310012")
        check_instruction("BEQ $10, $TP, 0xE", "ead10007")

        # Manually crafted
        check_instruction("BEQ $0, $12, 0xC67CA4", "e0c10024", offset=0xc67c5c)

    def test_BNEI(self):
        """Test the BNEI instruction"""

        # Top instructions
        check_instruction("BNEI $0, 0x1, 0x16", "e014000b")
        check_instruction("BNEI $11, 0x1, 0x1E", "eb14000f")
        check_instruction("BNEI $0, 0x1, 0xFFFFFFB4", "e014ffda")
        check_instruction("BNEI $4, 0x2, 0xDA", "e424006d")
        check_instruction("BNEI $12, 0x1, 0x8", "ec140004")

        # Randomly chosen instructions
        check_instruction("BNEI $12, 0x2, 0x6", "ec240003")
        check_instruction("BNEI $3, 0xC, 0xFFFF2D68", "e3c496b4")
        check_instruction("BNEI $4, 0x1, 0x10", "e4140008")
        check_instruction("BNEI $4, 0x1, 0x2A", "e4140015")
        check_instruction("BNEI $TP, 0xC, 0xF040", "edc47820")

    def test_BNE(self):
        """Test the BNE instruction"""

        # Top instructions
        check_instruction("BNE $TP, $7, 0xFFFFFFCC", "ed75ffe6")
        check_instruction("BNE $12, $TP, 0x6", "ecd50003")
        check_instruction("BNE $10, $11, 0x1C", "eab5000e")
        check_instruction("BNE $3, $0, 0xFFFF35A8", "e3059ad4")
        check_instruction("BNE $10, $3, 0xA", "ea350005")

        # Randomly chosen instructions
        check_instruction("BNE $4, $12, 0x8", "e4c50004")
        check_instruction("BNE $4, $1, 0x10", "e4150008")
        check_instruction("BNE $4, $12, 0x34", "e4c5001a")
        check_instruction("BNE $10, $11, 0x1C", "eab5000e")
        check_instruction("BNE $2, $11, 0xFFFFFFD8", "e2b5ffec")

    def test_BGEI(self):
        """Test the BGEI instruction"""

        # Top instructions
        check_instruction("BGEI $4, 0x3, 0xE", "e4380007")
        check_instruction("BGEI $11, 0x3, 0xFFFFFFF2", "eb38fff9")
        check_instruction("BGEI $TP, 0x0, 0x12", "ed080009")
        check_instruction("BGEI $12, 0x0, 0x22", "ec080011")
        check_instruction("BGEI $GP, 0xE, 0xFFFF2996", "eee894cb")

        # Randomly chosen instructions
        check_instruction("BGEI $4, 0x5, 0x52", "e4580029")
        check_instruction("BGEI $1, 0x4, 0xA", "e1480005")
        check_instruction("BGEI $8, 0x0, 0x10", "e8080008")
        check_instruction("BGEI $11, 0x3, 0xFFFFFFF2", "eb38fff9")

    def test_REPEAT(self):
        """Test the REPEAT instruction"""

        # Top instructions
        check_instruction("REPEAT $2, 0x2A", "e2090015")
        check_instruction("REPEAT $10, 0x16", "ea09000b")
        check_instruction("REPEAT $12, 0x6", "ec090003")
        check_instruction("REPEAT $11, 0x8", "eb090004")
        check_instruction("REPEAT $11, 0x6", "eb090003")

        # Randomly chosen instructions
        check_instruction("REPEAT $12, 0x24", "ec090012")
        check_instruction("REPEAT $9, 0x8", "e9090004")
        check_instruction("REPEAT $12, 0x14", "ec09000a")
        check_instruction("REPEAT $10, 0x6", "ea090003")
        check_instruction("REPEAT $10, 0x8", "ea090004")

    def test_EREPEAT(self):
        """Test the EREPEAT instruction"""

        # Top instructions
        check_instruction("EREPEAT 0xA", "e0190005")
        check_instruction("EREPEAT 0x24", "e0190012")
        check_instruction("EREPEAT 0x18", "e019000c")
        check_instruction("EREPEAT 0x12", "e0190009")
        check_instruction("EREPEAT 0x1C", "e019000e")

        # Randomly chosen instructions
        check_instruction("EREPEAT 0x12", "e0190009")
        check_instruction("EREPEAT 0x7E", "e019003f")
        check_instruction("EREPEAT 0x8", "e0190004")
        check_instruction("EREPEAT 0x1A", "e019000d")
        check_instruction("EREPEAT 0xC", "e0190006")

    def test_BLTI(self):
        """Test the BLTI instruction"""

        # Top instructions
        check_instruction("BLTI $12, 0x1, 0x26", "ec1c0013")
        check_instruction("BLTI $2, 0x2, 0xC", "e22c0006")
        check_instruction("BLTI $8, 0x0, 0x10", "e80c0008")
        check_instruction("BLTI $7, 0x1, 0x1A", "e71c000d")
        check_instruction("BLTI $12, 0x9, 0xEA52", "ec9c7529")

        # Randomly chosen instructions
        check_instruction("BLTI $4, 0x6, 0xFFFF25AE", "e46c92d7")
        check_instruction("BLTI $12, 0x1, 0x24", "ec1c0012")
        check_instruction("BLTI $9, 0xF, 0xFFFF1F0A", "e9fc8f85")
        check_instruction("BLTI $2, 0x2, 0x2A", "e22c0015")
        check_instruction("BLTI $12, 0x8, 0xFFFFFFCE", "ec8cffe7")

    def test_SW(self):
        """Test the SW instruction"""

        # Top instructions
        check_instruction("SW $4, (0x825BE0)", "e4e2825b")
        check_instruction("SW $4, (0x816834)", "e4368168")
        check_instruction("SW $4, (0x817318)", "e41a8173")
        check_instruction("SW $4, (0x826864)", "e4668268")
        check_instruction("SW $4, (0x826994)", "e4968269")

        # Randomly chosen instructions
        check_instruction("SW $1, (0x815864)", "e1668158")
        check_instruction("SW $1, (0x825BD8)", "e1da825b")
        check_instruction("SW $10, (0x6225AC)", "eaae6225")
        check_instruction("SW $GP, (0x9497CC)", "eece9497")
        check_instruction("SW $3, (0x6CEEF8)", "e3fa6cee")

    def test_LW(self):
        """Test the LW instruction"""

        # Top instructions
        check_instruction("LW $0, (0x8200)", "e0030082")
        check_instruction("LW $4, (0x816820)", "e4238168")
        check_instruction("LW $0, (0x8500)", "e0030085")
        check_instruction("LW $3, (0x816820)", "e3238168")
        check_instruction("LW $4, (0x81F0F0)", "e4f381f0")

        # Randomly chosen instructions
        check_instruction("LW $GP, (0x94CEE8)", "eeeb94ce")
        check_instruction("LW $4, (0x823608)", "e40b8236")
        check_instruction("LW $0, (0x815E40)", "e043815e")
        check_instruction("LW $0, (0x814D50)", "e053814d")
        check_instruction("LW $0, (0x8269C4)", "e0c78269")
