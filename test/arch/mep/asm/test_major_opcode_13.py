# Toshiba MeP-c4 - Major Opcode #13 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor13(object):

    def test_MOVU(self):
        """Test the MOVU instruction"""

        # Top instructions
        check_instruction("MOVU $0, 0xC901", "d00100c9", multi=2)
        check_instruction("MOVU $4, 0xC7C708", "d408c7c7", multi=2)
        check_instruction("MOVU $4, 0x202EFE", "d4fe202e", multi=2)
        check_instruction("MOVU $4, 0x202EE0", "d4e0202e", multi=2)
        check_instruction("MOVU $4, 0xC12A8E", "d48ec12a", multi=2)

        # Randomly chosen instructions
        check_instruction("MOVU $4, 0x1D7100", "d4001d71", multi=2)
        check_instruction("MOVU $4, 0x8A395B", "d45b8a39", multi=2)
        check_instruction("MOVU $4, 0x67A3E6", "d4e667a3", multi=2)
        check_instruction("MOVU $2, 0xCA2D02", "d202ca2d", multi=2)
        check_instruction("MOVU $1, 0xCE820C", "d10cce82", multi=2)

    def test_BCPEQ(self):
        """Test the BCPEQ instruction"""

        # Top instructions
        check_instruction("BCPEQ 0xE, 0xA504", "d8e45282")
        check_instruction("BCPEQ 0x4, 0xD5F4", "d8446afa")
        check_instruction("BCPEQ 0xC, 0xAADA", "d8c4556d")
        check_instruction("BCPEQ 0x7, 0xFFFF18F6", "d8748c7b")

        # Randomly chosen instructions
        check_instruction("BCPEQ 0x6, 0xFFFF18CA", "d8648c65")

    def test_BCPNE(self):
        """Test the BCPNE instruction"""

        # Top instructions
        check_instruction("BCPNE 0xF, 0x9DEA", "d8f54ef5")
        check_instruction("BCPNE 0x5, 0xFFFF18A4", "d8558c52")
        check_instruction("BCPNE 0x7, 0xFFFF18FA", "d8758c7d")
        check_instruction("BCPNE 0x1, 0x674E", "d81533a7")

        # Randomly chosen instructions
        check_instruction("BCPNE 0xB, 0xD820", "d8b56c10")
        check_instruction("BCPNE 0x8, 0xFFFF1922", "d8858c91")
        check_instruction("BCPNE 0xD, 0xA6C8", "d8d55364")
        check_instruction("BCPNE 0xA, 0xBDFE", "d8a55eff")
        check_instruction("BCPNE 0x8, 0xFFFF1920", "d8858c90")

    def test_BCPAT(self):
        """Test the BCPAT instruction"""

        # Top instructions
        check_instruction("BCPAT 0xE, 0xA526", "d8e65293")
        check_instruction("BCPAT 0xF, 0x9E4A", "d8f64f25")
        check_instruction("BCPAT 0x8, 0xFFFF1922", "d8868c91")
        check_instruction("BCPAT 0xC, 0x9D88", "d8c64ec4")
        check_instruction("BCPAT 0x7, 0xFFFF18FA", "d8768c7d")

        # Randomly chosen instructions
        check_instruction("BCPAT 0x6, 0xFFFF18D0", "d8668c68")
        check_instruction("BCPAT 0x7, 0xFFFF18FC", "d8768c7e")
        check_instruction("BCPAT 0x6, 0xFFFF18CE", "d8668c67")
        check_instruction("BCPAT 0x5, 0xFFFF18A8", "d8568c54")
        check_instruction("BCPAT 0xB, 0xADBE", "d8b656df")

    def test_BCPAF(self):
        """Test the BCPAF instruction"""

        # Top instructions
        check_instruction("BCPAF 0xE, 0xA304", "d8e75182")
        check_instruction("BCPAF 0x5, 0xFFFF18AA", "d8578c55")
        check_instruction("BCPAF 0xB, 0xFFFF01C8", "d8b780e4")
        check_instruction("BCPAF 0xF, 0x9E4E", "d8f74f27")
        check_instruction("BCPAF 0xD, 0xA412", "d8d75209")

        # Randomly chosen instructions
        check_instruction("BCPAF 0xB, 0xFFFF01CA", "d8b780e5")
        check_instruction("BCPAF 0xA, 0x9C2A", "d8a74e15")
        check_instruction("BCPAF 0x8, 0xFFFF1924", "d8878c92")
        check_instruction("BCPAF 0x6, 0xFFFF18D2", "d8678c69")
        check_instruction("BCPAF 0xC, 0xA71A", "d8c7538d")

    def test_JMP(self):
        """Test the JMP instruction"""

        # Top instructions
        check_instruction("JMP 0xC9706A", "db58c970")
        check_instruction("JMP 0xC7517A", "dbd8c751")
        check_instruction("JMP 0x4", "d8280000")
        check_instruction("JMP 0x80FF2C", "d96880ff")
        check_instruction("JMP 0x814174", "dba88141")

        # Randomly chosen instructions
        check_instruction("JMP 0xC3F782", "dc18c3f7")
        check_instruction("JMP 0xC814", "d8a800c8")
        check_instruction("JMP 0x9079EE", "df789079")
        check_instruction("JMP 0xC6982A", "d958c698")
        check_instruction("JMP 0xC3986C", "db68c398")

        # Manually crafted
        check_instruction("JMP 0xC3F782", "dc18c3f7", offset=0x1024)

    def test_BSR(self):
        """Test the BSR instruction"""

        # Top instructions
        check_instruction("BSR 0xFFFEFB20", "d909fefb", multi=2)
        check_instruction("BSR 0x603A92", "dc99603a", multi=2)
        check_instruction("BSR 0xAF64", "db2900af", multi=2)
        check_instruction("BSR 0x36C4", "de290036", multi=2)
        check_instruction("BSR 0xFFFC6AC4", "de29fc6a", multi=2)

        # Randomly chosen instructions
        check_instruction("BSR 0x22C", "d9690002", multi=2)
        check_instruction("BSR 0x5FEE6A", "db595fee", multi=2)
        check_instruction("BSR 0x4AFF4", "dfa904af", multi=2)
        check_instruction("BSR 0x1B126", "d93901b1", multi=2)
        check_instruction("BSR 0xFFFB3F76", "dbb9fb3f", multi=2)

        # Manually crafted
        check_instruction("BSR 0xC7FB84", "d869017f", offset=0xc67c78)

    def test_BSRV(self):
        """Test the BSRV instruction"""

        # Top instructions
        check_instruction("BSRV 0x8E8488", "dc4b8e84")
        check_instruction("BSRV 0x8E396E", "db7b8e39")
        check_instruction("BSRV 0xF785CE", "de7bf785")
        check_instruction("BSRV 0x6509F4", "dfab6509")
        check_instruction("BSRV 0x8F50C8", "de4b8f50")

        # Randomly chosen instructions
        check_instruction("BSRV 0x544BF6", "dfbb544b")
        check_instruction("BSRV 0x8CCA2A", "d95b8cca")
        check_instruction("BSRV 0x4F681E", "d8fb4f68")
        check_instruction("BSRV 0x8EAA8C", "dc6b8eaa")
        check_instruction("BSRV 0x30A030", "d98b30a0")
