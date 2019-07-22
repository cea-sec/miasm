# Toshiba MeP-c4 - Major Opcode #6 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor6(object):

    def test_ADD(self):
        """Test the ADD instruction"""

        # Top instructions
        check_instruction("ADD $SP, 12", "6f30")
        check_instruction("ADD $SP, -12", "6fd0")
        check_instruction("ADD $SP, 8", "6f20")
        check_instruction("ADD $SP, -8", "6fe0")
        check_instruction("ADD $4, 1", "6404")

        # Randomly chosen instructions
        check_instruction("ADD $2, -26", "6298")
        check_instruction("ADD $TP, 7", "6d1c")
        check_instruction("ADD $SP, 26", "6f68")
        check_instruction("ADD $8, -9", "68dc")
        check_instruction("ADD $6, 16", "6640")

    def test_SLT3(self):
        """Test the SLT3 instruction"""

        # Top instructions
        check_instruction("SLT3 $0, $4, 0xC", "6461", multi=2)
        check_instruction("SLT3 $0, $9, 0xC", "6961", multi=2)
        check_instruction("SLT3 $0, $12, 0xC", "6c61", multi=2)
        check_instruction("SLT3 $0, $GP, 0xC", "6e61", multi=2)
        check_instruction("SLT3 $0, $GP, 0xD", "6e69", multi=2)

        # Randomly chosen instructions
        check_instruction("SLT3 $0, $8, 0x14", "68a1", multi=2)
        check_instruction("SLT3 $0, $6, 0x0", "6601", multi=2)
        check_instruction("SLT3 $0, $2, 0xB", "6259", multi=2)
        check_instruction("SLT3 $0, $SP, 0x15", "6fa9", multi=2)
        check_instruction("SLT3 $0, $7, 0x14", "67a1", multi=2)

    def test_SRL(self):
        """Test the SRL instruction"""

        # Top instructions
        check_instruction("SRL $SP, 0xE", "6f72")
        check_instruction("SRL $12, 0x4", "6c22")
        check_instruction("SRL $12, 0x8", "6c42")
        check_instruction("SRL $12, 0x2", "6c12")
        check_instruction("SRL $5, 0xE", "6572")

        # Randomly chosen instructions
        check_instruction("SRL $3, 0x16", "63b2")
        check_instruction("SRL $0, 0x1F", "60fa")
        check_instruction("SRL $5, 0xF", "657a")
        check_instruction("SRL $6, 0xE", "6672")
        check_instruction("SRL $6, 0x1B", "66da")

    def test_SRA(self):
        """Test the SRA instruction"""

        # Top instructions
        check_instruction("SRA $1, 0xC", "6163")
        check_instruction("SRA $SP, 0xC", "6f63")
        check_instruction("SRA $5, 0xE", "6573")
        check_instruction("SRA $4, 0x1", "640b")
        check_instruction("SRA $12, 0x8", "6c43")

        # Randomly chosen instructions
        check_instruction("SRA $0, 0x1B", "60db")
        check_instruction("SRA $10, 0x17", "6abb")
        check_instruction("SRA $GP, 0xB", "6e5b")
        check_instruction("SRA $SP, 0x17", "6fbb")
        check_instruction("SRA $7, 0x17", "67bb")

    def test_SLTU3(self):
        """Test the SLTU3 instruction"""

        # Top instructions
        check_instruction("SLTU3 $0, $0, 0x1", "600d", multi=2)
        check_instruction("SLTU3 $0, $5, 0xD", "656d", multi=2)
        check_instruction("SLTU3 $0, $12, 0x1", "6c0d", multi=2)
        check_instruction("SLTU3 $0, $GP, 0xC", "6e65", multi=2)
        check_instruction("SLTU3 $0, $4, 0x4", "6425", multi=2)

        # Randomly chosen instructions
        check_instruction("SLTU3 $0, $9, 0x9", "694d", multi=2)
        check_instruction("SLTU3 $0, $TP, 0xF", "6d7d", multi=2)
        check_instruction("SLTU3 $0, $10, 0x1D", "6aed", multi=2)
        check_instruction("SLTU3 $0, $6, 0x10", "6685", multi=2)
        check_instruction("SLTU3 $0, $10, 0x1C", "6ae5", multi=2)

    def test_SLL(self):
        """Test the SLL instruction"""

        # Top instructions
        check_instruction("SLL $6, 0xC", "6666")
        check_instruction("SLL $SP, 0xD", "6f6e")
        check_instruction("SLL $0, 0x5", "602e")
        check_instruction("SLL $0, 0x2", "6016")
        check_instruction("SLL $0, 0x3", "601e")

        # Randomly chosen instructions
        check_instruction("SLL $8, 0x16", "68b6")
        check_instruction("SLL $SP, 0x4", "6f26")
        check_instruction("SLL $4, 0x19", "64ce")
        check_instruction("SLL $12, 0xA", "6c56")
        check_instruction("SLL $12, 0x17", "6cbe")

    def test_SLL3(self):
        """Test the SLL3 instruction"""

        # Top instructions
        check_instruction("SLL3 $0, $4, 0x5", "642f")
        check_instruction("SLL3 $0, $4, 0x3", "641f")
        check_instruction("SLL3 $0, $10, 0x8", "6a47")
        check_instruction("SLL3 $0, $GP, 0xD", "6e6f")
        check_instruction("SLL3 $0, $1, 0x3", "611f")

        # Randomly chosen instructions
        check_instruction("SLL3 $0, $11, 0x16", "6bb7")
        check_instruction("SLL3 $0, $TP, 0xD", "6d6f")
        check_instruction("SLL3 $0, $10, 0xB", "6a5f")
        check_instruction("SLL3 $0, $7, 0x6", "6737")
        check_instruction("SLL3 $0, $2, 0xF", "627f")
