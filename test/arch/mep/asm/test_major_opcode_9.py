# Toshiba MeP-c4 - Major Opcode #9 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor9(object):

    def test_ADD3(self):
        """Test the ADD3 instruction"""

        # Top instructions
        check_instruction("ADD3 $10, $4, $0", "940a")
        check_instruction("ADD3 $3, $0, $0", "9003")
        check_instruction("ADD3 $12, $4, $0", "940c")
        check_instruction("ADD3 $7, $12, $0", "9c07")
        check_instruction("ADD3 $TP, $4, $0", "940d")

        # Randomly chosen instructions
        check_instruction("ADD3 $4, $1, $9", "9194")
        check_instruction("ADD3 $7, $12, $9", "9c97")
        check_instruction("ADD3 $12, $9, $SP", "99fc")
        check_instruction("ADD3 $12, $TP, $7", "9d7c")
        check_instruction("ADD3 $4, $8, $SP", "98f4")
