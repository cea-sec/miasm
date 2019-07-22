# Toshiba MeP-c4 - Major Opcode #4 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor4(object):

    def test_ADD3(self):
        """Test the ADD3 instruction"""

        # Top instructions
        check_instruction("ADD3 $2, $SP, 0x20", "4220", multi=2)
        check_instruction("ADD3 $1, $SP, 0x14", "4114", multi=2)
        check_instruction("ADD3 $SP, $SP, 0x2C", "4f2c", multi=2)
        check_instruction("ADD3 $1, $SP, 0x20", "4120", multi=2)
        check_instruction("ADD3 $SP, $SP, 0x24", "4f24", multi=2)
        check_instruction("ADD3 $2, $SP, 0x4", "4204", multi=2)
        check_instruction("ADD3 $2, $SP, 0x8", "4208", multi=2)
        check_instruction("ADD3 $1, $SP, 0x8", "4108", multi=2)
        check_instruction("ADD3 $SP, $SP, 0x20", "4f20", multi=2)
        check_instruction("ADD3 $1, $SP, 0x4", "4104", multi=2)

        # Randomly chosen instructions
        check_instruction("ADD3 $11, $SP, 0x38", "4b38", multi=2)
        check_instruction("ADD3 $5, $SP, 0x30", "4530", multi=2)
        check_instruction("ADD3 $TP, $SP, 0x38", "4d38", multi=2)
        check_instruction("ADD3 $4, $SP, 0x70", "4470", multi=2)
        check_instruction("ADD3 $SP, $SP, 0xC", "4f0c", multi=2)
        check_instruction("ADD3 $10, $SP, 0x10", "4a10", multi=2)
        check_instruction("ADD3 $6, $SP, 0x7C", "467c", multi=2)
        check_instruction("ADD3 $11, $SP, 0x14", "4b14", multi=2)
        check_instruction("ADD3 $7, $SP, 0x3C", "473c", multi=2)
        check_instruction("ADD3 $SP, $SP, 0x48", "4f48", multi=2)

    def test_SW(self):
        """Test the SW instruction"""

        # Top instructions
        check_instruction("SW $6, 0x4($SP)", "4606", multi=2)
        check_instruction("SW $0, 0x4($SP)", "4006", multi=2)
        check_instruction("SW $8, 0x10($SP)", "4812", multi=2)
        check_instruction("SW $7, 0x8($SP)", "470a", multi=2)
        check_instruction("SW $8, 0x8($SP)", "480a", multi=2)
        check_instruction("SW $7, 0x4($SP)", "4706", multi=2)
        check_instruction("SW $8, 0xC($SP)", "480e", multi=2)
        check_instruction("SW $TP, 0x4($SP)", "4d06", multi=2)
        check_instruction("SW $8, 0x4($SP)", "4806", multi=2)
        check_instruction("SW $4, 0x40($SP)", "4442", multi=2)

        # Randomly chosen instructions
        check_instruction("SW $4, 0x30($SP)", "4432", multi=2)
        check_instruction("SW $9, 0x3C($SP)", "493e", multi=2)
        check_instruction("SW $6, 0x68($SP)", "466a", multi=2)
        check_instruction("SW $0, 0x40($TP)", "40c2", multi=2)
        check_instruction("SW $9, 0x68($SP)", "496a", multi=2)
        check_instruction("SW $4, 0x4($SP)", "4406", multi=2)
        check_instruction("SW $2, 0x18($SP)", "421a", multi=2)
        check_instruction("SW $10, 0x60($SP)", "4a62", multi=2)
        check_instruction("SW $GP, 0x14($SP)", "4e16", multi=2)
        check_instruction("SW $1, 0x20($SP)", "4122", multi=2)

    def test_LW(self):
        """Test the LW instruction"""

        # Top instructions
        check_instruction("LW $1, 0x8($SP)", "410b", multi=2)
        check_instruction("LW $6, 0x4($SP)", "4607", multi=2)
        check_instruction("LW $8, 0x10($SP)", "4813", multi=2)
        check_instruction("LW $1, 0x4($SP)", "4107", multi=2)
        check_instruction("LW $7, 0x8($SP)", "470b", multi=2)
        check_instruction("LW $8, 0x8($SP)", "480b", multi=2)
        check_instruction("LW $7, 0x4($SP)", "4707", multi=2)
        check_instruction("LW $8, 0xC($SP)", "480f", multi=2)
        check_instruction("LW $TP, 0x4($SP)", "4d07", multi=2)
        check_instruction("LW $8, 0x4($SP)", "4807", multi=2)

        # Randomly chosen instructions
        check_instruction("LW $9, 0x4C($SP)", "494f", multi=2)
        check_instruction("LW $2, 0x44($TP)", "42c7", multi=2)
        check_instruction("LW $6, 0x58($SP)", "465b", multi=2)
        check_instruction("LW $SP, 0x74($SP)", "4f77", multi=2)
        check_instruction("LW $4, 0x68($TP)", "44eb", multi=2)
        check_instruction("LW $3, 0x34($TP)", "43b7", multi=2)
        check_instruction("LW $6, 0x28($SP)", "462b", multi=2)
        check_instruction("LW $1, 0x68($TP)", "41eb", multi=2)
        check_instruction("LW $9, 0x28($SP)", "492b", multi=2)
        check_instruction("LW $12, 0x30($SP)", "4c33", multi=2)

    def test_LBU(self):
        """Test the LBU instruction"""

        # Top instructions
        check_instruction("LBU $1, 0x3F($TP)", "49bf", multi=2)
        check_instruction("LBU $2, 0x3F($TP)", "4abf", multi=2)
        check_instruction("LBU $4, 0x3F($TP)", "4cbf", multi=2)
        check_instruction("LBU $4, 0x9($TP)", "4c89", multi=2)
        check_instruction("LBU $4, 0x25($TP)", "4ca5", multi=2)
        check_instruction("LBU $4, 0xA($TP)", "4c8a", multi=2)
        check_instruction("LBU $4, 0x2($TP)", "4c82", multi=2)
        check_instruction("LBU $4, 0x1($TP)", "4c81", multi=2)
        check_instruction("LBU $4, 0x5($TP)", "4c85", multi=2)
        check_instruction("LBU $4, 0x6($TP)", "4c86", multi=2)

        # Randomly chosen instructions
        check_instruction("LBU $4, 0x21($TP)", "4ca1", multi=2)
        check_instruction("LBU $4, 0x22($TP)", "4ca2", multi=2)
        # Note: the following instruction can not be easily manipulated due to
        # expressions simplifications performed by miasm at assembly and
        # disassembly, i.e. ExprMem($TP + 0) is simplified into ExprMem($TP)
        #check_instruction("LBU $6, 0x0($TP)", "4e80", multi=2)
        check_instruction("LBU $7, 0x3C($TP)", "4fbc", multi=2)
        check_instruction("LBU $2, 0x4($TP)", "4a84", multi=2)
        check_instruction("LBU $7, 0x57($TP)", "4fd7", multi=2)
        check_instruction("LBU $3, 0x66($TP)", "4be6", multi=2)
        check_instruction("LBU $4, 0x31($TP)", "4cb1", multi=2)
        check_instruction("LBU $6, 0x59($TP)", "4ed9", multi=2)
        check_instruction("LBU $5, 0x66($TP)", "4de6", multi=2)
