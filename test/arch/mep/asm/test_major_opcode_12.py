# Toshiba MeP-c4 - Major Opcode #12 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor12(object):

    def test_ADD3(self):
        """Test the ADD3 instruction"""

        # Top instructions
        check_instruction("ADD3 $SP, $SP, -64", "cff0ffc0")
        check_instruction("ADD3 $SP, $SP, -44", "cff0ffd4")
        check_instruction("ADD3 $SP, $SP, -36", "cff0ffdc")
        check_instruction("ADD3 $12, $4, 0x48", "cc400048")
        check_instruction("ADD3 $SP, $SP, -68", "cff0ffbc")

        # Randomly chosen instructions
        check_instruction("ADD3 $12, $SP, 0x6", "ccf00006")
        check_instruction("ADD3 $12, $12, 0x3E4", "ccc003e4")
        check_instruction("ADD3 $7, $5, -31912", "c7508358")
        check_instruction("ADD3 $1, $8, 0x54", "c1800054")
        check_instruction("ADD3 $2, $8, 0x28", "c2800028")

    def test_MOV(self):
        """Test the MOV instruction"""

        # Top instructions
        check_instruction("MOV $11, 136", "cb010088", multi=2)
        check_instruction("MOV $10, 170", "ca0100aa", multi=2)
        check_instruction("MOV $2, 130", "c2010082", multi=2)
        check_instruction("MOV $2, 139", "c201008b", multi=2)
        check_instruction("MOV $0, 194", "c00100c2", multi=2)

        # Randomly chosen instructions
        check_instruction("MOV $12, 239", "cc0100ef", multi=2)
        check_instruction("MOV $1, 136", "c1010088", multi=2)
        check_instruction("MOV $3, 168", "c30100a8", multi=2)
        check_instruction("MOV $10, 133", "ca010085", multi=2)
        check_instruction("MOV $11, 32640", "cb017f80", multi=2)

    def test_MOVU(self):
        """Test the MOVU instruction"""

        # Top instructions
        check_instruction("MOVU $2, 0x0", "c2110000", multi=2)
        check_instruction("MOVU $2, 0x8002", "c2118002")
        check_instruction("MOVU $10, 0x8106", "ca118106")
        check_instruction("MOVU $11, 0x8105", "cb118105")
        check_instruction("MOVU $11, 0x8106", "cb118106")

        # Randomly chosen instructions
        check_instruction("MOVU $9, 0x8126", "c9118126")
        check_instruction("MOVU $7, 0xFF00", "c711ff00")
        check_instruction("MOVU $2, 0xE200", "c211e200")
        check_instruction("MOVU $10, 0xE102", "ca11e102")
        check_instruction("MOVU $11, 0xD6D8", "cb11d6d8")

    def test_MOVH(self):
        """Test the MOVH instruction"""

        # Top instructions
        check_instruction("MOVH $11, 0x8000", "cb218000")
        check_instruction("MOVH $11, 0x1000", "cb211000")
        check_instruction("MOVH $11, 0x100", "cb210100")
        check_instruction("MOVH $1, 0x101", "c1210101")
        check_instruction("MOVH $12, 0x81", "cc210081")

        # Randomly chosen instructions
        check_instruction("MOVH $4, 0xF4D5", "c421f4d5")
        check_instruction("MOVH $10, 0xFC00", "ca21fc00")
        check_instruction("MOVH $12, 0xC003", "cc21c003")
        check_instruction("MOVH $TP, 0x400", "cd210400")
        check_instruction("MOVH $7, 0x8000", "c7218000")

    def test_SLT3(self):
        """Test the SLT3 instruction"""

        # Top instructions
        check_instruction("SLT3 $0, $2, 0x908", "c0220908")
        check_instruction("SLT3 $0, $1, 0x90F", "c012090f")
        check_instruction("SLT3 $0, $1, 0x1CE", "c01201ce")
        check_instruction("SLT3 $0, $12, 0x801", "c0c20801")
        check_instruction("SLT3 $0, $4, 0x800", "c0420800")

        # Randomly chosen instructions
        check_instruction("SLT3 $2, $4, 0x6A18", "c2426a18")
        check_instruction("SLT3 $2, $11, -31153", "c2b2864f")
        check_instruction("SLT3 $11, $12, 0x5BFA", "cbc25bfa")
        check_instruction("SLT3 $SP, $4, -30809", "cf4287a7")
        check_instruction("SLT3 $0, $12, 0x21", "c0c20021")

    def test_SLTU3(self):
        """Test the SLTU3 instruction"""

        # Top instructions
        check_instruction("SLTU3 $11, $8, 0x8813", "cb838813")
        check_instruction("SLTU3 $12, $11, 0x2711", "ccb32711")
        check_instruction("SLTU3 $0, $11, 0x941", "c0b30941")
        check_instruction("SLTU3 $0, $12, 0x941", "c0c30941")
        check_instruction("SLTU3 $12, $8, 0x1001", "cc831001")

        # Randomly chosen instructions
        check_instruction("SLTU3 $8, $12, 0x8BA9", "c8c38ba9")
        check_instruction("SLTU3 $12, $11, 0x1E", "ccb3001e")
        check_instruction("SLTU3 $6, $GP, 0x6C90", "c6e36c90")
        check_instruction("SLTU3 $TP, $7, 0x86C3", "cd7386c3")
        check_instruction("SLTU3 $12, $10, 0x1", "cca30001")

    def test_OR3(self):
        """Test the OR3 instruction"""

        # Top instructions
        check_instruction("OR3 $1, $1, 0x1", "c1140001")
        check_instruction("OR3 $11, $11, 0x8", "cbb40008")
        check_instruction("OR3 $4, $4, 0x20", "c4440020")
        check_instruction("OR3 $12, $12, 0x1", "ccc40001")
        check_instruction("OR3 $12, $12, 0x2", "ccc40002")

        # Randomly chosen instructions
        check_instruction("OR3 $12, $GP, 0xC7", "cce400c7")
        check_instruction("OR3 $10, $3, 0x40", "ca340040")
        check_instruction("OR3 $3, $3, 0xFF97", "c334ff97")
        check_instruction("OR3 $9, $TP, 0x7A0D", "c9d47a0d")
        check_instruction("OR3 $1, $1, 0x1122", "c1141122")

    def test_AND3(self):
        """Test the AND3 instruction"""

        # Top instructions
        check_instruction("AND3 $10, $12, 0x1", "cac50001")
        check_instruction("AND3 $11, $4, 0x8", "cb450008")
        check_instruction("AND3 $12, $4, 0x1", "cc450001")
        check_instruction("AND3 $11, $12, 0x8", "cbc50008")
        check_instruction("AND3 $11, $12, 0x1", "cbc50001")

        # Randomly chosen instructions
        check_instruction("AND3 $12, $7, 0x1FF", "cc7501ff")
        check_instruction("AND3 $9, $10, 0x4E27", "c9a54e27")
        check_instruction("AND3 $4, $4, 0xFB", "c44500fb")
        check_instruction("AND3 $10, $7, 0x10", "ca750010")
        check_instruction("AND3 $8, $9, 0xCE", "c89500ce")

    def test_XOR3(self):
        """Test the XOR3 instruction"""

        # Top instructions
        check_instruction("XOR3 $GP, $0, 0x9D72", "ce069d72")
        check_instruction("XOR3 $10, $9, 0xDB3C", "ca96db3c")
        check_instruction("XOR3 $7, $7, 0x6060", "c7766060")
        check_instruction("XOR3 $12, $11, 0x4", "ccb60004")
        check_instruction("XOR3 $4, $4, 0x1", "c4460001")

        # Randomly chosen instructions
        check_instruction("XOR3 $TP, $9, 0x8704", "cd968704")
        check_instruction("XOR3 $11, $SP, 0x7411", "cbf67411")
        check_instruction("XOR3 $SP, $8, 0x8801", "cf868801")
        check_instruction("XOR3 $12, $8, 0x8648", "cc868648")
        check_instruction("XOR3 $5, $8, 0xC5", "c58600c5")

    def test_SB(self):
        """Test the SB instruction"""

        # Top instructions
        check_instruction("SB $12, 0x14($SP)", "ccf80014")
        check_instruction("SB $4, 0x4($SP)", "c4f80004")
        check_instruction("SB $4, 0x3($3)", "c4380003")
        check_instruction("SB $11, 0x17($SP)", "cbf80017")
        check_instruction("SB $12, 0x16($SP)", "ccf80016")

        # Randomly chosen instructions
        check_instruction("SB $TP, -31053($6)", "cd6886b3")
        check_instruction("SB $3, 0x6E($8)", "c388006e")
        check_instruction("SB $7, 0x81($8)", "c7880081")
        check_instruction("SB $11, 0x1FE($7)", "cb7801fe")
        check_instruction("SB $11, 0x7B($4)", "cb48007b")

    def test_SH(self):
        """Test the SH instruction"""

        # Top instructions
        check_instruction("SH $11, 0x8($12)", "cbc90008")
        check_instruction("SH $11, 0x2($4)", "cb490002")
        check_instruction("SH $4, 0xE($SP)", "c4f9000e")
        check_instruction("SH $4, 0xC($SP)", "c4f9000c")
        check_instruction("SH $11, 0x1E($4)", "cb49001e")

        # Randomly chosen instructions
        check_instruction("SH $SP, -30753($6)", "cf6987df")
        check_instruction("SH $12, 0x6C4($TP)", "ccd906c4")
        check_instruction("SH $4, 0x38($3)", "c4390038")
        check_instruction("SH $TP, 0x8($2)", "cd290008")
        check_instruction("SH $11, 0x62F5($10)", "cba962f5")

        # Manually generated instruction
        check_instruction("SH $0, 0x7FFF($1)", "c0197fff")
        check_instruction("SH $0, -32767($1)", "c0198001")

    def test_SW(self):
        """Test the SW instruction"""

        # Top instructions
        check_instruction("SW $12, 0x4($1)", "cc1a0004")
        check_instruction("SW $9, 0x4($6)", "c96a0004")
        check_instruction("SW $12, 0x10($4)", "cc4a0010")
        check_instruction("SW $10, 0xC($12)", "caca000c")
        check_instruction("SW $10, 0x4($12)", "caca0004")

        # Randomly chosen instructions
        check_instruction("SW $12, 0x100($1)", "cc1a0100")
        check_instruction("SW $10, 0x88($6)", "ca6a0088")
        check_instruction("SW $0, 0x188($SP)", "c0fa0188")
        check_instruction("SW $10, 0x22C($SP)", "cafa022c")
        check_instruction("SW $4, 0x60A9($SP)", "c4fa60a9")

    def test_LBU(self):
        """Test the LBU instruction"""

        # Top instructions
        check_instruction("LBU $10, 0x3($12)", "cacb0003")
        check_instruction("LBU $12, 0x2($0)", "cc0b0002")
        check_instruction("LBU $4, 0x2($7)", "c47b0002")
        check_instruction("LBU $12, 0x16($SP)", "ccfb0016")
        check_instruction("LBU $11, 0x2($4)", "cb4b0002")

        # Randomly chosen instructions
        check_instruction("LBU $12, 0x16($4)", "cc4b0016")
        check_instruction("LBU $2, 0x3($11)", "c2bb0003")
        check_instruction("LBU $7, 0x5($2)", "c72b0005")
        check_instruction("LBU $12, 0x1E1($1)", "cc1b01e1")
        check_instruction("LBU $10, -31425($6)", "ca6b853f")

    def test_LB(self):
        """Test the LB instruction"""

        # Top instructions
        check_instruction("LB $9, 0x26($1)", "c91c0026")
        check_instruction("LB $4, 0x5($7)", "c47c0005")
        check_instruction("LB $12, 0x14($SP)", "ccfc0014")
        check_instruction("LB $9, 0x2($12)", "c9cc0002")
        check_instruction("LB $12, 0x16($SP)", "ccfc0016")

        # Randomly chosen instructions
        check_instruction("LB $0, 0x5784($10)", "c0ac5784")
        check_instruction("LB $11, -31243($9)", "cb9c85f5")
        check_instruction("LB $5, 0x11($6)", "c56c0011")
        check_instruction("LB $4, 0x154($7)", "c47c0154")
        check_instruction("LB $12, 0x18($SP)", "ccfc0018")

    def test_LH(self):
        """Test the LH instruction"""

        # Top instructions
        check_instruction("LH $4, 0x14($SP)", "c4fd0014")
        check_instruction("LH $4, 0x6($8)", "c48d0006")
        check_instruction("LH $4, 0x10($7)", "c47d0010")
        check_instruction("LH $4, 0x4($8)", "c48d0004")
        check_instruction("LH $9, 0x10($1)", "c91d0010")

        # Randomly chosen instructions
        check_instruction("LH $4, 0x8($8)", "c48d0008")
        check_instruction("LH $12, 0x8($10)", "ccad0008")
        check_instruction("LH $6, -32042($6)", "c66d82d6")
        check_instruction("LH $9, -31509($8)", "c98d84eb")
        check_instruction("LH $0, 0x7E8D($6)", "c06d7e8d")

    def test_LW(self):
        """Test the LW instruction"""

        # Top instructions
        check_instruction("LW $4, 0x1C($8)", "c48e001c")
        check_instruction("LW $12, 0x4($11)", "ccbe0004")
        check_instruction("LW $7, 0x18($3)", "c73e0018")
        check_instruction("LW $2, 0x8($8)", "c28e0008")
        check_instruction("LW $4, 0x14($8)", "c48e0014")

        # Randomly chosen instructions
        check_instruction("LW $12, 0x1D48($7)", "cc7e1d48")
        check_instruction("LW $8, 0x58($1)", "c81e0058")
        check_instruction("LW $12, 0xB0($7)", "cc7e00b0")
        check_instruction("LW $SP, 0x6653($SP)", "cffe6653")
        check_instruction("LW $12, -8($10)", "ccaefff8")

    def test_LHU(self):
        """Test the LHU instruction"""

        # Top instructions
        check_instruction("LHU $3, 0x10($8)", "c38f0010")
        check_instruction("LHU $12, 0x10($1)", "cc1f0010")
        check_instruction("LHU $4, 0x2($8)", "c48f0002")
        check_instruction("LHU $4, 0x18($8)", "c48f0018")
        check_instruction("LHU $2, 0x10($8)", "c28f0010")

        # Randomly chosen instructions
        check_instruction("LHU $12, 0x94($8)", "cc8f0094")
        check_instruction("LHU $4, 0xE($6)", "c46f000e")
        check_instruction("LHU $11, 0x5B59($GP)", "cbef5b59")
        check_instruction("LHU $1, 0x601D($10)", "c1af601d")
        check_instruction("LHU $6, 0x74F6($11)", "c6bf74f6")
