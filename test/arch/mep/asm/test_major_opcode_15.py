# Toshiba MeP-c4 - Major Opcode #15 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor15(object):

    def test_DSP(self):
        """Test the DSP instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("DSP $1, $2, 0x3", "f1200003")

    def test_DSP0(self):
        """Test the DSP0 instruction"""

        # No samples were found
        assert(True)

    def test_DSP1(self):
        """Test the DSP1 instruction"""

        # No samples were found
        assert(True)

    def test_LDZ(self):
        """Test the LDZ instruction"""

        # Top instructions
        check_instruction("LDZ $10, $9", "fa910000")
        check_instruction("LDZ $SP, $12", "ffc10000")

    def test_AVE(self):
        """Test the AVE instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("AVE $1, $2", "f1210002")

    def test_ABS(self):
        """Test the ABS instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("ABS $1, $2", "f1210003")

    def test_MIN(self):
        """Test the MIN instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("MIN $1, $2", "f1210004")

    def test_MAX(self):
        """Test the MAX instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("MAX $1, $2", "f1210005")

    def test_MINU(self):
        """Test the MINU instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("MINU $1, $2", "f1210006")

    def test_MAXU(self):
        """Test the MAXU instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("MAXU $1, $2", "f1210007")

    def test_SADD(self):
        """Test the SADD instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SADD $1, $2", "f1210008")

    def test_SADDU(self):
        """Test the SADDU instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SADDU $1, $2", "f1210009")

    def test_SSUB(self):
        """Test the SSUB instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SSUB $1, $2", "f121000a")

    def test_SSUBU(self):
        """Test the SSUBU instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SSUBU $1, $2", "f121000b")

    def test_CLIP(self):
        """Test the CLIP instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("CLIP $1, 0x2", "f1011010")

    def test_CLIPU(self):
        """Test the CLIPU instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("CLIPU $1, 0x2", "f1011011")

    def test_MADD(self):
        """Test the MADD instruction"""

        # Top instructions
        check_instruction("MADD $3, $12", "f3c13004")
        check_instruction("MADD $11, $1", "fb113004")
        check_instruction("MADD $9, $1", "f9113004")
        check_instruction("MADD $10, $4", "fa413004")
        check_instruction("MADD $4, $11", "f4b13004")

        # Randomly chosen instructions
        check_instruction("MADD $7, $10", "f7a13004")
        check_instruction("MADD $0, $10", "f0a13004")
        check_instruction("MADD $12, $9", "fc913004")
        check_instruction("MADD $5, $TP", "f5d13004")
        check_instruction("MADD $10, $12", "fac13004")

    def test_MADDU(self):
        """Test the MADDU instruction"""

        # Top instructions
        check_instruction("MADDU $12, $11", "fcb13005")
        check_instruction("MADDU $6, $12", "f6c13005")
        check_instruction("MADDU $6, $11", "f6b13005")
        check_instruction("MADDU $6, $9", "f6913005")
        check_instruction("MADDU $6, $10", "f6a13005")

        # Randomly chosen instructions
        check_instruction("MADDU $10, $12", "fac13005")
        check_instruction("MADDU $10, $2", "fa213005")
        check_instruction("MADDU $1, $12", "f1c13005")
        check_instruction("MADDU $11, $10", "fba13005")
        check_instruction("MADDU $8, $12", "f8c13005")

    def test_MADDR(self):
        """Test the MADDR instruction"""

        # Top instructions
        check_instruction("MADDR $12, $3", "fc313006")
        check_instruction("MADDR $10, $2", "fa213006")
        check_instruction("MADDR $6, $12", "f6c13006")
        check_instruction("MADDR $11, $10", "fba13006")

    def test_MADDRU(self):
        """Test the MADDRU instruction"""

        # Top instructions
        check_instruction("MADDRU $11, $2", "fb213007")
        check_instruction("MADDRU $10, $9", "fa913007")
        check_instruction("MADDRU $12, $10", "fca13007")
        check_instruction("MADDRU $11, $1", "fb113007")
        check_instruction("MADDRU $12, $1", "fc113007")

        # Randomly chosen instructions
        check_instruction("MADDRU $1, $0", "f1013007")
        check_instruction("MADDRU $10, $3", "fa313007")
        check_instruction("MADDRU $12, $11", "fcb13007")
        check_instruction("MADDRU $12, $9", "fc913007")
        check_instruction("MADDRU $3, $1", "f3113007")

    def test_UCI(self):
        """Test the UCI instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("UCI $1, $2, 0x3", "f1220003")

    def test_STCB(self):
        """Test the STCB instruction"""

        # Top instructions
        check_instruction("STCB $11, 0x1000", "fb041000")
        check_instruction("STCB $3, 0x1005", "f3041005")
        check_instruction("STCB $1, 0x1004", "f1041004")
        check_instruction("STCB $11, 0x0", "fb040000")
        check_instruction("STCB $12, 0x4100", "fc044100")

        # Randomly chosen instructions
        check_instruction("STCB $2, 0x4007", "f2044007")
        check_instruction("STCB $10, 0x4002", "fa044002")
        check_instruction("STCB $11, 0x2", "fb040002")
        check_instruction("STCB $10, 0x420", "fa040420")
        check_instruction("STCB $4, 0x405", "f4040405")

    def test_LDCB(self):
        """Test the LDCB instruction"""

        # Top instructions
        check_instruction("LDCB $12, 0x3", "fc140003")
        check_instruction("LDCB $12, 0x1001", "fc141001")
        check_instruction("LDCB $11, 0x1000", "fb141000")
        check_instruction("LDCB $12, 0x1000", "fc141000")
        check_instruction("LDCB $12, 0x0", "fc140000")

        # Randomly chosen instructions
        check_instruction("LDCB $12, 0x420", "fc140420")
        check_instruction("LDCB $10, 0x1", "fa140001")
        check_instruction("LDCB $11, 0x5", "fb140005")
        check_instruction("LDCB $2, 0x4002", "f2144002")
        check_instruction("LDCB $1, 0x4005", "f1144005")

    def test_SBCPA(self):
        """Test the SBCPA instruction"""

        # Top instructions
        check_instruction("SBCPA $C5, ($GP+), -50", "f5e500ce")
        check_instruction("SBCPA $C5, ($GP+), -55", "f5e500c9")
        check_instruction("SBCPA $C6, ($9+), -50", "f69500ce")
        check_instruction("SBCPA $C4, ($TP+), -52", "f4d500cc")
        check_instruction("SBCPA $C6, ($4+), -55", "f64500c9")

        # Randomly chosen instructions
        check_instruction("SBCPA $C2, ($SP+), -51", "f2f500cd")
        check_instruction("SBCPA $C13, ($8+), -52", "fd8500cc")
        check_instruction("SBCPA $C2, ($TP+), -51", "f2d500cd")
        check_instruction("SBCPA $C6, ($6+), -55", "f66500c9")
        check_instruction("SBCPA $C2, ($10+), -51", "f2a500cd")

    def test_SHCPA(self):
        """Test the SHCPA instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SHCPA $C1, ($2+), 6", "f1251006")

    def test_SWCPA(self):
        """Test the SWCPA instruction"""

        # Top instructions
        check_instruction("SWCPA $C10, ($5+), 48", "fa552030")

        # Manually generated instruction
        check_instruction("SWCPA $C1, ($2+), 4", "f1252004")

    def test_SMCPA(self):
        """Test the SMCPA instruction"""

        # Top instructions
        check_instruction("SMCPA $C15, ($0+), -16", "ff0530f0")
        check_instruction("SMCPA $C15, ($0+), 32", "ff053020")

        # Manually generated instruction
        check_instruction("SMCPA $C1, ($2+), 8", "f1253008")

    def test_LBCPA(self):
        """Test the LBCPA instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LBCPA $C1, ($2+), 8", "f1254008")

    def test_LHCPA(self):
        """Test the LHCPA instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LHCPA $C1, ($2+), 8", "f1255008")

    def test_LWCPA(self):
        """Test the LWCPA instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LWCPA $C1, ($2+), 8", "f1256008")

    def test_LMCPA(self):
        """Test the LMCPA instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LMCPA $C1, ($2+), 8", "f1257008")

    def test_SBCPM0(self):
        """Test the SBCPM0 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SBCPM0 $C1, ($2+), 8", "f1250808")

    def test_SHCPM0(self):
        """Test the SHCPM0 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SHCPM0 $C1, ($2+), 8", "f1251808")

    def test_SWCPM0(self):
        """Test the SWCPM0 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SWCPM0 $C1, ($2+), 8", "f1252808")

    def test_SMCPM0(self):
        """Test the SMCPM0 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SMCPM0 $C1, ($2+), 8", "f1253808")

    def test_LBCPM0(self):
        """Test the LBCPM0 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LBCPM0 $C1, ($2+), 8", "f1254808")

    def test_LHCPM0(self):
        """Test the LHCPM0 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LHCPM0 $C1, ($2+), 8", "f1255808")

    def test_LWCPM0(self):
        """Test the LWCPM0 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LWCPM0 $C1, ($2+), 8", "f1256808")

    def test_LMCPM0(self):
        """Test the LMCPM0 instruction"""

        # Top instructions
        check_instruction("LMCPM0 $C3, ($12+), 8", "f3c57808")
        check_instruction("LMCPM0 $C1, ($11+), -32", "f1b578e0")
        check_instruction("LMCPM0 $C3, ($TP+), 48", "f3d57830")
        check_instruction("LMCPM0 $C3, ($GP+), -96", "f3e578a0")
        check_instruction("LMCPM0 $C3, ($SP+), -40", "f3f578d8")

    def test_SBCPM1(self):
        """Test the SBCPM1 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SBCPM1 $C1, ($2+), 8", "f1250c08")

    def test_SHCPM1(self):
        """Test the SHCPM1 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SHCPM1 $C1, ($2+), 8", "f1251c08")

    def test_SWCPM1(self):
        """Test the SWCPM1 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SWCPM1 $C1, ($2+), 8", "f1252c08")

    def test_SMCPM1(self):
        """Test the SMCPM1 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("SMCPM1 $C1, ($2+), 8", "f1253c08")

    def test_LBCPM1(self):
        """Test the LBCPM1 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LBCPM1 $C1, ($2+), 8", "f1254c08")

    def test_LHCPM1(self):
        """Test the LHCPM1 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LHCPM1 $C1, ($2+), 8", "f1255c08")

    def test_LWCPM1(self):
        """Test the LWCPM1 instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("LWCPM1 $C1, ($2+), 8", "f1256c08")

    def test_LMCPM1(self):
        """Test the LMCPM1 instruction"""

        # Top instructions
        check_instruction("LMCPM1 $C9, ($4+), 48", "f9457c30")
        check_instruction("LMCPM1 $C4, ($10+), 64", "f4a57c40")
        check_instruction("LMCPM1 $C4, ($TP+), -72", "f4d57cb8")
        check_instruction("LMCPM1 $C4, ($GP+), -32", "f4e57ce0")

    def test_CP(self):
        """Test the CP instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        #check_instruction("CP 0x280780", "f2870780")

    def test_CMOV(self):
        """Test the CMOV instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("CMOV $C0, $1", "f017f000")
        check_instruction("CMOV $1, $C0", "f017f001")
        check_instruction("CMOV $C28, $1", "fc17f008")
        check_instruction("CMOV $1, $C28", "fc17f009")

    def test_CMOVC(self):
        """Test the CMOVC instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("CMOVC $C0, $1", "f017f002")
        check_instruction("CMOVC $2, $C3", "f327f003")

    def test_CMOVH(self):
        """Test the CMOVH instruction"""

        # No samples were found
        assert(True)

        # Manually generated instruction
        check_instruction("CMOVH $C0, $1", "f017f100")
        check_instruction("CMOVH $2, $C3", "f327f101")
        check_instruction("CMOVH $C29, $12", "fdc7f108")
        check_instruction("CMOVH $SP, $C30", "fef7f109")

    def test_SWCP(self):
        """Test the SWCP instruction"""

        # Top instructions
        check_instruction("SWCP $C7, 197($12)", "f7cc00c5")
        check_instruction("SWCP $C1, 194($7)", "f17c00c2")
        check_instruction("SWCP $C14, -16690($10)", "feacbece")
        check_instruction("SWCP $C2, 24658($5)", "f25c6052")
        check_instruction("SWCP $C0, 27132($9)", "f09c69fc")

        # Randomly chosen instructions
        check_instruction("SWCP $C9, 195($10)", "f9ac00c3")
        check_instruction("SWCP $C5, -25704($5)", "f55c9b98")
        check_instruction("SWCP $C2, -31068($11)", "f2bc86a4")
        check_instruction("SWCP $C6, -27760($12)", "f6cc9390")
        check_instruction("SWCP $C4, -28337($SP)", "f4fc914f")

    def test_LWCP(self):
        """Test the LWCP instruction"""

        # Top instructions
        check_instruction("LWCP $C9, 9890($1)", "f91d26a2")
        check_instruction("LWCP $C1, 10757($6)", "f16d2a05")
        check_instruction("LWCP $C4, -14058($8)", "f48dc916")
        check_instruction("LWCP $C15, -26720($8)", "ff8d97a0")
        check_instruction("LWCP $C15, 26934($4)", "ff4d6936")

        # Randomly chosen instructions
        check_instruction("LWCP $C11, -25049($5)", "fb5d9e27")
        check_instruction("LWCP $C6, -25560($8)", "f68d9c28")
        check_instruction("LWCP $C7, -24867($GP)", "f7ed9edd")
        check_instruction("LWCP $C0, 30229($SP)", "f0fd7615")
        check_instruction("LWCP $C7, -25527($4)", "f74d9c49")

    def test_SMCP(self):
        """Test the SMCP instruction"""

        # Top instructions
        check_instruction("SMCP $C15, 2047($SP)", "fffe07ff")
        check_instruction("SMCP $C15, -1($SP)", "fffeffff")
        check_instruction("SMCP $C4, 17362($9)", "f49e43d2")
        check_instruction("SMCP $C3, 6490($4)", "f34e195a")
        check_instruction("SMCP $C2, -11232($10)", "f2aed420")

        # Randomly chosen instructions
        check_instruction("SMCP $C6, 201($7)", "f67e00c9")
        check_instruction("SMCP $C3, -25912($6)", "f36e9ac8")
        check_instruction("SMCP $C9, -25215($7)", "f97e9d81")
        check_instruction("SMCP $C0, -26294($7)", "f07e994a")
        check_instruction("SMCP $C3, 32566($11)", "f3be7f36")

    def test_LMCP(self):
        """Test the LMCP instruction"""

        # Top instructions
        check_instruction("LMCP $C9, 6994($11)", "f9bf1b52")
        check_instruction("LMCP $C12, -8368($3)", "fc3fdf50")
        check_instruction("LMCP $C4, -13277($GP)", "f4efcc23")
        check_instruction("LMCP $C15, 4095($SP)", "ffff0fff")
        check_instruction("LMCP $C15, -1($SP)", "ffffffff")

        # Randomly chosen instructions
        check_instruction("LMCP $C7, -24863($GP)", "f7ef9ee1")
        check_instruction("LMCP $C14, 16674($SP)", "feff4122")
        check_instruction("LMCP $C13, 1023($SP)", "fdff03ff")
        check_instruction("LMCP $C1, -32729($GP)", "f1ef8027")
        check_instruction("LMCP $C15, 30719($SP)", "ffff77ff")
