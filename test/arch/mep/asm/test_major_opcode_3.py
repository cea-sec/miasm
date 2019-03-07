# Toshiba MeP-c4 - Major Opcode #3 unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import check_instruction


class TestMajor3(object):

    def test_SWCPI(self):
        """Test the SWCPI instruction"""

        # Top instructions
        check_instruction("SWCPI $C0, ($2+)", "3020")
        check_instruction("SWCPI $C3, ($2+)", "3320")
        check_instruction("SWCPI $C3, ($3+)", "3330")
        check_instruction("SWCPI $C2, ($3+)", "3230")
        check_instruction("SWCPI $C0, ($3+)", "3030")

        # Randomly chosen instructions
        check_instruction("SWCPI $C2, ($2+)", "3220")
        check_instruction("SWCPI $C6, ($10+)", "36a0")
        check_instruction("SWCPI $C15, ($SP+)", "3ff0")
        check_instruction("SWCPI $C15, ($9+)", "3f90")
        check_instruction("SWCPI $C10, ($3+)", "3a30")

    def test_LWCPI(self):
        """Test the LWCPI instruction"""

        # Top instructions
        check_instruction("LWCPI $C10, ($3+)", "3a31")
        check_instruction("LWCPI $C7, ($2+)", "3721")
        check_instruction("LWCPI $C15, ($12+)", "3fc1")
        check_instruction("LWCPI $C1, ($3+)", "3131")
        check_instruction("LWCPI $C10, ($4+)", "3a41")

        # Randomly chosen instructions
        check_instruction("LWCPI $C0, ($1+)", "3011")
        check_instruction("LWCPI $C0, ($11+)", "30b1")
        check_instruction("LWCPI $C3, ($10+)", "33a1")
        check_instruction("LWCPI $C0, ($5+)", "3051")
        check_instruction("LWCPI $C2, ($3+)", "3231")

    def test_SMCPI(self):
        """Test the SMCPI instruction"""

        # Top instructions
        check_instruction("SMCPI $C10, ($SP+)", "3af2")
        check_instruction("SMCPI $C14, ($7+)", "3e72")
        check_instruction("SMCPI $C3, ($3+)", "3332")
        check_instruction("SMCPI $C8, ($10+)", "38a2")
        check_instruction("SMCPI $C0, ($3+)", "3032")

        # Randomly chosen instructions
        check_instruction("SMCPI $C5, ($10+)", "35a2")
        check_instruction("SMCPI $C9, ($3+)", "3932")
        check_instruction("SMCPI $C11, ($5+)", "3b52")
        check_instruction("SMCPI $C0, ($9+)", "3092")
        check_instruction("SMCPI $C10, ($5+)", "3a52")

    def test_LMCPI(self):
        """Test the LMCPI instruction"""

        # Top instructions
        check_instruction("LMCPI $C2, ($3+)", "3233")
        check_instruction("LMCPI $C0, ($3+)", "3033")
        check_instruction("LMCPI $C10, ($7+)", "3a73")
        check_instruction("LMCPI $C3, ($3+)", "3333")
        check_instruction("LMCPI $C0, ($0+)", "3003")

        # Randomly chosen instructions
        check_instruction("LMCPI $C0, ($SP+)", "30f3")
        check_instruction("LMCPI $C1, ($1+)", "3113")
        check_instruction("LMCPI $C3, ($0+)", "3303")
        check_instruction("LMCPI $C3, ($2+)", "3323")
        check_instruction("LMCPI $C13, ($9+)", "3d93")

    def test_SWCP(self):
        """Test the SWCP instruction"""

        # Top instructions
        check_instruction("SWCP $C1, ($4)", "3148")
        check_instruction("SWCP $C13, ($1)", "3d18")
        check_instruction("SWCP $C0, ($6)", "3068")
        check_instruction("SWCP $C10, ($7)", "3a78")
        check_instruction("SWCP $C0, ($10)", "30a8")

        # Randomly chosen instructions
        check_instruction("SWCP $C7, ($12)", "37c8")
        check_instruction("SWCP $C1, ($1)", "3118")
        check_instruction("SWCP $C10, ($5)", "3a58")
        check_instruction("SWCP $C8, ($11)", "38b8")
        check_instruction("SWCP $C11, ($3)", "3b38")

    def test_LWCP(self):
        """Test the LWCP instruction"""

        # Top instructions
        check_instruction("LWCP $C14, ($7)", "3e79")
        check_instruction("LWCP $C2, ($3)", "3239")
        check_instruction("LWCP $C14, ($5)", "3e59")
        check_instruction("LWCP $C6, ($10)", "36a9")
        check_instruction("LWCP $C6, ($TP)", "36d9")

        # Randomly chosen instructions
        check_instruction("LWCP $C11, ($9)", "3b99")
        check_instruction("LWCP $C1, ($1)", "3119")
        check_instruction("LWCP $C7, ($3)", "3739")
        check_instruction("LWCP $C2, ($4)", "3249")
        check_instruction("LWCP $C2, ($6)", "3269")

    def test_SMCP(self):
        """Test the SMCP instruction"""

        # Top instructions
        check_instruction("SMCP $C14, ($11)", "3eba")
        check_instruction("SMCP $C12, ($GP)", "3cea")
        check_instruction("SMCP $C4, ($GP)", "34ea")
        check_instruction("SMCP $C0, ($GP)", "30ea")
        check_instruction("SMCP $C12, ($0)", "3c0a")

        # Randomly chosen instructions
        check_instruction("SMCP $C3, ($4)", "334a")
        check_instruction("SMCP $C13, ($0)", "3d0a")
        check_instruction("SMCP $C3, ($3)", "333a")
        check_instruction("SMCP $C15, ($1)", "3f1a")
        check_instruction("SMCP $C13, ($SP)", "3dfa")

    def test_LMCP(self):
        """Test the LMCP instruction"""

        # Top instructions
        check_instruction("LMCP $C14, ($6)", "3e6b")
        check_instruction("LMCP $C14, ($4)", "3e4b")
        check_instruction("LMCP $C5, ($6)", "356b")
        check_instruction("LMCP $C9, ($4)", "394b")
        check_instruction("LMCP $C15, ($6)", "3f6b")

        # Randomly chosen instructions
        check_instruction("LMCP $C0, ($4)", "304b")
        check_instruction("LMCP $C0, ($GP)", "30eb")
        check_instruction("LMCP $C13, ($6)", "3d6b")
        check_instruction("LMCP $C11, ($6)", "3b6b")
        check_instruction("LMCP $C0, ($SP)", "30fb")
