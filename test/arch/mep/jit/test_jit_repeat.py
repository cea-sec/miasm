# Toshiba MeP-c4 - *REPEAT instructions JIT unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_jit import jit_instructions


class TestRepeat(object):
    def test_repeat(self):
        """Test REPEAT jit"""

        # Instructions that will be jitted
        instructions = "MOV R0, 8\n"
        instructions += "REPEAT R0, 0x6\n"
        instructions += "ADD R1, 1\n"
        instructions += "ADD R2, 1\n"  # <-RPE
        instructions += "ADD R3, 1"

        # Jit
        jitter = jit_instructions(instructions)

        # Check expected results
        assert(jitter.cpu.R0 == 8)
        assert(jitter.cpu.R1 == 8)
        assert(jitter.cpu.R2 == 8)
        assert(jitter.cpu.R3 == 8)

    def test_erepeat_0(self):
        """Test EREPEAT jit"""

        # Instructions that will be jitted
        instructions = "EREPEAT 0xA\n"
        instructions += "ADD R1, 1\n"
        instructions += "BEQI R1, 0x6, 0x8\n"
        instructions += "ADD R2, 1\n"
        instructions += "ADD R3, 1"  # <- RPE

        # Jit
        jitter = jit_instructions(instructions)

        # Check expected results
        assert(jitter.cpu.R1 == 6)
        assert(jitter.cpu.R2 == 5)
        assert(jitter.cpu.R3 == 5)

    def test_erepeat_1(self):
        """Test EREPEAT jit"""

        # Instructions that will be jitted
        instructions = "EREPEAT 0x8\n"
        instructions += "ADD R1, 1\n"
        instructions += "ADD R2, 1\n"
        instructions += "ADD R3, 1\n"
        instructions += "BEQI R1, 0x6, 0x4\n"  # <- RPE
        instructions += "ADD R2, 1\n"
        instructions += "ADD R3, 1"

        # Jit
        jitter = jit_instructions(instructions)

        # Check expected results
        assert(jitter.cpu.R1 == 6)
        assert(jitter.cpu.R2 == 7)
        assert(jitter.cpu.R3 == 7)

    def test_erepeat_2(self):
        """Test EREPEAT jit"""

        # Instructions that will be jitted
        instructions = "EREPEAT 0x8\n"
        instructions += "ADD R1, 1\n"
        instructions += "ADD R2, 1\n"
        instructions += "ADD R3, 1\n"  # <- RPE
        instructions += "BEQI R3, 0x6, 0x4"

        # Jit
        jitter = jit_instructions(instructions)

        # Check expected results
        assert(jitter.cpu.R1 == 6)
        assert(jitter.cpu.R2 == 6)
        assert(jitter.cpu.R3 == 6)

    def test_erepeat_3(self):
        """Test EREPEAT jit"""

        # Instructions that will be jitted
        instructions = "EREPEAT 0x8\n"
        instructions += "ADD R1, 1\n"
        instructions += "ADD R2, 1\n"
        instructions += "BEQI R1, 0x6, 0x6\n"  # <- RPE
        instructions += "ADD R3, 1"

        # Jit
        jitter = jit_instructions(instructions)

        # Check expected results
        assert(jitter.cpu.R1 == 6)
        assert(jitter.cpu.R2 == 6)
        assert(jitter.cpu.R3 == 5)
