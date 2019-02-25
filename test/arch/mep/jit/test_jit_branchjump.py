# Toshiba MeP-c4 - Branch/Jump instructions JIT unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_jit import jit_instructions


class TestBranchJump(object):

    def test_blti(self):
        """Test BLTI jit"""

        # Instructions that will be jitted
        instructions = "MOV R0, 1\n"
        instructions += "BLTI R0, 0x2, 0x6\n"
        instructions += "MOV R0, 0\n"
        instructions += "MOV R1, 1"

        # Jit
        jitter = jit_instructions(instructions)

        # Check expected results
        assert(jitter.cpu.R0 == 1)
        assert(jitter.cpu.R1 == 1)
