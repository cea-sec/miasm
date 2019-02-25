# Toshiba MeP-c4 - Data cache instructions unit tests
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import exec_instruction


class TestDataCache(object):

    def test_cache(self):
        """Test CACHE execution"""

        # CACHE imm4, (Rm)
        exec_instruction("CACHE 0x0, (R0)", [], [])
