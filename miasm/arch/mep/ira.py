# Toshiba MeP-c4 - miasm IR analysis
# Guillaume Valadon <guillaume@valadon.net>

from miasm.arch.mep.sem import ir_mepb, ir_mepl
from miasm.ir.analysis import ira


class ir_a_mepb(ir_mepb, ira):
    """MeP high level IR manipulations - Big Endian

    Notes:
        - it is mandatory for symbolic execution.
    """

    def __init__(self, loc_db=None):
        ir_mepb.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0

    # Note: the following are abstract method and must be implemented
    def sizeof_char(self):
        "Return the size of a char in bits"
        return 8

    def sizeof_short(self):
        "Return the size of a short in bits"
        return 16

    def sizeof_int(self):
        "Return the size of an int in bits"
        return 32

    def sizeof_long(self):
        "Return the size of a long in bits"
        return 32

    def sizeof_pointer(self):
        "Return the size of a void* in bits"
        return 32


class ir_a_mepl(ir_mepl, ir_a_mepb):
    """MeP high level IR manipulations - Little Endian"""

    def __init__(self, loc_db=None):
        ir_a_mepb.__init__(self, loc_db)
