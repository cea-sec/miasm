# Toshiba MeP-c4 - miasm disassembly engine
# Guillaume Valadon <guillaume@valadon.net>

from miasm.core.asmblock import disasmEngine
from miasm.arch.mep.arch import mn_mep


class dis_mepb(disasmEngine):
    """MeP miasm disassembly engine - Big Endian

       Notes:
           - its is mandatory to call the miasm Machine
    """

    attrib = "b"

    def __init__(self, bs=None, **kwargs):
        super(dis_mepb, self).__init__(mn_mep, self.attrib, bs, **kwargs)


class dis_mepl(dis_mepb):
    """MeP miasm disassembly engine - Little Endian"""
    attrib = "l"
