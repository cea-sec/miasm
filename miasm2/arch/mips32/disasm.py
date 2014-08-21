from miasm2.core.asmbloc import asm_constraint, disasmEngine
from arch import mn_mips32



class dis_mips32b(disasmEngine):
    attrib = 'b'
    def __init__(self, bs=None, **kwargs):
        super(dis_mips32b, self).__init__(mn_mips32, self.attrib, bs, **kwargs)


class dis_mips32l(disasmEngine):
    attrib = "l"
    def __init__(self, bs=None, **kwargs):
        super(dis_mips32l, self).__init__(mn_mips32, self.attrib, bs, **kwargs)


