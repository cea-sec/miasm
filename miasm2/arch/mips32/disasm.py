from miasm2.core.asmbloc import asm_constraint, disasmEngine
from arch import mn_mips32b, mn_mips32l



class dis_mips32b(disasmEngine):
    attrib = None
    def __init__(self, bs=None, **kwargs):
        super(dis_mips32b, self).__init__(mn_mips32b, self.attrib, bs, **kwargs)


class dis_mips32l(disasmEngine):
    attrib = None
    def __init__(self, bs=None, **kwargs):
        super(dis_mips32l, self).__init__(mn_mips32l, self.attrib, bs, **kwargs)


