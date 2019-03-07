from miasm.arch.ppc.arch import mn_ppc
from miasm.core.asmblock import disasmEngine

class dis_ppc32b(disasmEngine):
    def __init__(self, bs=None, **kwargs):
        super(dis_ppc32b, self).__init__(mn_ppc, None, bs, **kwargs)
        self.attrib = 'b'
