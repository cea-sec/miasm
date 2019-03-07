from miasm.core.asmblock import disasmEngine
from miasm.arch.msp430.arch import mn_msp430


class dis_msp430(disasmEngine):

    def __init__(self, bs=None, **kwargs):
        super(dis_msp430, self).__init__(mn_msp430, None, bs, **kwargs)
