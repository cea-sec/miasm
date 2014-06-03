from miasm2.core.asmbloc import disasmEngine
from arch import mn_msp430


class dis_msp430(disasmEngine):

    def __init__(self, bs=None, **kwargs):
        super(dis_msp430, self).__init__(mn_msp430, None, bs, **kwargs)
