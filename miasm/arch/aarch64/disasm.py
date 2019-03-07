from miasm.core.asmblock import disasmEngine
from miasm.arch.aarch64.arch import mn_aarch64

cb_aarch64_funcs = []


def cb_aarch64_disasm(*args, **kwargs):
    for func in cb_aarch64_funcs:
        func(*args, **kwargs)


class dis_aarch64b(disasmEngine):
    attrib = "b"
    def __init__(self, bs=None, **kwargs):
        super(dis_aarch64b, self).__init__(
            mn_aarch64, self.attrib, bs,
            dis_block_callback = cb_aarch64_disasm,
            **kwargs)


class dis_aarch64l(disasmEngine):
    attrib = "l"
    def __init__(self, bs=None, **kwargs):
        super(dis_aarch64l, self).__init__(
            mn_aarch64, self.attrib, bs,
            dis_block_callback = cb_aarch64_disasm,
            **kwargs)
