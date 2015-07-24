from miasm2.core.asmbloc import asm_constraint, disasmEngine
from miasm2.arch.aarch64.arch import mn_aarch64

cb_aarch64_funcs = []


def cb_aarch64_disasm(mn, attrib, pool_bin, cur_bloc, offsets_to_dis, symbol_pool):
    for func in cb_aarch64_funcs:
        func(mn, attrib, pool_bin, cur_bloc, offsets_to_dis, symbol_pool)


class dis_aarch64b(disasmEngine):
    attrib = "b"
    def __init__(self, bs=None, **kwargs):
        super(dis_aarch64b, self).__init__(
            mn_aarch64, self.attrib, bs,
            dis_bloc_callback = cb_aarch64_disasm,
            **kwargs)


class dis_aarch64l(disasmEngine):
    attrib = "l"
    def __init__(self, bs=None, **kwargs):
        super(dis_aarch64l, self).__init__(
            mn_aarch64, self.attrib, bs,
            dis_bloc_callback = cb_aarch64_disasm,
            **kwargs)
