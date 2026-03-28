from miasm.core.asmblock import disasmEngine
from miasm.arch.riscv.arch import mn_riscv


cb_riscv_funcs = []


def cb_riscv_disasm(*args, **kwargs):
    for func in cb_riscv_funcs:
        func(*args, **kwargs)


class dis_riscv(disasmEngine):
    attrib = None

    def __init__(self, bs=None, **kwargs):
        super(dis_riscv, self).__init__(mn_riscv, self.attrib, bs, **kwargs)
        self.dis_block_callback = cb_riscv_disasm

class dis_riscv64(dis_riscv):
    attrib = 64