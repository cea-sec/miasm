from miasm2.core.asmbloc import asm_constraint, asm_label, disasmEngine
from miasm2.expression.expression import ExprId
from arch import mn_x86


def cb_x86_callpop(mn, attrib, pool_bin, cur_bloc, offsets_to_dis, symbol_pool):
    """
    1000: call 1005
    1005: pop
    """
    if len(cur_bloc.lines) < 1:
        return
    l = cur_bloc.lines[-1]
    if l.name != 'CALL':
        return
    dst = l.args[0]
    if not (isinstance(dst, ExprId) and isinstance(dst.name, asm_label)):
        return
    if dst.name.offset != l.offset + l.l:
        return
    l.name = 'PUSH'
    # cur_bloc.bto.pop()
    cur_bloc.bto[0].c_bto = asm_constraint.c_next


cb_x86_funcs = [cb_x86_callpop]


def cb_x86_disasm(mn, attrib, pool_bin, cur_bloc, offsets_to_dis, symbol_pool):
    for func in cb_x86_funcs:
        func(mn, attrib, pool_bin, cur_bloc, offsets_to_dis, symbol_pool)


class dis_x86(disasmEngine):
    attrib = None

    def __init__(self, bs=None, **kwargs):
        super(dis_x86, self).__init__(mn_x86, self.attrib, bs, **kwargs)
        self.dis_bloc_callback = cb_x86_disasm


class dis_x86_16(dis_x86):
    attrib = 16


class dis_x86_32(dis_x86):
    attrib = 32


class dis_x86_64(dis_x86):
    attrib = 64
