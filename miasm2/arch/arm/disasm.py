from miasm2.core.asmbloc import asm_constraint, disasmEngine
from arch import mn_arm, mn_armt


def cb_arm_fix_call(
    mn, attrib, pool_bin, cur_bloc, offsets_to_dis, symbol_pool):
    """
    for arm:
    MOV        LR, PC
    LDR        PC, [R5, 0x14]
    * is a subcall *

    """
    if len(cur_bloc.lines) < 2:
        return
    l1 = cur_bloc.lines[-1]
    l2 = cur_bloc.lines[-2]
    if l1.name != "LDR":
        return
    if l2.name != "MOV":
        return
    # print cur_bloc
    # print l1
    if not l1.args[0] in mn.pc.values():
        return
    if not l2.args[1] in mn.pc.values():
        return
    cur_bloc.add_cst(l1.offset + 4, asm_constraint.c_next, symbol_pool)
    offsets_to_dis.add(l1.offset + 4)

cb_arm_funcs = [cb_arm_fix_call]


def cb_arm_disasm(mn, attrib, pool_bin, cur_bloc, offsets_to_dis, symbol_pool):
    for func in cb_arm_funcs:
        func(mn, attrib, pool_bin, cur_bloc, offsets_to_dis, symbol_pool)


class dis_armb(disasmEngine):
    attrib = 'b'
    def __init__(self, bs=None, **kwargs):
        super(dis_armb, self).__init__(mn_arm, self.attrib, bs, **kwargs)
        self.dis_bloc_callback = cb_arm_disasm

class dis_arml(disasmEngine):
    attrib = 'l'
    def __init__(self, bs=None, **kwargs):
        super(dis_arml, self).__init__(mn_arm, self.attrib, bs, **kwargs)
        self.dis_bloc_callback = cb_arm_disasm

class dis_armtb(disasmEngine):
    attrib = 'b'
    def __init__(self, bs=None, **kwargs):
        super(dis_armtb, self).__init__(mn_armt, self.attrib, bs, **kwargs)

class dis_armtl(disasmEngine):
    attrib = 'l'
    def __init__(self, bs=None, **kwargs):
        super(dis_armtl, self).__init__(mn_armt, self.attrib, bs, **kwargs)
