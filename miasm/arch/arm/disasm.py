from future.utils import viewvalues

from miasm.core.asmblock import AsmConstraint, disasmEngine
from miasm.arch.arm.arch import mn_arm, mn_armt


def cb_arm_fix_call(mdis, cur_block, offsets_to_dis):
    """
    for arm:
    MOV        LR, PC
    LDR        PC, [R5, 0x14]
    * is a subcall *

    """
    if len(cur_block.lines) < 2:
        return
    l1 = cur_block.lines[-1]
    l2 = cur_block.lines[-2]
    if l1.name != "LDR":
        return
    if l2.name != "MOV":
        return

    values = viewvalues(mdis.arch.pc)
    if not l1.args[0] in values:
        return
    if not l2.args[1] in values:
        return
    loc_key_cst = mdis.loc_db.get_or_create_offset_location(l1.offset + 4)
    cur_block.add_cst(loc_key_cst, AsmConstraint.c_next)
    offsets_to_dis.add(l1.offset + 4)

cb_arm_funcs = [cb_arm_fix_call]


def cb_arm_disasm(*args, **kwargs):
    for func in cb_arm_funcs:
        func(*args, **kwargs)


class dis_armb(disasmEngine):
    attrib = 'b'
    def __init__(self, bs=None, **kwargs):
        super(dis_armb, self).__init__(mn_arm, self.attrib, bs, **kwargs)
        self.dis_block_callback = cb_arm_disasm

class dis_arml(disasmEngine):
    attrib = 'l'
    def __init__(self, bs=None, **kwargs):
        super(dis_arml, self).__init__(mn_arm, self.attrib, bs, **kwargs)
        self.dis_block_callback = cb_arm_disasm

class dis_armtb(disasmEngine):
    attrib = 'b'
    def __init__(self, bs=None, **kwargs):
        super(dis_armtb, self).__init__(mn_armt, self.attrib, bs, **kwargs)

class dis_armtl(disasmEngine):
    attrib = 'l'
    def __init__(self, bs=None, **kwargs):
        super(dis_armtl, self).__init__(mn_armt, self.attrib, bs, **kwargs)
