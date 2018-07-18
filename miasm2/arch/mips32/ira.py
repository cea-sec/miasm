#-*- coding:utf-8 -*-

from miasm2.expression.expression import ExprAff, ExprInt, ExprId
from miasm2.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock
from miasm2.ir.analysis import ira
from miasm2.arch.mips32.sem import ir_mips32l, ir_mips32b

class ir_a_mips32l(ir_mips32l, ira):
    def __init__(self, loc_db=None):
        ir_mips32l.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.V0

    def post_add_asmblock_to_ircfg(self, block, ircfg, ir_blocks):
        IntermediateRepresentation.post_add_asmblock_to_ircfg(self, block, ircfg, ir_blocks)
        new_irblocks = []
        for irb in ir_blocks:
            pc_val = None
            lr_val = None
            for assignblk in irb:
                pc_val = assignblk.get(self.arch.regs.PC, pc_val)
                lr_val = assignblk.get(self.arch.regs.RA, lr_val)

            if pc_val is None or lr_val is None:
                new_irblocks.append(irb)
                continue
            if lr_val.is_loc():
                offset = self.loc_db.get_location_offset(lr_val.loc_key)
                if offset is not None:
                    lr_val = ExprInt(offset, 32)
            if not lr_val.is_int():
                continue

            instr = block.lines[-2]
            if int(lr_val) != instr.offset + 8:
                raise ValueError("Wrong arg")

            # CALL
            lbl = block.get_next()
            new_lbl = self.gen_label()
            call_assignblks, extra_irblocks = self.call_effects(pc_val, instr)
            ir_blocks += extra_irblocks
            irs.append(AssignBlock([ExprAff(self.IRDst,
                                            ExprId(lbl, size=self.pc.size))],
                                   instr))
            new_irblocks.append(IRBlock(new_lbl, call_assignblks))
            new_irblocks.append(irb.set_dst(ExprId(new_lbl, size=self.pc.size)))
        return new_irblocks

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

    def sizeof_char(self):
        return 8

    def sizeof_short(self):
        return 16

    def sizeof_int(self):
        return 32

    def sizeof_long(self):
        return 32

    def sizeof_pointer(self):
        return 32



class ir_a_mips32b(ir_mips32b, ir_a_mips32l):
    def __init__(self, loc_db=None):
        ir_mips32b.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.V0
