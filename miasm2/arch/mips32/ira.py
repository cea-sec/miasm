#-*- coding:utf-8 -*-

from miasm2.expression.expression import ExprAff, ExprInt, ExprId
from miasm2.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock
from miasm2.ir.analysis import ira
from miasm2.arch.mips32.sem import ir_mips32l, ir_mips32b
from miasm2.core.asmblock import expr_is_int_or_label, expr_is_label

class ir_a_mips32l(ir_mips32l, ira):
    def __init__(self, symbol_pool=None):
        ir_mips32l.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.V0

    def pre_add_instr(self, block, instr, irb_cur, ir_blocks_all, gen_pc_updt):
        # Avoid adding side effects, already done in post_add_bloc
        return irb_cur

    def post_add_bloc(self, block, ir_blocks):
        IntermediateRepresentation.post_add_bloc(self, block, ir_blocks)
        for irb in ir_blocks:
            pc_val = None
            lr_val = None
            for assignblk in irb.irs:
                pc_val = assignblk.get(self.arch.regs.PC, pc_val)
                lr_val = assignblk.get(self.arch.regs.RA, lr_val)

            if pc_val is None or lr_val is None:
                continue
            if not expr_is_int_or_label(lr_val):
                continue
            if expr_is_label(lr_val):
                lr_val = ExprInt(lr_val.name.offset, 32)

            line = block.lines[-2]
            if lr_val.arg != line.offset + 8:
                raise ValueError("Wrong arg")

            # CALL
            lbl = block.get_next()
            new_lbl = self.gen_label()
            irs = self.call_effects(pc_val, line)
            irs.append(AssignBlock([ExprAff(self.IRDst,
                                            ExprId(lbl, size=self.pc.size))]))
            nblock = IRBlock(new_lbl, irs)
            nblock.lines = [line] * len(irs)
            self.blocks[new_lbl] = nblock
            irb.dst = ExprId(new_lbl, size=self.pc.size)

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
    def __init__(self, symbol_pool=None):
        ir_mips32b.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.V0
