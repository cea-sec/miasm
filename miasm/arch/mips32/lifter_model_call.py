#-*- coding:utf-8 -*-

from miasm.expression.expression import ExprAssign, ExprOp
from miasm.ir.ir import IRBlock, AssignBlock
from miasm.ir.analysis import LifterModelCall
from miasm.arch.mips32.sem import Lifter_Mips32l, Lifter_Mips32b

class LifterModelCallMips32l(Lifter_Mips32l, LifterModelCall):
    def __init__(self, loc_db):
        Lifter_Mips32l.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.V0

    def call_effects(self, ad, instr):
        call_assignblk = AssignBlock(
            [
                ExprAssign(
                    self.ret_reg,
                    ExprOp(
                        'call_func_ret',
                        ad,
                        self.arch.regs.A0,
                        self.arch.regs.A1,
                        self.arch.regs.A2,
                        self.arch.regs.A3,
                    )
                ),
            ],
            instr
        )

        return [call_assignblk], []


    def add_asmblock_to_ircfg(self, block, ircfg, gen_pc_updt=False):
        """
        Add a native block to the current IR
        @block: native assembly block
        @ircfg: IRCFG instance
        @gen_pc_updt: insert PC update effects between instructions
        """
        loc_key = block.loc_key
        ir_blocks_all = []

        assignments = []
        for index, instr in enumerate(block.lines):
            if loc_key is None:
                assignments = []
                loc_key = self.get_loc_key_for_instr(instr)
            if instr.is_subcall():
                assert index == len(block.lines) - 2

                # Add last instruction first (before call)
                split = self.add_instr_to_current_state(
                    block.lines[-1], block, assignments,
                    ir_blocks_all, gen_pc_updt
                )
                assert not split
                # Add call effects after the delay splot
                split = self.add_instr_to_current_state(
                    instr, block, assignments,
                    ir_blocks_all, gen_pc_updt
                )
                assert split
                break
            split = self.add_instr_to_current_state(
                instr, block, assignments,
                ir_blocks_all, gen_pc_updt
            )
            if split:
                ir_blocks_all.append(IRBlock(self.loc_db, loc_key, assignments))
                loc_key = None
                assignments = []
        if loc_key is not None:
            ir_blocks_all.append(IRBlock(self.loc_db, loc_key, assignments))

        new_ir_blocks_all = self.post_add_asmblock_to_ircfg(block, ircfg, ir_blocks_all)
        for irblock in new_ir_blocks_all:
            ircfg.add_irblock(irblock)
        return new_ir_blocks_all

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



class LifterModelCallMips32b(Lifter_Mips32b, LifterModelCallMips32l):
    def __init__(self, loc_db):
        Lifter_Mips32b.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.V0
