#-*- coding:utf-8 -*-

from miasm.ir.analysis import LifterModelCall
from miasm.ir.ir import IRBlock
from miasm.arch.arm.sem import Lifter_Arml, Lifter_Armtl, Lifter_Armb, Lifter_Armtb, tab_cond
from miasm.expression.expression import ExprAssign, ExprOp, ExprLoc, ExprCond
from miasm.ir.ir import AssignBlock

class LifterModelCallArmlBase(Lifter_Arml, LifterModelCall):
    def __init__(self, loc_db):
        Lifter_Arml.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0

class LifterModelCallArmbBase(Lifter_Armb, LifterModelCall):
    def __init__(self, loc_db):
        Lifter_Armb.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0


class LifterModelCallArml(LifterModelCallArmlBase):

    def __init__(self, loc_db):
        LifterModelCallArmlBase.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0

    def call_effects(self, ad, instr):
        call_assignblk = AssignBlock(
            [
                ExprAssign(
                    self.ret_reg,
                    ExprOp(
                        'call_func_ret',
                        ad,
                        self.arch.regs.R0,
                        self.arch.regs.R1,
                        self.arch.regs.R2,
                        self.arch.regs.R3,
                    )
                ),
                ExprAssign(
                    self.sp,
                    ExprOp('call_func_stack', ad, self.sp)
                ),
            ],
            instr
        )


        cond = instr.additional_info.cond
        if cond == 14: # COND_ALWAYS:
            return [call_assignblk], []

        # Call is a conditional instruction
        cond = tab_cond[cond]

        loc_next = self.get_next_loc_key(instr)
        loc_next_expr = ExprLoc(loc_next, 32)
        loc_do = self.loc_db.add_location()
        loc_do_expr = ExprLoc(loc_do, 32)
        dst_cond = ExprCond(cond, loc_do_expr, loc_next_expr)

        call_assignblks = [
            call_assignblk,
            AssignBlock([ExprAssign(self.IRDst, loc_next_expr)], instr),
        ]
        e_do = IRBlock(self.loc_db, loc_do, call_assignblks)
        assignblks_out = [
            AssignBlock([ExprAssign(self.IRDst, dst_cond)], instr)
        ]
        return assignblks_out, [e_do]


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

class LifterModelCallArmb(LifterModelCallArmbBase, LifterModelCallArml):

    def __init__(self, loc_db):
        LifterModelCallArmbBase.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0


class LifterModelCallArmtl(Lifter_Armtl, LifterModelCallArml):
    def __init__(self, loc_db):
        Lifter_Armtl.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0

class LifterModelCallArmtb(LifterModelCallArmtl, Lifter_Armtb, LifterModelCallArmb):
    def __init__(self, loc_db):
        Lifter_Armtb.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0
