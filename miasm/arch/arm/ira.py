#-*- coding:utf-8 -*-

from miasm.ir.analysis import ira
from miasm.ir.ir import IRBlock
from miasm.arch.arm.sem import ir_arml, ir_armtl, ir_armb, ir_armtb, tab_cond
from miasm.expression.expression import ExprAssign, ExprOp, ExprLoc, ExprCond
from miasm.ir.ir import AssignBlock

class ir_a_arml_base(ir_arml, ira):
    def __init__(self, loc_db=None):
        ir_arml.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0

class ir_a_armb_base(ir_armb, ira):
    def __init__(self, loc_db=None):
        ir_armb.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0


class ir_a_arml(ir_a_arml_base):

    def __init__(self, loc_db=None):
        ir_a_arml_base.__init__(self, loc_db)
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
        e_do = IRBlock(loc_do, call_assignblks)
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

class ir_a_armb(ir_a_armb_base, ir_a_arml):

    def __init__(self, loc_db=None):
        ir_a_armb_base.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0


class ir_a_armtl(ir_armtl, ir_a_arml):
    def __init__(self, loc_db=None):
        ir_armtl.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0

class ir_a_armtb(ir_a_armtl, ir_armtb, ir_a_armb):
    def __init__(self, loc_db=None):
        ir_armtb.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R0
