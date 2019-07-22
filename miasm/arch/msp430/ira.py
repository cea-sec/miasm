#-*- coding:utf-8 -*-

from miasm.ir.analysis import ira
from miasm.arch.msp430.sem import ir_msp430
from miasm.ir.ir import AssignBlock
from miasm.expression.expression import *

class ir_a_msp430_base(ir_msp430, ira):

    def __init__(self, loc_db=None):
        ir_msp430.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.R15

    def call_effects(self, addr, instr):
        call_assignblk = AssignBlock(
            [
                ExprAssign(self.ret_reg, ExprOp('call_func_ret', addr, self.sp, self.arch.regs.R15)),
                ExprAssign(self.sp, ExprOp('call_func_stack', addr, self.sp))
            ],
            instr
        )
        return [call_assignblk], []

class ir_a_msp430(ir_a_msp430_base):

    def __init__(self, loc_db=None):
        ir_a_msp430_base.__init__(self, loc_db)

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

