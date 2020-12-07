#-*- coding:utf-8 -*-

from miasm.ir.analysis import LifterModelCall
from miasm.arch.msp430.sem import Lifter_MSP430
from miasm.ir.ir import AssignBlock
from miasm.expression.expression import *

class LifterModelCallMsp430Base(Lifter_MSP430, LifterModelCall):

    def __init__(self, loc_db):
        Lifter_MSP430.__init__(self, loc_db)
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

class LifterModelCallMsp430(LifterModelCallMsp430Base):

    def __init__(self, loc_db):
        LifterModelCallMsp430Base.__init__(self, loc_db)

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

