#-*- coding:utf-8 -*-

from miasm.expression.expression import ExprAssign, ExprOp
from miasm.ir.ir import AssignBlock
from miasm.ir.analysis import LifterModelCall
from miasm.arch.x86.sem import Lifter_X86_16, Lifter_X86_32, Lifter_X86_64


class LifterModelCall_x86_16(Lifter_X86_16, LifterModelCall):

    def __init__(self, loc_db):
        Lifter_X86_16.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.AX

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

class LifterModelCall_x86_32(Lifter_X86_32, LifterModelCall_x86_16):

    def __init__(self, loc_db):
        Lifter_X86_32.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.EAX

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


class LifterModelCall_x86_64(Lifter_X86_64, LifterModelCall_x86_16):

    def __init__(self, loc_db):
        Lifter_X86_64.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.RAX

    def call_effects(self, ad, instr):
        call_assignblk = AssignBlock(
            [
                ExprAssign(
                    self.ret_reg,
                    ExprOp(
                        'call_func_ret',
                        ad,
                        self.sp,
                        self.arch.regs.RCX,
                        self.arch.regs.RDX,
                        self.arch.regs.R8,
                        self.arch.regs.R9,
                    )
                ),
                ExprAssign(self.sp, ExprOp('call_func_stack', ad, self.sp)),
            ],
            instr
        )
        return [call_assignblk], []

    def sizeof_char(self):
        return 8

    def sizeof_short(self):
        return 16

    def sizeof_int(self):
        return 32

    def sizeof_long(self):
        return 64

    def sizeof_pointer(self):
        return 64
