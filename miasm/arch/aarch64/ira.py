#-*- coding:utf-8 -*-

from miasm.ir.analysis import LifterModelCall
from miasm.arch.aarch64.sem import Lifter_Aarch64l, Lifter_Aarch64b


class ir_a_aarch64l_base(Lifter_Aarch64l, LifterModelCall):

    def __init__(self, loc_db):
        Lifter_Aarch64l.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0


class ir_a_aarch64b_base(Lifter_Aarch64b, LifterModelCall):

    def __init__(self, loc_db):
        Lifter_Aarch64b.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0


class ir_a_aarch64l(ir_a_aarch64l_base):

    def __init__(self, loc_db):
        ir_a_aarch64l_base.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0

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


class ir_a_aarch64b(ir_a_aarch64b_base, ir_a_aarch64l):

    def __init__(self, loc_db):
        ir_a_aarch64b_base.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0
