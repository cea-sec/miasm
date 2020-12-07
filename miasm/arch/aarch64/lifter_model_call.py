#-*- coding:utf-8 -*-

from miasm.ir.analysis import LifterModelCall
from miasm.arch.aarch64.sem import Lifter_Aarch64l, Lifter_Aarch64b


class LifterModelCallAarch64lBase(Lifter_Aarch64l, LifterModelCall):

    def __init__(self, loc_db):
        Lifter_Aarch64l.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0


class LifterModelCallAarch64bBase(Lifter_Aarch64b, LifterModelCall):

    def __init__(self, loc_db):
        Lifter_Aarch64b.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0


class LifterModelCallAarch64l(LifterModelCallAarch64lBase):

    def __init__(self, loc_db):
        LifterModelCallAarch64lBase.__init__(self, loc_db)
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


class LifterModelCallAarch64b(LifterModelCallAarch64bBase, LifterModelCallAarch64l):

    def __init__(self, loc_db):
        LifterModelCallAarch64bBase.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0
