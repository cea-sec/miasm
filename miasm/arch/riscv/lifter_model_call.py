#-*- coding:utf-8 -*-

from miasm.ir.analysis import LifterModelCall
from miasm.arch.riscv.sem import Lifter_Riscv64

class LifterModelCallRiscv64Base(Lifter_Riscv64, LifterModelCall):

    def __init__(self, loc_db):
        Lifter_Riscv64.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.X0


class LifterModelCallRiscv64(LifterModelCallRiscv64Base):

    def __init__(self, loc_db):
        LifterModelCallRiscv64Base.__init__(self, loc_db)
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