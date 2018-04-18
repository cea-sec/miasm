#-*- coding:utf-8 -*-

from miasm2.ir.analysis import ira
from miasm2.arch.arm.sem import ir_arml, ir_armtl, ir_armb, ir_armtb


class ir_a_arml_base(ir_arml, ira):
    def __init__(self, symbol_pool=None):
        ir_arml.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R0

class ir_a_armb_base(ir_armb, ira):
    def __init__(self, symbol_pool=None):
        ir_armb.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R0


class ir_a_arml(ir_a_arml_base):

    def __init__(self, symbol_pool=None):
        ir_a_arml_base.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R0

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

    def __init__(self, symbol_pool=None):
        ir_a_armb_base.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R0


class ir_a_armtl(ir_armtl, ir_a_arml):
    def __init__(self, symbol_pool=None):
        ir_armtl.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R0

class ir_a_armtb(ir_a_armtl, ir_armtb, ir_a_armb):
    def __init__(self, symbol_pool=None):
        ir_armtb.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R0
