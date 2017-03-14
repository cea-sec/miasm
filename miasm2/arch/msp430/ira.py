#-*- coding:utf-8 -*-

from miasm2.ir.analysis import ira
from miasm2.arch.msp430.sem import ir_msp430


class ir_a_msp430_base(ir_msp430, ira):

    def __init__(self, symbol_pool=None):
        ir_msp430.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R15


class ir_a_msp430(ir_a_msp430_base):

    def __init__(self, symbol_pool=None):
        ir_a_msp430_base.__init__(self, symbol_pool)

    # for test XXX TODO
    def set_dead_regs(self, irblock):
        irblock.rw[-1][1].add(self.arch.regs.zf)
        irblock.rw[-1][1].add(self.arch.regs.nf)
        irblock.rw[-1][1].add(self.arch.regs.of)
        irblock.rw[-1][1].add(self.arch.regs.cf)

        irblock.rw[-1][1].add(self.arch.regs.res)
        irblock.rw[-1][1].add(self.arch.regs.scg1)
        irblock.rw[-1][1].add(self.arch.regs.scg0)
        irblock.rw[-1][1].add(self.arch.regs.osc)
        irblock.rw[-1][1].add(self.arch.regs.cpuoff)
        irblock.rw[-1][1].add(self.arch.regs.gie)

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

