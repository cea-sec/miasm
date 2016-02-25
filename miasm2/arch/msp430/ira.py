#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.ir.ir import ir, irbloc, AssignBlock
from miasm2.ir.analysis import ira
from miasm2.arch.msp430.sem import ir_msp430
from miasm2.arch.msp430.regs import *
# from miasm2.core.graph import DiGraph


class ir_a_msp430_base(ir_msp430, ira):

    def __init__(self, symbol_pool=None):
        ir_msp430.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R15


class ir_a_msp430(ir_a_msp430_base):

    def __init__(self, symbol_pool=None):
        ir_a_msp430_base.__init__(self, symbol_pool)

    # for test XXX TODO
    def set_dead_regs(self, b):
        b.rw[-1][1].add(self.arch.regs.zf)
        b.rw[-1][1].add(self.arch.regs.nf)
        b.rw[-1][1].add(self.arch.regs.of)
        b.rw[-1][1].add(self.arch.regs.cf)

        b.rw[-1][1].add(self.arch.regs.res)
        b.rw[-1][1].add(self.arch.regs.scg1)
        b.rw[-1][1].add(self.arch.regs.scg0)
        b.rw[-1][1].add(self.arch.regs.osc)
        b.rw[-1][1].add(self.arch.regs.cpuoff)
        b.rw[-1][1].add(self.arch.regs.gie)

    def post_add_bloc(self, bloc, ir_blocs):
        ir.post_add_bloc(self, bloc, ir_blocs)
        l = bloc.lines[-1]
        if not l.is_subcall():
            return

        for irb in ir_blocs:
            pc_val = None
            for assignblk in irb.irs:
                pc_val = assignblk.get(PC, pc_val)
            if pc_val is None:
                continue

            l = bloc.lines[-1]
            lbl = bloc.get_next()
            new_lbl = self.gen_label()
            irs = self.call_effects(pc_val)
            irs.append(AssignBlock([ExprAff(self.IRDst,
                                            ExprId(lbl, size=self.pc.size))]))
            nbloc = irbloc(new_lbl, irs)
            nbloc.lines = [l] * len(irs)
            self.blocs[new_lbl] = nbloc
            irb.dst = ExprId(new_lbl, size=self.pc.size)

    def get_out_regs(self, b):
        return set([self.ret_reg, self.sp])

