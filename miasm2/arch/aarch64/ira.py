#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.ir.ir import ir, irbloc, AssignBlock
from miasm2.ir.analysis import ira
from miasm2.arch.aarch64.sem import ir_aarch64l, ir_aarch64b
from miasm2.arch.aarch64.regs import *


class ir_a_aarch64l_base(ir_aarch64l, ira):

    def __init__(self, symbol_pool=None):
        ir_aarch64l.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.X0


class ir_a_aarch64b_base(ir_aarch64b, ira):

    def __init__(self, symbol_pool=None):
        ir_aarch64b.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.X0


class ir_a_aarch64l(ir_a_aarch64l_base):

    def __init__(self, symbol_pool=None):
        ir_a_aarch64l_base.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.X0

    # for test XXX TODO
    def set_dead_regs(self, b):
        b.rw[-1][1].add(self.arch.regs.zf)
        b.rw[-1][1].add(self.arch.regs.nf)
        b.rw[-1][1].add(self.arch.regs.of)
        b.rw[-1][1].add(self.arch.regs.cf)

    def post_add_bloc(self, bloc, ir_blocs):
        ir.post_add_bloc(self, bloc, ir_blocs)
        for irb in ir_blocs:
            pc_val = None
            lr_val = None
            for assignblk in irb.irs:
                pc_val = assignblk.get(PC, pc_val)
                lr_val = assignblk.get(LR, lr_val)
            if pc_val is None or lr_val is None:
                continue
            if not isinstance(lr_val, ExprInt):
                continue

            l = bloc.lines[-1]
            if lr_val.arg != l.offset + l.l:
                continue

            # CALL
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

    def __init__(self, symbol_pool=None):
        ir_a_aarch64b_base.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.X0
