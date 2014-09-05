#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.core.graph import DiGraph
from miasm2.ir.ir import ir, irbloc
from miasm2.ir.analysis import ira
from miasm2.arch.x86.sem import ir_x86_16, ir_x86_32, ir_x86_64


class ir_a_x86_16(ir_x86_16, ira):

    def __init__(self, symbol_pool=None):
        ir_x86_16.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.AX

    # for test XXX TODO
    def set_dead_regs(self, b):
        b.rw[-1][1].add(self.arch.regs.zf)
        b.rw[-1][1].add(self.arch.regs.of)
        b.rw[-1][1].add(self.arch.regs.pf)
        b.rw[-1][1].add(self.arch.regs.cf)
        b.rw[-1][1].add(self.arch.regs.nf)
        b.rw[-1][1].add(self.arch.regs.af)

    def get_out_regs(self, b):
        return set([self.ret_reg, self.sp])

    def add_unused_regs(self):
        leaves = [self.blocs[n] for n in self.g.leafs()]
        for b in leaves:
            self.set_dead_regs(b)

    def call_effects(self, ad):
        irs = [[ExprAff(self.ret_reg, ExprOp('call_func_ret', ad, self.sp)),
                ExprAff(self.sp, ExprOp('call_func_stack', ad, self.sp)),
                ]]
        return irs

    def post_add_bloc(self, bloc, ir_blocs):
        ir.post_add_bloc(self, bloc, ir_blocs)
        if not bloc.lines:
            return
        l = bloc.lines[-1]
        sub_call_dst = None
        if not l.is_subcall():
            return
        sub_call_dst = l.args[0]
        if self.ExprIsLabel(sub_call_dst):
            sub_call_dst = sub_call_dst.name
        for b in ir_blocs:
            l = b.lines[-1]
            sub_call_dst = None
            if not l.is_subcall():
                continue
            sub_call_dst = l.args[0]
            if self.ExprIsLabel(sub_call_dst):
                sub_call_dst = sub_call_dst.name
            lbl = bloc.get_next()
            new_lbl = self.gen_label()
            irs = self.call_effects(l.args[0])
            irs.append([ExprAff(self.IRDst, ExprId(lbl, size=self.pc.size))])

            nbloc = irbloc(new_lbl, irs)
            nbloc.lines = [l]
            self.blocs[new_lbl] = nbloc
            b.dst = ExprId(new_lbl, size=self.pc.size)
        return


class ir_a_x86_32(ir_x86_32, ir_a_x86_16):

    def __init__(self, symbol_pool=None):
        ir_x86_32.__init__(self, symbol_pool)
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


class ir_a_x86_64(ir_x86_64, ir_a_x86_16):

    def __init__(self, symbol_pool=None):
        ir_x86_64.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.RAX

    def call_effects(self, ad):
        irs = [[ExprAff(self.ret_reg, ExprOp('call_func_ret', ad, self.sp,
                                             self.arch.regs.RCX,
                                             self.arch.regs.RDX,
                                             self.arch.regs.R8,
                                             self.arch.regs.R9,
                                             )),
                ExprAff(self.sp, ExprOp('call_func_stack', ad, self.sp)),
                ]]
        return irs
