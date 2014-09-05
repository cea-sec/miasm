#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.ir.ir import ir, irbloc
from miasm2.ir.analysis import ira
from miasm2.arch.arm.sem import ir_arm, ir_armt
from miasm2.arch.arm.regs import *
# from miasm2.core.graph import DiGraph


class ir_a_arm_base(ir_arm, ira):

    def __init__(self, symbol_pool=None):
        ir_arm.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R0


class ir_a_arm(ir_a_arm_base):

    def __init__(self, symbol_pool=None):
        ir_a_arm_base.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R0

    # for test XXX TODO
    def set_dead_regs(self, b):
        b.rw[-1][1].add(self.arch.regs.zf)
        b.rw[-1][1].add(self.arch.regs.nf)
        b.rw[-1][1].add(self.arch.regs.of)
        b.rw[-1][1].add(self.arch.regs.cf)

    def call_effects(self, ad):
        irs = [[ExprAff(self.ret_reg, ExprOp('call_func_ret', ad, self.sp)),
                ExprAff(self.sp, ExprOp('call_func_stack', ad, self.sp)),
                ]]
        return irs

    def post_add_bloc(self, bloc, ir_blocs):
        ir.post_add_bloc(self, bloc, ir_blocs)
        # flow_graph = DiGraph()
        for irb in ir_blocs:
            # print 'X'*40
            # print irb
            pc_val = None
            lr_val = None
            for exprs in irb.irs:
                for e in exprs:
                    if e.dst == PC:
                        pc_val = e.src
                    if e.dst == LR:
                        lr_val = e.src
            if pc_val is None or lr_val is None:
                continue
            if not isinstance(lr_val, ExprInt):
                continue

            l = bloc.lines[-1]
            if lr_val.arg != l.offset + l.l:
                continue
            # print 'IS CALL!'
            lbl = bloc.get_next()
            new_lbl = self.gen_label()
            irs = self.call_effects(pc_val)
            irs.append([ExprAff(self.IRDst, ExprId(lbl, size=self.pc.size))])
            nbloc = irbloc(new_lbl, irs)
            nbloc.lines = [l]
            self.blocs[new_lbl] = nbloc
            irb.dst = ExprId(new_lbl, size=self.pc.size)

        """
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
            sub_call_dst_b = None
            sub_call_dst_b = l.args[0]
            #if self.ExprIsLabel(sub_call_dst_b):
            #    sub_call_dst_b = sub_call_dst.name
            #if str(b.dst) == str(sub_call_dst_b):
            #    pass
            if not l.is_subcall():
                continue
            if b.dst != sub_call_dst_b:
                continue
            sub_call_dst_b = l.args[0]
            if self.ExprIsLabel(sub_call_dst_b):
                sub_call_dst_b = sub_call_dst.name
            lbl = bloc.get_next()
            new_lbl = self.gen_label()
            irs = self.call_effects(l.args[0])
            nbloc = irbloc(new_lbl, ExprId(lbl, size=self.pc.size), irs)
            nbloc.lines = [l]
            self.blocs[new_lbl] = nbloc
            b.dst = ExprId(new_lbl, size=self.pc.size)
        return
        """

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


class ir_a_armt(ir_armt, ir_a_arm):

    def __init__(self, symbol_pool):
        ir_armt.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.R0
