#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.expression.expression import *
from miasm2.ir.ir import ir, irbloc
from miasm2.ir.analysis import ira
from miasm2.arch.mips32.sem import ir_mips32
from miasm2.arch.mips32.regs import *
from miasm2.core.asmbloc import expr_is_int_or_label, expr_is_label
class ir_a_mips32(ir_mips32, ira):

    def __init__(self, symbol_pool=None):
        ir_mips32.__init__(self, symbol_pool)
        self.ret_reg = self.arch.regs.V0

    def get_next_break_label(self, instr):
        l = self.symbol_pool.getby_offset_create(instr.offset  + 8)
        return l

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
        for irb in ir_blocs:
            # print 'X'*40
            # print irb
            pc_val = None
            lr_val = None
            for exprs in irb.irs:
                for e in exprs:
                    if e.dst == PC:
                        pc_val = e.src
                    if e.dst == RA:
                        lr_val = e.src
            #print "XXX", pc_val, lr_val
            if pc_val is None or lr_val is None:
                continue
            if not expr_is_int_or_label(lr_val):
                continue
            if expr_is_label(lr_val):
                lr_val = ExprInt32(lr_val.name.offset)

            l = bloc.lines[-2]
            #print 'TEST', l, hex(lr_val.arg), hex(l.offset + 8)
            #print lr_val.arg, hex(l.offset + l.l)
            if lr_val.arg != l.offset + 8:
                fds
                continue
            # print 'IS CALL!'
            lbl = bloc.get_next()
            new_lbl = self.gen_label()
            irs = self.call_effects(pc_val)
            nbloc = irbloc(new_lbl, ExprId(lbl, size=self.pc.size), irs)
            nbloc.lines = [l]
            self.blocs[new_lbl] = nbloc
            irb.dst = ExprId(new_lbl, size=self.pc.size)

    def get_out_regs(self, b):
        return set([self.ret_reg, self.sp])


