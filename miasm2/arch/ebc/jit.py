#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.jitter.jitload import jitter
from miasm2.core import asmbloc
from miasm2.core.utils import pck32, pck64, upck32, upck64

log = None

class jitter_ebc(jitter):
    def __init__(self, *args, **kwargs):
        from miasm2.arch.ebc.sem import ir_ebc_32
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_ebc_32(sp), *args, **kwargs)
        self.vm.set_little_endian()
        self.ir_arch.jit_pc = self.ir_arch.arch.regs.IP
    def get_stack_arg_uint32_t(self, n):
        regs = self.cpu.get_gpreg()
        return upck32(self.vm.get_mem(regs['R0'] + 4 * n, 4))
    def func_ret(self, ret_addr, ret_value=None):
        self.pc = self.cpu.IP = ret_addr
        if  ret_value is not None:
            self.cpu.R7 = ret_value
        return True
    def push_uint32_t(self, v):
        regs = self.cpu.get_gpreg()
        regs['R0'] -= 4
        self.cpu.set_gpreg(regs)
        self.vm.set_mem(regs['R0'], pck32(v))
    def push_uint64_t(self, v):
        regs = self.cpu.get_gpreg()
        regs['R0'] -= 8
        self.cpu.set_gpreg(regs)
        self.vm.set_mem(regs['R0'], pck64(v))
    def pop_uint64_t(self):
        regs = self.cpu.get_gpreg()
        x = upck64(self.vm.get_mem(regs['R0'], 8))
        regs['R0'] += 8
        self.cpu.set_gpreg(regs)
        return x

