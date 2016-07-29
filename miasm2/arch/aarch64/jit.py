import logging

from miasm2.jitter.jitload import jitter, named_arguments
from miasm2.core import asmbloc
from miasm2.core.utils import *
from miasm2.arch.aarch64.sem import ir_aarch64b, ir_aarch64l

log = logging.getLogger('jit_aarch64')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_aarch64l(jitter):
    max_reg_arg = 8

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_aarch64l(sp), *args, **kwargs)
        self.vm.set_little_endian()

    def push_uint64_t(self, v):
        self.cpu.SP -= 8
        self.vm.set_mem(self.cpu.SP, pck64(v))

    def pop_uint64_t(self):
        x = upck32(self.vm.get_mem(self.cpu.SP, 8))
        self.cpu.SP += 8
        return x

    def get_stack_arg(self, n):
        x = upck64(self.vm.get_mem(self.cpu.SP + 8 * n, 8))
        return x

    # calling conventions

    @named_arguments
    def func_args_stdcall(self, n_args):
        args = []
        for i in xrange(min(n_args, self.max_reg_arg)):
            args.append(self.cpu.get_gpreg()['X%d' % i])
        for i in xrange(max(0, n_args - self.max_reg_arg)):
            args.append(self.get_stack_arg(i))
        ret_ad = self.cpu.LR
        return ret_ad, args

    def func_ret_stdcall(self, ret_addr, ret_value=None):
        self.pc = self.cpu.PC = ret_addr
        if ret_value is not None:
            self.cpu.X0 = ret_value
        return True

    def get_arg_n_stdcall(self, n):
        if n < self.max_reg_arg:
            arg = self.cpu.get_gpreg()['X%d' % n]
        else:
            arg = self.get_stack_arg(n - self.max_reg_arg)
        return arg

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc


class jitter_aarch64b(jitter_aarch64l):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_aarch64b(sp), *args, **kwargs)
        self.vm.set_big_endian()
