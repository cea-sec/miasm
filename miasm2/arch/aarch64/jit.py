import logging

from miasm2.jitter.jitload import jitter, named_arguments
from miasm2.core import asmblock
from miasm2.core.utils import pck64, upck64
from miasm2.arch.aarch64.sem import ir_aarch64b, ir_aarch64l

log = logging.getLogger('jit_aarch64')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_aarch64l(jitter):
    max_reg_arg = 8

    def __init__(self, *args, **kwargs):
        sp = asmblock.AsmSymbolPool()
        jitter.__init__(self, ir_aarch64l(sp), *args, **kwargs)
        self.vm.set_little_endian()

    def push_uint64_t(self, value):
        self.cpu.SP -= 8
        self.vm.set_mem(self.cpu.SP, pck64(value))

    def pop_uint64_t(self):
        value = upck64(self.vm.get_mem(self.cpu.SP, 8))
        self.cpu.SP += 8
        return value

    def get_stack_arg(self, index):
        return upck64(self.vm.get_mem(self.cpu.SP + 8 * index, 8))

    # calling conventions

    @named_arguments
    def func_args_stdcall(self, n_args):
        args = []
        for i in xrange(min(n_args, self.max_reg_arg)):
            args.append(getattr(self.cpu, 'X%d' % i))
        for i in xrange(max(0, n_args - self.max_reg_arg)):
            args.append(self.get_stack_arg(i))
        ret_ad = self.cpu.LR
        return ret_ad, args

    def func_ret_stdcall(self, ret_addr, ret_value=None):
        self.pc = self.cpu.PC = ret_addr
        if ret_value is not None:
            self.cpu.X0 = ret_value
        return True

    def get_arg_n_stdcall(self, index):
        if index < self.max_reg_arg:
            arg = self.cpu.get_gpreg()['X%d' % index]
        else:
            arg = self.get_stack_arg(index - self.max_reg_arg)
        return arg

    def func_prepare_stdcall(self, ret_addr, *args):
        for index in xrange(min(len(args), 4)):
            setattr(self.cpu, 'X%d' % index, args[index])
        for index in xrange(4, len(args)):
            self.vm.set_mem(self.cpu.SP + 8 * (index - 4), pck64(args[index]))
        self.cpu.LR = ret_addr

    func_args_systemv = func_args_stdcall
    func_ret_systemv = func_ret_stdcall
    get_arg_n_systemv = get_arg_n_stdcall
    func_prepare_systemv = func_prepare_stdcall

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc


class jitter_aarch64b(jitter_aarch64l):

    def __init__(self, *args, **kwargs):
        sp = asmblock.AsmSymbolPool()
        jitter.__init__(self, ir_aarch64b(sp), *args, **kwargs)
        self.vm.set_big_endian()
