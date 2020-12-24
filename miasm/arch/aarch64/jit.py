from builtins import range
import logging

from miasm.jitter.jitload import Jitter, named_arguments
from miasm.core.utils import pck64, upck64
from miasm.arch.aarch64.sem import Lifter_Aarch64b, Lifter_Aarch64l

log = logging.getLogger('jit_aarch64')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_aarch64l(Jitter):
    max_reg_arg = 8

    def __init__(self, loc_db, *args, **kwargs):
        Jitter.__init__(self, Lifter_Aarch64l(loc_db), *args, **kwargs)
        self.vm.set_little_endian()

    def push_uint64_t(self, value):
        self.cpu.SP -= 8
        self.vm.set_mem(self.cpu.SP, pck64(value))

    def pop_uint64_t(self):
        value = self.vm.get_u64(self.cpu.SP)
        self.cpu.SP += 8
        return value

    def get_stack_arg(self, index):
        return self.vm.get_u64(self.cpu.SP + 8 * index)

    # calling conventions

    @named_arguments
    def func_args_stdcall(self, n_args):
        args = []
        for i in range(min(n_args, self.max_reg_arg)):
            args.append(getattr(self.cpu, 'X%d' % i))
        for i in range(max(0, n_args - self.max_reg_arg)):
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
        for index in range(min(len(args), 4)):
            setattr(self.cpu, 'X%d' % index, args[index])
        for index in range(4, len(args)):
            self.vm.set_mem(self.cpu.SP + 8 * (index - 4), pck64(args[index]))
        self.cpu.LR = ret_addr

    func_args_systemv = func_args_stdcall
    func_ret_systemv = func_ret_stdcall
    get_arg_n_systemv = get_arg_n_stdcall
    func_prepare_systemv = func_prepare_stdcall

    def init_run(self, *args, **kwargs):
        Jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc


class jitter_aarch64b(jitter_aarch64l):

    def __init__(self, loc_db, *args, **kwargs):
        Jitter.__init__(self, Lifter_Aarch64b(loc_db), *args, **kwargs)
        self.vm.set_big_endian()
