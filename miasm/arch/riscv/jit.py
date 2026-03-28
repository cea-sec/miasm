from builtins import range
import logging

from miasm.jitter.jitload import Jitter, named_arguments
from miasm.core.utils import pck64, upck64
from miasm.arch.riscv.sem import Lifter_Riscv64

log = logging.getLogger('jit_riscv64')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_riscv64(Jitter):
    # a0 - a7
    max_reg_arg = 8

    def __init__(self, loc_db, *args, **kwargs):
        Jitter.__init__(self, Lifter_Riscv64(loc_db), *args, **kwargs)
        self.vm.set_little_endian() # RISC-V is little-endian

    def push_uint64_t(self, value):
        self.cpu.X2 -= 8
        self.vm.set_mem(self.cpu.X2, pck64(value))

    def pop_uint64_t(self):
        value = self.vm.get_u64(self.cpu.X2)
        self.cpu.X2 += 8
        return value

    def get_stack_arg(self, index):
        return self.vm.get_u64(self.cpu.X2 + 8 * index)

    # calling conventions

    @named_arguments
    def func_args_stdcall(self, n_args):
        args = []
        for i in range(min(n_args, self.max_reg_arg)):
            args.append(getattr(self.cpu, 'X%d' % (10 + i)))
        for i in range(max(0, n_args - self.max_reg_arg)):
            args.append(self.get_stack_arg(i))
        ret_ad = self.cpu.X1
        return ret_ad, args
    def func_ret_stdcall(self, ret_addr, ret_value=None):
        self.pc = self.cpu.PC = ret_addr
        if ret_value is not None:
            self.cpu.X10 = ret_value
        return True


    def get_arg_n_stdcall(self, index):
        if index < self.max_reg_arg:
            # a0..a7 = X10..X17
            reg_name = 'X%d' % (10 + index)
            arg = self.cpu.get_gpreg()[reg_name]
        else:
            arg = self.get_stack_arg(index - self.max_reg_arg)
        return arg

    def func_prepare_stdcall(self, ret_addr, *args):
        for index in range(min(len(args), self.max_reg_arg)):
            setattr(self.cpu, 'X%d' % (10 + index), args[index])
        for index in range(self.max_reg_arg, len(args)):
            self.vm.set_mem(self.cpu.X2 + 8 * (index - self.max_reg_arg),
                            pck64(args[index]))
        self.cpu.X1 = ret_addr

    func_args_systemv    = func_args_stdcall
    func_ret_systemv     = func_ret_stdcall
    get_arg_n_systemv    = get_arg_n_stdcall
    func_prepare_systemv = func_prepare_stdcall

    def init_run(self, *args, **kwargs):
        Jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc