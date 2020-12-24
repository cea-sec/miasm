from builtins import range
from miasm.jitter.jitload import Jitter, named_arguments
from miasm.arch.ppc.sem import Lifter_PPC32b
import struct

import logging

log = logging.getLogger('jit_ppc')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_ppc32b(Jitter):
    max_reg_arg = 8

    def __init__(self, loc_db, *args, **kwargs):
        super(jitter_ppc32b, self).__init__(Lifter_PPC32b(loc_db),
                                            *args, **kwargs)
        self.vm.set_big_endian()

    def push_uint32_t(self, v):
        self.cpu.R1 -= 4
        self.vm.set_mem(self.cpu.R1, struct.pack(">I", v))

    def pop_uint32_t(self):
        x = struct.unpack(">I", self.vm.get_mem(self.cpu.R1, 4))[0]
        self.cpu.R1 += 4
        return x

    def get_stack_arg(self, n):
        x = struct.unpack(">I", self.vm.get_mem(self.cpu.R1 + 8 + 4 * n, 4))[0]
        return x

    @named_arguments
    def func_args_systemv(self, n_args):
        args = [self.get_arg_n_systemv(i) for i in range(n_args)]
        ret_ad = self.cpu.LR
        return ret_ad, args

    def func_ret_systemv(self, ret_addr, ret_value1=None, ret_value2=None):
        self.pc = self.cpu.PC = ret_addr
        if ret_value1 is not None:
            self.cpu.R3 = ret_value1
        if ret_value2 is not None:
            self.cpu.R4 = ret_value2
        return True

    def func_prepare_systemv(self, ret_addr, *args):
        for index in range(min(len(args), self.max_reg_arg)):
            setattr(self.cpu, 'R%d' % (index + 3), args[index])
        for index in range(len(args) - 1, self.max_reg_arg - 1, -1):
            self.push_uint32_t(args[index])

        # reserve room for LR save word and backchain
        self.cpu.R1 -= 8

        self.cpu.LR = ret_addr

    def get_arg_n_systemv(self, index):
        if index < self.max_reg_arg:
            arg = getattr(self.cpu, 'R%d' % (index + 3))
        else:
            arg = self.get_stack_arg(index - self.max_reg_arg)
        return arg


    def init_run(self, *args, **kwargs):
        Jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc
