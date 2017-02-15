import logging

from miasm2.jitter.jitload import jitter, named_arguments
from miasm2.core import asmbloc
from miasm2.core.utils import pck32, upck32
from miasm2.arch.arm.sem import ir_armb, ir_arml

log = logging.getLogger('jit_arm')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_arml(jitter):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.AsmSymbolPool()
        jitter.__init__(self, ir_arml(sp), *args, **kwargs)
        self.vm.set_little_endian()

    def push_uint32_t(self, value):
        self.cpu.SP -= 4
        self.vm.set_mem(self.cpu.SP, pck32(value))

    def pop_uint32_t(self):
        value = upck32(self.vm.get_mem(self.cpu.SP, 4))
        self.cpu.SP += 4
        return value

    def get_stack_arg(self, index):
        return upck32(self.vm.get_mem(self.cpu.SP + 4 * index, 4))

    # calling conventions

    @named_arguments
    def func_args_stdcall(self, n_args):
        args = []
        for i in xrange(min(n_args, 4)):
            args.append(self.cpu.get_gpreg()['R%d' % i])
        for i in xrange(max(0, n_args - 4)):
            args.append(self.get_stack_arg(i))
        ret_ad = self.cpu.LR
        return ret_ad, args

    def func_ret_stdcall(self, ret_addr, ret_value=None):
        self.pc = self.cpu.PC = ret_addr
        if ret_value is not None:
            self.cpu.R0 = ret_value
        return True

    def get_arg_n_stdcall(self, index):
        if index < 4:
            arg = self.cpu.get_gpreg()['R%d' % index]
        else:
            arg = self.get_stack_arg(index-4)
        return arg

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc

class jitter_armb(jitter_arml):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.AsmSymbolPool()
        jitter.__init__(self, ir_armb(sp), *args, **kwargs)
        self.vm.set_big_endian()
