from miasm2.jitter.jitload import jitter
from miasm2.core import asmbloc
from miasm2.core.utils import *
from miasm2.arch.mips32.sem import ir_mips32

import logging

log = logging.getLogger('jit_mips32')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_mips32(jitter):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_mips32(sp), *args, **kwargs)
        self.my_ir.jit_pc = self.my_ir.arch.regs.PC
        self.my_ir.attrib = 'l'

    def vm_push_uint32_t(self, v):
        self.cpu.SP -= 4
        self.vm.vm_set_mem(self.cpu.SP, pck32(v))

    def vm_pop_uint32_t(self):
        x = upck32(self.vm.vm_get_mem(self.cpu.SP, 4))
        self.cpu.SP += 4
        return x

    def get_stack_arg(self, n):
        x = upck32(self.vm.vm_get_mem(self.cpu.SP + 4 * n, 4))
        return x

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc
