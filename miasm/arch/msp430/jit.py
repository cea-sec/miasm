from miasm.jitter.jitload import Jitter
from miasm.core.locationdb import LocationDB
from miasm.core.utils import pck16, upck16
from miasm.arch.msp430.sem import Lifter_MSP430

import logging

log = logging.getLogger('jit_msp430')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_msp430(Jitter):

    def __init__(self, loc_db, *args, **kwargs):
        Jitter.__init__(self, Lifter_MSP430(loc_db), *args, **kwargs)
        self.vm.set_little_endian()

    def push_uint16_t(self, value):
        regs = self.cpu.get_gpreg()
        regs['SP'] -= 2
        self.cpu.set_gpreg(regs)
        self.vm.set_mem(regs['SP'], pck16(value))

    def pop_uint16_t(self):
        regs = self.cpu.get_gpreg()
        value = self.vm.get_u16(regs['SP'])
        regs['SP'] += 2
        self.cpu.set_gpreg(regs)
        return value

    def get_stack_arg(self, index):
        regs = self.cpu.get_gpreg()
        value = self.vm.get_u16(regs['SP'] + 2 * index)
        return value

    def init_run(self, *args, **kwargs):
        Jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc

