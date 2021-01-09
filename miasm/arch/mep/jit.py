# Toshiba MeP-c4 - miasm jitter
# Guillaume Valadon <guillaume@valadon.net>
# Note: inspiration from msp430/jit.py

from miasm.jitter.jitload import Jitter
from miasm.core.utils import *
from miasm.jitter.codegen import CGen
from miasm.ir.translators.C import TranslatorC
from miasm.arch.mep.sem import Lifter_MEPl, Lifter_MEPb

import logging

log = logging.getLogger("jit_mep")
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)


class mep_CGen(CGen):
    """
    Translate a block containing MeP instructions to C

    Note: it is used to emulate the *REPEAT instructions
    """

    def __init__(self, lifter):
        self.lifter = lifter
        self.PC = self.lifter.arch.regs.PC
        self.translator = TranslatorC(self.lifter.loc_db)
        self.init_arch_C()

    def gen_pre_code(self, attrib):
        """Generate C code inserted before the current block"""

        # Call the base class method
        out = super(mep_CGen, self).gen_pre_code(attrib)

        # Set the PC register value explicitly
        out.append("mycpu->PC = 0x%X;" % attrib.instr.offset)
        out.append("mycpu->last_addr = mycpu->PC;");

        return out

    def gen_post_code(self, attrib, pc_value):
        """Generate C code inserted after the current block"""

        # Call the base class method
        out = super(mep_CGen, self).gen_post_code(attrib, pc_value)

        # Implement the *REPEAT instructions logics
        tmp = r"""
        /* *REPEAT instructions logic */
        {
            uint32_t is_repeat_end = mycpu->is_repeat_end;
            mycpu->is_repeat_end = !!(mycpu->last_addr == (mycpu->RPE&~0x1));

            if (is_repeat_end && !mycpu->take_jmp &&
                   (mycpu->in_erepeat || mycpu->RPC)) {
                 if (mycpu->RPC)
                       mycpu->RPC --;

                 //printf("Go repeat  %X\n", mycpu->RPB);
                 DST_value = mycpu->RPB;
                 BlockDst->address = mycpu->RPB;
                 return JIT_RET_NO_EXCEPTION;
             }
        }
        """

        out += tmp.split('`\n')
        return out


class jitter_mepl(Jitter):

    C_Gen = mep_CGen

    def __init__(self, loc_db, *args, **kwargs):
        Jitter.__init__(self, Lifter_MEPl(loc_db), *args, **kwargs)
        self.vm.set_little_endian()
        self.lifter.jit_pc = self.lifter.arch.regs.PC

    def push_uint16_t(self, v):
        regs = self.cpu.get_gpreg()
        regs["SP"] -= 2
        self.cpu.set_gpreg(regs)
        self.vm.set_mem(regs["SP"], pck16(v))

    def pop_uint16_t(self):
        regs = self.cpu.get_gpreg()
        x = self.vm.get_u16(regs["SP"])
        regs["SP"] += 2
        self.cpu.set_gpreg(regs)
        return x

    def get_stack_arg(self, n):
        regs = self.cpu.get_gpreg()
        x = self.vm.get_u16(regs["SP"] + 2 * n)
        return x

    def init_run(self, *args, **kwargs):
        Jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc


class jitter_mepb(jitter_mepl):

    def __init__(self, loc_db, *args, **kwargs):
        Jitter.__init__(self, Lifter_MEPb(loc_db), *args, **kwargs)
        self.vm.set_big_endian()
        self.lifter.jit_pc = self.lifter.arch.regs.PC
