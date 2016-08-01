import logging

from miasm2.jitter.jitload import jitter
from miasm2.core import asmbloc
from miasm2.core.utils import *
from miasm2.arch.mips32.sem import ir_mips32l, ir_mips32b
from miasm2.jitter.codegen import CGen
import miasm2.expression.expression as m2_expr

log = logging.getLogger('jit_mips32')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)


class mipsCGen(CGen):
    CODE_INIT = CGen.CODE_INIT + r"""
    unsigned int branch_dst_pc;
    unsigned int branch_dst_irdst;
    unsigned int branch_dst_set=0;
    """

    CODE_RETURN_NO_EXCEPTION = r"""
    %s:
    if (branch_dst_set) {
        %s = %s;
        BlockDst->address = %s;
    } else {
        BlockDst->address = %s;
    }
    return JIT_RET_NO_EXCEPTION;
    """

    def __init__(self, ir_arch):
        super(mipsCGen, self).__init__(ir_arch)
        self.delay_slot_dst = m2_expr.ExprId("branch_dst_irdst")
        self.delay_slot_set = m2_expr.ExprId("branch_dst_set")

    def block2assignblks(self, block):
        irblocks_list = super(mipsCGen, self).block2assignblks(block)
        for instr, irblocks in zip(block.lines, irblocks_list):
            if not instr.breakflow():
                continue
            for irblock in irblocks:
                for i, assignblock in enumerate(irblock.irs):
                    if self.ir_arch.pc not in assignblock:
                        continue
                    # Add internal branch destination
                    assignblock[self.delay_slot_dst] = assignblock[
                        self.ir_arch.pc]
                    assignblock[self.delay_slot_set] = m2_expr.ExprInt(1, 32)
                    # Replace IRDst with next instruction
                    assignblock[self.ir_arch.IRDst] = m2_expr.ExprId(
                        self.ir_arch.get_next_instr(instr))
                    irblock.dst = m2_expr.ExprId(
                        self.ir_arch.get_next_instr(instr))
        return irblocks_list

    def gen_finalize(self, block):
        """
        Generate the C code for the final block instruction
        """

        lbl = self.get_block_post_label(block)
        out = (self.CODE_RETURN_NO_EXCEPTION % (lbl.name,
                                                self.C_PC,
                                                m2_expr.ExprId('branch_dst_irdst'),
                                                m2_expr.ExprId('branch_dst_irdst'),
                                                self.id_to_c(m2_expr.ExprInt(lbl.offset, 32)))
               ).split('\n')
        return out


class jitter_mips32l(jitter):

    C_Gen = mipsCGen

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_mips32l(sp), *args, **kwargs)
        self.vm.set_little_endian()

    def push_uint32_t(self, v):
        self.cpu.SP -= 4
        self.vm.set_mem(self.cpu.SP, pck32(v))

    def pop_uint32_t(self):
        x = upck32(self.vm.get_mem(self.cpu.SP, 4))
        self.cpu.SP += 4
        return x

    def get_stack_arg(self, n):
        x = upck32(self.vm.get_mem(self.cpu.SP + 4 * n, 4))
        return x

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc


class jitter_mips32b(jitter_mips32l):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_mips32b(sp), *args, **kwargs)
        self.vm.set_big_endian()
