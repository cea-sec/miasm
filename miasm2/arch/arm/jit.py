from builtins import range
import logging

from miasm2.jitter.jitload import Jitter, named_arguments
from miasm2.core.locationdb import LocationDB
from miasm2.core.utils import pck32, upck32
from miasm2.arch.arm.sem import ir_armb, ir_arml, ir_armtl, ir_armtb, cond_dct_inv, tab_cond
from miasm2.jitter.codegen import CGen
from miasm2.expression.expression import ExprId, ExprAssign, ExprCond
from miasm2.ir.ir import IRBlock, AssignBlock
from miasm2.ir.translators.C import TranslatorC
from miasm2.expression.simplifications import expr_simp_high_to_explicit

log = logging.getLogger('jit_arm')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)



class arm_CGen(CGen):

    def block2assignblks(self, block):
        """
        Return the list of irblocks for a native @block
        @block: AsmBlock
        """
        irblocks_list = []
        index = -1
        while index + 1 < len(block.lines):
            index += 1
            instr = block.lines[index]

            if instr.name.startswith("IT"):
                assignments = []
                label = self.ir_arch.get_instr_label(instr)
                irblocks = []
                index, irblocks = self.ir_arch.do_it_block(label, index, block, assignments, True)
                irblocks_list += irblocks
                continue


            assignblk_head, assignblks_extra = self.ir_arch.instr2ir(instr)
            # Keep result in ordered list as first element is the assignblk head
            # The remainings order is not really important
            irblock_head = self.assignblk_to_irbloc(instr, assignblk_head)
            irblocks = [irblock_head] + assignblks_extra


            # Simplify high level operators
            out = []
            for irblock in irblocks:
                new_irblock = irblock.simplify(expr_simp_high_to_explicit)[1]
                out.append(new_irblock)
            irblocks = out


            for irblock in irblocks:
                assert irblock.dst is not None
            irblocks_list.append(irblocks)
        return irblocks_list


class jitter_arml(Jitter):
    C_Gen = arm_CGen

    def __init__(self, *args, **kwargs):
        sp = LocationDB()
        Jitter.__init__(self, ir_arml(sp), *args, **kwargs)
        self.vm.set_little_endian()

    def push_uint32_t(self, value):
        self.cpu.SP -= 4
        self.vm.set_mem(self.cpu.SP, pck32(value))

    def pop_uint32_t(self):
        value = self.vm.get_u32(self.cpu.SP)
        self.cpu.SP += 4
        return value

    def get_stack_arg(self, index):
        return self.vm.get_u32(self.cpu.SP + 4 * index)

    # calling conventions

    @named_arguments
    def func_args_stdcall(self, n_args):
        args = [self.get_arg_n_stdcall(i) for i in range(n_args)]
        ret_ad = self.cpu.LR
        return ret_ad, args

    def func_ret_stdcall(self, ret_addr, ret_value1=None, ret_value2=None):
        self.pc = self.cpu.PC = ret_addr
        if ret_value1 is not None:
            self.cpu.R0 = ret_value1
        if ret_value2 is not None:
            self.cpu.R1 = ret_value2
        return True

    def func_prepare_stdcall(self, ret_addr, *args):
        for index in range(min(len(args), 4)):
            setattr(self.cpu, 'R%d' % index, args[index])
        for index in reversed(range(4, len(args))):
            self.push_uint32_t(args[index])
        self.cpu.LR = ret_addr

    def get_arg_n_stdcall(self, index):
        if index < 4:
            arg = getattr(self.cpu, 'R%d' % index)
        else:
            arg = self.get_stack_arg(index-4)
        return arg

    func_args_systemv = func_args_stdcall
    func_ret_systemv = func_ret_stdcall
    func_prepare_systemv = func_prepare_stdcall
    get_arg_n_systemv = get_arg_n_stdcall

    def syscall_args_systemv(self, n_args):
        args = [self.cpu.R0, self.cpu.R1, self.cpu.R2, self.cpu.R3,
            self.cpu.R4, self.cpu.R5][:n_args]
        return args

    def syscall_ret_systemv(self, value):
        self.cpu.R0 = value

    def init_run(self, *args, **kwargs):
        Jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc


class jitter_armb(jitter_arml):
    C_Gen = arm_CGen

    def __init__(self, *args, **kwargs):
        sp = LocationDB()
        Jitter.__init__(self, ir_armb(sp), *args, **kwargs)
        self.vm.set_big_endian()


class jitter_armtl(jitter_arml):
    C_Gen = arm_CGen

    def __init__(self, *args, **kwargs):
        sp = LocationDB()
        Jitter.__init__(self, ir_armtl(sp), *args, **kwargs)
        self.vm.set_little_endian()
