import logging

from miasm2.jitter.jitload import jitter, named_arguments
from miasm2.core import asmbloc
from miasm2.core.utils import *
from miasm2.arch.x86.sem import ir_x86_16, ir_x86_32, ir_x86_64

log = logging.getLogger('jit_x86')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_x86_16(jitter):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_x86_16(sp), *args, **kwargs)
        self.vm.set_little_endian()
        self.ir_arch.jit_pc = self.ir_arch.arch.regs.RIP
        self.ir_arch.do_stk_segm = False
        self.orig_irbloc_fix_regs_for_mode = self.ir_arch.irbloc_fix_regs_for_mode
        self.ir_arch.irbloc_fix_regs_for_mode = self.ir_archbloc_fix_regs_for_mode

    def ir_archbloc_fix_regs_for_mode(self, irbloc, attrib=64):
        self.orig_irbloc_fix_regs_for_mode(irbloc, 64)

    def push_uint16_t(self, v):
        self.cpu.SP -= self.ir_arch.sp.size / 8
        self.vm.set_mem(self.cpu.SP, pck16(v))

    def pop_uint16_t(self):
        x = upck16(self.vm.get_mem(self.cpu.SP, self.ir_arch.sp.size / 8))
        self.cpu.SP += self.ir_arch.sp.size / 8
        return x

    def get_stack_arg(self, n):
        x = upck16(self.vm.get_mem(self.cpu.SP + 4 * n, 4))
        return x

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.IP = self.pc


class jitter_x86_32(jitter):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_x86_32(sp), *args, **kwargs)
        self.vm.set_little_endian()
        self.ir_arch.jit_pc = self.ir_arch.arch.regs.RIP
        self.ir_arch.do_stk_segm = False

        self.orig_irbloc_fix_regs_for_mode = self.ir_arch.irbloc_fix_regs_for_mode
        self.ir_arch.irbloc_fix_regs_for_mode = self.ir_archbloc_fix_regs_for_mode

    def ir_archbloc_fix_regs_for_mode(self, irbloc, attrib=64):
        self.orig_irbloc_fix_regs_for_mode(irbloc, 64)

    def push_uint32_t(self, v):
        self.cpu.ESP -= self.ir_arch.sp.size / 8
        self.vm.set_mem(self.cpu.ESP, pck32(v))

    def pop_uint32_t(self):
        x = upck32(self.vm.get_mem(self.cpu.ESP, self.ir_arch.sp.size / 8))
        self.cpu.ESP += self.ir_arch.sp.size / 8
        return x

    def get_stack_arg(self, n):
        x = upck32(self.vm.get_mem(self.cpu.ESP + 4 * n, 4))
        return x

    # calling conventions

    # stdcall
    @named_arguments
    def func_args_stdcall(self, n_args):
        ret_ad = self.pop_uint32_t()
        args = [self.pop_uint32_t() for _ in xrange(n_args)]
        return ret_ad, args

    def func_ret_stdcall(self, ret_addr, ret_value1=None, ret_value2=None):
        self.cpu.EIP = ret_addr
        if ret_value1 is not None:
            self.cpu.EAX = ret_value1
        if ret_value2 is not None:
            self.cpu.EDX = ret_value

    # cdecl
    @named_arguments
    def func_args_cdecl(self, n_args):
        ret_ad = self.pop_uint32_t()
        args = [self.get_stack_arg(i) for i in xrange(n_args)]
        return ret_ad, args

    def func_ret_cdecl(self, ret_addr, ret_value):
        self.cpu.EIP = ret_addr
        self.cpu.EAX = ret_value

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.EIP = self.pc


class jitter_x86_64(jitter):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_x86_64(sp), *args, **kwargs)
        self.vm.set_little_endian()
        self.ir_arch.jit_pc = self.ir_arch.arch.regs.RIP
        self.ir_arch.do_stk_segm = False

        self.orig_irbloc_fix_regs_for_mode = self.ir_arch.irbloc_fix_regs_for_mode
        self.ir_arch.irbloc_fix_regs_for_mode = self.ir_archbloc_fix_regs_for_mode

    def ir_archbloc_fix_regs_for_mode(self, irbloc, attrib=64):
        self.orig_irbloc_fix_regs_for_mode(irbloc, 64)

    def push_uint64_t(self, v):
        self.cpu.RSP -= self.ir_arch.sp.size / 8
        self.vm.set_mem(self.cpu.RSP, pck64(v))

    def pop_uint64_t(self):
        x = upck64(self.vm.get_mem(self.cpu.RSP, self.ir_arch.sp.size / 8))
        self.cpu.RSP += self.ir_arch.sp.size / 8
        return x

    def get_stack_arg(self, n):
        x = upck64(self.vm.get_mem(self.cpu.RSP + 8 * n, 8))
        return x

    @named_arguments
    def func_args_stdcall(self, n_args):
        args_regs = ['RCX', 'RDX', 'R8', 'R9']
        ret_ad = self.pop_uint64_t()
        args = []
        for i in xrange(min(n_args, 4)):
            args.append(self.cpu.get_gpreg()[args_regs[i]])
        for i in xrange(max(0, n_args - 4)):
            args.append(self.get_stack_arg(i))
        return ret_ad, args

    def func_ret_stdcall(self, ret_addr, ret_value=None):
        self.pc = self.cpu.RIP = ret_addr
        if ret_value is not None:
            self.cpu.RAX = ret_value
        return True

    @named_arguments
    def func_args_cdecl(self, n_args):
        args_regs = ['RCX', 'RDX', 'R8', 'R9']
        ret_ad = self.pop_uint64_t()
        args = []
        for i in xrange(min(n_args, 4)):
            args.append(self.cpu.get_gpreg()[args_regs[i]])
        for i in xrange(max(0, n_args - 4)):
            args.append(self.get_stack_arg(i))
        return ret_ad, args

    def func_ret_cdecl(self, ret_addr, ret_value=None):
        self.pc = self.cpu.RIP = ret_addr
        if ret_value is not None:
            self.cpu.RAX = ret_value
        return True

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.RIP = self.pc
