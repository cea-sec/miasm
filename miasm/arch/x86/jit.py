from builtins import range
import logging

from miasm.jitter.jitload import Jitter, named_arguments
from miasm.arch.x86.sem import Lifter_X86_16, Lifter_X86_32, Lifter_X86_64
from miasm.jitter.codegen import CGen
from miasm.ir.translators.C import TranslatorC

log = logging.getLogger('jit_x86')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)


class x86_32_CGen(CGen):
    def __init__(self, lifter):
        self.lifter = lifter
        self.PC = self.lifter.arch.regs.RIP
        self.translator = TranslatorC(self.lifter.loc_db)
        self.init_arch_C()

    def gen_post_code(self, attrib, pc_value):
        out = []
        if attrib.log_regs:
            # Update PC for dump_gpregs
            out.append("%s = %s;" % (self.C_PC, pc_value))
            out.append('dump_gpregs_32(jitcpu->cpu);')
        return out

class x86_64_CGen(x86_32_CGen):
    def gen_post_code(self, attrib, pc_value):
        out = []
        if attrib.log_regs:
            # Update PC for dump_gpregs
            out.append("%s = %s;" % (self.C_PC, pc_value))
            out.append('dump_gpregs_64(jitcpu->cpu);')
        return out

class jitter_x86_16(Jitter):

    C_Gen = x86_32_CGen

    def __init__(self, loc_db, *args, **kwargs):
        Jitter.__init__(self, Lifter_X86_16(loc_db), *args, **kwargs)
        self.vm.set_little_endian()
        self.lifter.do_stk_segm = False
        self.orig_irbloc_fix_regs_for_mode = self.lifter.irbloc_fix_regs_for_mode
        self.lifter.irbloc_fix_regs_for_mode = self.lifterbloc_fix_regs_for_mode

    def lifterbloc_fix_regs_for_mode(self, irblock, attrib=64):
        return self.orig_irbloc_fix_regs_for_mode(irblock, 64)

    def push_uint16_t(self, value):
        self.cpu.SP -= self.lifter.sp.size // 8
        self.vm.set_u16(self.cpu.SP, value)

    def pop_uint16_t(self):
        value = self.vm.get_u16(self.cpu.SP)
        self.cpu.SP += self.lifter.sp.size // 8
        return value

    def get_stack_arg(self, index):
        return self.vm.get_u16(self.cpu.SP + 4 * index)

    def init_run(self, *args, **kwargs):
        Jitter.init_run(self, *args, **kwargs)
        self.cpu.IP = self.pc


class jitter_x86_32(Jitter):

    C_Gen = x86_32_CGen

    def __init__(self, loc_db, *args, **kwargs):
        Jitter.__init__(self, Lifter_X86_32(loc_db), *args, **kwargs)
        self.vm.set_little_endian()
        self.lifter.do_stk_segm = False

        self.orig_irbloc_fix_regs_for_mode = self.lifter.irbloc_fix_regs_for_mode
        self.lifter.irbloc_fix_regs_for_mode = self.lifterbloc_fix_regs_for_mode

    def lifterbloc_fix_regs_for_mode(self, irblock, attrib=64):
        return self.orig_irbloc_fix_regs_for_mode(irblock, 64)

    def push_uint16_t(self, value):
        self.cpu.ESP -= self.lifter.sp.size // 8
        self.vm.set_u16(self.cpu.ESP, value)

    def pop_uint16_t(self):
        value = self.vm.get_u16(self.cpu.ESP)
        self.cpu.ESP += self.lifter.sp.size // 8
        return value

    def push_uint32_t(self, value):
        self.cpu.ESP -= self.lifter.sp.size // 8
        self.vm.set_u32(self.cpu.ESP, value)

    def pop_uint32_t(self):
        value = self.vm.get_u32(self.cpu.ESP)
        self.cpu.ESP += self.lifter.sp.size // 8
        return value

    def get_stack_arg(self, index):
        return self.vm.get_u32(self.cpu.ESP + 4 * index)

    def init_run(self, *args, **kwargs):
        Jitter.init_run(self, *args, **kwargs)
        self.cpu.EIP = self.pc

    # calling conventions

    # stdcall
    @named_arguments
    def func_args_stdcall(self, n_args):
        ret_ad = self.pop_uint32_t()
        args = [self.pop_uint32_t() for _ in range(n_args)]
        return ret_ad, args

    def func_ret_stdcall(self, ret_addr, ret_value1=None, ret_value2=None):
        self.pc = self.cpu.EIP = ret_addr
        if ret_value1 is not None:
            self.cpu.EAX = ret_value1
        if ret_value2 is not None:
            self.cpu.EDX = ret_value2

    def func_prepare_stdcall(self, ret_addr, *args):
        for arg in reversed(args):
            self.push_uint32_t(arg)
        self.push_uint32_t(ret_addr)

    get_arg_n_stdcall = get_stack_arg

    # cdecl
    @named_arguments
    def func_args_cdecl(self, n_args):
        ret_ad = self.pop_uint32_t()
        args = [self.get_stack_arg(i) for i in range(n_args)]
        return ret_ad, args

    def func_ret_cdecl(self, ret_addr, ret_value1=None, ret_value2=None):
        self.pc = self.cpu.EIP = ret_addr
        if ret_value1 is not None:
            self.cpu.EAX = ret_value1
        if ret_value2 is not None:
            self.cpu.EDX = ret_value2

    get_arg_n_cdecl = get_stack_arg

    # System V
    func_args_systemv = func_args_cdecl
    func_ret_systemv = func_ret_cdecl
    func_prepare_systemv = func_prepare_stdcall
    get_arg_n_systemv = get_stack_arg


    # fastcall
    @named_arguments
    def func_args_fastcall(self, n_args):
        args_regs = ['ECX', 'EDX']
        ret_ad = self.pop_uint32_t()
        args = []
        for i in range(n_args):
            args.append(self.get_arg_n_fastcall(i))
        return ret_ad, args

    def func_prepare_fastcall(self, ret_addr, *args):
        args_regs = ['ECX', 'EDX']
        for i in range(min(len(args), len(args_regs))):
            setattr(self.cpu, args_regs[i], args[i])
        remaining_args = args[len(args_regs):]
        for arg in reversed(remaining_args):
            self.push_uint32_t(arg)
        self.push_uint32_t(ret_addr)

    def get_arg_n_fastcall(self, index):
        args_regs = ['ECX', 'EDX']
        if index < len(args_regs):
            return getattr(self.cpu, args_regs[index])
        return self.get_stack_arg(index - len(args_regs))

    def syscall_args_systemv(self, n_args):
        # Documentation: http://man7.org/linux/man-pages/man2/syscall.2.html
        # args: 
        #   i386          ebx   ecx   edx   esi   edi   ebp   -
        args = [self.cpu.EBX, self.cpu.ECX, self.cpu.EDX, self.cpu.ESI,
                self.cpu.EDI, self.cpu.EBP][:n_args]
        return args

    def syscall_ret_systemv(self, value):
        # Documentation: http://man7.org/linux/man-pages/man2/syscall.2.html
        self.cpu.EAX = value


class jitter_x86_64(Jitter):

    C_Gen = x86_64_CGen
    args_regs_systemv = ['RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9']
    args_regs_stdcall = ['RCX', 'RDX', 'R8', 'R9']

    def __init__(self, loc_db, *args, **kwargs):
        Jitter.__init__(self, Lifter_X86_64(loc_db), *args, **kwargs)
        self.vm.set_little_endian()
        self.lifter.do_stk_segm = False

        self.orig_irbloc_fix_regs_for_mode = self.lifter.irbloc_fix_regs_for_mode
        self.lifter.irbloc_fix_regs_for_mode = self.lifterbloc_fix_regs_for_mode

    def lifterbloc_fix_regs_for_mode(self, irblock, attrib=64):
        return self.orig_irbloc_fix_regs_for_mode(irblock, 64)

    def push_uint64_t(self, value):
        self.cpu.RSP -= self.lifter.sp.size // 8
        self.vm.set_u64(self.cpu.RSP, value)

    def pop_uint64_t(self):
        value = self.vm.get_u64(self.cpu.RSP)
        self.cpu.RSP += self.lifter.sp.size // 8
        return value

    def get_stack_arg(self, index):
        return self.vm.get_u64(self.cpu.RSP + 8 * index)

    def init_run(self, *args, **kwargs):
        Jitter.init_run(self, *args, **kwargs)
        self.cpu.RIP = self.pc

    # calling conventions

    # stdcall
    @named_arguments
    def func_args_stdcall(self, n_args):
        args_regs = self.args_regs_stdcall
        ret_ad = self.pop_uint64_t()
        args = []
        for i in range(min(n_args, 4)):
            args.append(self.cpu.get_gpreg()[args_regs[i]])
        for i in range(max(0, n_args - 4)):
            # Take into account the shadow registers on the stack 
            # (Microsoft 64bit stdcall ABI)
            # => Skip the first 4 stack parameters
            args.append(self.get_stack_arg(4 + i))
        return ret_ad, args

    def func_prepare_stdcall(self, ret_addr, *args):
        args_regs = self.args_regs_stdcall
        for i in range(min(len(args), len(args_regs))):
            setattr(self.cpu, args_regs[i], args[i])
        remaining_args = args[len(args_regs):]
        for arg in reversed(remaining_args):
            self.push_uint64_t(arg)
        self.push_uint64_t(ret_addr)

    def func_ret_stdcall(self, ret_addr, ret_value=None):
        self.pc = self.cpu.RIP = ret_addr
        if ret_value is not None:
            self.cpu.RAX = ret_value
        return True

    # cdecl
    func_args_cdecl = func_args_stdcall
    func_ret_cdecl = func_ret_stdcall
    func_prepare_cdecl = func_prepare_stdcall

    # System V

    def get_arg_n_systemv(self, index):
        args_regs = self.args_regs_systemv
        if index < len(args_regs):
            return getattr(self.cpu, args_regs[index])
        return self.get_stack_arg(index - len(args_regs))

    @named_arguments
    def func_args_systemv(self, n_args):
        ret_ad = self.pop_uint64_t()
        args = [self.get_arg_n_systemv(index) for index in range(n_args)]
        return ret_ad, args

    func_ret_systemv = func_ret_cdecl

    def func_prepare_systemv(self, ret_addr, *args):
        args_regs = self.args_regs_systemv
        self.push_uint64_t(ret_addr)
        for i in range(min(len(args), len(args_regs))):
            setattr(self.cpu, args_regs[i], args[i])
        remaining_args = args[len(args_regs):]
        for arg in reversed(remaining_args):
            self.push_uint64_t(arg)

    def syscall_args_systemv(self, n_args):
        args = [self.cpu.RDI, self.cpu.RSI, self.cpu.RDX, self.cpu.R10,
                self.cpu.R8, self.cpu.R9][:n_args]
        return args

    def syscall_ret_systemv(self, value):
        self.cpu.RAX = value
