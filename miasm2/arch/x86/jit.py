from miasm2.jitter.jitload import jitter
from miasm2.core import asmbloc
from miasm2.core.utils import *
from miasm2.arch.x86.sem import ir_x86_16, ir_x86_32, ir_x86_64


import logging

log = logging.getLogger('jit_x86')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_x86_16(jitter):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_x86_16(sp), *args, **kwargs)
        self.my_ir.jit_pc = self.my_ir.arch.regs.RIP
        self.my_ir.do_stk_segm = False
        self.orig_irbloc_fix_regs_for_mode = self.my_ir.irbloc_fix_regs_for_mode
        self.my_ir.irbloc_fix_regs_for_mode = self.my_irbloc_fix_regs_for_mode

    def my_irbloc_fix_regs_for_mode(self, irbloc, attrib=64):
        self.orig_irbloc_fix_regs_for_mode(irbloc, 64)

    def vm_push_uint16_t(self, v):
        self.cpu.SP -= self.my_ir.sp.size / 8
        self.vm.vm_set_mem(self.cpu.SP, pck16(v))

    def vm_pop_uint16_t(self):
        x = upck16(self.vm.vm_get_mem(self.cpu.SP, self.my_ir.sp.size / 8))
        self.cpu.SP += self.my_ir.sp.size / 8
        return x

    def get_stack_arg(self, n):
        x = upck16(self.vm.vm_get_mem(self.cpu.SP + 4 * n, 4))
        return x

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.IP = self.pc


class jitter_x86_32(jitter):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_x86_32(sp), *args, **kwargs)
        self.my_ir.jit_pc = self.my_ir.arch.regs.RIP
        self.my_ir.do_stk_segm = False

        self.orig_irbloc_fix_regs_for_mode = self.my_ir.irbloc_fix_regs_for_mode
        self.my_ir.irbloc_fix_regs_for_mode = self.my_irbloc_fix_regs_for_mode

    def my_irbloc_fix_regs_for_mode(self, irbloc, attrib=64):
        self.orig_irbloc_fix_regs_for_mode(irbloc, 64)

    def vm_push_uint32_t(self, v):
        self.cpu.ESP -= self.my_ir.sp.size / 8
        self.vm.vm_set_mem(self.cpu.ESP, pck32(v))

    def vm_pop_uint32_t(self):
        x = upck32(self.vm.vm_get_mem(self.cpu.ESP, self.my_ir.sp.size / 8))
        self.cpu.ESP += self.my_ir.sp.size / 8
        return x

    def get_stack_arg(self, n):
        x = upck32(self.vm.vm_get_mem(self.cpu.ESP + 4 * n, 4))
        return x

    # calling conventions

    # stdcall
    def func_args_stdcall(self, n_args):
        ret_ad = self.vm_pop_uint32_t()
        args = []
        for _ in xrange(n_args):
            args.append(self.vm_pop_uint32_t())
        log.debug('%s %s %s' % (whoami(), hex(ret_ad), [hex(x) for x in args]))
        return ret_ad, args

    def func_ret_stdcall(self, ret_addr, ret_value1=None, ret_value2=None):
        self.cpu.EIP = ret_addr
        if ret_value1 is not None:
            self.cpu.EAX = ret_value1
        if ret_value2 is not None:
            self.cpu.EDX = ret_value

    # cdecl
    def func_args_cdecl(self, n_args, dolog=True):
        ret_ad = self.vm_pop_uint32_t()
        args = []
        for i in xrange(n_args):
            args.append(self.get_stack_arg(i))
        if dolog:
            log.debug('%s %s %s' %
                      (whoami(), hex(ret_ad), [hex(x) for x in args]))
        return ret_ad, args

    def func_ret_cdecl(self, ret_addr, ret_value):
        self.cpu.EIP = ret_addr
        self.cpu.EAX = ret_value

    def add_lib_handler(self, libs, user_globals=None):
        """Add a function to handle libs call with breakpoints
        @libs: libimp instance
        @user_globals: dictionnary for defined user function
        """
        if user_globals is None:
            user_globals = {}

        from miasm2.jitter.os_dep import win_api_x86_32

        def handle_lib(jitter):
            fname = libs.fad2cname[jitter.pc]
            if fname in user_globals:
                f = user_globals[fname]
            elif fname in win_api_x86_32.__dict__:
                f = win_api_x86_32.__dict__[fname]
            else:
                log.debug('%s' % repr(fname))
                raise ValueError('unknown api', hex(jitter.vm_pop_uint32_t()), repr(fname))
            f(jitter)
            jitter.pc = getattr(jitter.cpu, jitter.my_ir.pc.name)
            return True

        for f_addr in libs.fad2cname:
            self.add_breakpoint(f_addr, handle_lib)

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.EIP = self.pc


class jitter_x86_64(jitter):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_x86_64(sp), *args, **kwargs)
        self.my_ir.jit_pc = self.my_ir.arch.regs.RIP
        self.my_ir.do_stk_segm = False

        self.orig_irbloc_fix_regs_for_mode = self.my_ir.irbloc_fix_regs_for_mode
        self.my_ir.irbloc_fix_regs_for_mode = self.my_irbloc_fix_regs_for_mode

    def my_irbloc_fix_regs_for_mode(self, irbloc, attrib=64):
        self.orig_irbloc_fix_regs_for_mode(irbloc, 64)

    def vm_push_uint64_t(self, v):
        self.cpu.RSP -= self.my_ir.sp.size / 8
        self.vm.vm_set_mem(self.cpu.RSP, pck64(v))

    def vm_pop_uint64_t(self):
        x = upck64(self.vm.vm_get_mem(self.cpu.RSP, self.my_ir.sp.size / 8))
        self.cpu.RSP += self.my_ir.sp.size / 8
        return x

    def get_stack_arg(self, n):
        x = upck64(self.vm.vm_get_mem(self.cpu.RSP + 8 * n, 8))
        return x

    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.RIP = self.pc
