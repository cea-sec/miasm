from miasm2.jitter.jitload import jitter
from miasm2.core import asmbloc
from miasm2.core.utils import *
from miasm2.arch.arm.sem import ir_arml

import logging

log = logging.getLogger('jit_arm')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

class jitter_arml(jitter):

    def __init__(self, *args, **kwargs):
        sp = asmbloc.asm_symbol_pool()
        jitter.__init__(self, ir_arml(sp), *args, **kwargs)
        self.vm.set_little_endian()
        self.ir_arch.jit_pc = self.ir_arch.arch.regs.PC

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

    # calling conventions

    def func_args_stdcall(self, n_args):
        args = []
        for i in xrange(min(n_args, 4)):
            args.append(self.cpu.get_gpreg()['R%d' % i])
        for i in xrange(max(0, n_args - 4)):
            args.append(self.get_stack_arg(i))

        ret_ad = self.cpu.LR
        log.debug('%s %s %s' % (whoami(), hex(ret_ad), [hex(x) for x in args]))
        return ret_ad, args

    def func_ret_stdcall(self, ret_addr, ret_value=None):
        self.pc = self.cpu.PC = ret_addr
        if ret_value is not None:
            self.cpu.R0 = ret_value
        return True

    def get_arg_n_stdcall(self, n):
        if n < 4:
            arg = self.cpu.get_gpreg()['R%d' % n]
        else:
            arg = self.get_stack_arg(n-4)
        return arg

    def add_lib_handler(self, libs, user_globals=None):
        """Add a function to handle libs call with breakpoints
        @libs: libimp instance
        @user_globals: dictionnary for defined user function
        """
        if user_globals is None:
            user_globals = {}

        from miasm2.os_dep import linux_stdlib

        def handle_lib(jitter):
            fname = libs.fad2cname[jitter.pc]
            if fname in user_globals:
                f = user_globals[fname]
            elif fname in linux_stdlib.__dict__:
                f = linux_stdlib.__dict__[fname]
            else:
                log.debug('%s' % repr(fname))
                raise ValueError('unknown api', hex(jitter.pop_uint32_t()), repr(fname))
            f(jitter)
            jitter.pc = getattr(jitter.cpu, jitter.ir_arch.pc.name)
            return True

        for f_addr in libs.fad2cname:
            self.add_breakpoint(f_addr, handle_lib)


    def init_run(self, *args, **kwargs):
        jitter.init_run(self, *args, **kwargs)
        self.cpu.PC = self.pc

class jitter_armb(jitter_arml):
    def __init__(self, *args, **kwargs):
        jitter_arml.__init__(self)
        self.vm.set_big_endian()
