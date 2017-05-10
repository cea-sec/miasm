
import logging
from functools import wraps
from collections import Sequence, namedtuple, Iterator

from miasm2.jitter.csts import *
from miasm2.core.utils import *
from miasm2.core.bin_stream import bin_stream_vm
from miasm2.core.interval import interval
from miasm2.jitter.emulatedsymbexec import EmulatedSymbExec
from miasm2.jitter.codegen import CGen
from miasm2.jitter.jitcore_cc_base import JitCore_Cc_Base

hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log = logging.getLogger('jitload.py')
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)
log_func = logging.getLogger('jit function call')
log_func.addHandler(hnd)
log_func.setLevel(logging.CRITICAL)

try:
    from miasm2.jitter import VmMngr
except ImportError:
    log.error('cannot import VmMngr')


def named_arguments(func):
    """Function decorator to allow the use of .func_args_*() methods
    with either the number of arguments or the list of the argument
    names.

    The wrapper is also used to log the argument values.

    @func: function

    """
    @wraps(func)
    def newfunc(self, args):
        if isinstance(args, Sequence):
            ret_ad, arg_vals = func(self, len(args))
            arg_vals = namedtuple("args", args)(*arg_vals)
            # func_name(arguments) return address
            log_func.info('%s(%s) ret addr: %s',
                          get_caller_name(1),
                          ', '.join("%s=0x%x" % (field, value)
                                    for field, value in arg_vals._asdict(
                                    ).iteritems()),
                         hex(ret_ad))
            return ret_ad, namedtuple("args", args)(*arg_vals)
        else:
            ret_ad, arg_vals = func(self, args)
            # func_name(arguments) return address
            log_func.info('%s(%s) ret addr: %s',
                get_caller_name(1),
                ', '.join(hex(arg) for arg in arg_vals),
                hex(ret_ad))
            return ret_ad, arg_vals
    return newfunc


class CallbackHandler(object):

    "Handle a list of callback"

    def __init__(self):
        self.callbacks = {}  # Key -> [callback list]

    def add_callback(self, name, callback):
        """Add a callback to the key @name, iff the @callback isn't already
        assigned to it"""
        if callback not in self.callbacks.get(name, []):
            self.callbacks[name] = self.callbacks.get(name, []) + [callback]

    def set_callback(self, name, *args):
        "Set the list of callback for key 'name'"
        self.callbacks[name] = list(args)

    def get_callbacks(self, name):
        "Return the list of callbacks associated to key 'name'"
        return self.callbacks.get(name, [])

    def remove_callback(self, callback):
        """Remove the callback from the list.
        Return the list of empty keys (removed)"""

        to_check = set()
        for key, cb_list in self.callbacks.items():
            try:
                cb_list.remove(callback)
                to_check.add(key)
            except ValueError:
                pass

        empty_keys = []
        for key in to_check:
            if len(self.callbacks[key]) == 0:
                empty_keys.append(key)
                del(self.callbacks[key])

        return empty_keys

    def has_callbacks(self, name):
        return name in self.callbacks

    def call_callbacks(self, name, *args):
        """Call callbacks associated to key 'name' with arguments args. While
        callbacks return True, continue with next callback.
        Iterator on other results."""

        res = True

        for c in self.get_callbacks(name):
            res = c(*args)
            if res is not True:
                yield res

    def __call__(self, name, *args):
        "Wrapper for call_callbacks"
        return self.call_callbacks(name, *args)


class CallbackHandlerBitflag(CallbackHandler):

    "Handle a list of callback with conditions on bitflag"

    def call_callbacks(self, bitflag, *args):
        """Call each callbacks associated with bit set in bitflag. While
        callbacks return True, continue with next callback.
        Iterator on other results"""

        res = True
        for bitflag_expected in self.callbacks:
            if bitflag_expected & bitflag == bitflag_expected:
                # If the flag matched
                for res in super(CallbackHandlerBitflag,
                                 self).call_callbacks(bitflag_expected, *args):
                    if res is not True:
                        yield res


class ExceptionHandle():

    "Return type for exception handler"

    def __init__(self, except_flag):
        self.except_flag = except_flag

    @classmethod
    def memoryBreakpoint(cls):
        return cls(EXCEPT_BREAKPOINT_INTERN)

    def __eq__(self, to_cmp):
        if not isinstance(to_cmp, ExceptionHandle):
            return False
        return (self.except_flag == to_cmp.except_flag)


class jitter:

    "Main class for JIT handling"

    C_Gen = CGen

    def __init__(self, ir_arch, jit_type="gcc"):
        """Init an instance of jitter.
        @ir_arch: ir instance for this architecture
        @jit_type: JiT backend to use. Available options are:
            - "gcc"
            - "tcc"
            - "llvm"
            - "python"
        """

        self.arch = ir_arch.arch
        self.attrib = ir_arch.attrib
        arch_name = ir_arch.arch.name  # (ir_arch.arch.name, ir_arch.attrib)

        try:
            if arch_name == "x86":
                from miasm2.jitter.arch import JitCore_x86 as jcore
            elif arch_name == "arm":
                from miasm2.jitter.arch import JitCore_arm as jcore
            elif arch_name == "aarch64":
                from miasm2.jitter.arch import JitCore_aarch64 as jcore
            elif arch_name == "msp430":
                from miasm2.jitter.arch import JitCore_msp430 as jcore
            elif arch_name == "mips32":
                from miasm2.jitter.arch import JitCore_mips32 as jcore
            else:
                raise ValueError("unknown jit arch: %s" % arch_name)
        except ImportError:
            raise RuntimeError('Unsupported jit arch: %s' % arch_name)

        self.vm = VmMngr.Vm()
        self.cpu = jcore.JitCpu()
        self.ir_arch = ir_arch
        self.bs = bin_stream_vm(self.vm)

        self.symbexec = EmulatedSymbExec(self.cpu, self.vm, self.ir_arch, {})
        self.symbexec.reset_regs()

        try:
            if jit_type == "tcc":
                from miasm2.jitter.jitcore_tcc import JitCore_Tcc as JitCore
            elif jit_type == "llvm":
                from miasm2.jitter.jitcore_llvm import JitCore_LLVM as JitCore
            elif jit_type == "python":
                from miasm2.jitter.jitcore_python import JitCore_Python as JitCore
            elif jit_type == "gcc":
                from miasm2.jitter.jitcore_gcc import JitCore_Gcc as JitCore
            else:
                raise ValueError("Unknown jitter %s" % jit_type)
        except ImportError:
            raise RuntimeError('Unsupported jitter: %s' % jit_type)

        self.jit = JitCore(self.ir_arch, self.bs)
        if isinstance(self.jit, JitCore_Cc_Base):
            self.jit.init_codegen(self.C_Gen(self.ir_arch))
        elif jit_type == "python":
            self.jit.set_cpu_vm(self.cpu, self.vm)

        self.cpu.init_regs()
        self.vm.init_memory_page_pool()
        self.vm.init_code_bloc_pool()
        self.vm.init_memory_breakpoint()

        self.jit.load()
        self.cpu.vmmngr = self.vm
        self.cpu.jitter = self.jit
        self.stack_size = 0x10000
        self.stack_base = 0x1230000

        # Init callback handler
        self.breakpoints_handler = CallbackHandler()
        self.exceptions_handler = CallbackHandlerBitflag()
        self.init_exceptions_handler()
        self.exec_cb = None

    def init_exceptions_handler(self):
        "Add common exceptions handlers"

        def exception_automod(jitter):
            "Tell the JiT backend to update blocks modified"

            self.jit.updt_automod_code(jitter.vm)
            self.vm.set_exception(0)

            return True

        def exception_memory_breakpoint(jitter):
            "Stop the execution and return an identifier"
            return ExceptionHandle.memoryBreakpoint()

        self.add_exception_handler(EXCEPT_CODE_AUTOMOD, exception_automod)
        self.add_exception_handler(EXCEPT_BREAKPOINT_INTERN,
                                   exception_memory_breakpoint)

    def add_breakpoint(self, addr, callback):
        """Add a callback associated with addr.
        @addr: breakpoint address
        @callback: function with definition (jitter instance)
        """
        self.breakpoints_handler.add_callback(addr, callback)
        self.jit.add_disassembly_splits(addr)
        # De-jit previously jitted blocks
        self.jit.updt_automod_code_range(self.vm, [(addr, addr)])

    def set_breakpoint(self, addr, *args):
        """Set callbacks associated with addr.
        @addr: breakpoint address
        @args: functions with definition (jitter instance)
        """
        self.breakpoints_handler.set_callback(addr, *args)
        self.jit.add_disassembly_splits(addr)

    def remove_breakpoints_by_callback(self, callback):
        """Remove callbacks associated with breakpoint.
        @callback: callback to remove
        """
        empty_keys = self.breakpoints_handler.remove_callback(callback)
        for key in empty_keys:
            self.jit.remove_disassembly_splits(key)

    def add_exception_handler(self, flag, callback):
        """Add a callback associated with an exception flag.
        @flag: bitflag
        @callback: function with definition (jitter instance)
        """
        self.exceptions_handler.add_callback(flag, callback)

    def runbloc(self, pc):
        """Wrapper on JiT backend. Run the code at PC and return the next PC.
        @pc: address of code to run"""

        return self.jit.runbloc(self.cpu, pc, self.breakpoints_handler.callbacks)

    def runiter_once(self, pc):
        """Iterator on callbacks results on code running from PC.
        Check exceptions before breakpoints."""

        self.pc = pc

        # Callback called before exec
        if self.exec_cb is not None:
            res = self.exec_cb(self)
            if res is not True:
                yield res

        # Check breakpoints
        old_pc = self.pc
        for res in self.breakpoints_handler.call_callbacks(self.pc, self):
            if res is not True:
                if isinstance(res, collections.Iterator):
                    # If the breakpoint is a generator, yield it step by step
                    for tmp in res:
                        yield tmp
                else:
                    yield res

        # Check exceptions (raised by breakpoints)
        exception_flag = self.get_exception()
        for res in self.exceptions_handler(exception_flag, self):
            if res is not True:
                if isinstance(res, collections.Iterator):
                    for tmp in res:
                        yield tmp
                else:
                    yield res

        # If a callback changed pc, re call every callback
        if old_pc != self.pc:
            return

        # Exceptions should never be activated before run
        assert(self.get_exception() == 0)

        # Run the bloc at PC
        self.pc = self.runbloc(self.pc)

        # Check exceptions (raised by the execution of the block)
        exception_flag = self.get_exception()
        for res in self.exceptions_handler(exception_flag, self):
            if res is not True:
                if isinstance(res, collections.Iterator):
                    for tmp in res:
                        yield tmp
                else:
                    yield res

    def init_run(self, pc):
        """Create an iterator on pc with runiter.
        @pc: address of code to run
        """
        self.run_iterator = self.runiter_once(pc)
        self.pc = pc
        self.run = True

    def continue_run(self, step=False):
        """PRE: init_run.
        Continue the run of the current session until iterator returns or run is
        set to False.
        If step is True, run only one time.
        Return the iterator value"""

        while self.run:
            try:
                return self.run_iterator.next()
            except StopIteration:
                pass

            self.run_iterator = self.runiter_once(self.pc)

            if step is True:
                return None

        return None

    def init_stack(self):
        self.vm.add_memory_page(
            self.stack_base, PAGE_READ | PAGE_WRITE, "\x00" * self.stack_size,
            "Stack")
        sp = self.arch.getsp(self.attrib)
        setattr(self.cpu, sp.name, self.stack_base + self.stack_size)
        # regs = self.cpu.get_gpreg()
        # regs[sp.name] = self.stack_base+self.stack_size
        # self.cpu.set_gpreg(regs)

    def get_exception(self):
        return self.cpu.get_exception() | self.vm.get_exception()

    # commun functions
    def get_str_ansi(self, addr, max_char=None):
        """Get ansi str from vm.
        @addr: address in memory
        @max_char: maximum len"""
        l = 0
        tmp = addr
        while ((max_char is None or l < max_char) and
               self.vm.get_mem(tmp, 1) != "\x00"):
            tmp += 1
            l += 1
        return self.vm.get_mem(addr, l)

    def get_str_unic(self, addr, max_char=None):
        """Get unicode str from vm.
        @addr: address in memory
        @max_char: maximum len"""
        l = 0
        tmp = addr
        while ((max_char is None or l < max_char) and
               self.vm.get_mem(tmp, 2) != "\x00\x00"):
            tmp += 2
            l += 2
        s = self.vm.get_mem(addr, l)
        s = s[::2]  # TODO: real unicode decoding
        return s

    def set_str_ansi(self, addr, s):
        """Set an ansi string in memory"""
        s = s + "\x00"
        self.vm.set_mem(addr, s)

    def set_str_unic(self, addr, s):
        """Set an unicode string in memory"""
        s = "\x00".join(list(s)) + '\x00' * 3
        self.vm.set_mem(addr, s)

    @staticmethod
    def handle_lib(jitter):
        """Resolve the name of the function which cause the handler call. Then
        call the corresponding handler from users callback.
        """
        fname = jitter.libs.fad2cname[jitter.pc]
        if fname in jitter.user_globals:
            func = jitter.user_globals[fname]
        else:
            log.debug('%r', fname)
            raise ValueError('unknown api', hex(jitter.pc), repr(fname))
        ret = func(jitter)
        jitter.pc = getattr(jitter.cpu, jitter.ir_arch.pc.name)

        # Don't break on a None return
        if ret is None:
            return True
        else:
            return ret

    def handle_function(self, f_addr):
        """Add a brakpoint which will trigger the function handler"""
        self.add_breakpoint(f_addr, self.handle_lib)

    def add_lib_handler(self, libs, user_globals=None):
        """Add a function to handle libs call with breakpoints
        @libs: libimp instance
        @user_globals: dictionary for defined user function
        """
        if user_globals is None:
            user_globals = {}

        self.libs = libs
        self.user_globals = user_globals

        for f_addr in libs.fad2cname:
            self.handle_function(f_addr)

    def eval_expr(self, expr):
        """Eval expression @expr in the context of the current instance. Side
        effects are passed on it"""
        self.symbexec.update_engine_from_cpu()
        ret = self.symbexec.apply_expr(expr)
        self.symbexec.update_cpu_from_engine()

        return ret
