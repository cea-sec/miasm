import logging
import warnings
from functools import wraps
from collections import namedtuple
try:
    from collections.abc import Sequence, Iterator
except ImportError:
    from collections import Sequence, Iterator

from future.utils import viewitems

from miasm.jitter.csts import *
from miasm.core.utils import *
from miasm.core.bin_stream import bin_stream_vm
from miasm.jitter.emulatedsymbexec import EmulatedSymbExec
from miasm.jitter.codegen import CGen
from miasm.jitter.jitcore_cc_base import JitCore_Cc_Base

hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log = logging.getLogger('jitload.py')
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)
log_func = logging.getLogger('jit function call')
log_func.addHandler(hnd)
log_func.setLevel(logging.CRITICAL)

try:
    from miasm.jitter import VmMngr
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
            log_func.info(
                '%s(%s) ret addr: %s',
                get_caller_name(1),
                ', '.join(
                    "%s=0x%x" % (field, value)
                    for field, value in viewitems(arg_vals._asdict())
                ),
                hex(ret_ad)
            )
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

    def add_callback(self, key, callback):
        """Add a callback to the key @key, iff the @callback isn't already
        assigned to it"""
        if callback not in self.callbacks.get(key, []):
            self.callbacks[key] = self.callbacks.get(key, []) + [callback]

    def set_callback(self, key, *args):
        "Set the list of callback for key 'key'"
        self.callbacks[key] = list(args)

    def get_callbacks(self, key):
        "Return the list of callbacks associated to key 'key'"
        return self.callbacks.get(key, [])

    def remove_callback(self, callback):
        """Remove the callback from the list.
        Return the list of empty keys (removed)"""

        to_check = set()
        for key, cb_list in viewitems(self.callbacks):
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

    def has_callbacks(self, key):
        return key in self.callbacks

    def remove_key(self, key):
        """Remove and return all callbacks associated to @key"""
        callbacks = self.callbacks.get(key, [])
        del self.callbacks[key]
        return callbacks

    def call_callbacks(self, key, *args):
        """Call callbacks associated to key 'key' with arguments args. While
        callbacks return True, continue with next callback.
        Iterator on other results."""

        res = True

        for c in self.get_callbacks(key):
            res = c(*args)
            if res is not True:
                yield res

    def __call__(self, key, *args):
        "Wrapper for call_callbacks"
        return self.call_callbacks(key, *args)


class CallbackHandlerBitflag(CallbackHandler):

    "Handle a list of callback with conditions on bitflag"

    def call_callbacks(self, bitflag, *args):
        """Call each callbacks associated with bit set in bitflag. While
        callbacks return True, continue with next callback.
        Iterator on other results"""

        for bitflag_expected in self.callbacks:
            if bitflag_expected & bitflag == bitflag_expected:
                # If the flag matched
                for res in super(CallbackHandlerBitflag,
                                 self).call_callbacks(bitflag_expected, *args):
                    if res is not True:
                        yield res


class ExceptionHandle(object):

    "Return type for exception handler"

    def __init__(self, except_flag):
        self.except_flag = except_flag

    @classmethod
    def memoryBreakpoint(cls):
        return cls(EXCEPT_BREAKPOINT_MEMORY)

    def __eq__(self, to_cmp):
        if not isinstance(to_cmp, ExceptionHandle):
            return False
        return (self.except_flag == to_cmp.except_flag)

    def __ne__(self, to_cmp):
        return not self.__eq__(to_cmp)


class JitterException(Exception):

    "Raised when any unhandled exception occurs (in jitter.vm or jitter.cpu)"

    def __init__(self, exception_flag):
        super(JitterException, self).__init__()
        self.exception_flag = exception_flag

    def __str__(self):
        return "A jitter exception occurred: %s (0x%x)" % (
            self.exception_flag_to_str(), self.exception_flag
        )

    def exception_flag_to_str(self):
        exception_flag_list = []
        for name, value in JitterExceptions.items():
            if value & self.exception_flag == value:
                exception_flag_list.append(name)
        return ' & '.join(exception_flag_list)


class Jitter(object):

    "Main class for JIT handling"

    C_Gen = CGen

    def __init__(self, lifter, jit_type="gcc"):
        """Init an instance of jitter.
        @lifter: Lifter instance for this architecture
        @jit_type: JiT backend to use. Available options are:
            - "gcc"
            - "llvm"
            - "python"
        """

        self.arch = lifter.arch
        self.attrib = lifter.attrib
        arch_name = lifter.arch.name  # (lifter.arch.name, lifter.attrib)
        self.running = False

        try:
            if arch_name == "x86":
                from miasm.jitter.arch import JitCore_x86 as jcore
            elif arch_name == "arm":
                from miasm.jitter.arch import JitCore_arm as jcore
            elif arch_name == "armt":
                from miasm.jitter.arch import JitCore_arm as jcore
                lifter.arch.name = 'arm'
            elif arch_name == "aarch64":
                from miasm.jitter.arch import JitCore_aarch64 as jcore
            elif arch_name == "msp430":
                from miasm.jitter.arch import JitCore_msp430 as jcore
            elif arch_name == "mips32":
                from miasm.jitter.arch import JitCore_mips32 as jcore
            elif arch_name == "ppc32":
                from miasm.jitter.arch import JitCore_ppc32 as jcore
            elif arch_name == "mep":
                from miasm.jitter.arch import JitCore_mep as jcore
            else:
                raise ValueError("unknown jit arch: %s" % arch_name)
        except ImportError:
            raise RuntimeError('Unsupported jit arch: %s' % arch_name)

        self.vm = VmMngr.Vm()
        self.cpu = jcore.JitCpu()
        self.lifter = lifter
        self.bs = bin_stream_vm(self.vm)
        self.ircfg = self.lifter.new_ircfg()

        self.symbexec = EmulatedSymbExec(
            self.cpu, self.vm, self.lifter, {}
        )
        self.symbexec.reset_regs()

        try:
            if jit_type == "llvm":
                from miasm.jitter.jitcore_llvm import JitCore_LLVM as JitCore
            elif jit_type == "python":
                from miasm.jitter.jitcore_python import JitCore_Python as JitCore
            elif jit_type == "gcc":
                from miasm.jitter.jitcore_gcc import JitCore_Gcc as JitCore
            else:
                raise ValueError("Unknown jitter %s" % jit_type)
        except ImportError:
            raise RuntimeError('Unsupported jitter: %s' % jit_type)

        self.jit = JitCore(self.lifter, self.bs)
        if isinstance(self.jit, JitCore_Cc_Base):
            self.jit.init_codegen(self.C_Gen(self.lifter))
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

        self.add_exception_handler(EXCEPT_CODE_AUTOMOD, exception_automod)

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

    def get_breakpoint(self, addr):
        """
        Return breakpoints handlers for address @addr
        @addr: integer
        """
        return self.breakpoints_handler.get_callbacks(addr)

    def remove_breakpoints_by_callback(self, callback):
        """Remove callbacks associated with breakpoint.
        @callback: callback to remove
        """
        empty_keys = self.breakpoints_handler.remove_callback(callback)
        for key in empty_keys:
            self.jit.remove_disassembly_splits(key)

    def remove_breakpoints_by_address(self, address):
        """Remove all breakpoints associated with @address.
        @address: address of breakpoints to remove
        """
        callbacks = self.breakpoints_handler.remove_key(address)
        if callbacks:
            self.jit.remove_disassembly_splits(address)

    def add_exception_handler(self, flag, callback):
        """Add a callback associated with an exception flag.
        @flag: bitflag
        @callback: function with definition (jitter instance)
        """
        self.exceptions_handler.add_callback(flag, callback)

    def run_at(self, pc):
        """Wrapper on JiT backend. Run the code at PC and return the next PC.
        @pc: address of code to run"""

        return self.jit.run_at(
            self.cpu, pc,
            set(self.breakpoints_handler.callbacks)
        )

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
                if isinstance(res, Iterator):
                    # If the breakpoint is a generator, yield it step by step
                    for tmp in res:
                        yield tmp
                else:
                    yield res

        # Check exceptions (raised by breakpoints)
        exception_flag = self.get_exception()
        for res in self.exceptions_handler(exception_flag, self):
            if res is not True:
                if isinstance(res, Iterator):
                    for tmp in res:
                        yield tmp
                else:
                    yield res

        # If a callback changed pc, re call every callback
        if old_pc != self.pc:
            return

        # Exceptions should never be activated before run
        exception_flag = self.get_exception()
        if exception_flag:
            raise JitterException(exception_flag)

        # Run the block at PC
        self.pc = self.run_at(self.pc)

        # Check exceptions (raised by the execution of the block)
        exception_flag = self.get_exception()
        for res in self.exceptions_handler(exception_flag, self):
            if res is not True:
                if isinstance(res, Iterator):
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
        self.running = True

    def continue_run(self, step=False, trace=False):
        """PRE: init_run.
        Continue the run of the current session until iterator returns or run is
        set to False.
        If step is True, run only one time.
        If trace is True, activate trace log option until execution stops
        Return the iterator value"""

        if trace:
            self.set_trace_log()
        while self.running:
            try:
                return next(self.run_iterator)
            except StopIteration:
                pass

            self.run_iterator = self.runiter_once(self.pc)

            if step is True:
                break
        if trace:
            self.set_trace_log(False, False, False)
        return None


    def run(self, addr):
        """
        Launch emulation
        @addr: (int) start address
        """
        self.init_run(addr)
        return self.continue_run()

    def run_until(self, addr, trace=False):
        """PRE: init_run.
        Continue the run of the current session until iterator returns, run is
        set to False or addr is reached.
        If trace is True, activate trace log option until execution stops
        Return the iterator value"""

        def stop_exec(jitter):
            jitter.remove_breakpoints_by_callback(stop_exec)
            return False
        self.add_breakpoint(addr, stop_exec)
        return self.continue_run(trace=trace)

    def init_stack(self):
        self.vm.add_memory_page(
            self.stack_base,
            PAGE_READ | PAGE_WRITE,
            b"\x00" * self.stack_size,
            "Stack")
        sp = self.arch.getsp(self.attrib)
        setattr(self.cpu, sp.name, self.stack_base + self.stack_size)
        # regs = self.cpu.get_gpreg()
        # regs[sp.name] = self.stack_base+self.stack_size
        # self.cpu.set_gpreg(regs)

    def get_exception(self):
        return self.cpu.get_exception() | self.vm.get_exception()

    # commun functions
    def get_c_str(self, addr, max_char=None):
        """Get C str from vm.
        @addr: address in memory
        @max_char: maximum len"""
        l = 0
        tmp = addr
        while ((max_char is None or l < max_char) and
               self.vm.get_mem(tmp, 1) != b"\x00"):
            tmp += 1
            l += 1
        value = self.vm.get_mem(addr, l)
        value = force_str(value)
        return value

    def set_c_str(self, addr, value):
        """Set C str str from vm.
        @addr: address in memory
        @value: str"""
        value = force_bytes(value)
        self.vm.set_mem(addr, value + b'\x00')

    def get_str_ansi(self, addr, max_char=None):
        raise NotImplementedError("Deprecated: use os_dep.win_api_x86_32.get_win_str_a")

    def get_str_unic(self, addr, max_char=None):
        raise NotImplementedError("Deprecated: use os_dep.win_api_x86_32.get_win_str_a")

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
        jitter.pc = getattr(jitter.cpu, jitter.lifter.pc.name)

        # Don't break on a None return
        if ret is None:
            return True
        else:
            return ret

    def handle_function(self, f_addr):
        """Add a breakpoint which will trigger the function handler"""
        self.add_breakpoint(f_addr, self.handle_lib)

    def add_lib_handler(self, libs, user_globals=None):
        """Add a function to handle libs call with breakpoints
        @libs: libimp instance
        @user_globals: dictionary for defined user function
        """
        if user_globals is None:
            user_globals = {}

        self.libs = libs
        out = {}
        for name, func in viewitems(user_globals):
            out[name] = func
        self.user_globals = out

        for f_addr in libs.fad2cname:
            self.handle_function(f_addr)

    def eval_expr(self, expr):
        """Eval expression @expr in the context of the current instance. Side
        effects are passed on it"""
        self.symbexec.update_engine_from_cpu()
        ret = self.symbexec.eval_updt_expr(expr)
        self.symbexec.update_cpu_from_engine()

        return ret

    def set_trace_log(self,
                      trace_instr=True, trace_regs=True,
                      trace_new_blocks=False):
        """
        Activate/Deactivate trace log options

        @trace_instr: activate instructions tracing log
        @trace_regs: activate registers tracing log
        @trace_new_blocks: dump new code blocks log
        """

        # As trace state changes, clear already jitted blocks
        self.jit.clear_jitted_blocks()

        self.jit.log_mn = trace_instr
        self.jit.log_regs = trace_regs
        self.jit.log_newbloc = trace_new_blocks


class jitter(Jitter):
    """
    DEPRECATED object
    Use Jitter instead of jitter
    """


    def __init__(self, *args, **kwargs):
        warnings.warn("Deprecated API: use Jitter")
        super(jitter, self).__init__(*args, **kwargs)
