#!/usr/bin/env python

import os
from miasm2.core import asmbloc

from miasm2.jitter.csts import *
from miasm2.core.utils import *
from miasm2.core.bin_stream import bin_stream
from miasm2.ir.ir2C import init_arch_C

import logging

log = logging.getLogger('jitload.py')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

try:
    from jitcore_tcc import JitCore_Tcc
except ImportError:
    log.error('cannot import jit tcc')

try:
    from jitcore_llvm import JitCore_LLVM
except ImportError:
    log.error('cannot import jit llvm')

try:
    from jitcore_python import JitCore_Python
except ImportError:
    log.error('cannot import jit python')


class bin_stream_vm(bin_stream):

    def __init__(self, vm, offset=0L, base_offset=0L):
        self.offset = offset
        self.base_offset = base_offset
        self.vm = vm

    def getlen(self):
        return 0xFFFFFFFFFFFFFFFF

    def getbytes(self, start, l=1):
        try:
            s = self.vm.get_mem(start + self.base_offset, l)
        except:
            raise IOError('cannot get mem ad', hex(start))
        return s

    def readbs(self, l=1):
        try:
            s = self.vm.get_mem(self.offset + self.base_offset, l)
        except:
            raise IOError('cannot get mem ad', hex(self.offset))
        self.offset += l
        return s

    def writebs(self, l=1):
        raise ValueError('writebs unsupported')

    def setoffset(self, val):
        self.offset = val





class CallbackHandler(object):

    "Handle a list of callback"

    def __init__(self):
        self.callbacks = {}  # Key -> [callback list]

    def add_callback(self, name, callback):
        "Add a callback to the key 'name'"
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

    def __call__(self, bitflag, *args):
        """Call each callbacks associated with bit set in bitflag. While
        callbacks return True, continue with next callback.
        Iterator on other results"""

        res = True
        for b in self.callbacks.keys():

            if b & bitflag != 0:
                # If the flag matched
                for res in self.call_callbacks(b, *args):
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

    def __init__(self, ir_arch, jit_type="tcc"):
        """Init an instance of jitter.
        @ir_arch: ir instance for this architecture
        @jit_type: JiT backend to use. Available options are:
            - "tcc"
            - "llvm"
            - "python"
        """

        self.arch = ir_arch.arch
        self.attrib = ir_arch.attrib
        arch_name = ir_arch.arch.name  # (ir_arch.arch.name, ir_arch.attrib)
        if arch_name == "x86":
            from arch import JitCore_x86 as jcore
        elif arch_name == "arm":
            from arch import JitCore_arm as jcore
        elif arch_name == "msp430":
            from arch import JitCore_msp430 as jcore
        elif arch_name == "mips32":
            from arch import JitCore_mips32 as jcore
        else:
            raise ValueError("unsupported jit arch!")

        self.cpu = jcore.JitCpu()
        self.vm = jcore.VmMngr()
        self.bs = bin_stream_vm(self.vm)
        self.ir_arch = ir_arch
        init_arch_C(self.arch)

        if jit_type == "tcc":
            self.jit = JitCore_Tcc(self.ir_arch, self.bs)
        elif jit_type == "llvm":
            self.jit = JitCore_LLVM(self.ir_arch, self.bs)
        elif jit_type == "python":
            self.jit = JitCore_Python(self.ir_arch, self.bs)
        else:
            raise Exception("Unkown JiT Backend")

        self.cpu.init_regs()
        self.vm.init_memory_page_pool()
        self.vm.init_code_bloc_pool()
        self.vm.init_memory_breakpoint()

        self.vm.set_addr2obj(self.jit.addr2obj)

        self.jit.load()
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
            "Tell the JiT backend to update blocs modified"
            addr = self.vm.get_last_write_ad()
            size = self.vm.get_last_write_size()

            self.jit.updt_automod_code(self.vm, addr, size)
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

        return self.jit.runbloc(self.cpu, self.vm, pc)

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
        for res in self.breakpoints_handler(self.pc, self):
            if res is not True:
                yield res

        # If a callback changed pc, re call every callback
        if old_pc != self.pc:
            return

        # Exceptions should never be activated before run
        assert(self.get_exception() == 0)

        # Run the bloc at PC
        self.pc = self.runbloc(self.pc)

        # Check exceptions
        exception_flag = self.get_exception()
        for res in self.exceptions_handler(exception_flag, self):
            if res is not True:
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
            self.stack_base, PAGE_READ | PAGE_WRITE, "\x00" * self.stack_size)
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
