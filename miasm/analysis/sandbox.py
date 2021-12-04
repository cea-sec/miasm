from __future__ import print_function
from builtins import range

import os
import logging
from argparse import ArgumentParser

from future.utils import viewitems, viewvalues
from past.builtins import basestring

from miasm.analysis.machine import Machine
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis import debugging
from miasm.jitter.jitload import log_func
from miasm.core.utils import force_bytes


class Sandbox(object):

    """
    Parent class for Sandbox abstraction
    """

    CALL_FINISH_ADDR = 0x13371acc

    @staticmethod
    def code_sentinelle(jitter):
        jitter.running = False
        return False

    @classmethod
    def _classes_(cls):
        """
        Iterator on parent classes except Sanbox
        """
        for base_cls in cls.__bases__:
            # Avoid infinite loop
            if base_cls == Sandbox:
                continue

            yield base_cls

    classes = property(lambda x: x.__class__._classes_())

    def __init__(self, loc_db, fname, options, custom_methods=None, **kwargs):
        """
        Initialize a sandbox
        @fname: str file name
        @options: namespace instance of specific options
        @custom_methods: { str => func } for custom API implementations
        """

        # Initialize
        assert isinstance(fname, basestring)
        self.fname = fname
        self.options = options
        self.loc_db = loc_db
        if custom_methods is None:
            custom_methods = {}
        kwargs["loc_db"] = loc_db
        for cls in self.classes:
            if cls == Sandbox:
                continue
            if issubclass(cls, OS):
                cls.__init__(self, custom_methods, **kwargs)
            else:
                cls.__init__(self, **kwargs)

        # Logging options
        self.jitter.set_trace_log(
            trace_instr=self.options.singlestep,
            trace_regs=self.options.singlestep,
            trace_new_blocks=self.options.dumpblocs
        )

        if not self.options.quiet_function_calls:
            log_func.setLevel(logging.INFO)

    @classmethod
    def parser(cls, *args, **kwargs):
        """
        Return instance of instance parser with expecting options.
        Extra parameters are passed to parser initialisation.
        """

        parser = ArgumentParser(*args, **kwargs)
        parser.add_argument('-a', "--address",
                            help="Force entry point address", default=None)
        parser.add_argument('-b', "--dumpblocs", action="store_true",
                            help="Log disasm blocks")
        parser.add_argument('-z', "--singlestep", action="store_true",
                            help="Log single step")
        parser.add_argument('-d', "--debugging", action="store_true",
                            help="Debug shell")
        parser.add_argument('-g', "--gdbserver", type=int,
                            help="Listen on port @port")
        parser.add_argument("-j", "--jitter",
                            help="Jitter engine. Possible values are: gcc (default), llvm, python",
                            default="gcc")
        parser.add_argument(
            '-q', "--quiet-function-calls", action="store_true",
                            help="Don't log function calls")
        parser.add_argument('-i', "--dependencies", action="store_true",
                            help="Load PE and its dependencies")

        for base_cls in cls._classes_():
            base_cls.update_parser(parser)
        return parser

    def run(self, addr=None):
        """
        Launch emulation (gdbserver, debugging, basic JIT).
        @addr: (int) start address
        """
        if addr is None and self.options.address is not None:
            addr = int(self.options.address, 0)

        if any([self.options.debugging, self.options.gdbserver]):
            dbg = debugging.Debugguer(self.jitter)
            self.dbg = dbg
            dbg.init_run(addr)

            if self.options.gdbserver:
                port = self.options.gdbserver
                print("Listen on port %d" % port)
                gdb = self.machine.gdbserver(dbg, port)
                self.gdb = gdb
                gdb.run()
            else:
                cmd = debugging.DebugCmd(dbg)
                self.cmd = cmd
                cmd.cmdloop()

        else:
            self.jitter.init_run(addr)
            self.jitter.continue_run()

    def call(self, prepare_cb, addr, *args):
        """
        Direct call of the function at @addr, with arguments @args prepare in
        calling convention implemented by @prepare_cb
        @prepare_cb: func(ret_addr, *args)
        @addr: address of the target function
        @args: arguments
        """
        self.jitter.init_run(addr)
        self.jitter.add_breakpoint(self.CALL_FINISH_ADDR, self.code_sentinelle)
        prepare_cb(self.CALL_FINISH_ADDR, *args)
        self.jitter.continue_run()



class OS(object):

    """
    Parent class for OS abstraction
    """

    def __init__(self, custom_methods, **kwargs):
        pass

    @classmethod
    def update_parser(cls, parser):
        pass


class Arch(object):

    """
    Parent class for Arch abstraction
    """

    # Architecture name
    _ARCH_ = None

    def __init__(self, loc_db, **kwargs):
        self.machine = Machine(self._ARCH_)
        self.jitter = self.machine.jitter(loc_db, self.options.jitter)

    @classmethod
    def update_parser(cls, parser):
        pass


class OS_Win(OS):
    # DLL to import
    ALL_IMP_DLL = [
        "ntdll.dll", "kernel32.dll", "user32.dll",
        "ole32.dll", "urlmon.dll",
        "ws2_32.dll", 'advapi32.dll', "psapi.dll",
    ]
    modules_path = "win_dll"

    def __init__(self, custom_methods, *args, **kwargs):
        from miasm.jitter.loader.pe import vm_load_pe, vm_load_pe_libs,\
            preload_pe, libimp_pe, vm_load_pe_and_dependencies
        from miasm.os_dep import win_api_x86_32, win_api_x86_32_seh
        methods = dict((name, func) for name, func in viewitems(win_api_x86_32.__dict__))
        methods.update(custom_methods)

        super(OS_Win, self).__init__(methods, *args, **kwargs)

        # Import manager
        libs = libimp_pe()
        self.libs = libs
        win_api_x86_32.winobjs.runtime_dll = libs

        self.name2module = {}
        fname_basename = os.path.basename(self.fname).lower()

        # Load main pe
        with open(self.fname, "rb") as fstream:
            self.pe = vm_load_pe(
                self.jitter.vm,
                fstream.read(),
                load_hdr=self.options.load_hdr,
                name=self.fname,
                winobjs=win_api_x86_32.winobjs,
                **kwargs
            )
            self.name2module[fname_basename] = self.pe

        # Load library
        if self.options.loadbasedll:

            # Load libs in memory
            self.name2module.update(
                vm_load_pe_libs(
                    self.jitter.vm,
                    self.ALL_IMP_DLL,
                    libs,
                    self.modules_path,
                    winobjs=win_api_x86_32.winobjs,
                    **kwargs
                )
            )

            # Patch libs imports
            for pe in viewvalues(self.name2module):
                preload_pe(self.jitter.vm, pe, libs)

        if self.options.dependencies:
            vm_load_pe_and_dependencies(
                self.jitter.vm,
                fname_basename,
                self.name2module,
                libs,
                self.modules_path,
                winobjs=win_api_x86_32.winobjs,
                **kwargs
            )

        win_api_x86_32.winobjs.current_pe = self.pe

        # Fix pe imports
        preload_pe(self.jitter.vm, self.pe, libs)

        # Library calls handler
        self.jitter.add_lib_handler(libs, methods)

        # Manage SEH
        if self.options.use_windows_structs:
            win_api_x86_32_seh.main_pe_name = fname_basename
            win_api_x86_32_seh.main_pe = self.pe
            win_api_x86_32.winobjs.hcurmodule = self.pe.NThdr.ImageBase
            win_api_x86_32_seh.name2module = self.name2module
            win_api_x86_32_seh.set_win_fs_0(self.jitter)
            win_api_x86_32_seh.init_seh(self.jitter)

        self.entry_point = self.pe.rva2virt(
            self.pe.Opthdr.AddressOfEntryPoint)

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument('-o', "--load-hdr", action="store_true",
                            help="Load pe hdr")
        parser.add_argument('-y', "--use-windows-structs", action="store_true",
                            help="Create and use windows structures (peb, ldr, seh, ...)")
        parser.add_argument('-l', "--loadbasedll", action="store_true",
                            help="Load base dll (path './win_dll')")
        parser.add_argument('-r', "--parse-resources",
                            action="store_true", help="Load resources")


class OS_Linux(OS):

    PROGRAM_PATH = "./program"

    def __init__(self, custom_methods, *args, **kwargs):
        from miasm.jitter.loader.elf import vm_load_elf, preload_elf, libimp_elf
        from miasm.os_dep import linux_stdlib
        methods = linux_stdlib.__dict__
        methods.update(custom_methods)

        super(OS_Linux, self).__init__(methods, *args, **kwargs)

        # Import manager
        self.libs = libimp_elf()

        with open(self.fname, "rb") as fstream:
            self.elf = vm_load_elf(
                self.jitter.vm,
                fstream.read(),
                name=self.fname,
                **kwargs
            )
        preload_elf(self.jitter.vm, self.elf, self.libs)

        self.entry_point = self.elf.Ehdr.entry

        # Library calls handler
        self.jitter.add_lib_handler(self.libs, methods)
        linux_stdlib.ABORT_ADDR = self.CALL_FINISH_ADDR

        # Arguments
        self.argv = [self.PROGRAM_PATH]
        if self.options.command_line:
             self.argv += self.options.command_line
        self.envp = self.options.environment_vars

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument('-c', '--command-line',
                            action="append",
                            default=[],
                            help="Command line arguments")
        parser.add_argument('--environment-vars',
                            action="append",
                            default=[],
                            help="Environment variables arguments")
        parser.add_argument('--mimic-env',
                            action="store_true",
                            help="Mimic the environment of a starting executable")

class OS_Linux_str(OS):

    PROGRAM_PATH = "./program"

    def __init__(self, custom_methods, *args, **kwargs):
        from miasm.jitter.loader.elf import libimp_elf
        from miasm.os_dep import linux_stdlib
        methods = linux_stdlib.__dict__
        methods.update(custom_methods)

        super(OS_Linux_str, self).__init__(methods, *args, **kwargs)

        # Import manager
        libs = libimp_elf()
        self.libs = libs

        data = open(self.fname, "rb").read()
        self.options.load_base_addr = int(self.options.load_base_addr, 0)
        self.jitter.vm.add_memory_page(
            self.options.load_base_addr, PAGE_READ | PAGE_WRITE, data,
            "Initial Str"
        )

        # Library calls handler
        self.jitter.add_lib_handler(libs, methods)
        linux_stdlib.ABORT_ADDR = self.CALL_FINISH_ADDR

        # Arguments
        self.argv = [self.PROGRAM_PATH]
        if self.options.command_line:
             self.argv += self.options.command_line
        self.envp = self.options.environment_vars

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument('-c', '--command-line',
                            action="append",
                            default=[],
                            help="Command line arguments")
        parser.add_argument('--environment-vars',
                            action="append",
                            default=[],
                            help="Environment variables arguments")
        parser.add_argument('--mimic-env',
                            action="store_true",
                            help="Mimic the environment of a starting executable")
        parser.add_argument("load_base_addr", help="load base address")


class Arch_x86(Arch):
    _ARCH_ = None  # Arch name
    STACK_SIZE = 0x10000
    STACK_BASE = 0x130000

    def __init__(self, loc_db, **kwargs):
        super(Arch_x86, self).__init__(loc_db, **kwargs)

        if self.options.usesegm:
            self.jitter.lifter.do_stk_segm = True
            self.jitter.lifter.do_ds_segm = True
            self.jitter.lifter.do_str_segm = True
            self.jitter.lifter.do_all_segm = True

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument('-s', "--usesegm", action="store_true",
                            help="Use segments")


class Arch_x86_32(Arch_x86):
    _ARCH_ = "x86_32"


class Arch_x86_64(Arch_x86):
    _ARCH_ = "x86_64"


class Arch_arml(Arch):
    _ARCH_ = "arml"
    STACK_SIZE = 0x100000
    STACK_BASE = 0x100000

    def __init__(self, loc_db, **kwargs):
        super(Arch_arml, self).__init__(loc_db, **kwargs)

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()


class Arch_armb(Arch):
    _ARCH_ = "armb"
    STACK_SIZE = 0x100000
    STACK_BASE = 0x100000

    def __init__(self, loc_db, **kwargs):
        super(Arch_armb, self).__init__(loc_db, **kwargs)

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()


class Arch_armtl(Arch):
    _ARCH_ = "armtl"
    STACK_SIZE = 0x100000
    STACK_BASE = 0x100000

    def __init__(self, loc_db, **kwargs):
        super(Arch_armtl, self).__init__(loc_db, **kwargs)

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()


class Arch_mips32b(Arch):
    _ARCH_ = "mips32b"
    STACK_SIZE = 0x100000
    STACK_BASE = 0x100000

    def __init__(self, loc_db, **kwargs):
        super(Arch_mips32b, self).__init__(loc_db, **kwargs)

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()


class Arch_aarch64l(Arch):
    _ARCH_ = "aarch64l"
    STACK_SIZE = 0x100000
    STACK_BASE = 0x100000

    def __init__(self, loc_db, **kwargs):
        super(Arch_aarch64l, self).__init__(loc_db, **kwargs)

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()


class Arch_aarch64b(Arch):
    _ARCH_ = "aarch64b"
    STACK_SIZE = 0x100000
    STACK_BASE = 0x100000

    def __init__(self, loc_db, **kwargs):
        super(Arch_aarch64b, self).__init__(loc_db, **kwargs)

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()

class Arch_ppc(Arch):
    _ARCH_ = None

class Arch_ppc32(Arch):
    _ARCH_ = None

class Arch_ppc32b(Arch_ppc32):
    _ARCH_ = "ppc32b"

class Sandbox_Win_x86_32(Sandbox, Arch_x86_32, OS_Win):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        # Pre-stack some arguments
        self.jitter.push_uint32_t(2)
        self.jitter.push_uint32_t(1)
        self.jitter.push_uint32_t(0)
        self.jitter.push_uint32_t(self.CALL_FINISH_ADDR)

        # Set the runtime guard
        self.jitter.add_breakpoint(self.CALL_FINISH_ADDR, self.__class__.code_sentinelle)

    def run(self, addr=None):
        """
        If addr is not set, use entrypoint
        """
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Win_x86_32, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_stdcall)
        super(self.__class__, self).call(prepare_cb, addr, *args)


class Sandbox_Win_x86_64(Sandbox, Arch_x86_64, OS_Win):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        # reserve stack for local reg
        for _ in range(0x4):
            self.jitter.push_uint64_t(0)

        # Pre-stack return address
        self.jitter.push_uint64_t(self.CALL_FINISH_ADDR)

        # Set the runtime guard
        self.jitter.add_breakpoint(
            self.CALL_FINISH_ADDR,
            self.__class__.code_sentinelle
        )

    def run(self, addr=None):
        """
        If addr is not set, use entrypoint
        """
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Win_x86_64, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_stdcall)
        super(self.__class__, self).call(prepare_cb, addr, *args)


class Sandbox_Linux_x86_32(Sandbox, Arch_x86_32, OS_Linux):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        # Pre-stack some arguments
        if self.options.mimic_env:
            env_ptrs = []
            for env in self.envp:
                env = force_bytes(env)
                env += b"\x00"
                self.jitter.cpu.ESP -= len(env)
                ptr = self.jitter.cpu.ESP
                self.jitter.vm.set_mem(ptr, env)
                env_ptrs.append(ptr)
            argv_ptrs = []
            for arg in self.argv:
                arg = force_bytes(arg)
                arg += b"\x00"
                self.jitter.cpu.ESP -= len(arg)
                ptr = self.jitter.cpu.ESP
                self.jitter.vm.set_mem(ptr, arg)
                argv_ptrs.append(ptr)

            self.jitter.push_uint32_t(self.CALL_FINISH_ADDR)
            self.jitter.push_uint32_t(0)
            for ptr in reversed(env_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.push_uint32_t(0)
            for ptr in reversed(argv_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.push_uint32_t(len(self.argv))
        else:
            self.jitter.push_uint32_t(self.CALL_FINISH_ADDR)

        # Set the runtime guard
        self.jitter.add_breakpoint(
            self.CALL_FINISH_ADDR,
            self.__class__.code_sentinelle
        )

    def run(self, addr=None):
        """
        If addr is not set, use entrypoint
        """
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Linux_x86_32, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_systemv)
        super(self.__class__, self).call(prepare_cb, addr, *args)



class Sandbox_Linux_x86_64(Sandbox, Arch_x86_64, OS_Linux):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        # Pre-stack some arguments
        if self.options.mimic_env:
            env_ptrs = []
            for env in self.envp:
                env = force_bytes(env)
                env += b"\x00"
                self.jitter.cpu.RSP -= len(env)
                ptr = self.jitter.cpu.RSP
                self.jitter.vm.set_mem(ptr, env)
                env_ptrs.append(ptr)
            argv_ptrs = []
            for arg in self.argv:
                arg = force_bytes(arg)
                arg += b"\x00"
                self.jitter.cpu.RSP -= len(arg)
                ptr = self.jitter.cpu.RSP
                self.jitter.vm.set_mem(ptr, arg)
                argv_ptrs.append(ptr)

            self.jitter.push_uint64_t(self.CALL_FINISH_ADDR)
            self.jitter.push_uint64_t(0)
            for ptr in reversed(env_ptrs):
                self.jitter.push_uint64_t(ptr)
            self.jitter.push_uint64_t(0)
            for ptr in reversed(argv_ptrs):
                self.jitter.push_uint64_t(ptr)
            self.jitter.push_uint64_t(len(self.argv))
        else:
            self.jitter.push_uint64_t(self.CALL_FINISH_ADDR)

        # Set the runtime guard
        self.jitter.add_breakpoint(
            self.CALL_FINISH_ADDR,
            self.__class__.code_sentinelle
        )

    def run(self, addr=None):
        """
        If addr is not set, use entrypoint
        """
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Linux_x86_64, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_systemv)
        super(self.__class__, self).call(prepare_cb, addr, *args)


class Sandbox_Linux_arml(Sandbox, Arch_arml, OS_Linux):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        # Pre-stack some arguments
        if self.options.mimic_env:
            env_ptrs = []
            for env in self.envp:
                env = force_bytes(env)
                env += b"\x00"
                self.jitter.cpu.SP -= len(env)
                ptr = self.jitter.cpu.SP
                self.jitter.vm.set_mem(ptr, env)
                env_ptrs.append(ptr)
            argv_ptrs = []
            for arg in self.argv:
                arg = force_bytes(arg)
                arg += b"\x00"
                self.jitter.cpu.SP -= len(arg)
                ptr = self.jitter.cpu.SP
                self.jitter.vm.set_mem(ptr, arg)
                argv_ptrs.append(ptr)

            # Round SP to 4
            self.jitter.cpu.SP = self.jitter.cpu.SP & ~ 3

            self.jitter.push_uint32_t(0)
            for ptr in reversed(env_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.push_uint32_t(0)
            for ptr in reversed(argv_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.push_uint32_t(len(self.argv))

        self.jitter.cpu.LR = self.CALL_FINISH_ADDR

        # Set the runtime guard
        self.jitter.add_breakpoint(
            self.CALL_FINISH_ADDR,
            self.__class__.code_sentinelle
        )

    def run(self, addr=None):
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Linux_arml, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_systemv)
        super(self.__class__, self).call(prepare_cb, addr, *args)


class Sandbox_Linux_armtl(Sandbox, Arch_armtl, OS_Linux):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        # Pre-stack some arguments
        if self.options.mimic_env:
            env_ptrs = []
            for env in self.envp:
                env = force_bytes(env)
                env += b"\x00"
                self.jitter.cpu.SP -= len(env)
                ptr = self.jitter.cpu.SP
                self.jitter.vm.set_mem(ptr, env)
                env_ptrs.append(ptr)
            argv_ptrs = []
            for arg in self.argv:
                arg = force_bytes(arg)
                arg += b"\x00"
                self.jitter.cpu.SP -= len(arg)
                ptr = self.jitter.cpu.SP
                self.jitter.vm.set_mem(ptr, arg)
                argv_ptrs.append(ptr)

            # Round SP to 4
            self.jitter.cpu.SP = self.jitter.cpu.SP & ~ 3

            self.jitter.push_uint32_t(0)
            for ptr in reversed(env_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.push_uint32_t(0)
            for ptr in reversed(argv_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.push_uint32_t(len(self.argv))

        self.jitter.cpu.LR = self.CALL_FINISH_ADDR

        # Set the runtime guard
        self.jitter.add_breakpoint(
            self.CALL_FINISH_ADDR,
            self.__class__.code_sentinelle
        )

    def run(self, addr=None):
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Linux_armtl, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_systemv)
        super(self.__class__, self).call(prepare_cb, addr, *args)



class Sandbox_Linux_mips32b(Sandbox, Arch_mips32b, OS_Linux):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        # Pre-stack some arguments
        if self.options.mimic_env:
            env_ptrs = []
            for env in self.envp:
                env = force_bytes(env)
                env += b"\x00"
                self.jitter.cpu.SP -= len(env)
                ptr = self.jitter.cpu.SP
                self.jitter.vm.set_mem(ptr, env)
                env_ptrs.append(ptr)
            argv_ptrs = []
            for arg in self.argv:
                arg = force_bytes(arg)
                arg += b"\x00"
                self.jitter.cpu.SP -= len(arg)
                ptr = self.jitter.cpu.SP
                self.jitter.vm.set_mem(ptr, arg)
                argv_ptrs.append(ptr)

            self.jitter.push_uint32_t(0)
            for ptr in reversed(env_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.push_uint32_t(0)
            for ptr in reversed(argv_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.push_uint32_t(len(self.argv))

        self.jitter.cpu.RA = 0x1337beef

        # Set the runtime guard
        self.jitter.add_breakpoint(
            0x1337beef,
            self.__class__.code_sentinelle
        )

    def run(self, addr=None):
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Linux_mips32b, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_systemv)
        super(self.__class__, self).call(prepare_cb, addr, *args)


class Sandbox_Linux_armb_str(Sandbox, Arch_armb, OS_Linux_str):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        self.jitter.cpu.LR = self.CALL_FINISH_ADDR

        # Set the runtime guard
        self.jitter.add_breakpoint(self.CALL_FINISH_ADDR, self.__class__.code_sentinelle)

    def run(self, addr=None):
        if addr is None and self.options.address is not None:
            addr = int(self.options.address, 0)
        super(Sandbox_Linux_armb_str, self).run(addr)


class Sandbox_Linux_arml_str(Sandbox, Arch_arml, OS_Linux_str):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        self.jitter.cpu.LR = self.CALL_FINISH_ADDR

        # Set the runtime guard
        self.jitter.add_breakpoint(self.CALL_FINISH_ADDR, self.__class__.code_sentinelle)

    def run(self, addr=None):
        if addr is None and self.options.address is not None:
            addr = int(self.options.address, 0)
        super(Sandbox_Linux_arml_str, self).run(addr)


class Sandbox_Linux_aarch64l(Sandbox, Arch_aarch64l, OS_Linux):

    def __init__(self, loc_db, *args, **kwargs):
        Sandbox.__init__(self, loc_db, *args, **kwargs)

        # Pre-stack some arguments
        if self.options.mimic_env:
            env_ptrs = []
            for env in self.envp:
                env = force_bytes(env)
                env += b"\x00"
                self.jitter.cpu.SP -= len(env)
                ptr = self.jitter.cpu.SP
                self.jitter.vm.set_mem(ptr, env)
                env_ptrs.append(ptr)
            argv_ptrs = []
            for arg in self.argv:
                arg = force_bytes(arg)
                arg += b"\x00"
                self.jitter.cpu.SP -= len(arg)
                ptr = self.jitter.cpu.SP
                self.jitter.vm.set_mem(ptr, arg)
                argv_ptrs.append(ptr)

            self.jitter.push_uint64_t(0)
            for ptr in reversed(env_ptrs):
                self.jitter.push_uint64_t(ptr)
            self.jitter.push_uint64_t(0)
            for ptr in reversed(argv_ptrs):
                self.jitter.push_uint64_t(ptr)
            self.jitter.push_uint64_t(len(self.argv))

        self.jitter.cpu.LR = self.CALL_FINISH_ADDR

        # Set the runtime guard
        self.jitter.add_breakpoint(
            self.CALL_FINISH_ADDR,
            self.__class__.code_sentinelle
        )

    def run(self, addr=None):
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Linux_aarch64l, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_systemv)
        super(self.__class__, self).call(prepare_cb, addr, *args)

class Sandbox_Linux_ppc32b(Sandbox, Arch_ppc32b, OS_Linux):

    STACK_SIZE = 0x10000
    STACK_BASE = 0xbfce0000

    # The glue between the kernel and the ELF ABI on Linux/PowerPC is
    # implemented in glibc/sysdeps/powerpc/powerpc32/dl-start.S, so we
    # have to play the role of ld.so here.
    def __init__(self, loc_db, *args, **kwargs):
        super(Sandbox_Linux_ppc32b, self).__init__(loc_db, *args, **kwargs)

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()
        self.jitter.cpu.R1 -= 8

        # Pre-stack some arguments
        if self.options.mimic_env:
            env_ptrs = []
            for env in self.envp:
                env = force_bytes(env)
                env += b"\x00"
                self.jitter.cpu.R1 -= len(env)
                ptr = self.jitter.cpu.R1
                self.jitter.vm.set_mem(ptr, env)
                env_ptrs.append(ptr)
            argv_ptrs = []
            for arg in self.argv:
                arg = force_bytes(arg)
                arg += b"\x00"
                self.jitter.cpu.R1 -= len(arg)
                ptr = self.jitter.cpu.R1
                self.jitter.vm.set_mem(ptr, arg)
                argv_ptrs.append(ptr)

            self.jitter.push_uint32_t(0)
            for ptr in reversed(env_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.cpu.R5 = self.jitter.cpu.R1	# envp
            self.jitter.push_uint32_t(0)
            for ptr in reversed(argv_ptrs):
                self.jitter.push_uint32_t(ptr)
            self.jitter.cpu.R4 = self.jitter.cpu.R1	# argv
            self.jitter.cpu.R3 = len(self.argv)		# argc
            self.jitter.push_uint32_t(self.jitter.cpu.R3)

            self.jitter.cpu.R6 = 0			# auxp
            self.jitter.cpu.R7 = 0			# termination function

            # From the glibc, we should push a 0 here to distinguish a
            # dynamically linked executable from a statically linked one.
            # We actually do not do it and attempt to be somehow compatible
            # with both types of executables.
            #self.jitter.push_uint32_t(0)

        self.jitter.cpu.LR = self.CALL_FINISH_ADDR

        # Set the runtime guard
        self.jitter.add_breakpoint(
            self.CALL_FINISH_ADDR,
            self.__class__.code_sentinelle
        )

    def run(self, addr=None):
        """
        If addr is not set, use entrypoint
        """
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Linux_ppc32b, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_systemv)
        super(self.__class__, self).call(prepare_cb, addr, *args)
