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



class Arch(object):
    """
    Parent class for Arch abstraction
    """

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument(
            "-j",
            "--jitter",
            help="Jitter engine. Possible values are: gcc (default), llvm, python",
            default="gcc",
        )
        parser.add_argument(
            "-b", "--dumpblocs", action="store_true", help="Log disasm blocks"
        )
        parser.add_argument(
            "-z", "--singlestep", action="store_true", help="Log single step"
        )

    def __init__(self, loc_db, options):
        self.machine = Machine(self._ARCH_)
        self.jitter = self.machine.jitter(loc_db, options.jitter)

        # Logging options
        self.jitter.set_trace_log(
            trace_instr=options.singlestep,
            trace_regs=options.singlestep,
            trace_new_blocks=options.dumpblocs,
        )


class Sandbox(object):
    """
    Parent class for Sandbox abstraction
    """

    CALL_FINISH_ADDR = 0x13371ACC

    def __init__(self, loc_db, options, custom_methods=None):
        self.arch = self.CLS_ARCH(loc_db, options)
        self.os = self.CLS_OS(self.arch.jitter, options, custom_methods)
        self.jitter = self.arch.jitter

    @staticmethod
    def code_sentinelle(jitter):
        jitter.run = False
        return False

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument(
            "-a", "--address", help="Force entry point address", default=None,
        )
        parser.add_argument(
            "-d", "--debugging", action="store_true", help="Debug shell",
        )
        parser.add_argument(
            "-g", "--gdbserver", type=int, help="Listen on port @port",
        )

        cls.CLS_ARCH.update_parser(parser)
        cls.CLS_OS.update_parser(parser)

    @classmethod
    def parser(cls, *args, **kwargs):
        """
        Return instance of instance parser with expecting options.
        Extra parameters are passed to parser initialisation.
        """

        parser = ArgumentParser(*args, **kwargs)
        cls.update_parser(parser)
        return parser

    def run(self, addr=None):
        """
        Launch emulation (gdbserver, debugging, basic JIT).
        @addr: (int) start address
        """
        if addr is not None:
            addr = addr
        elif self.options.address is not None:
            addr = int(self.options.address, 0)
        else:
            addr = self.entry_point

        if any([self.options.debugging, self.options.gdbserver]):
            dbg = debugging.Debugguer(self.arch.jitter)
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
            self.arch.jitter.init_run(addr)
            self.arch.jitter.continue_run()

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


class Arch_x86_32(Arch):
    _ARCH_ = "x86_32"  # Arch name

    def __init__(self, loc_db, options):
        super(Arch_x86_32, self).__init__(loc_db, options)

        if options.usesegm:
            self.jitter.lifter.do_stk_segm = True
            self.jitter.lifter.do_ds_segm = True
            self.jitter.lifter.do_str_segm = True
            self.jitter.lifter.do_all_segm = True

    @classmethod
    def update_parser(cls, parser):
        Arch.update_parser(parser)
        parser.add_argument("-s", "--usesegm", action="store_true", help="Use segments")


class Arch_arml(Arch):
    _ARCH_ = "arml"


class Arch_armb(Arch):
    _ARCH_ = "armb"


class Arch_aarch64l(Arch):
    _ARCH_ = "aarch64l"


class Arch_aarch64b(Arch):
    _ARCH_ = "aarch64b"


class Arch_ppc32b(Arch):
    _ARCH_ = "ppc32b"


class Arch_x86_64(Arch):
    _ARCH_ = "x86_64"


class Arch_mips32b(Arch):
    _ARCH_ = "mips32b"


class Arch_mips32l(Arch):
    _ARCH_ = "mips32l"


class OS_WinXP32(OS):
    LOADED_DLLS = [
        "ntdll.dll",
        "kernel32.dll",
        "user32.dll",
        "ole32.dll",
        "urlmon.dll",
        "ws2_32.dll",
        "advapi32.dll",
        "psapi.dll",
    ]

    PATH_DLLS = "win_dll"

    STACK_SIZE = 0x10000
    STACK_BASE = 0x130000

    def __init__(self, jitter, options, custom_methods=None):
        from miasm.jitter.loader.pe import (
            vm_load_pe,
            vm_load_pe_libs,
            preload_pe,
            LoaderWindows,
            vm_load_pe_and_dependencies,
        )
        from miasm.os_dep import win_api_x86_32, win_api_x86_32_seh

        self.jitter = jitter
        methods = dict(
            (name, func) for name, func in viewitems(win_api_x86_32.__dict__)
        )
        methods.update(custom_methods)

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()

        # Import manager
        libs = LoaderWindows()
        self.libs = libs
        win_api_x86_32.winobjs.runtime_dll = libs

        self.name2module = {}
        fname_basename = os.path.basename(options.filename).lower()

        # Load main pe
        with open(options.filename, "rb") as fstream:
            self.pe = vm_load_pe(
                self.jitter.vm,
                fstream.read(),
                load_hdr=options.load_hdr,
                name=options.filename,
                winobjs=win_api_x86_32.winobjs,
            )
            self.name2module[fname_basename] = self.pe

        win_api_x86_32.winobjs.current_pe = self.pe

        # Load library
        if options.loadbasedll:
            # Load libs in memory
            self.name2module.update(
                vm_load_pe_libs(
                    self.jitter.vm,
                    self.LOADED_DLLS,
                    libs,
                    self.PATH_DLLS,
                    winobjs=win_api_x86_32.winobjs,
                )
            )

            # Patch libs imports
            for pe in viewvalues(self.name2module):
                preload_pe(self.jitter.vm, pe, libs)

        if options.dependencies:
            vm_load_pe_and_dependencies(
                self.jitter.vm,
                fname_basename,
                self.name2module,
                libs,
                self.PATH_DLLS,
                winobjs=win_api_x86_32.winobjs,
            )

        # Fix pe imports
        preload_pe(self.jitter.vm, self.pe, libs)

        # Library calls handler
        self.jitter.add_lib_handler(libs, methods)

        # Manage SEH
        if options.use_windows_structs:
            win_api_x86_32_seh.main_pe_name = fname_basename
            win_api_x86_32_seh.main_pe = self.pe
            win_api_x86_32.winobjs.hcurmodule = self.pe.NThdr.ImageBase
            win_api_x86_32_seh.name2module = self.name2module
            win_api_x86_32_seh.set_win_fs_0(self.jitter)
            win_api_x86_32_seh.init_seh(self.jitter)

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument("filename", help="PE Filename")
        parser.add_argument("-o", "--load-hdr", action="store_true", help="Load pe hdr")
        parser.add_argument(
            "-y",
            "--use-windows-structs",
            action="store_true",
            help="Create and use windows structures (peb, ldr, seh, ...)",
        )
        parser.add_argument(
            "-l",
            "--loadbasedll",
            action="store_true",
            help="Load base dll (path './win_dll')",
        )
        parser.add_argument(
            "-r", "--parse-resources", action="store_true", help="Load resources"
        )
        parser.add_argument(
            "-i",
            "--dependencies",
            action="store_true",
            help="Load PE and its dependencies",
        )
        parser.add_argument(
            "-q",
            "--quiet-function-calls",
            action="store_true",
            help="Don't log function calls",
        )


class Sandbox_WinXP_x86_32(Sandbox):
    CLS_ARCH = Arch_x86_32
    CLS_OS = OS_WinXP32

    def __init__(self, loc_db, options, custom_methods=None):
        super(Sandbox_WinXP_x86_32, self).__init__(loc_db, options, custom_methods)
        self.pe = self.os.pe
        self.libs = self.os.libs

        self.entry_point = self.pe.rva2virt(self.pe.Opthdr.AddressOfEntryPoint)

        self.options = options
        self.loc_db = loc_db

        # Pre-stack return address
        self.jitter.push_uint32_t(self.CALL_FINISH_ADDR)
        self.jitter.add_breakpoint(self.CALL_FINISH_ADDR, self.code_sentinelle)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop("prepare_cb", self.jitter.func_prepare_stdcall)
        super(Sandbox_WinXP_x86_32, self).call(prepare_cb, addr, *args)


class Sandbox_WinXP_x86_64(Sandbox):
    CLS_ARCH = Arch_x86_64
    CLS_OS = OS_WinXP32

    def __init__(self, loc_db, options, custom_methods=None):
        super(Sandbox_WinXP_x86_64, self).__init__(loc_db, options, custom_methods)
        self.pe = self.os.pe
        self.libs = self.os.libs

        self.entry_point = self.pe.rva2virt(self.pe.Opthdr.AddressOfEntryPoint)

        self.options = options
        self.loc_db = loc_db

        # Pre-stack return address
        self.jitter.push_uint64_t(self.CALL_FINISH_ADDR)
        self.jitter.add_breakpoint(self.CALL_FINISH_ADDR, self.code_sentinelle)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop("prepare_cb", self.jitter.func_prepare_stdcall)
        super(Sandbox_WinXP_x86_64, self).call(prepare_cb, addr, *args)


class OS_Linux(OS):

    CALL_FINISH_ADDR = 0x13371ACC

    STACK_SIZE = 0x100000
    STACK_BASE = 0x100000

    def __init__(self, jitter, options, custom_methods=None):
        from miasm.jitter.loader.elf import vm_load_elf, preload_elf, LoaderUnix
        from miasm.os_dep import linux_stdlib

        methods = linux_stdlib.__dict__
        methods.update(custom_methods)

        self.jitter = jitter

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()

        # Import manager
        self.libs = LoaderUnix()

        with open(options.filename, "rb") as fstream:
            self.elf = vm_load_elf(
                self.jitter.vm, fstream.read(), name=options.filename,
            )
        preload_elf(self.jitter.vm, self.elf, self.libs)

        self.entry_point = self.elf.Ehdr.entry

        # Library calls handler
        self.jitter.add_lib_handler(self.libs, methods)
        linux_stdlib.ABORT_ADDR = self.CALL_FINISH_ADDR

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument("filename", help="ELF Filename")
        parser.add_argument(
            "-c",
            "--command-line",
            action="append",
            default=[],
            help="Command line arguments",
        )
        parser.add_argument(
            "--environment-vars",
            action="append",
            default=[],
            help="Environment variables arguments",
        )
        parser.add_argument(
            "--mimic-env",
            action="store_true",
            help="Mimic the environment of a starting executable",
        )


class OS_Linux_shellcode(OS):

    CALL_FINISH_ADDR = 0x13371ACC

    STACK_SIZE = 0x100000
    STACK_BASE = 0x100000

    def __init__(self, jitter, options, custom_methods=None):
        from miasm.jitter.loader.elf import vm_load_elf, preload_elf, LoaderUnix
        from miasm.os_dep import linux_stdlib

        methods = linux_stdlib.__dict__
        methods.update(custom_methods)

        self.jitter = jitter

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.stack_base = self.STACK_BASE
        self.jitter.init_stack()

        # Import manager
        self.libs = LoaderUnix()

        data = open(options.filename, "rb").read()
        options.load_base_addr = int(options.load_base_addr, 0)
        self.jitter.vm.add_memory_page(
            options.load_base_addr, PAGE_READ | PAGE_WRITE, data, "Initial shellcode"
        )

        # Library calls handler
        self.jitter.add_lib_handler(self.libs, methods)
        linux_stdlib.ABORT_ADDR = self.CALL_FINISH_ADDR

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument("filename", help="shellcode")
        parser.add_argument("load_base_addr", help="load base address")
        parser.add_argument(
            "-c",
            "--command-line",
            action="append",
            default=[],
            help="Command line arguments",
        )
        parser.add_argument(
            "--environment-vars",
            action="append",
            default=[],
            help="Environment variables arguments",
        )
        parser.add_argument(
            "--mimic-env",
            action="store_true",
            help="Mimic the environment of a starting executable",
        )


class Sandbox_Linux_x86_32(Sandbox):
    CLS_ARCH = Arch_x86_32
    CLS_OS = OS_Linux
    PROGRAM_PATH = "./program"

    def __init__(self, loc_db, options, custom_methods=None):
        super(Sandbox_Linux_x86_32, self).__init__(loc_db, options, custom_methods)
        self.elf = self.os.elf
        self.libs = self.os.libs

        self.entry_point = self.elf.Ehdr.entry

        self.options = options
        self.loc_db = loc_db

        # Arguments
        self.argv = [self.PROGRAM_PATH]
        if self.options.command_line:
            self.argv += self.options.command_line
        self.envp = self.options.environment_vars

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
            self.CALL_FINISH_ADDR, self.__class__.code_sentinelle
        )

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop("prepare_cb", self.jitter.func_prepare_systemv)
        super(Sandbox_Linux_x86_32, self).call(prepare_cb, addr, *args)


class Sandbox_Linux_arml(Sandbox):
    CLS_ARCH = Arch_arml
    CLS_OS = OS_Linux
    PROGRAM_PATH = "./program"

    def __init__(self, loc_db, options, custom_methods=None):
        super(Sandbox_Linux_arml, self).__init__(loc_db, options, custom_methods)
        self.elf = self.os.elf
        self.libs = self.os.libs

        self.entry_point = self.elf.Ehdr.entry

        self.options = options
        self.loc_db = loc_db

        # Arguments
        self.argv = [self.PROGRAM_PATH]
        if self.options.command_line:
            self.argv += self.options.command_line
        self.envp = self.options.environment_vars

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
            self.jitter.cpu.SP = self.jitter.cpu.SP & ~3

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
            self.CALL_FINISH_ADDR, self.__class__.code_sentinelle
        )

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop("prepare_cb", self.jitter.func_prepare_systemv)
        super(Sandbox_Linux_arml, self).call(prepare_cb, addr, *args)


class Sandbox_Linux_arml_shellcode(Sandbox):
    CLS_ARCH = Arch_arml
    CLS_OS = OS_Linux_shellcode
    PROGRAM_PATH = "./program"

    def __init__(self, loc_db, options, custom_methods=None):
        super(Sandbox_Linux_arml_shellcode, self).__init__(
            loc_db, options, custom_methods
        )
        self.libs = self.os.libs

        self.entry_point = options.load_base_addr

        self.options = options
        self.loc_db = loc_db

        # Arguments
        self.argv = [self.PROGRAM_PATH]
        if self.options.command_line:
            self.argv += self.options.command_line
        self.envp = self.options.environment_vars

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
            self.jitter.cpu.SP = self.jitter.cpu.SP & ~3

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
            self.CALL_FINISH_ADDR, self.__class__.code_sentinelle
        )

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop("prepare_cb", self.jitter.func_prepare_systemv)
        super(Sandbox_Linux_arml_shellcode, self).call(prepare_cb, addr, *args)


class Sandbox_Linux_armb_shellcode(Sandbox_Linux_arml_shellcode):
    CLS_ARCH = Arch_armb
    CLS_OS = OS_Linux_shellcode
    PROGRAM_PATH = "./program"


class Sandbox_Linux_armb(Sandbox):
    CLS_ARCH = Arch_armb
    CLS_OS = OS_Linux
    PROGRAM_PATH = "./program"


class Sandbox_Linux_aarch64l(Sandbox):
    CLS_ARCH = Arch_aarch64l
    CLS_OS = OS_Linux
    PROGRAM_PATH = "./program"

    def __init__(self, loc_db, options, custom_methods=None):
        super(Sandbox_Linux_aarch64l, self).__init__(loc_db, options, custom_methods)
        self.elf = self.os.elf
        self.libs = self.os.libs

        self.entry_point = self.elf.Ehdr.entry

        self.options = options
        self.loc_db = loc_db

        # Arguments
        self.argv = [self.PROGRAM_PATH]
        if self.options.command_line:
            self.argv += self.options.command_line
        self.envp = self.options.environment_vars

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
            self.CALL_FINISH_ADDR, self.__class__.code_sentinelle
        )


class Sandbox_Linux_ppc32b(Sandbox):
    CLS_ARCH = Arch_ppc32b
    CLS_OS = OS_Linux
    PROGRAM_PATH = "./program"

    def __init__(self, loc_db, options, custom_methods=None):
        super(Sandbox_Linux_ppc32b, self).__init__(loc_db, options, custom_methods)
        self.elf = self.os.elf
        self.libs = self.os.libs

        self.entry_point = self.elf.Ehdr.entry

        self.options = options
        self.loc_db = loc_db

        self.jitter.push_uint32_t(self.CALL_FINISH_ADDR)

        # Set the runtime guard
        self.jitter.add_breakpoint(
            self.CALL_FINISH_ADDR, self.__class__.code_sentinelle
        )

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop("prepare_cb", self.jitter.func_prepare_stdcall)
        super(Sandbox_Linux_ppc32b, self).call(prepare_cb, addr, *args)


class Sandbox_Linux_x86_64(Sandbox):
    CLS_ARCH = Arch_x86_64
    CLS_OS = OS_Linux
    PROGRAM_PATH = "./program"

    def __init__(self, loc_db, options, custom_methods=None):
        super(Sandbox_Linux_x86_64, self).__init__(loc_db, options, custom_methods)
        self.elf = self.os.elf
        self.libs = self.os.libs

        self.entry_point = self.elf.Ehdr.entry

        self.options = options
        self.loc_db = loc_db

        # Arguments
        self.argv = [self.PROGRAM_PATH]
        if self.options.command_line:
            self.argv += self.options.command_line
        self.envp = self.options.environment_vars

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
            self.CALL_FINISH_ADDR, self.__class__.code_sentinelle
        )


class Sandbox_Linux_mips32b(Sandbox):
    CLS_ARCH = Arch_mips32b
    CLS_OS = OS_Linux
    PROGRAM_PATH = "./program"

    def __init__(self, loc_db, options, custom_methods=None):
        super(Sandbox_Linux_mips32b, self).__init__(loc_db, options, custom_methods)
        self.elf = self.os.elf
        self.libs = self.os.libs

        self.entry_point = self.elf.Ehdr.entry

        self.options = options
        self.loc_db = loc_db

        # Arguments
        self.argv = [self.PROGRAM_PATH]
        if self.options.command_line:
            self.argv += self.options.command_line
        self.envp = self.options.environment_vars

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

        self.jitter.cpu.RA = 0x1337BEEF

        # Set the runtime guard
        self.jitter.add_breakpoint(
            self.CALL_FINISH_ADDR, self.__class__.code_sentinelle
        )

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop("prepare_cb", self.jitter.func_prepare_systemv)
        super(Sandbox_Linux_mips32b, self).call(prepare_cb, addr, *args)


class Sandbox_Linux_mips32l(Sandbox_Linux_mips32b):
    CLS_ARCH = Arch_mips32l
    CLS_OS = OS_Linux
    PROGRAM_PATH = "./program"
