import os, sys
from argparse import ArgumentParser
from miasm2.analysis.machine import Machine
from miasm2.jitter.jitload import vm_load_pe, preload_pe, libimp
from miasm2.jitter.jitload import vm_load_elf, libimp, preload_elf
from miasm2.os_dep import win_api_x86_32, win_api_x86_32_seh
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.analysis import debugging

class Sandbox(object):
    """
    Parent class for Sandbox abstraction
    """

    @staticmethod
    def code_sentinelle(jitter):
        print 'Emulation stop'
        jitter.run = False
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

    classes = property(lambda x:x.__class__._classes_())

    def __init__(self, fname, options, custom_methods = {}):
        """
        Initialize a sandbox
        @fname: str file name
        @options: namespace instance of specific options
        @custom_methods: { str => func } for custom API implementations
        """

        # Initialize
        self.fname = fname
        self.options = options
        for cls in self.classes:
            if cls == Sandbox:
                continue
            if issubclass(cls, OS):
                cls.__init__(self, custom_methods)
            else:
                cls.__init__(self)

        # Logging options
        if self.options.singlestep:
            self.jitter.jit.log_mn = True
            self.jitter.jit.log_regs = True

        if self.options.dumpblocs:
            self.jitter.jit.log_newbloc = True

    @classmethod
    def parser(cls, *args, **kwargs):
        """
        Return instance of instance parser with expecting options.
        Extra parameters are passed to parser initialisation.
        """

        parser = ArgumentParser(*args, **kwargs)
        parser.add_argument('-a', "--address",
                            help="Force entry point address", default=None)
        parser.add_argument('-x', "--dumpall", action="store_true",
                            help="Load base dll")
        parser.add_argument('-b', "--dumpblocs", action="store_true",
                            help="Log disasm blocks")
        parser.add_argument('-z', "--singlestep", action="store_true",
                            help="Log single step")
        parser.add_argument('-d', "--debugging", action="store_true",
                            help="Debug shell")
        parser.add_argument('-g', "--gdbserver", type=int,
                            help="Listen on port @port")
        parser.add_argument("-j", "--jitter",
                            help="Jitter engine. Possible values are: tcc (default), llvm, python",
                            default="tcc")

        for base_cls in cls._classes_():
            base_cls.update_parser(parser)
        return parser

    def run(self, addr=None):
        """
        Launch emulation (gdbserver, debugging, basic JIT).
        @addr: (int) start address
        """
        if addr is None and self.options.address is not None:
            addr = int(self.options.address, 16)

        if any([self.options.debugging, self.options.gdbserver]):
            dbg = debugging.Debugguer(self.jitter)
            self.dbg = dbg
            dbg.init_run(addr)

            if self.options.gdbserver is not False:
                port = self.options.gdbserver
                print "Listen on port %d" % port
                gdb = self.machine.gdbserver(dbg, port)
                self.gdb = gdb
                gdb.run()
            else:
                cmd = debugging.DebugCmd(dbg)
                self.cmd = cmd
                cmd.cmdloop()

        else:
            print "Start emulation", hex(addr)
            self.jitter.init_run(addr)
            print self.jitter.continue_run()


class OS(object):
    """
    Parent class for OS abstraction
    """

    def __init__(self, custom_methods):
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
    def __init__(self):
        self.machine = Machine(self._ARCH_)
        self.jitter = self.machine.jitter(self.options.jitter)

    @classmethod
    def update_parser(cls, parser):
        pass


class OS_Win(OS):
    # DLL to import
    ALL_IMP_DLL = ["ntdll.dll", "kernel32.dll", "user32.dll",
                   "ole32.dll", "urlmon.dll",
                   "ws2_32.dll", 'advapi32.dll', "psapi.dll",
               ]

    def __init__(self, custom_methods, *args, **kwargs):
        super(OS_Win, self).__init__(custom_methods, *args, **kwargs)

        # Import manager
        libs = libimp()
        self.libs = libs
        win_api_x86_32.winobjs.runtime_dll = libs

        # Load library
        if self.options.loadbasedll:
            all_pe = []

            # Load libs in memory
            for dll_fname in self.ALL_IMP_DLL:
                fname = os.path.join('win_dll', dll_fname)
                e_lib = vm_load_pe(self.jitter.vm, fname)

                libs.add_export_lib(e_lib, dll_fname)
                all_pe.append(e_lib)

            # Patch libs imports
            for pe in all_pe:
                preload_pe(self.jitter.vm, pe, libs)

        # Load main pe
        self.pe = vm_load_pe(self.jitter.vm, self.fname)

        # Fix pe imports
        preload_pe(self.jitter.vm, self.pe, libs)

        # Library calls handler
        self.jitter.add_lib_handler(libs, custom_methods)

        # Manage SEH
        if self.options.use_seh:
            win_api_x86_32_seh.main_pe_name = self.fname
            win_api_x86_32_seh.main_pe = self.pe
            win_api_x86_32_seh.loaded_modules = self.ALL_IMP_DLL
            win_api_x86_32_seh.init_seh(self.jitter)
            win_api_x86_32_seh.set_win_fs_0(self.jitter)

        self.entry_point =  self.pe.rva2virt(self.pe.Opthdr.AddressOfEntryPoint)

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument('-o', "--loadhdr", action="store_true",
                            help="Load pe hdr")
        parser.add_argument('-e', "--loadmainpe", action="store_true",
                            help="Load main pe")
        parser.add_argument('-y', "--use-seh", action="store_true",
                            help="Use windows SEH")
        parser.add_argument('-l', "--loadbasedll", action="store_true",
                            help="Load base dll (path './win_dll')")
        parser.add_argument('-r', "--parse-resources",
                            action="store_true", help="Load resources")


class OS_Linux(OS):

    def __init__(self, custom_methods, *args, **kwargs):
        super(OS_Linux, self).__init__(custom_methods, *args, **kwargs)

        # Import manager
        libs = libimp()
        self.libs = libs

        elf = vm_load_elf(self.jitter.vm, self.fname)
        self.elf = elf
        preload_elf(self.jitter.vm, elf, libs)

        # Library calls handler
        self.jitter.add_lib_handler(libs, custom_methods)

class OS_Linux_str(OS):
    def __init__(self, custom_methods, *args, **kwargs):
        super(OS_Linux_str, self).__init__(custom_methods, *args, **kwargs)

        # Import manager
        libs = libimp()
        self.libs = libs

        data = open(self.fname).read()
        self.options.load_base_addr = int(self.options.load_base_addr, 16)
        self.jitter.vm.add_memory_page(self.options.load_base_addr, PAGE_READ | PAGE_WRITE, data)

        # Library calls handler
        self.jitter.add_lib_handler(libs, custom_methods)

    @classmethod
    def update_parser(cls, parser):
        parser.add_argument("load_base_addr", help="load base address")



class Arch_x86_32(Arch):
    _ARCH_ = "x86_32"
    STACK_SIZE = 0x100000

    def __init__(self):
        super(Arch_x86_32, self).__init__()

        if self.options.usesegm:
            self.jitter.ir_arch.do_stk_segm=  True
            self.jitter.ir_arch.do_ds_segm=  True
            self.jitter.ir_arch.do_str_segm = True
            self.jitter.ir_arch.do_all_segm = True

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.init_stack()


    @classmethod
    def update_parser(cls, parser):
        parser.add_argument('-s', "--usesegm", action="store_true",
                          help="Use segments fs:")


class Arch_arml(Arch):
    _ARCH_ = "arml"
    STACK_SIZE = 0x100000

    def __init__(self):
        super(Arch_arml, self).__init__()

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.init_stack()

class Arch_armb(Arch):
    _ARCH_ = "armb"
    STACK_SIZE = 0x100000

    def __init__(self):
        super(Arch_armb, self).__init__()

        # Init stack
        self.jitter.stack_size = self.STACK_SIZE
        self.jitter.init_stack()



class Sandbox_Win_x86_32(Sandbox, Arch_x86_32, OS_Win):

    def __init__(self, *args, **kwargs):
        Sandbox.__init__(self, *args, **kwargs)

        # Pre-stack some arguments
        self.jitter.push_uint32_t(2)
        self.jitter.push_uint32_t(1)
        self.jitter.push_uint32_t(0)
        self.jitter.push_uint32_t(0x1337beef)

        # Set the runtime guard
        self.jitter.add_breakpoint(0x1337beef, self.__class__.code_sentinelle)


    def run(self, addr = None):
        """
        If addr is not set, use entrypoint
        """
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Win_x86_32, self).run(addr)


class Sandbox_Linux_x86_32(Sandbox, Arch_x86_32, OS_Linux):

    def __init__(self, *args, **kwargs):
        Sandbox.__init__(self, *args, **kwargs)

        # Pre-stack some arguments
        self.jitter.push_uint32_t(2)
        self.jitter.push_uint32_t(1)
        self.jitter.push_uint32_t(0)
        self.jitter.push_uint32_t(0x1337beef)

        # Set the runtime guard
        self.jitter.add_breakpoint(0x1337beef, self.__class__.code_sentinelle)


    def run(self, addr = None):
        """
        If addr is not set, use entrypoint
        """
        if addr is None:
            addr = self.entry_point
        super(Sandbox_Linux_x86_32, self).run(addr)



class Sandbox_Linux_arml(Sandbox, Arch_arml, OS_Linux):

    def __init__(self, *args, **kwargs):
        Sandbox.__init__(self, *args, **kwargs)

        self.jitter.cpu.LR = 0x1337beef

        # Set the runtime guard
        self.jitter.add_breakpoint(0x1337beef, self.__class__.code_sentinelle)


    def run(self, addr = None):
        if addr is None and self.options.address is not None:
            addr = int(self.options.address, 16)
        super(Sandbox_Linux_arml, self).run(addr)

class Sandbox_Linux_armb_str(Sandbox, Arch_armb, OS_Linux_str):

    def __init__(self, *args, **kwargs):
        Sandbox.__init__(self, *args, **kwargs)

        self.jitter.cpu.LR = 0x1337beef

        # Set the runtime guard
        self.jitter.add_breakpoint(0x1337beef, self.__class__.code_sentinelle)


    def run(self, addr = None):
        if addr is None and self.options.address is not None:
            addr = int(self.options.address, 16)
        super(Sandbox_Linux_armb_str, self).run(addr)


class Sandbox_Linux_arml_str(Sandbox, Arch_arml, OS_Linux_str):

    def __init__(self, *args, **kwargs):
        Sandbox.__init__(self, *args, **kwargs)

        self.jitter.cpu.LR = 0x1337beef

        # Set the runtime guard
        self.jitter.add_breakpoint(0x1337beef, self.__class__.code_sentinelle)


    def run(self, addr = None):
        if addr is None and self.options.address is not None:
            addr = int(self.options.address, 16)
        super(Sandbox_Linux_arml_str, self).run(addr)
