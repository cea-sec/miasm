from __future__ import print_function
from builtins import map
from builtins import range
import cmd
from future.utils import viewitems

from miasm.core.utils import hexdump
from miasm.core.interval import interval
import miasm.jitter.csts as csts
from miasm.jitter.jitload import ExceptionHandle


class DebugBreakpoint(object):

    "Debug Breakpoint parent class"
    pass


class DebugBreakpointSoft(DebugBreakpoint):

    "Stand for software breakpoint"

    def __init__(self, addr):
        self.addr = addr

    def __str__(self):
        return "Soft BP @0x%08x" % self.addr


class DebugBreakpointTerminate(DebugBreakpoint):
    "Stand for an execution termination"

    def __init__(self, status):
        self.status = status

    def __str__(self):
        return "Terminate with %s" % self.status


class DebugBreakpointMemory(DebugBreakpoint):

    "Stand for memory breakpoint"

    type2str = {csts.BREAKPOINT_READ: "R",
                csts.BREAKPOINT_WRITE: "W"}

    def __init__(self, addr, size, access_type):
        self.addr = addr
        self.access_type = access_type
        self.size = size

    def __str__(self):
        bp_type = ""
        for k, v in viewitems(self.type2str):
            if k & self.access_type != 0:
                bp_type += v
        return "Memory BP @0x%08x, Size 0x%08x, Type %s" % (
            self.addr,
            self.size,
            bp_type
        )

    @classmethod
    def get_access_type(cls, read=False, write=False):
        value = 0
        for k, v in viewitems(cls.type2str):
            if v == "R" and read is True:
                value += k
            if v == "W" and write is True:
                value += k
        return value


class Debugguer(object):

    "Debugguer linked with a Jitter instance"

    def __init__(self, myjit):
        "myjit : jitter instance"
        self.myjit = myjit
        self.bp_list = []     # DebugBreakpointSoft list
        self.mem_bp_list = []  # DebugBreakpointMemory list
        self.mem_watched = []  # Memory areas watched
        self.init_memory_breakpoint()

    def init_run(self, addr):
        self.myjit.init_run(addr)

    def add_breakpoint(self, addr):
        "Add bp @addr"
        bp = DebugBreakpointSoft(addr)
        func = lambda x: bp
        bp.func = func
        self.bp_list.append(bp)
        self.myjit.add_breakpoint(addr, func)

    def init_memory_breakpoint(self):
        "Set exception handler on EXCEPT_BREAKPOINT_MEMORY"
        def exception_memory_breakpoint(jitter):
            "Stop the execution and return an identifier"
            return ExceptionHandle.memoryBreakpoint()

        self.myjit.add_exception_handler(csts.EXCEPT_BREAKPOINT_MEMORY,
                                         exception_memory_breakpoint)


    def add_memory_breakpoint(self, addr, size, read=False, write=False):
        "add mem bp @[addr, addr + size], on read/write/both"
        access_type = DebugBreakpointMemory.get_access_type(read=read,
                                                            write=write)
        dbm = DebugBreakpointMemory(addr, size, access_type)
        self.mem_bp_list.append(dbm)
        self.myjit.vm.add_memory_breakpoint(addr, size, access_type)

    def remove_breakpoint(self, dbs):
        "remove the DebugBreakpointSoft instance"
        self.bp_list.remove(dbs)
        self.myjit.remove_breakpoints_by_callback(dbs.func)

    def remove_breakpoint_by_addr(self, addr):
        "remove breakpoints @ addr"
        for bp in self.get_breakpoint_by_addr(addr):
            self.remove_breakpoint(bp)

    def remove_memory_breakpoint(self, dbm):
        "remove the DebugBreakpointMemory instance"
        self.mem_bp_list.remove(dbm)
        self.myjit.vm.remove_memory_breakpoint(dbm.addr, dbm.access_type)

    def remove_memory_breakpoint_by_addr_access(self, addr, read=False,
                                                write=False):
        "remove breakpoints @ addr"
        access_type = DebugBreakpointMemory.get_access_type(read=read,
                                                            write=write)
        for bp in self.mem_bp_list:
            if bp.addr == addr and bp.access_type == access_type:
                self.remove_memory_breakpoint(bp)

    def get_breakpoint_by_addr(self, addr):
        ret = []
        for dbgsoft in self.bp_list:
            if dbgsoft.addr == addr:
                ret.append(dbgsoft)
        return ret

    def get_breakpoints(self):
        return self.bp_list

    def active_trace(self, mn=None, regs=None, newbloc=None):
        if mn is not None:
            self.myjit.jit.log_mn = mn
        if regs is not None:
            self.myjit.jit.log_regs = regs
        if newbloc is not None:
            self.myjit.jit.log_newbloc = newbloc

    def handle_exception(self, res):
        if not res:
            # A breakpoint has stopped the execution
            return DebugBreakpointTerminate(res)

        if isinstance(res, DebugBreakpointSoft):
            print("Breakpoint reached @0x%08x" % res.addr)
        elif isinstance(res, ExceptionHandle):
            if res == ExceptionHandle.memoryBreakpoint():
                print("Memory breakpoint reached @0x%08x" % self.myjit.pc)

                memory_read = self.myjit.vm.get_memory_read()
                if len(memory_read) > 0:
                    print("Read:")
                    for start_address, end_address in memory_read:
                        print("- from 0x%08x to 0x%08x" % (start_address, end_address))
                memory_write = self.myjit.vm.get_memory_write()
                if len(memory_write) > 0:
                    print("Write:")
                    for start_address, end_address in memory_write:
                        print("- from 0x%08x to 0x%08x" % (start_address, end_address))

                # Remove flag
                except_flag = self.myjit.vm.get_exception()
                self.myjit.vm.set_exception(except_flag ^ res.except_flag)
                # Clean memory access data
                self.myjit.vm.reset_memory_access()
            else:
                raise NotImplementedError("Unknown Except")
        else:
            raise NotImplementedError("type res")

        # Repropagate res
        return res

    def step(self):
        "Step in jit"

        self.myjit.jit.set_options(jit_maxline=1)
        # Reset all jitted blocks
        self.myjit.jit.clear_jitted_blocks()

        res = self.myjit.continue_run(step=True)
        self.handle_exception(res)

        self.myjit.jit.set_options(jit_maxline=50)
        self.on_step()

        return res

    def run(self):
        status = self.myjit.continue_run()
        return self.handle_exception(status)

    def get_mem(self, addr, size=0xF):
        "hexdump @addr, size"

        hexdump(self.myjit.vm.get_mem(addr, size))

    def get_mem_raw(self, addr, size=0xF):
        "hexdump @addr, size"
        return self.myjit.vm.get_mem(addr, size)

    def watch_mem(self, addr, size=0xF):
        self.mem_watched.append((addr, size))

    def on_step(self):
        for addr, size in self.mem_watched:
            print("@0x%08x:" % addr)
            self.get_mem(addr, size)

    def get_reg_value(self, reg_name):
        return getattr(self.myjit.cpu, reg_name)

    def set_reg_value(self, reg_name, value):

        # Handle PC case
        if reg_name == self.myjit.lifter.pc.name:
            self.init_run(value)

        setattr(self.myjit.cpu, reg_name, value)

    def get_gpreg_all(self):
        "Return general purposes registers"
        return self.myjit.cpu.get_gpreg()


class DebugCmd(cmd.Cmd, object):

    "CommandLineInterpreter for Debugguer instance"

    color_g = '\033[92m'
    color_e = '\033[0m'
    color_b = '\033[94m'
    color_r = '\033[91m'

    intro = color_g + "=== Miasm2 Debugging shell ===\nIf you need help, "
    intro += "type 'help' or '?'" + color_e
    prompt = color_b + "$> " + color_e

    def __init__(self, dbg):
        "dbg : Debugguer"
        self.dbg = dbg
        super(DebugCmd, self).__init__()

    # Debug methods

    def print_breakpoints(self):
        bp_list = self.dbg.bp_list
        if len(bp_list) == 0:
            print("No breakpoints.")
        else:
            for i, b in enumerate(bp_list):
                print("%d\t0x%08x" % (i, b.addr))

    def print_memory_breakpoints(self):
        bp_list = self.dbg.mem_bp_list
        if len(bp_list) == 0:
            print("No memory breakpoints.")
        else:
            for _, bp in enumerate(bp_list):
                print(str(bp))

    def print_watchmems(self):
        watch_list = self.dbg.mem_watched
        if len(watch_list) == 0:
            print("No memory watchpoints.")
        else:
            print("Num\tAddress  \tSize")
            for i, w in enumerate(watch_list):
                addr, size = w
                print("%d\t0x%08x\t0x%08x" % (i, addr, size))

    def print_registers(self):
        regs = self.dbg.get_gpreg_all()

        # Display settings
        title1 = "Registers"
        title2 = "Values"
        max_name_len = max(map(len, list(regs) + [title1]))

        # Print value table
        s = "%s%s    |    %s" % (
            title1, " " * (max_name_len - len(title1)), title2)
        print(s)
        print("-" * len(s))
        for name, value in sorted(viewitems(regs), key=lambda x: x[0]):
            print(
                "%s%s    |    %s" % (
                    name,
                    " " * (max_name_len - len(name)),
                    hex(value).replace("L", "")
                )
            )

    def add_breakpoints(self, bp_addr):
        for addr in bp_addr:
            addr = int(addr, 0)

            good = True
            for i, dbg_obj in enumerate(self.dbg.bp_list):
                if dbg_obj.addr == addr:
                    good = False
                    break
            if good is False:
                print("Breakpoint 0x%08x already set (%d)" % (addr, i))
            else:
                l = len(self.dbg.bp_list)
                self.dbg.add_breakpoint(addr)
                print("Breakpoint 0x%08x successfully added ! (%d)" % (addr, l))

    display_mode = {
        "mn": None,
        "regs": None,
        "newbloc": None
    }

    def update_display_mode(self):
        self.display_mode = {
            "mn": self.dbg.myjit.jit.log_mn,
            "regs": self.dbg.myjit.jit.log_regs,
            "newbloc": self.dbg.myjit.jit.log_newbloc
        }

    # Command line methods
    def print_warning(self, s):
        print(self.color_r + s + self.color_e)

    def onecmd(self, line):
        cmd_translate = {
            "h": "help",
            "q": "exit",
            "e": "exit",
            "!": "exec",
            "r": "run",
            "i": "info",
            "b": "breakpoint",
            "m": "memory_breakpoint",
            "s": "step",
            "d": "dump"
        }

        if len(line) >= 2 and \
           line[1] == " " and \
           line[:1] in cmd_translate:
            line = cmd_translate[line[:1]] + line[1:]

        if len(line) == 1 and line in cmd_translate:
            line = cmd_translate[line]

        r = super(DebugCmd, self).onecmd(line)
        return r

    def can_exit(self):
        return True

    def do_display(self, arg):
        if arg == "":
            self.help_display()
            return

        args = arg.split(" ")
        if args[-1].lower() not in ["on", "off"]:
            self.print_warning("/!\ %s not in 'on' / 'off'" % args[-1])
            return
        mode = args[-1].lower() == "on"
        d = {}
        for a in args[:-1]:
            d[a] = mode
        self.dbg.active_trace(**d)
        self.update_display_mode()

    def help_display(self):
        print("Enable/Disable tracing.")
        print("Usage: display <mode1> <mode2> ... on|off")
        print("Available modes are:")
        for k in self.display_mode:
            print("\t%s" % k)
        print("Use 'info display' to get current values")

    def do_watchmem(self, arg):
        if arg == "":
            self.help_watchmem()
            return

        args = arg.split(" ")
        if len(args) >= 2:
            size = int(args[1], 0)
        else:
            size = 0xF

        addr = int(args[0], 0)

        self.dbg.watch_mem(addr, size)

    def help_watchmem(self):
        print("Add a memory watcher.")
        print("Usage: watchmem <addr> [size]")
        print("Use 'info watchmem' to get current memory watchers")

    def do_info(self, arg):
        av_info = [
            "registers",
            "display",
            "breakpoints",
            "memory_breakpoint",
            "watchmem"
        ]

        if arg == "":
            print("'info' must be followed by the name of an info command.")
            print("List of info subcommands:")
            for k in av_info:
                print("\t%s" % k)

        if arg.startswith("b"):
            # Breakpoint
            self.print_breakpoints()

        if arg.startswith("m"):
            # Memory breakpoints
            self.print_memory_breakpoints()

        if arg.startswith("d"):
            # Display
            self.update_display_mode()
            for k, v in viewitems(self.display_mode):
                print("%s\t\t%s" % (k, v))

        if arg.startswith("w"):
            # Watchmem
            self.print_watchmems()

        if arg.startswith("r"):
            # Registers
            self.print_registers()

    def help_info(self):
        print("Generic command for showing things about the program being")
        print("debugged. Use 'info' without arguments to get the list of")
        print("available subcommands.")

    def do_breakpoint(self, arg):
        if arg == "":
            self.help_breakpoint()
        else:
            addrs = arg.split(" ")
            self.add_breakpoints(addrs)

    def help_breakpoint(self):
        print("Add breakpoints to argument addresses.")
        print("Example:")
        print("\tbreakpoint 0x11223344")
        print("\tbreakpoint 1122 0xabcd")

    def do_memory_breakpoint(self, arg):
        if arg == "":
            self.help_memory_breakpoint()
            return
        args = arg.split(" ")
        if len(args) > 3 or len(args) <= 1:
            self.help_memory_breakpoint()
            return
        address = int(args[0], 0)
        size = int(args[1], 0)
        if len(args) == 2:
            self.dbg.add_memory_breakpoint(address, size, read=True, write=True)
        else:
            self.dbg.add_memory_breakpoint(address,
                                           size,
                                           read=('r' in args[2]),
                                           write=('w' in args[2]))

    def help_memory_breakpoint(self):
        print("Add memory breakpoints to memory space defined by a starting")
        print("address and a size on specified access type (default is 'rw').")
        print("Example:")
        print("\tmemory_breakpoint 0x11223344 0x100 r")
        print("\tmemory_breakpoint 1122 10")

    def do_step(self, arg):
        if arg == "":
            nb = 1
        else:
            nb = int(arg)
        for _ in range(nb):
            self.dbg.step()

    def help_step(self):
        print("Step program until it reaches a different source line.")
        print("Argument N means do this N times (or till program stops")
        print("for another reason).")

    def do_dump(self, arg):
        if arg == "":
            self.help_dump()
        else:
            args = arg.split(" ")
            if len(args) >= 2:
                size = int(args[1], 0)
            else:
                size = 0xF
            addr = int(args[0], 0)

            self.dbg.get_mem(addr, size)

    def help_dump(self):
        print("Dump <addr> [size]. Dump size bytes at addr.")

    def do_run(self, _):
        self.dbg.run()

    def help_run(self):
        print("Launch or continue the current program")

    def do_exit(self, _):
        return True

    def do_exec(self, line):
        try:
            print(eval(line))
        except Exception as error:
            print("*** Error: %s" % error)

    def help_exec(self):
        print("Exec a python command.")
        print("You can also use '!' shortcut.")

    def help_exit(self):
        print("Exit the interpreter.")
        print("You can also use the Ctrl-D shortcut.")

    def help_help(self):
        print("Print help")

    def postloop(self):
        print('\nGoodbye !')
        super(DebugCmd, self).postloop()

    do_EOF = do_exit
    help_EOF = help_exit
