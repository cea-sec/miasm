import sys
import os
from argparse import ArgumentParser
from miasm2.jitter.jitload import vm_load_pe, preload_pe, libimp
from miasm2.jitter.jitload import bin_stream_vm
from miasm2.jitter.csts import *
from miasm2.jitter.os_dep import win_api_x86_32
from miasm2.analysis import debugging, gdbserver, machine

# Debug settings #
from pdb import pm

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

#

# Handle arguments

parser = ArgumentParser(
    description="Sandbox a PE binary with x86 32bits engine")
parser.add_argument("filename", help="PE binary")
parser.add_argument("-r", "--log-regs",
                    help="Log registers value for each instruction",
                    action="store_true")
parser.add_argument("-m", "--log-mn",
                    help="Log desassembly conversion for each instruction",
                    action="store_true")
parser.add_argument("-n", "--log-newbloc",
                    help="Log basic blocks processed by the Jitter",
                    action="store_true")
parser.add_argument("-j", "--jitter",
                    help="Jitter engine. Possible values are : tcc (default), llvm",
                    default="tcc")
parser.add_argument("-d", "--debugging",
                    help="Attach a CLI debugguer to the sandboxed programm",
                    action="store_true")
parser.add_argument("-g", "--gdbserver",
                    help="Listen on [port] with a GDB server",
                    type=int,
                    default=False)
args = parser.parse_args()

# User defined methods


def msvcrt_memset(myjit):
    ret_ad, args = myjit.func_args_cdecl(3)
    dst, c, size = args

    myjit.vm.vm_set_mem(dst, chr(c & 0xFF) * size)
    myjit.func_ret_cdecl(ret_ad, 0)


def msvcrt_memcpy(myjit):
    ret_ad, args = myjit.func_args_cdecl(3)
    dst, src, size = args

    x = myjit.vm.vm_get_mem(src, size)
    myjit.vm.vm_set_mem(dst, x)
    myjit.func_ret_cdecl(ret_ad, 0)

# Breakpoint callbacks


def code_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    print "End Emulation"
    return True

# x86 32 bits engine instanciation
myjit = machine.Machine("x86_32").jitter(jit_type=args.jitter)
myjit.init_stack()
libs = libimp()

# Set libs for win_32 api
win_api_x86_32.winobjs.runtime_dll = libs

# Load PE and get entry point address
e = vm_load_pe(myjit.vm, args.filename)
preload_pe(myjit.vm, e, libs)

addr = e.rva2virt(e.Opthdr.AddressOfEntryPoint)

# Log level (if available with jitter engine)
myjit.jit.log_regs = args.log_regs
myjit.jit.log_mn = args.log_mn
myjit.jit.log_newbloc = args.log_newbloc

# Set up stack
myjit.vm_push_uint32_t(0x1337beef)

# Set callbacks
myjit.add_breakpoint(0x1337beef, code_sentinelle)

myjit.add_lib_handler(libs, globals())

# Start Emulation
myjit.init_run(addr)

# Handle debugging
if any([args.debugging, args.gdbserver]):
    dbg = debugging.Debugguer(myjit)
    if args.debugging is True:
        cmd = debugging.DebugCmd(dbg)
        cmd.cmdloop()
    else:
        gdb = gdbserver.GdbServer_x86_32(dbg, args.gdbserver)
        print("Listenning on port %d" % args.gdbserver)
        gdb.run()

else:
    print(myjit.continue_run())

# Performance tests
#
# import cProfile
# cProfile.run(r'run_bin(myjit, addr)')

# Test if emulation ended properly
assert(myjit.run is False)
