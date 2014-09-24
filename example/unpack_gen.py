import sys, os
from optparse import OptionParser
from miasm2.analysis.machine import Machine
from miasm2.jitter.jitload import vm_load_pe, preload_pe, libimp
from miasm2.jitter.jitload import bin_stream_vm
from miasm2.jitter.os_dep import win_api_x86_32, win_api_x86_32_seh
from miasm2.analysis import debugging

# Debug settings
import inspect
from pdb import pm

# Environment settings
filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

parser = OptionParser(usage = "usage: %prog [options] file")
parser.add_option('-a', "--address", dest="address", metavar="ADDRESS",
                  help="Force entry point address", default=None)
parser.add_option('-s', "--segm", dest="usesegm", action="store_true",
                  help="Use segments fs:", default=False)
parser.add_option('-o', "--hdr", dest="loadhdr", action="store_true",
                  help="Load pe hdr", default=False)
parser.add_option('-l', "--loadbasedll", dest="loadbasedll",
                  action="store_true", help="Load base dll (path './win_dll')",
                  default=False)
parser.add_option('-x', "--dumpall", dest="dumpall", action="store_true",
                  help="Load base dll", default=False)
parser.add_option('-e', "--loadmainpe", dest="loadmainpe", action="store_true",
                  help="Load main pe", default=False)
parser.add_option('-r', "--parseresources", dest="parse_resources",
                  action="store_true", help="Load resources", default=False)
parser.add_option('-b', "--dumpblocs", dest="dumpblocs", action="store_true",
                  help="Log disasm blocks", default=False)
parser.add_option('-y', "--useseh", dest="use_seh", action="store_true",
                  help="Use windows SEH", default=False)
parser.add_option('-z', "--singlestep", dest="singlestep", action="store_true",
                  help="Log single step", default=False)
parser.add_option('-d', "--debugging", dest="debugging", action="store_true",
                  help="Debug shell", default=False)
parser.add_option('-g', "--gdbserver", dest="gdbserver",
                  help="Listen on port @port", default=False)
parser.add_option("-j", "--jitter", dest="jitter",
                    help="Jitter engine. Possible values are : tcc (default),\
llvm, python",
                    default="tcc")

(options, args) = parser.parse_args(sys.argv[1:])
if not args:
    parser.print_help()
    sys.exit(0)

#### INSERT HERE CUSTOM DLL METHODS ###
#######################################

fname = args[0]
machine = Machine("x86_32")

myjit = machine.jitter(options.jitter)
if options.usesegm:
    myjit.ir_arch.do_stk_segm=  True
    myjit.ir_arch.do_ds_segm=  True
    myjit.ir_arch.do_str_segm = True
    myjit.ir_arch.do_all_segm = True

bs = bin_stream_vm(myjit.vm)
myjit.jit.bs = bs

# Init stack
myjit.stack_size = 0x100000
myjit.init_stack()

# Import manager
libs = libimp()

# Set libs for win_32 api
win_api_x86_32.winobjs.runtime_dll = libs

all_imp_dll = []
if options.loadbasedll:

    # Load library
    all_imp_dll = ["ntdll.dll", "kernel32.dll", "user32.dll",
                   "ole32.dll", "urlmon.dll",
                   "ws2_32.dll", 'advapi32.dll', "psapi.dll"
                   ]
    mod_list = all_imp_dll
    all_pe = []
    # Load libs in memory
    for n in mod_list:
        fname_dll = os.path.join('win_dll', n)
        e_lib = vm_load_pe(myjit.vm, fname_dll)

        libs.add_export_lib(e_lib, n)
        all_pe.append(e_lib)

    # Patch libs imports
    for ee in all_pe:
        preload_pe(myjit.vm, ee, libs)


# Load main pe
e = vm_load_pe(myjit.vm, fname)

# Fix mainpe imports
preload_pe(myjit.vm, e, libs)

# Library calls handler
myjit.add_lib_handler(libs, globals())

# Manage SEH
if options.use_seh:
    win_api_x86_32_seh.main_pe_name = fname
    win_api_x86_32_seh.main_pe = e
    win_api_x86_32_seh.loaded_modules = all_imp_dll
    win_api_x86_32_seh.init_seh(myjit)
    win_api_x86_32_seh.set_win_fs_0(myjit)

# Get entry point address
if options.address is not None:
    addr = int(options.address, 16)
else:
    addr =  e.rva2virt(e.Opthdr.AddressOfEntryPoint)

# Logging options
if options.singlestep:
    myjit.jit.log_mn = True
    myjit.jit.log_regs = True

if options.dumpblocs:
    myjit.jit.log_newbloc = True

# Pre-stack some arguments
myjit.vm_push_uint32_t(2)
myjit.vm_push_uint32_t(1)
myjit.vm_push_uint32_t(0)
myjit.vm_push_uint32_t(0x1337beef)

# Set the runtime guard
def code_sentinelle(myjit):
    print 'emulation stop'
    myjit.run = False
    return False

myjit.add_breakpoint(0x1337beef, code_sentinelle)

#### INSERT HERE CUSTOM BREAKPOINTS ###
#######################################

# Run
if any([options.debugging, options.gdbserver]):
    dbg = debugging.Debugguer(myjit)
    dbg.init_run(addr)

    if options.gdbserver is not False:
        port = int(options.gdbserver)
        print "Listen on port %d" % port
        gdb = machine.gdbserver(dbg, port)
        gdb.run()
    else:
        cmd = debugging.DebugCmd(dbg)
        cmd.cmdloop()

else:
    print "Start emulation", hex(addr)
    myjit.init_run(addr)
    print myjit.continue_run()
