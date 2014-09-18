import sys
import os
import inspect
import logging
import struct
from argparse import ArgumentParser

from elfesteem import pe
from elfesteem import *
from elfesteem.strpatchwork import StrPatchwork

from miasm2.core import asmbloc
from miasm2.jitter.jitload import vm_load_pe, preload_pe, libimp
from miasm2.jitter.jitload import bin_stream_vm
from miasm2.jitter.csts import *
from miasm2.jitter.os_dep import win_api_x86_32

from miasm2.analysis.machine import Machine
# Debug settings #
from pdb import pm

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

#

# Handle arguments
parser = ArgumentParser(description="Sandbox a PE binary packed with UPX")
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
parser.add_argument("-g", "--graph",
                    help="Export the CFG graph in graph.txt",
                    action="store_true")
parser.add_argument("-v", "--verbose",
                    help="Verbose mode",
                    action="store_true")
args = parser.parse_args()

# Verbose mode
if args.verbose is True:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)

# Init arch
machine = Machine("x86_32")
myjit = machine.jitter(args.jitter)
myjit.init_stack()

# Log level (if available with jitter engine)
myjit.jit.log_regs = args.log_regs
myjit.jit.log_mn = args.log_mn
myjit.jit.log_newbloc = args.log_newbloc

# Load pe and get entry point address
e = vm_load_pe(myjit.vm, args.filename)
libs = libimp()
preload_pe(myjit.vm, e, libs)

if args.verbose is True:
    myjit.vm.vm_dump_memory_page_pool()
ep = e.rva2virt(e.Opthdr.AddressOfEntryPoint)

# Ensure there is one and only one leave (for OEP discovering)
mdis = machine.dis_engine(myjit.bs)
mdis.dont_dis_nulstart_bloc = True
ab = mdis.dis_multibloc(ep)

bb = asmbloc.basicblocs(ab)
leaves = bb.get_bad_dst()
assert(len(leaves) == 1)
l = leaves.pop()
logging.info(l)
end_label = l.label.offset

logging.info('final label')
logging.info(end_label)

# Export CFG graph (dot format)
if args.graph is True:
    g = asmbloc.bloc2graph(ab)
    open("graph.txt", "w").write(g)

# User defined methods


def kernel32_GetProcAddress(myjit):
    global libs
    ret_ad, args = myjit.func_args_stdcall(2)
    libbase, fname = args

    dst_ad = myjit.cpu.EBX
    logging.info('EBX ' + hex(dst_ad))

    if fname < 0x10000:
        fname = fname
    else:
        fname = myjit.get_str_ansi(fname)
    logging.info(fname)

    ad = libs.lib_get_add_func(libbase, fname, dst_ad)
    myjit.func_ret_stdcall(ret_ad, ad)

# Set libs for win_32 api
win_api_x86_32.winobjs.runtime_dll = libs
if args.verbose is True:
    myjit.vm.vm_dump_memory_page_pool()

# Set up stack
myjit.vm_push_uint32_t(1)  # reason code if dll
myjit.vm_push_uint32_t(1)  # reason code if dll
myjit.vm_push_uint32_t(0x1337beef)

# Breakpoint callbacks


def update_binary(myjit):
    e.Opthdr.AddressOfEntryPoint = e.virt2rva(myjit.pc)
    logging.info('updating binary')
    for s in e.SHList:
        sdata = myjit.vm.vm_get_mem(e.rva2virt(s.addr), s.rawsize)
        e.virt[e.rva2virt(s.addr)] = sdata


# Set callbacks
myjit.add_breakpoint(end_label, update_binary)
myjit.add_lib_handler(libs, globals())

# Run until breakpoint is reached
myjit.init_run(ep)
myjit.continue_run()


regs = myjit.cpu.vm_get_gpreg()


new_dll = []


# XXXXX

e.SHList.align_sections(0x1000, 0x1000)
logging.info(repr(e.SHList))
st = StrPatchwork()
st[0] = e.content

# get back data from emulator
for s in e.SHList:
    ad1 = e.rva2virt(s.addr)
    ad2 = ad1 + len(s.data)
    st[s.offset] = e.virt(ad1, ad2)
# e.content = str(st)

e.DirRes = pe.DirRes(e)
e.DirImport.impdesc = None
logging.info(repr(e.DirImport.impdesc))
new_dll = libs.gen_new_lib(e)
logging.info(new_dll)
e.DirImport.impdesc = []
e.DirImport.add_dlldesc(new_dll)
s_myimp = e.SHList.add_section(name="myimp", rawsize=len(e.DirImport))
logging.info(repr(e.SHList))
e.DirImport.set_rva(s_myimp.addr)

# XXXX TODO
e.NThdr.optentries[pe.DIRECTORY_ENTRY_DELAY_IMPORT].rva = 0

e.Opthdr.AddressOfEntryPoint = e.virt2rva(end_label)
bname, fname = os.path.split(args.filename)
fname = os.path.join(bname, fname.replace('.', '_'))
open(fname + '_unupx.bin', 'w').write(str(e))
