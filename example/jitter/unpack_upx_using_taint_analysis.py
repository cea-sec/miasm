from __future__ import print_function
import os
import logging
from pdb import pm
from miasm.loader import pe
from miasm.analysis.sandbox import Sandbox_Win_x86_32

from miasm.os_dep.common import get_win_str_a

from miasm.analysis.taint_helpers import enable_taint_analysis, display_all_taint
from miasm.jitter.csts import EXCEPT_TAINT_MEM


# User defined methods

def kernel32_GetProcAddress(jitter):
    """Hook on GetProcAddress to note where UPX stores import pointers"""
    ret_ad, args = jitter.func_args_stdcall(["libbase", "fname"])
    # Handle ordinal imports
    fname = (args.fname if args.fname < 0x10000
             else get_win_str_a(jitter, args.fname))
    logging.error(fname)

    # Get the generated address of the library
    ad = sb.libs.lib_get_add_func(args.libbase, fname)
    # Add a breakpoint in case of a call on the resolved function
    # NOTE: never happens in UPX, just for skeleton
    jitter.handle_function(ad)

    # Using taint analysis to find where the return value is saved
    start_analysis(jitter, sb.libs, args.libbase, fname)

    jitter.func_ret_stdcall(ret_ad, ad)


def lib_add_dst_ad(mylibimp, libad, imp_ord_or_name, dst_ad):
    """Add the destination address of the address of the function in the libimp structure"""

    if not imp_ord_or_name in mylibimp.lib_imp2dstad[libad]:
        mylibimp.lib_imp2dstad[libad][imp_ord_or_name] = set()
    mylibimp.lib_imp2dstad[libad][imp_ord_or_name].add(dst_ad)


jitter_global = None
libs_global = None
libbase_global = None
fname_global = None
def start_analysis(jitter, libs, libbase, fname):
    global jitter_global
    global libs_global
    global libbase_global
    global fname_global
    jitter_global = jitter
    libs_global = libs
    libbase_global = libbase
    fname_global = fname

    print("[+] Start Taint Analysis")

    # Add taint origin
    color_index = 0
    jitter.taint.taint_register(color_index, jitter.jit.codegen.regs_index["RAX"])

    jitter.jit.log_mn = True

    return True


def on_taint_memory(jitter):
    display_all_taint(jitter)
    last_mem = jitter.taint.last_tainted_memory(0)
    addr, size = last_mem[0]
    print("\t[>] FOUND : %x->%s" % (addr, fname_global))
    lib_add_dst_ad(libs_global, libbase_global, fname_global, addr) # Add the import (use during PE rebuild)
    jitter.taint.untaint_all()
    jitter.vm.set_exception(jitter.vm.get_exception() & (~EXCEPT_TAINT_MEM))
    jitter.jit.log_mn = False
    return True


parser = Sandbox_Win_x86_32.parser(description="Generic UPX unpacker")
parser.add_argument("filename", help="PE Filename")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")
parser.add_argument("--graph",
                    help="Export the CFG graph in graph.dot",
                    action="store_true")
options = parser.parse_args()
options.load_hdr = True
options.taint = True
sb = Sandbox_Win_x86_32(options.filename, options, globals(),
                        parse_reloc=False)


if options.verbose is True:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)

if options.verbose is True:
    print(sb.jitter.vm)

# Ensure there is one and only one leave (for OEP discovering)
mdis = sb.machine.dis_engine(sb.jitter.bs)
mdis.dont_dis_nulstart_bloc = True
asmcfg = mdis.dis_multiblock(sb.entry_point)

leaves = list(asmcfg.get_bad_blocks())
assert(len(leaves) == 1)
l = leaves.pop()
logging.info(l)
end_offset = mdis.loc_db.get_location_offset(l.loc_key)

logging.info('final offset')
logging.info(hex(end_offset))

# Export CFG graph (dot format)
if options.graph is True:
    open("graph.dot", "w").write(asmcfg.dot())


if options.verbose is True:
    print(sb.jitter.vm)


def update_binary(jitter):
    sb.pe.Opthdr.AddressOfEntryPoint = sb.pe.virt2rva(jitter.pc)
    logging.info('updating binary')
    for s in sb.pe.SHList:
        sdata = sb.jitter.vm.get_mem(sb.pe.rva2virt(s.addr), s.rawsize)
        sb.pe.rva.set(s.addr, sdata)

    # Stop execution
    jitter.run = False
    return False

# Set callbacks
sb.jitter.add_breakpoint(end_offset, update_binary)

#####################TAINT##########################
enable_taint_analysis(sb.jitter)
color_index = 0

sb.jitter.add_exception_handler(EXCEPT_TAINT_MEM, on_taint_memory)
sb.jitter.taint.enable_taint_mem_cb(color_index)
####################################################

# Run
sb.run()

# Rebuild PE
# Alternative solution: miasm.jitter.loader.pe.vm2pe(sb.jitter, out_fname,
# libs=sb.libs, e_orig=sb.pe)
new_dll = []

sb.pe.SHList.align_sections(0x1000, 0x1000)
logging.info(repr(sb.pe.SHList))

sb.pe.DirRes = pe.DirRes(sb.pe)
sb.pe.DirImport.impdesc = None
logging.info(repr(sb.pe.DirImport.impdesc))
new_dll = sb.libs.gen_new_lib(sb.pe)
logging.info(new_dll)
sb.pe.DirImport.impdesc = []
sb.pe.DirImport.add_dlldesc(new_dll)
s_myimp = sb.pe.SHList.add_section(name="myimp", rawsize=len(sb.pe.DirImport))
logging.info(repr(sb.pe.SHList))
sb.pe.DirImport.set_rva(s_myimp.addr)

# XXXX TODO
sb.pe.NThdr.optentries[pe.DIRECTORY_ENTRY_DELAY_IMPORT].rva = 0

bname, fname = os.path.split(options.filename)
fname = os.path.join(bname, fname.replace('.', '_'))
open(fname + '_unupx.bin', 'wb').write(bytes(sb.pe))
