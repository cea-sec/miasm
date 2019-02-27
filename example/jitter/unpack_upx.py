from __future__ import print_function
import os
import logging
from pdb import pm
from elfesteem import pe
from miasm.analysis.sandbox import Sandbox_Win_x86_32

# User defined methods

def kernel32_GetProcAddress(jitter):
    """Hook on GetProcAddress to note where UPX stores import pointers"""
    ret_ad, args = jitter.func_args_stdcall(["libbase", "fname"])

    # When the function is called, EBX is a pointer to the destination buffer
    dst_ad = jitter.cpu.EBX
    logging.error('EBX ' + hex(dst_ad))

    # Handle ordinal imports
    fname = (args.fname if args.fname < 0x10000
             else jitter.get_str_ansi(args.fname))
    logging.error(fname)

    # Get the generated address of the library, and store it in memory to
    # dst_ad
    ad = sb.libs.lib_get_add_func(args.libbase, fname, dst_ad)
    # Add a breakpoint in case of a call on the resolved function
    # NOTE: never happens in UPX, just for skeleton
    jitter.handle_function(ad)

    jitter.func_ret_stdcall(ret_ad, ad)


parser = Sandbox_Win_x86_32.parser(description="Generic UPX unpacker")
parser.add_argument("filename", help="PE Filename")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")
parser.add_argument("--graph",
                    help="Export the CFG graph in graph.dot",
                    action="store_true")
options = parser.parse_args()
options.load_hdr = True

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
