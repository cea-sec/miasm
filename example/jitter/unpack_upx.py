from __future__ import print_function
import os
import logging
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.jitter.loader.pe import vm2pe
from miasm.core.locationdb import LocationDB

from miasm.os_dep.common import get_win_str_a

# User defined methods

def kernel32_GetProcAddress(jitter):
    """Hook on GetProcAddress to note where UPX stores import pointers"""
    ret_ad, args = jitter.func_args_stdcall(["libbase", "fname"])

    # When the function is called, EBX is a pointer to the destination buffer
    dst_ad = jitter.cpu.EBX
    logging.error('EBX ' + hex(dst_ad))

    # Handle ordinal imports
    fname = (args.fname if args.fname < 0x10000
             else get_win_str_a(jitter, args.fname))
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

loc_db = LocationDB()
sb = Sandbox_Win_x86_32(
    loc_db, options.filename, options, globals(),
    parse_reloc=False
)


if options.verbose is True:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)

if options.verbose is True:
    print(sb.jitter.vm)

# Ensure there is one and only one leave (for OEP discovering)
mdis = sb.machine.dis_engine(sb.jitter.bs, loc_db=loc_db)
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


def stop(jitter):
    logging.info('OEP reached')

    # Stop execution
    jitter.running = False
    return False

# Set callbacks
sb.jitter.add_breakpoint(end_offset, stop)

# Run
sb.run()

# Construct the output filename
bname, fname = os.path.split(options.filename)
fname = os.path.join(bname, fname.replace('.', '_'))
out_fname = fname + '_unupx.bin'

# Rebuild the PE thanks to `vm2pe`
#
# vm2pe will:
# - set the new entry point to the current address (ie, the OEP)
# - dump each section from the virtual memory into the new PE
# - use `sb.libs` to generate a new import directory, and use it in the new PE
# - save the resulting PE in `out_fname`

vm2pe(sb.jitter, out_fname, libs=sb.libs, e_orig=sb.pe)
