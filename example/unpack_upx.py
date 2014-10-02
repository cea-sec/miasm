from pdb import pm
import os
from miasm2.analysis.sandbox import Sandbox_Win_x86_32
import logging
from miasm2.core import asmbloc
from elfesteem.strpatchwork import StrPatchwork
from elfesteem import pe

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


# User defined methods

def kernel32_GetProcAddress(jitter):
    ret_ad, args = jitter.func_args_stdcall(2)
    libbase, fname = args

    dst_ad = jitter.cpu.EBX
    logging.info('EBX ' + hex(dst_ad))

    if fname < 0x10000:
        fname = fname
    else:
        fname = jitter.get_str_ansi(fname)
    logging.info(fname)

    ad = sb.libs.lib_get_add_func(libbase, fname, dst_ad)
    jitter.func_ret_stdcall(ret_ad, ad)



parser = Sandbox_Win_x86_32.parser(description="Generic UPX unpacker")
parser.add_argument("filename", help="PE Filename")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")
parser.add_argument("--graph",
                    help="Export the CFG graph in graph.txt",
                    action="store_true")
options = parser.parse_args()
sb = Sandbox_Win_x86_32(options.filename, options, globals())


if options.verbose is True:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)

if options.verbose is True:
    sb.jitter.vm.vm_dump_memory_page_pool()


ep = sb.entry_point

# Ensure there is one and only one leave (for OEP discovering)
mdis = sb.machine.dis_engine(sb.jitter.bs)
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
if options.graph is True:
    g = asmbloc.bloc2graph(ab)
    open("graph.txt", "w").write(g)


if options.verbose is True:
    sb.jitter.vm.vm_dump_memory_page_pool()


def update_binary(jitter):
    sb.pe.Opthdr.AddressOfEntryPoint = sb.pe.virt2rva(jitter.pc)
    logging.info('updating binary')
    for s in sb.pe.SHList:
        sdata = sb.jitter.vm.vm_get_mem(sb.pe.rva2virt(s.addr), s.rawsize)
        sb.pe.virt[sb.pe.rva2virt(s.addr)] = sdata


# Set callbacks
sb.jitter.add_breakpoint(end_label, update_binary)


sb.run()

regs = sb.jitter.cpu.vm_get_gpreg()
new_dll = []
# XXXXX

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

sb.pe.Opthdr.AddressOfEntryPoint = sb.pe.virt2rva(end_label)
bname, fname = os.path.split(options.filename)
fname = os.path.join(bname, fname.replace('.', '_'))
open(fname + '_unupx.bin', 'w').write(str(sb.pe))
