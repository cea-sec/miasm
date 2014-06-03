import sys
from elfesteem import pe_init
from miasm2.arch.x86.disasm import dis_x86_32
from miasm2.core.asmbloc import bloc2graph
from miasm2.core.bin_stream import bin_stream_pe

if len(sys.argv) != 3:
    print 'Example:'
    print "%s box_upx.exe 0x410f90" % sys.argv[0]
    sys.exit(0)

fname = sys.argv[1]
ad = int(sys.argv[2], 16)
e = pe_init.PE(open(fname).read())
bs = bin_stream_pe(e.virt)

mdis = dis_x86_32(bs)
# inform the engine not to disasm nul instructions
mdis.dont_dis_nulstart_bloc = True
blocs = mdis.dis_multibloc(ad)

g = bloc2graph(blocs)
open('graph.txt', 'w').write(g)
