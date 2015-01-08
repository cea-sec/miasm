import sys
from miasm2.arch.x86.disasm import dis_x86_32
from miasm2.core.asmbloc import bloc2graph
from miasm2.analysis.binary import Container

if len(sys.argv) != 3:
    print 'Example:'
    print "%s samples/box_upx.exe 0x410f90" % sys.argv[0]
    sys.exit(0)

addr = int(sys.argv[2], 16)
cont = Container.from_stream(open(sys.argv[1]))
mdis = dis_x86_32(cont.bin_stream)
# Inform the engine to avoid disassembling null instructions
mdis.dont_dis_nulstart_bloc = True
blocs = mdis.dis_multibloc(addr)

graph = bloc2graph(blocs)
open('graph.txt', 'w').write(graph)
