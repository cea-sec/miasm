import sys
from miasm2.arch.x86.disasm import dis_x86_32
from miasm2.analysis.binary import Container
from pdb import pm

if len(sys.argv) != 3:
    print 'Example:'
    print "%s samples/box_upx.exe 0x407570" % sys.argv[0]
    sys.exit(0)

addr = int(sys.argv[2], 0)
cont = Container.from_stream(open(sys.argv[1]))
mdis = dis_x86_32(cont.bin_stream)
# Inform the engine to avoid disassembling null instructions
mdis.dont_dis_nulstart_bloc = True
blocks = mdis.dis_multibloc(addr)

open('graph.dot', 'w').write(blocks.dot())
