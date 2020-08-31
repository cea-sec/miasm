from __future__ import print_function
import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

fdesc = open(sys.argv[1], 'rb')
loc_db = LocationDB()

# The Container will provide a *bin_stream*, bytes source for the disasm engine
# It will prodive a view from a PE or an ELF.
cont = Container.from_stream(fdesc, loc_db)

# The Machine, instantiated with the detected architecture, will provide tools
# (disassembler, etc.) to work with this architecture
machine = Machine(cont.arch)

# Instantiate a disassembler engine, using the previous bin_stream and its
# associated location DB. The assembly listing will use the binary symbols
mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)

# Run a recursive traversal disassembling from the entry point
# (do not follow sub functions by default)
addr = cont.entry_point
asmcfg = mdis.dis_multiblock(addr)

# Display each basic blocks
for block in asmcfg.blocks:
    print(block)

# Output control flow graph in a dot file
open('bin_cfg.dot', 'w').write(asmcfg.dot())
