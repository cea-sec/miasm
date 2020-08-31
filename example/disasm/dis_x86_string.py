from __future__ import print_function
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

# The Container will provide a *bin_stream*, bytes source for the disasm engine
loc_db = LocationDB()
cont = Container.from_string(
    b"\x83\xf8\x10\x74\x07\x89\xc6\x0f\x47\xc3\xeb\x08\x89\xc8\xe8\x31\x33\x22\x11\x40\xc3",
    loc_db
)

# Instantiate a x86 32 bit architecture
machine = Machine("x86_32")

# Instantiate a disassembler engine, using the previous bin_stream and its
# associated location DB.
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)

# Run a recursive traversal disassembling from address 0
asmcfg = mdis.dis_multiblock(0)

# Display each basic blocks
for block in asmcfg.blocks:
    print(block)

# Output control flow graph in a dot file
open('str_cfg.dot', 'w').write(asmcfg.dot())
