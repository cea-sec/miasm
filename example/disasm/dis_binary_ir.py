from __future__ import print_function
import sys
from future.utils import viewvalues
from miasm2.analysis.binary import Container
from miasm2.analysis.machine import Machine

#####################################
# Common section from dis_binary.py #
#####################################

fdesc = open(sys.argv[1], 'rb')

cont = Container.from_stream(fdesc)

machine = Machine(cont.arch)

mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)

addr = cont.entry_point
asmcfg = mdis.dis_multiblock(addr)

#####################################
#    End common section             #
#####################################

# Get an IR converter
ir_arch = machine.ir(mdis.loc_db)

# Get the IR of the asmcfg
ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

# Display each IR basic blocks
for irblock in viewvalues(ircfg.blocks):
    print(irblock)

# Output ir control flow graph in a dot file
open('bin_ir_cfg.dot', 'w').write(ircfg.dot())
