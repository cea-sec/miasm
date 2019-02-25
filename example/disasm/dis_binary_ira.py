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

# Get an IRA converter
# The sub call are modelised by default operators
# call_func_ret and call_func_stack
ir_arch_analysis = machine.ira(mdis.loc_db)

# Get the IR of the asmcfg
ircfg_analysis = ir_arch_analysis.new_ircfg_from_asmcfg(asmcfg)

# Display each IR basic blocks
for irblock in viewvalues(ircfg_analysis.blocks):
    print(irblock)

# Output ir control flow graph in a dot file
open('bin_ira_cfg.dot', 'w').write(ircfg_analysis.dot())
