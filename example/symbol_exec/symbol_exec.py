from __future__ import print_function
from argparse import ArgumentParser

from future.utils import viewvalues
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine

parser = ArgumentParser("Simple SymbolicExecution demonstrator")
parser.add_argument("target_binary", help="Target binary path")
parser.add_argument("--address", help="Starting address for emulation. If not set, use the entrypoint")
parser.add_argument("--steps", help="Log emulation state after each instruction", action="store_true")
options = parser.parse_args()

###################################################################
# Common section from example/disam/dis_binary_lift_model_call.py #
###################################################################

fdesc = open(options.target_binary, 'rb')
loc_db = LocationDB()

cont = Container.from_stream(fdesc, loc_db)

machine = Machine(cont.arch)

mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)

# no address -> entry point
# 0xXXXXXX -> use this address
# symbol -> resolve then use
if options.address is None:
    addr = cont.entry_point
else:
    try:
        addr = int(options.address, 0)
    except ValueError:
        addr = loc_db.get_name_offset(options.address)
asmcfg = mdis.dis_multiblock(addr)

lifter = machine.lifter_model_call(mdis.loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

#####################################
#    End common section             #
#####################################

# Instantiate a Symbolic Execution engine with default value for registers
symb = SymbolicExecutionEngine(lifter)

# Emulate until the next address cannot be resolved (`ret`, unresolved condition, etc.)
cur_addr = symb.run_at(ircfg, addr, step=options.steps)

# Modified elements
print('Modified registers:')
symb.dump(mems=False)
print('Modified memory (should be empty):')
symb.dump(ids=False)
