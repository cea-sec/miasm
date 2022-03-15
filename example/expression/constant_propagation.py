"""
Example of "constant expression" propagation.
A "constant expression" is an expression based on constants or init regs.

"""

from argparse import ArgumentParser

from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.analysis.cst_propag import propagate_cst_expr
from miasm.analysis.data_flow import DeadRemoval, \
    merge_blocks, remove_empty_assignblks
from miasm.expression.simplifications import expr_simp
from miasm.core.locationdb import LocationDB



parser = ArgumentParser(description="Constant expression propagation")
parser.add_argument('filename', help="File to analyze")
parser.add_argument('address', help="Starting address for disassembly engine")
parser.add_argument('-s', "--simplify", action="store_true",
                    help="Apply simplifications rules (liveness, graph simplification, ...)")

args = parser.parse_args()


machine = Machine("x86_32")

loc_db = LocationDB()
cont = Container.from_stream(open(args.filename, 'rb'), loc_db)
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
lifter = machine.lifter_model_call(mdis.loc_db)
addr = int(args.address, 0)
deadrm = DeadRemoval(lifter)

asmcfg = mdis.dis_multiblock(addr)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
entry_points = set([mdis.loc_db.get_offset_location(addr)])

init_infos = lifter.arch.regs.regs_init
cst_propag_link = propagate_cst_expr(lifter, ircfg, addr, init_infos)

if args.simplify:
    ircfg.simplify(expr_simp)
    modified = True
    while modified:
        modified = False
        modified |= deadrm(ircfg)
        modified |= remove_empty_assignblks(ircfg)
        modified |= merge_blocks(ircfg, entry_points)


open("%s.propag.dot" % args.filename, 'w').write(ircfg.dot())
