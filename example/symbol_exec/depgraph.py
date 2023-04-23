from __future__ import print_function
from builtins import range
from argparse import ArgumentParser
from pdb import pm
import json

from future.utils import viewitems

from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.analysis.depgraph import DependencyGraph
from miasm.expression.expression import ExprMem, ExprId, ExprInt
from miasm.core.locationdb import LocationDB

parser = ArgumentParser(description="Dependency grapher")
parser.add_argument("filename", help="Binary to analyse")
parser.add_argument("func_addr", help="Function address")
parser.add_argument("target_addr", help="Address to start")
parser.add_argument("element", nargs="+", help="Elements to track")
parser.add_argument("-m", "--architecture",
                    help="Architecture (%s)" % Machine.available_machine())
parser.add_argument("-i", "--implicit", help="Use implicit tracking",
                    action="store_true")
parser.add_argument("--unfollow-mem", help="Stop on memory statements",
                    action="store_true")
parser.add_argument("--unfollow-call", help="Stop on call statements",
                    action="store_true")
parser.add_argument("--do-not-simplify", help="Do not simplify expressions",
                    action="store_true")
parser.add_argument("--rename-args",
                    help="Rename common arguments (@32[ESP_init] -> Arg1)",
                    action="store_true")
parser.add_argument("--json",
                    help="Output solution in JSON",
                    action="store_true")
args = parser.parse_args()
loc_db = LocationDB()
# Get architecture
with open(args.filename, "rb") as fstream:
    cont = Container.from_stream(fstream, loc_db)

arch = args.architecture if args.architecture else cont.arch
machine = Machine(arch)

# Check elements
elements = set()
regs = machine.mn.regs.all_regs_ids_byname
for element in args.element:
    try:
        elements.add(regs[element])
    except KeyError:
        raise ValueError("Unknown element '%s'" % element)

mdis = machine.dis_engine(cont.bin_stream, dont_dis_nulstart_bloc=True, loc_db=loc_db)
lifter = machine.lifter_model_call(loc_db)

# Common argument forms
init_ctx = {}
if args.rename_args:
    if arch == "x86_32":
        # StdCall example
        for i in range(4):
            e_mem = ExprMem(ExprId("ESP_init", 32) + ExprInt(4 * (i + 1), 32), 32)
            init_ctx[e_mem] = ExprId("arg%d" % i, 32)

# Disassemble the targeted function
asmcfg = mdis.dis_multiblock(int(args.func_addr, 0))

# Generate IR
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

# Get the instance
dg = DependencyGraph(
    ircfg, implicit=args.implicit,
    apply_simp=not args.do_not_simplify,
    follow_mem=not args.unfollow_mem,
    follow_call=not args.unfollow_call
)

# Build information
target_addr = int(args.target_addr, 0)
target = dg.address_to_location(target_addr)

# Enumerate solutions
json_solutions = []
for sol_nb, sol in enumerate(dg.get(target["loc_key"], elements, target["line_nb"], set())):
    fname = "sol_%d.dot" % sol_nb
    with open(fname, "w") as fdesc:
            fdesc.write(sol.graph.dot())

    results = sol.emul(lifter, ctx=init_ctx)
    tokens = {str(k): str(v) for k, v in viewitems(results)}
    if not args.json:
        result = ", ".join("=".join(x) for x in viewitems(tokens))
        print("Solution %d: %s -> %s" % (sol_nb,
                                         result,
                                         fname))
        if sol.has_loop:
            print('\tLoop involved')

    if args.implicit:
        sat = sol.is_satisfiable
        constraints = {}
        if sat:
            for element in sol.constraints:
                try:
                    result = '0x%x' % sol.constraints[element].as_long()
                except AttributeError:
                    result = str(sol.constraints[element])
                constraints[element] = result
        if args.json:
            tokens["satisfiability"] = sat
            tokens["constraints"] = {
                str(k): str(v)
                for k, v in viewitems(constraints)
            }
        else:
            print("\tSatisfiability: %s %s" % (sat, constraints))

    if args.json:
        tokens["has_loop"] = sol.has_loop
        json_solutions.append(tokens)


if args.json:
    print(json.dumps(json_solutions))
