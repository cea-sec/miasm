from argparse import ArgumentParser
from pdb import pm

from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from miasm2.analysis.depgraph import DependencyGraph
from miasm2.expression.expression import ExprMem, ExprId, ExprInt32

parser = ArgumentParser("Dependency grapher")
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
args = parser.parse_args()

# Get architecture
with open(args.filename) as fstream:
    cont = Container.from_stream(fstream)

arch = args.architecture if args.architecture else cont.arch
machine = Machine(arch)

# Check elements
elements = set()
regs = machine.mn.regs.all_regs_ids_byname
for element in args.element:
    try:
	elements.add(regs[element.upper()])
    except KeyError:
	raise ValueError("Unknown element '%s'" % element)

mdis = machine.dis_engine(cont.bin_stream, dont_dis_nulstart_bloc=True)
ir_arch = machine.ira(mdis.symbol_pool)

# Common argument forms
init_ctx = {}
if args.rename_args:
    if arch == "x86_32":
        # StdCall example
        for i in xrange(4):
            e_mem = ExprMem(ExprId("ESP_init") + ExprInt32(4 * (i + 1)), 32)
            init_ctx[e_mem] = ExprId("arg%d" % i)

# Disassemble the targeted function
blocks = mdis.dis_multibloc(int(args.func_addr, 16))

# Generate IR
for block in blocks:
    ir_arch.add_bloc(block)

# Build the IRA Graph
ir_arch.gen_graph()

# Get the instance
dg = DependencyGraph(ir_arch, implicit=args.implicit,
		     apply_simp=not(args.do_not_simplify),
		     follow_mem=not(args.unfollow_mem),
		     follow_call=not(args.unfollow_call))

# Build information
target_addr = int(args.target_addr, 16)
current_block = list(ir_arch.getby_offset(target_addr))[0]
line_nb = 0
for line_nb, line in enumerate(current_block.lines):
    if line.offset == target_addr:
	break

# Enumerate solutions
for sol_nb, sol in enumerate(dg.get(current_block.label, elements, line_nb, set())):
	fname = "sol_%d.dot" % sol_nb
	with open(fname, "w") as fdesc:
		fdesc.write(sol.graph.dot())
	result = ", ".join("%s: %s" % (k, v)
			   for k, v in sol.emul(ctx=init_ctx).iteritems())
	print "Solution %d: %s -> %s" % (sol_nb,
					 result,
					 fname)
        if args.implicit:
            sat = sol.is_satisfiable
            constraints = ""
            if sat:
                constraints = {}
                for element in sol.constraints:
                    constraints[element] = hex(sol.constraints[element].as_long())
            print "\tSatisfiability: %s %s" % (sat, constraints)
