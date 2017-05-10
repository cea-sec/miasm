import logging
from argparse import ArgumentParser
from pdb import pm

from miasm2.analysis.binary import Container
from miasm2.core.asmblock import log_asmblock, AsmLabel, AsmCFG
from miasm2.expression.expression import ExprId
from miasm2.core.interval import interval
from miasm2.analysis.machine import Machine
from miasm2.analysis.data_flow import dead_simp, DiGraphDefUse, ReachingDefinitions
from miasm2.expression.simplifications import expr_simp

log = logging.getLogger("dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)


parser = ArgumentParser("Disassemble a binary")
parser.add_argument('filename', help="File to disassemble")
parser.add_argument('address', help="Starting address for disassembly engine",
                    nargs="*")
parser.add_argument('-m', '--architecture', help="architecture: " + \
                        ",".join(Machine.available_machine()))
parser.add_argument('-f', "--followcall", action="store_true",
                    help="Follow call instructions")
parser.add_argument('-b', "--blockwatchdog", default=None, type=int,
                    help="Maximum number of basic block to disassemble")
parser.add_argument('-n', "--funcswatchdog", default=None, type=int,
                    help="Maximum number of function to disassemble")
parser.add_argument('-r', "--recurfunctions", action="store_true",
                    help="Disassemble founded functions")
parser.add_argument('-v', "--verbose", action="store_true", help="Verbose mode")
parser.add_argument('-g', "--gen_ir", action="store_true",
                    help="Compute the intermediate representation")
parser.add_argument('-z', "--dis-nulstart-block", action="store_true",
                    help="Do not disassemble NULL starting block")
parser.add_argument('-l', "--dontdis-retcall", action="store_true",
                    help="If set, disassemble only call destinations")
parser.add_argument('-s', "--simplify", action="count",
                    help="Apply simplifications rules (liveness, graph simplification, ...)")
parser.add_argument('-o', "--shiftoffset", default=None,
                    type=lambda x: int(x, 0),
                    help="Shift input binary by an offset")
parser.add_argument('-a', "--try-disasm-all", action="store_true",
                    help="Try to disassemble the whole binary")
parser.add_argument('-i', "--image", action="store_true",
                    help="Display image representation of disasm")
parser.add_argument('-c', "--rawbinary", default=False, action="store_true",
                    help="Don't interpret input as ELF/PE/...")
parser.add_argument('-d', "--defuse", action="store_true",
                    help="Dump the def-use graph in file 'defuse.dot'."
                    "The defuse is dumped after simplifications if -s option is specified")

args = parser.parse_args()

if args.verbose:
    log_asmblock.setLevel(logging.DEBUG)

log.info('Load binary')
if args.rawbinary:
    shift = args.shiftoffset if args.shiftoffset is not None else 0
    cont = Container.fallback_container(open(args.filename).read(),
                                        None, addr=shift)
else:
    with open(args.filename) as fdesc:
        cont = Container.from_stream(fdesc, addr=args.shiftoffset)

default_addr = cont.entry_point
bs = cont.bin_stream
e = cont.executable
log.info('ok')

log.info("import machine...")
# Use the guessed architecture or the specified one
arch = args.architecture if args.architecture else cont.arch
if not arch:
    print "Architecture recognition fail. Please specify it in arguments"
    exit(-1)

# Instance the arch-dependent machine
machine = Machine(arch)
mn, dis_engine = machine.mn, machine.dis_engine
ira, ir = machine.ira, machine.ir
log.info('ok')

mdis = dis_engine(bs, symbol_pool=cont.symbol_pool)
# configure disasm engine
mdis.dontdis_retcall = args.dontdis_retcall
mdis.blocs_wd = args.blockwatchdog
mdis.dont_dis_nulstart_bloc = not args.dis_nulstart_block
mdis.follow_call = args.followcall

todo = []
addrs = []
for addr in args.address:
    try:
        addrs.append(int(addr, 0))
    except ValueError:
        # Second chance, try with symbol
        addrs.append(mdis.symbol_pool.getby_name(addr).offset)

if len(addrs) == 0 and default_addr is not None:
    addrs.append(default_addr)
for ad in addrs:
    todo += [(mdis, None, ad)]

done = set()
all_funcs = set()
all_funcs_blocks = {}


done_interval = interval()
finish = False

# Main disasm loop
while not finish and todo:
    while not finish and todo:
        mdis, caller, ad = todo.pop(0)
        if ad in done:
            continue
        done.add(ad)
        allblocks = mdis.dis_multibloc(ad)

        log.info('func ok %.16x (%d)' % (ad, len(all_funcs)))

        all_funcs.add(ad)
        all_funcs_blocks[ad] = allblocks
        for block in allblocks:
            for l in block.lines:
                done_interval += interval([(l.offset, l.offset + l.l)])

        if args.funcswatchdog is not None:
            args.funcswatchdog -= 1
        if args.recurfunctions:
            for block in allblocks:
                instr = block.get_subcall_instr()
                if not instr:
                    continue
                for dest in instr.getdstflow(mdis.symbol_pool):
                    if not (isinstance(dest, ExprId) and isinstance(dest.name, AsmLabel)):
                        continue
                    todo.append((mdis, instr, dest.name.offset))

        if args.funcswatchdog is not None and args.funcswatchdog <= 0:
            finish = True

    if args.try_disasm_all:
        for a, b in done_interval.intervals:
            if b in done:
                continue
            log.debug('add func %s' % hex(b))
            todo.append((mdis, None, b))


# Generate dotty graph
all_blocks = AsmCFG()
for blocks in all_funcs_blocks.values():
    all_blocks += blocks


log.info('generate graph file')
open('graph_execflow.dot', 'w').write(all_blocks.dot(offset=True))

log.info('generate intervals')

all_lines = []
total_l = 0

print done_interval
if args.image:
    log.info('build img')
    done_interval.show()

for i, j in done_interval.intervals:
    log.debug((hex(i), "->", hex(j)))


all_lines.sort(key=lambda x: x.offset)
open('lines.dot', 'w').write('\n'.join([str(l) for l in all_lines]))
log.info('total lines %s' % total_l)


# Bonus, generate IR graph
if args.gen_ir:
    log.info("generating IR and IR analysis")

    ir_arch = ir(mdis.symbol_pool)
    ir_arch_a = ira(mdis.symbol_pool)
    ir_arch.blocks = {}
    ir_arch_a.blocks = {}
    for ad, all_block in all_funcs_blocks.items():
        log.info("generating IR... %x" % ad)
        for block in all_block:
            ir_arch_a.add_bloc(block)
            ir_arch.add_bloc(block)

    log.info("Print blocks (without analyse)")
    for label, block in ir_arch.blocks.iteritems():
        print block

    log.info("Gen Graph... %x" % ad)

    log.info("Print blocks (with analyse)")
    for label, block in ir_arch_a.blocks.iteritems():
        print block

    if args.simplify > 0:
        dead_simp(ir_arch_a)

    if args.defuse:
        reachings = ReachingDefinitions(ir_arch_a)
        open('graph_defuse.dot', 'w').write(DiGraphDefUse(reachings).dot())

    out = ir_arch_a.graph.dot()
    open('graph_irflow.dot', 'w').write(out)
    out = ir_arch.graph.dot()
    open('graph_irflow_raw.dot', 'w').write(out)

    if args.simplify > 1:
        ir_arch_a.simplify(expr_simp)
        modified = True
        while modified:
            modified = False
            modified |= dead_simp(ir_arch_a)
            modified |= ir_arch_a.remove_empty_assignblks()
            modified |= ir_arch_a.remove_jmp_blocks()
            modified |= ir_arch_a.merge_blocks()

        open('graph_irflow_reduced.dot', 'w').write(ir_arch_a.graph.dot())
