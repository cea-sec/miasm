import os
import logging
from argparse import ArgumentParser
from pdb import pm

from miasm2.analysis.binary import Container
from miasm2.core.asmbloc import log_asmbloc, asm_label, bloc2graph
from miasm2.expression.expression import ExprId
from miasm2.core.interval import interval
from miasm2.analysis.machine import Machine

log = logging.getLogger("dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


parser = ArgumentParser("Disassemble a binary")
parser.add_argument('architecture', help="architecture: " + \
                        ",".join(Machine.available_machine()))
parser.add_argument('filename', help="File to disassemble")
parser.add_argument('address', help="Starting address for disassembly engine",
                    nargs="+")
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
parser.add_argument('-s', "--simplify", action="store_true",
                    help="Use the liveness analysis pass")
parser.add_argument('-o', "--shiftoffset", default=None, type=int,
                    help="Shift input binary by an offset")
parser.add_argument('-a', "--try-disasm-all", action="store_true",
                    help="Try to disassemble the whole binary")
parser.add_argument('-i', "--image", action="store_true",
                    help="Display image representation of disasm")

args = parser.parse_args()

if args.verbose:
    log_asmbloc.setLevel(logging.DEBUG)

log.info("import machine...")
machine = Machine(args.architecture)
mn, dis_engine = machine.mn, machine.dis_engine
ira, ir = machine.ira, machine.ir
log.info('ok')

log.info('Load binary')
with open(args.filename) as fdesc:
    cont = Container.from_stream(fdesc, addr=args.shiftoffset)

default_addr = cont.entry_point
bs = cont.bin_stream
e = cont.executable

log.info('ok')
mdis = dis_engine(bs)
# configure disasm engine
mdis.dontdis_retcall = args.dontdis_retcall
mdis.blocs_wd = args.blockwatchdog
mdis.dont_dis_nulstart_bloc = not args.dis_nulstart_block

todo = []
addrs = [int(a, 16) for a in args.address]

if len(addrs) == 0 and default_addr is not None:
    addrs.append(default_addr)
for ad in addrs:
    todo = [(mdis, None, ad)]

done = set()
all_funcs = set()
all_funcs_blocs = {}


done_interval = interval()
finish = False

# Main disasm loop
while not finish and todo:
    while not finish and todo:
        mdis, caller, ad = todo.pop(0)
        if ad in done:
            continue
        done.add(ad)
        ab = mdis.dis_multibloc(ad)

        log.info('func ok %.16x (%d)' % (ad, len(all_funcs)))

        all_funcs.add(ad)
        all_funcs_blocs[ad] = ab
        for b in ab:
            for l in b.lines:
                done_interval += interval([(l.offset, l.offset + l.l)])

        if args.funcswatchdog is not None:
            args.funcswatchdog -= 1
        if args.recurfunctions:
            for b in ab:
                i = b.get_subcall_instr()
                if not i:
                    continue
                for d in i.getdstflow(mdis.symbol_pool):
                    if not (isinstance(d, ExprId) and isinstance(d.name, asm_label)):
                        continue
                    todo.append((mdis, i, d.name.offset))

        if args.funcswatchdog is not None and args.funcswatchdog <= 0:
            finish = True

    if args.try_disasm_all:
        for a, b in done_interval.intervals:
            if b in done:
                continue
            log.debug('add func %s' % hex(b))
            todo.append((mdis, None, b))


# Generate dotty graph
all_blocs = []
for blocs in all_funcs_blocs.values():
    all_blocs += blocs
    # for b in blocs:
    #    print b

log.info('generate graph file')
g = bloc2graph(all_blocs, True)
open('graph_execflow.txt', 'w').write(g)

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
open('lines.txt', 'w').write('\n'.join([str(l) for l in all_lines]))
log.info('total lines %s' % total_l)


# Bonus, generate IR graph
if args.gen_ir:
    log.info("generating IR and IR analysis")

    ir_arch = ir(mdis.symbol_pool)
    ir_arch_a = ira(mdis.symbol_pool)
    ir_arch.blocs = {}
    ir_arch_a.blocs = {}
    for ad, all_bloc in all_funcs_blocs.items():
        log.info("generating IR... %x" % ad)
        for b in all_bloc:
            ir_arch_a.add_bloc(b)
            ir_arch.add_bloc(b)

    log.info("Print blocs (without analyse)")
    for label, bloc in ir_arch.blocs.iteritems():
        print bloc

    log.info("Gen Graph... %x" % ad)

    log.info("Print blocs (with analyse)")
    for label, bloc in ir_arch_a.blocs.iteritems():
        print bloc
    ir_arch_a.gen_graph()

    if args.simplify:
        ir_arch_a.dead_simp()

    out = ir_arch_a.graph()
    open('graph_irflow.txt', 'w').write(out)
