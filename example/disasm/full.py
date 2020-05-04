from __future__ import print_function
import logging
from argparse import ArgumentParser
from pdb import pm

from future.utils import viewitems, viewvalues

from miasm.analysis.binary import Container
from miasm.core.asmblock import log_asmblock, AsmCFG
from miasm.core.interval import interval
from miasm.analysis.machine import Machine
from miasm.analysis.data_flow import \
    DiGraphDefUse, ReachingDefinitions, load_from_int
from miasm.expression.simplifications import expr_simp
from miasm.analysis.ssa import SSADiGraph
from miasm.ir.ir import AssignBlock, IRBlock
from miasm.analysis.simplifier import IRCFGSimplifierCommon, IRCFGSimplifierSSA

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
parser.add_argument('-v', "--verbose", action="count", help="Verbose mode",
                    default=0)
parser.add_argument('-g', "--gen_ir", action="store_true",
                    help="Compute the intermediate representation")
parser.add_argument('-z', "--dis-nulstart-block", action="store_true",
                    help="Do not disassemble NULL starting block")
parser.add_argument('-l', "--dontdis-retcall", action="store_true",
                    help="If set, disassemble only call destinations")
parser.add_argument('-s', "--simplify", action="count",
                    help="Apply simplifications rules (liveness, graph simplification, ...)",
                    default=0)
parser.add_argument("--base-address", default=0,
                    type=lambda x: int(x, 0),
                    help="Base address of the input binary")
parser.add_argument('-a', "--try-disasm-all", action="store_true",
                    help="Try to disassemble the whole binary")
parser.add_argument('-i', "--image", action="store_true",
                    help="Display image representation of disasm")
parser.add_argument('-c', "--rawbinary", default=False, action="store_true",
                    help="Don't interpret input as ELF/PE/...")
parser.add_argument('-d', "--defuse", action="store_true",
                    help="Dump the def-use graph in file 'defuse.dot'."
                    "The defuse is dumped after simplifications if -s option is specified")
parser.add_argument('-p', "--ssa", action="store_true",
                    help="Generate the ssa form in  'ssa.dot'.")
parser.add_argument('-x', "--propagexpr", action="store_true",
                    help="Do Expression propagation.")
parser.add_argument('-e', "--loadint", action="store_true",
                    help="Load integers from binary in fixed memory lookup.")
parser.add_argument('-j', "--calldontmodstack", action="store_true",
                    help="Consider stack high is not modified in subcalls")


args = parser.parse_args()

if args.verbose:
    log_asmblock.setLevel(logging.DEBUG)

log.info('Load binary')
if args.rawbinary:
    cont = Container.fallback_container(open(args.filename, "rb").read(),
                                        vm=None, addr=args.base_address)
else:
    with open(args.filename, "rb") as fdesc:
        cont = Container.from_stream(fdesc, addr=args.base_address)

default_addr = cont.entry_point
bs = cont.bin_stream
e = cont.executable
log.info('ok')

log.info("import machine...")
# Use the guessed architecture or the specified one
arch = args.architecture if args.architecture else cont.arch
if not arch:
    print("Architecture recognition fail. Please specify it in arguments")
    exit(-1)

# Instance the arch-dependent machine
machine = Machine(arch)
mn, dis_engine = machine.mn, machine.dis_engine
ira, ir = machine.ira, machine.ir
log.info('ok')

mdis = dis_engine(bs, loc_db=cont.loc_db)
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
        loc_key = mdis.loc_db.get_name_location(addr)
        offset = mdis.loc_db.get_location_offset(loc_key)
        addrs.append(offset)

if len(addrs) == 0 and default_addr is not None:
    addrs.append(default_addr)
for ad in addrs:
    todo += [(mdis, None, ad)]

done = set()
all_funcs = set()
all_funcs_blocks = {}


done_interval = interval()
finish = False

entry_points = set()
# Main disasm loop
while not finish and todo:
    while not finish and todo:
        mdis, caller, ad = todo.pop(0)
        if ad in done:
            continue
        done.add(ad)
        asmcfg = mdis.dis_multiblock(ad)
        entry_points.add(mdis.loc_db.get_offset_location(ad))

        log.info('func ok %.16x (%d)' % (ad, len(all_funcs)))

        all_funcs.add(ad)
        all_funcs_blocks[ad] = asmcfg
        for block in asmcfg.blocks:
            for l in block.lines:
                done_interval += interval([(l.offset, l.offset + l.l)])

        if args.funcswatchdog is not None:
            args.funcswatchdog -= 1
        if args.recurfunctions:
            for block in asmcfg.blocks:
                instr = block.get_subcall_instr()
                if not instr:
                    continue
                for dest in instr.getdstflow(mdis.loc_db):
                    if not dest.is_loc():
                        continue
                    offset = mdis.loc_db.get_location_offset(dest.loc_key)
                    todo.append((mdis, instr, offset))

        if args.funcswatchdog is not None and args.funcswatchdog <= 0:
            finish = True

    if args.try_disasm_all:
        for a, b in done_interval.intervals:
            if b in done:
                continue
            log.debug('add func %s' % hex(b))
            todo.append((mdis, None, b))


# Generate dotty graph
all_asmcfg = AsmCFG(mdis.loc_db)
for blocks in viewvalues(all_funcs_blocks):
    all_asmcfg += blocks


log.info('generate graph file')
open('graph_execflow.dot', 'w').write(all_asmcfg.dot(offset=True))

log.info('generate intervals')

all_lines = []
total_l = 0

print(done_interval)
if args.image:
    log.info('build img')
    done_interval.show()

for i, j in done_interval.intervals:
    log.debug((hex(i), "->", hex(j)))


all_lines.sort(key=lambda x: x.offset)
open('lines.dot', 'w').write('\n'.join(str(l) for l in all_lines))
log.info('total lines %s' % total_l)


if args.propagexpr:
    args.gen_ir = True


class IRADelModCallStack(ira):
        def call_effects(self, addr, instr):
            assignblks, extra = super(IRADelModCallStack, self).call_effects(addr, instr)
            if not args.calldontmodstack:
                return assignblks, extra
            out = []
            for assignblk in assignblks:
                dct = dict(assignblk)
                dct = {
                    dst:src for (dst, src) in viewitems(dct) if dst != self.sp
                }
                out.append(AssignBlock(dct, assignblk.instr))
            return out, extra


# Bonus, generate IR graph
if args.gen_ir:
    log.info("generating IR and IR analysis")

    ir_arch = ir(mdis.loc_db)
    ir_arch_a = IRADelModCallStack(mdis.loc_db)

    ircfg = ir_arch.new_ircfg()
    ircfg_a = ir_arch.new_ircfg()

    ir_arch.blocks = {}
    ir_arch_a.blocks = {}

    head = list(entry_points)[0]

    for ad, asmcfg in viewitems(all_funcs_blocks):
        log.info("generating IR... %x" % ad)
        for block in asmcfg.blocks:
            ir_arch.add_asmblock_to_ircfg(block, ircfg)
            ir_arch_a.add_asmblock_to_ircfg(block, ircfg_a)

    log.info("Print blocks (without analyse)")
    for label, block in viewitems(ir_arch.blocks):
        print(block)

    log.info("Gen Graph... %x" % ad)

    log.info("Print blocks (with analyse)")
    for label, block in viewitems(ir_arch_a.blocks):
        print(block)

    if args.simplify > 0:
        log.info("Simplify...")
        ircfg_simplifier = IRCFGSimplifierCommon(ir_arch_a)
        ircfg_simplifier.simplify(ircfg_a, head)
        log.info("ok...")

    if args.defuse:
        reachings = ReachingDefinitions(ircfg_a)
        open('graph_defuse.dot', 'w').write(DiGraphDefUse(reachings).dot())

    out = ircfg.dot()
    open('graph_irflow_raw.dot', 'w').write(out)
    out = ircfg_a.dot()
    open('graph_irflow.dot', 'w').write(out)

    if args.ssa and not args.propagexpr:
        if len(entry_points) != 1:
            raise RuntimeError("Your graph should have only one head")
        ssa = SSADiGraph(ircfg_a)
        ssa.transform(head)
        open("ssa.dot", "w").write(ircfg_a.dot())


if args.propagexpr:

    def is_addr_ro_variable(bs, addr, size):
        """
        Return True if address at @addr is a read-only variable.
        WARNING: Quick & Dirty

        @addr: integer representing the address of the variable
        @size: size in bits

        """
        try:
            _ = bs.getbytes(addr, size // 8)
        except IOError:
            return False
        return True

    class CustomIRCFGSimplifierSSA(IRCFGSimplifierSSA):
        def do_simplify(self, ssa, head):
            modified = super(CustomIRCFGSimplifierSSA, self).do_simplify(ssa, head)
            if args.loadint:
                modified |= load_from_int(ssa.graph, bs, is_addr_ro_variable)

        def simplify(self, ircfg, head):
            ssa = self.ircfg_to_ssa(ircfg, head)
            ssa = self.do_simplify_loop(ssa, head)
            ircfg = self.ssa_to_unssa(ssa, head)

            ircfg_simplifier = IRCFGSimplifierCommon(self.ir_arch)
            ircfg_simplifier.deadremoval.add_expr_to_original_expr(ssa.ssa_variable_to_expr)
            ircfg_simplifier.simplify(ircfg, head)
            return ircfg

    head = list(entry_points)[0]
    simplifier = CustomIRCFGSimplifierSSA(ir_arch_a)
    ircfg = simplifier.simplify(ircfg_a, head)
    open('final.dot', 'w').write(ircfg.dot())
