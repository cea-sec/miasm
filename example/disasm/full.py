from __future__ import print_function
import logging
from argparse import ArgumentParser
from pdb import pm

from future.utils import viewitems, viewvalues

from miasm.analysis.binary import Container
from miasm.core.asmblock import log_asmblock
from miasm.analysis.machine import Machine
from miasm.analysis.data_flow import \
    DiGraphDefUse, ReachingDefinitions, \
    replace_stack_vars, load_from_int, \
    expr_has_mem, ExprPropagationHelper, \
    insert_stk_lvl

from miasm.analysis.ssa import SSADiGraph
from miasm.ir.ir import AssignBlock
from miasm.analysis.simplifier import IRCFGSimplifierCommon, IRCFGSimplifierSSA

from miasm.expression.expression import ExprMem, ExprAssign, ExprId, \
    ExprInt, ExprLoc, ExprOp, ExprAssign
from miasm.expression.simplifications import expr_simp
from miasm.ir.ir import AssignBlock, IRBlock
from miasm.core.interval import interval
from miasm.analysis.ssa import irblock_has_phi

from miasm.expression.expression_helper import get_expr_base_offset

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
parser.add_argument('-y', "--stack2var", action="store_true",
                    help="*Try* to do transform stack accesses into variables. "
                    "Use only with --propagexpr option. "
                    "WARNING: not reliable, may fail.")
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

if not args.address and default_addr is not None:
    addr = default_addr
else:
    try:
        addr = int(args.address[0], 0)
    except ValueError:
        # Second chance, try with symbol
        loc_key = mdis.loc_db.get_name_location(args.address[0])
        addr = mdis.loc_db.get_location_offset(loc_key)

# Main disasm loop
asmcfg = mdis.dis_multiblock(addr)
head = mdis.loc_db.get_offset_location(addr)

log.info('func ok %.16x' % addr)

log.info('generate graph file')
open('graph_execflow.dot', 'w').write(asmcfg.dot(offset=True))

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

    ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)
    ircfg_a = ir_arch_a.new_ircfg_from_asmcfg(asmcfg)

    ir_arch.blocks = {}
    ir_arch_a.blocks = {}

    log.info("Print blocks (without analyse)")
    for label, block in viewitems(ir_arch.blocks):
        print(block)

    log.info("Gen Graph... %x" % addr)

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
        ssa = SSADiGraph(ircfg_a)
        ssa.transform(head)
        open("ssa.dot", "w").write(ircfg_a.dot())


if args.propagexpr:
    open("start.dot", "w").write(ircfg_a.dot())


    interfer_index = 0

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
            #open('/tmp/oo_%d.dot' % self.cpt, 'w').write(ssa.graph.dot())
            #self.cpt += 1
            if args.loadint:
                modified |= load_from_int(ssa.graph, bs, is_addr_ro_variable)
            return modified

        def simplify(self, ircfg, head):
            insert_stk_lvl(self.ir_arch, ircfg, self.stk_lvl)
            open('stk_ssa.dot', 'w').write(ircfg.dot())
            ssa = self.ircfg_to_ssa(ircfg, head)
            ssa = self.do_simplify_loop(ssa, head)
            open('last_ssa.dot', 'w').write(ssa.graph.dot())
            ircfg = self.ssa_to_unssa(ssa, head)

            if args.stack2var:
                replace_stack_vars(self.ir_arch, ircfg)


            ircfg_simplifier = IRCFGSimplifierCommon(self.ir_arch)
            ircfg_simplifier.deadremoval.add_expr_to_original_expr(ssa.ssa_variable_to_expr)
            ircfg_simplifier.simplify(ircfg, head)
            return ircfg


    open('xxx.dot', 'w').write(ircfg_a.dot())


    simplifier = CustomIRCFGSimplifierSSA(ir_arch_a)


    simplifier.cpt = 0
    ircfg = simplifier.simplify(ircfg_a, head)
    open('final.dot', 'w').write(ircfg.dot())
