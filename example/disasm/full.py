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
    ComputeAlias
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
    def assignblk_has_sp_mem_access(assignblk):
        reads = set()
        for dst, src in viewitems(assignblk):
            assign = ExprAssign(dst, src)
            reads.update(assign.get_r(mem_read=True))
        mems = set(expr for expr in reads if expr.is_mem())
        for mem in mems:
            ptr, offset = get_expr_base_offset(mem.ptr)
            if ptr == ir_arch_a.sp:
                return True
        return False

    def remove_self_interference(ssa, head):
        global interfer_index
        compute_alias = ComputeAlias(ir_arch_a)
        modified = False
        for block in list(viewvalues(ssa.graph.blocks)):
            #print(block)
            irs = []
            stk_lvl_cur = None
            for idx, assignblk in enumerate(block):
                #print(idx)
                all_dsts = set(assignblk.keys())
                aliasing_mems = set()
                for dst, src in viewitems(assignblk):
                    uses = src.get_r(mem_read=True)
                    if dst.is_mem():
                        uses.update(dst.ptr.get_r(mem_read=True))
                    uses = set(expr for expr in uses if expr.is_mem())
                    for use in uses:
                        for dst in all_dsts:
                            if compute_alias.test_may_alias(dst, use):
                                aliasing_mems.add(use)
                if aliasing_mems:
                    out = {}
                    interfer_srcs = {}
                    for expr in aliasing_mems:
                        interfer_srcs[expr] = ExprId("tmp_%d" % interfer_index, expr.size)
                        interfer_index += 1
                    #print(interfer_srcs)
                    for dst, src in viewitems(assignblk):
                        if dst.is_mem():
                            dst = ExprMem(dst.ptr.replace_expr(interfer_srcs), dst.size)
                        src = src.replace_expr(interfer_srcs)
                        out[dst] = src
                    new_vars = dict((src, dst) for dst, src in viewitems(interfer_srcs))
                    #print("NEW", new_vars)
                    irs.append(
                        AssignBlock(
                            new_vars,
                            assignblk.instr
                        )
                    )
                    irs.append(AssignBlock(out, assignblk.instr))
                    modified = True
                else:
                    irs.append(assignblk)
            #print(irs)
            ssa.graph.blocks[block.loc_key] = IRBlock(block.loc_key, irs)
        if modified:
            open('ttt.dot', 'w').write(ssa.graph.dot())
        return modified

    def does_sp_mem_write(assignblk):
        for dst in assignblk:
            if not dst.is_mem():
                continue
            base, offset = get_expr_base_offset(dst.ptr)
            if base == ir_arch_a.sp:
                return True
        return False

    def do_del_stk_above(assignblk):
        if not stk_lvl in assignblk:
            return assignblk, False
        if not does_sp_mem_write(assignblk):
            return assignblk, False
        if assignblk_has_sp_mem_access(assignblk):
            return assignblk, False
        out = {}

        stk_lvl_cur = assignblk[stk_lvl]
        sp_base, sp_offset = get_expr_base_offset(stk_lvl_cur)

        modified = False
        for dst, src in viewitems(assignblk):
            if not dst.is_mem():
                out[dst] = src
                continue
            base, offset = get_expr_base_offset(dst.ptr)
            if base != sp_base:
                out[dst] = src
                continue
            ptr = dst.ptr
            diff = expr_simp((ptr - stk_lvl_cur).msb())
            if diff.is_int() and int(diff) == 1:
                modified = True
                continue
        if not modified:
            return assignblk, False
        return AssignBlock(out, assignblk.instr), True

    def propagate_stk_lvl(ssa, head):
        """
        Upward propagate the stk_lvl for each block.
        Conditions of propagation:
        - no memory access which may alias to stack
        """
        print("START STK LVL PROPAG")
        worklist = set((loc_key, None) for loc_key in ssa.graph.blocks)
        done = set()
        while worklist:
            job = worklist.pop()
            if job in done:
                continue
            done.add(job)

            loc_key, stk_lvl_cur = job
            block = ssa.graph.blocks[loc_key]
            print("Analyse stk", stk_lvl_cur)
            print(block)
            irs = list(block)
            for idx, assignblk in reversed(list(enumerate(block))):
                if stk_lvl not in assignblk:
                    # Should be Phi assignblk
                    if idx == 0:
                        # XXX TODO: check if stk_lvl does not come from a Phi
                        # => In this case, don't propagate to predecessors
                        continue
                    else:
                        stk_lvl_cur = None
                        continue

                if stk_lvl_cur is None:
                    if assignblk_has_sp_mem_access(assignblk):
                        continue
                    stk_lvl_cur = assignblk[stk_lvl]
                    continue

                stk_lvl_local = assignblk[stk_lvl]
                #print('*'*30, stk_lvl_cur)
                #print(assignblk)

                diff = expr_simp((stk_lvl_local - stk_lvl_cur).msb())
                if diff.is_int() and int(diff) == 1:
                    # The stack level of the next block is above us
                    # so we can set our new stack level
                    print('REPLACE')
                    print(assignblk)
                    out = dict(assignblk)
                    out[stk_lvl] = stk_lvl_cur
                    new_assignblk = AssignBlock(out, assignblk.instr)
                    # XXXXXXXXXXXXXXXXXXX DEL
                    #new_assignblk = do_del_stk_above(new_assignblk)
                    irs[idx] = new_assignblk
                    assignblk = new_assignblk
                    #print(irs[idx])
                """
                # XXXXXXXXXXXXXXXXXXX DEL
                #new_assignblk = do_del_stk_above(new_assignblk)
                else:
                    if does_sp_mem_write(assignblk):
                        out = dict(assignblk)
                        out[stk_lvl] = stk_lvl_cur
                        new_assignblk = AssignBlock(out, assignblk.instr)
                        new_assignblk = do_del_stk_above(new_assignblk)
                        irs[idx] = new_assignblk
                """

                if assignblk_has_sp_mem_access(assignblk):
                    stk_lvl_cur = None
                """
                new_assignblk = dict(assignblk)
                for lval in assignblk:
                    if AssignblkNode(block.loc_key, idx, lval) not in useful:
                        del new_assignblk[lval]
                        modified = True
                irs.append(AssignBlock(new_assignblk, assignblk.instr))
                """
            ssa.graph.blocks[block.loc_key] = IRBlock(block.loc_key, irs)
            # Propagate to predecessors
            if stk_lvl_cur is not None:
                print("Propagate stk lvl to predecessors", stk_lvl_cur)
                print(block)
                for pred in ssa.graph.predecessors(loc_key):
                    worklist.add((pred, stk_lvl_cur))



        return False


    def del_above_stk_write(ssa, head):
        """
        Del writes to memory above stack level
        """
        print("TEST DEL ABOVE")
        modified = False
        for block in list(viewvalues(ssa.graph.blocks)):
            irs = []
            modified_block = False
            for assignblk in block:
                new_assignblk, assignblk_modified = do_del_stk_above(assignblk)
                irs.append(new_assignblk)
                if assignblk_modified:
                    modified_block = True
            if modified_block:
                ssa.graph.blocks[block.loc_key] = IRBlock(block.loc_key, irs)
                modified = True
        return modified


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
            ssa = self.ircfg_to_ssa(ircfg, head)
            ssa = self.do_simplify_loop(ssa, head)
            ircfg = self.ssa_to_unssa(ssa, head)

            if args.stack2var:
                replace_stack_vars(self.ir_arch, ircfg)

            open('last_ssa.dot', 'w').write(ssa.graph.dot())

            ircfg_simplifier = IRCFGSimplifierCommon(self.ir_arch)
            ircfg_simplifier.deadremoval.add_expr_to_original_expr(ssa.ssa_variable_to_expr)
            ircfg_simplifier.simplify(ircfg, head)
            return ircfg


    sp = ir_arch_a.arch.regs.ESP
    """
    top_num = 0
    for block in list(viewvalues(ircfg_a.blocks)):
        irs = []
        for idx, assignblk in enumerate(block):
            if sp not in assignblk:
                irs.append(assignblk)
                continue
            value = assignblk[sp]
            diff = expr_simp((value - sp).msb())
            if not diff.is_int():
                irs.append(assignblk)
                continue
            diff = int(diff)
            if diff:
                irs.append(assignblk)
                continue
            out = dict(assignblk)
            offset = int(expr_simp(value - sp))
            for x in range(0, offset, 4):
                out[ExprMem(sp + ExprInt(x, 32), 32)] = ExprId("TOP_%d" % top_num, 32)#ExprInt(0, 32)
                top_num += 1
            new_assignblk = AssignBlock(out, assignblk.instr)
            print(new_assignblk)
            irs.append(AssignBlock(new_assignblk, assignblk.instr))
        ircfg_a.blocks[block.loc_key] = IRBlock(block.loc_key, irs)
    """

    def insert_stk_lvl(ircfg, stk_lvl):
        """
        Insert in each assignblock the stack level *after* it's execution
        """
        for block in list(viewvalues(ircfg_a.blocks)):
            irs = []
            for assignblk in block:
                if sp not in assignblk:
                    stk_value = sp
                else:
                    stk_value = assignblk[sp]
                out = dict(assignblk)
                out[stk_lvl] = stk_value
                new_assignblk = AssignBlock(out, assignblk.instr)
                irs.append(AssignBlock(new_assignblk, assignblk.instr))
            ircfg_a.blocks[block.loc_key] = IRBlock(block.loc_key, irs)

    stk_lvl = ExprId('stk_lvl', ir_arch_a.sp.size)
    insert_stk_lvl(ircfg_a, stk_lvl)

    open('xxx.dot', 'w').write(ircfg_a.dot())
    #fds
    simplifier = CustomIRCFGSimplifierSSA(ir_arch_a)

    simplifier.ssa_forbidden_regs.add(stk_lvl)

    def my_is_unkillable(self, lval, rval):
        #print(lval)
        if old_unkillable(lval, rval):
            return True
        if lval == stk_lvl:
            return True
        return False

    old_unkillable = simplifier.deadremoval.is_unkillable_destination
    simplifier.deadremoval.is_unkillable_destination = lambda lval, rval: my_is_unkillable(simplifier.deadremoval, lval, rval)

    simplifier.passes.append(propagate_stk_lvl)
    simplifier.passes.append(del_above_stk_write)
    simplifier.passes.append(remove_self_interference)

    simplifier.cpt = 0
    ircfg = simplifier.simplify(ircfg_a, head)
    open('final.dot', 'w').write(ircfg.dot())

    """
    from miasm.analysis.data_flow import PropagateWithSymbolicExec
    print("PROPAG")
    xx = PropagateWithSymbolicExec(ir_arch_a, ircfg_a)
    xx.simplify(head)
    xx.do_replacement(head)
    open('out.dot', 'w').write(ircfg.dot())
    """
