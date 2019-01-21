import os
import tempfile

import idaapi
import ida_kernwin
import idc
import ida_funcs
import idautils
from miasm2.core.asmblock import is_int
from miasm2.core.bin_stream_ida import bin_stream_ida
from miasm2.expression.simplifications import expr_simp
from miasm2.ir.ir import IRBlock, AssignBlock

from miasm2.analysis.ssa import SSADiGraph, UnSSADiGraph, DiGraphLivenessSSA

from miasm2.analysis.data_flow import dead_simp,  \
    merge_blocks, remove_empty_assignblks, \
    PropagateExpr, load_from_int


from utils import guess_machine, expr2colorstr




TYPE_GRAPH_IR = 0
TYPE_GRAPH_IRSSA = 1
TYPE_GRAPH_IRSSAUNSSA = 2

OPTION_GRAPH_CODESIMPLIFY = 1
OPTION_GRAPH_DONTMODSTACK = 2
OPTION_GRAPH_LOADMEMINT = 4


class GraphIRForm(ida_kernwin.Form):

    def __init__(self):
        ida_kernwin.Form.__init__(
            self,
            r"""BUTTON YES* Launch
BUTTON CANCEL NONE
Graph IR Settings

{FormChangeCb}
Analysis:
<Graph IR :{rGraphIR}>
<Graph IR + SSA :{rGraphIRSSA}>
<Graph IR + SSA + UnSSA :{rGraphIRSSAUNSSA}>{cScope}>

Options:
<Simplify code:{rCodeSimplify}>
<Subcalls dont change stack:{rDontModStack}>
<Load static memory:{rLoadMemInt}>{cOptions}>
""",
            {
                'FormChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange),
                'cScope': ida_kernwin.Form.RadGroupControl(
                    (
                        "rGraphIR",
                        "rGraphIRSSA",
                        "rGraphIRSSAUNSSA"
                    )
                ),
                'cOptions': ida_kernwin.Form.ChkGroupControl(
                    (
                        "rCodeSimplify",
                        "rDontModStack",
                        "rLoadMemInt"
                    )
                ),
            }
        )
        form, _ = self.Compile()
        form.rCodeSimplify.checked = True
        form.rDontModStack.checked = False
        form.rLoadMemInt.checked = False

    def OnFormChange(self, _):
        return 1


# Override Miasm asmblock default label naming convention to shrink block size
# in IDA

def label_init(self, name="", offset=None):
    self.fixedblocs = False
    if is_int(name):
        name = "loc_%X" % (int(name) & 0xFFFFFFFFFFFFFFFF)
    self.name = name
    self.attrib = None
    if offset is None:
        self.offset = None
    else:
        self.offset = int(offset)


def label_str(self):
    if isinstance(self.offset, (int, long)):
        return "%s:0x%x" % (self.name, self.offset)
    return "%s:%s" % (self.name, str(self.offset))


def color_irblock(irblock, ir_arch):
    out = []
    lbl = idaapi.COLSTR("%s:" % ir_arch.loc_db.pretty_str(irblock.loc_key), idaapi.SCOLOR_INSN)
    out.append(lbl)
    for assignblk in irblock:
        for dst, src in sorted(assignblk.iteritems()):
            dst_f = expr2colorstr(dst, loc_db=ir_arch.loc_db)
            src_f = expr2colorstr(src, loc_db=ir_arch.loc_db)
            line = idaapi.COLSTR("%s = %s" % (dst_f, src_f), idaapi.SCOLOR_INSN)
            out.append('    %s' % line)
        out.append("")
    out.pop()
    return "\n".join(out)


class GraphMiasmIR(idaapi.GraphViewer):

    def __init__(self, ircfg, title, result):
        idaapi.GraphViewer.__init__(self, title)
        self.ircfg = ircfg
        self.result = result
        self.names = {}

    def OnRefresh(self):
        self.Clear()
        addr_id = {}
        for irblock in self.ircfg.blocks.values():
            id_irblock = self.AddNode(color_irblock(irblock, self.ircfg))
            addr_id[irblock] = id_irblock

        for irblock in self.ircfg.blocks.values():
            if not irblock:
                continue
            all_dst = self.ircfg.dst_trackback(irblock)
            for dst in all_dst:
                if not dst.is_loc():
                    continue
                if not dst.loc_key in self.ircfg.blocks:
                    continue
                dst_block = self.ircfg.blocks[dst.loc_key]
                node1 = addr_id[irblock]
                node2 = addr_id[dst_block]
                self.AddEdge(node1, node2)
        return True

    def OnGetText(self, node_id):
        return str(self[node_id])

    def OnSelect(self, _):
        return True

    def OnClick(self, _):
        return True

    def Show(self):
        if not idaapi.GraphViewer.Show(self):
            return False
        return True


def is_addr_ro_variable(bs, addr, size):
    """
    Return True if address at @addr is a read-only variable.
    WARNING: Quick & Dirty

    @addr: integer representing the address of the variable
    @size: size in bits

    """
    try:
        _ = bs.getbytes(addr, size/8)
    except IOError:
        return False
    return True


def build_graph(start_addr, type_graph, simplify=False, dontmodstack=True, loadint=False, verbose=False):
    machine = guess_machine(addr=start_addr)
    dis_engine, ira = machine.dis_engine, machine.ira

    class IRADelModCallStack(ira):
        def call_effects(self, addr, instr):
            assignblks, extra = super(IRADelModCallStack, self).call_effects(addr, instr)
            if not dontmodstack:
                return assignblks, extra
            out = []
            for assignblk in assignblks:
                dct = dict(assignblk)
                dct = {
                    dst:src for (dst, src) in dct.iteritems() if dst != self.sp
                }
                out.append(AssignBlock(dct, assignblk.instr))
            return out, extra


    if verbose:
        print "Arch", dis_engine

    fname = idc.GetInputFile()
    if verbose:
        print fname

    bs = bin_stream_ida()
    mdis = dis_engine(bs)
    ir_arch = IRADelModCallStack(mdis.loc_db)


    # populate symbols with ida names
    for addr, name in idautils.Names():
        if name is None:
            continue
        if (mdis.loc_db.get_offset_location(addr) or
            mdis.loc_db.get_name_location(name)):
            # Symbol alias
            continue
        mdis.loc_db.add_location(name, addr)

    if verbose:
        print "start disasm"
    if verbose:
        print hex(start_addr)

    asmcfg = mdis.dis_multiblock(start_addr)
    entry_points = set([mdis.loc_db.get_offset_location(start_addr)])
    if verbose:
        print "generating graph"
        open('asm_flow.dot', 'w').write(asmcfg.dot())
        print "generating IR... %x" % start_addr

    ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

    if verbose:
        print "IR ok... %x" % start_addr

    for irb in ircfg.blocks.itervalues():
        irs = []
        for assignblk in irb:
            new_assignblk = {
                expr_simp(dst): expr_simp(src)
                for dst, src in assignblk.iteritems()
            }
            irs.append(AssignBlock(new_assignblk, instr=assignblk.instr))
        ircfg.blocks[irb.loc_key] = IRBlock(irb.loc_key, irs)

    if verbose:
        out = ircfg.dot()
        open(os.path.join(tempfile.gettempdir(), 'graph.dot'), 'wb').write(out)
    title = "Miasm IR graph"


    if simplify:
        dead_simp(ir_arch, ircfg)
        ircfg.simplify(expr_simp)
        modified = True
        while modified:
            modified = False
            modified |= dead_simp(ir_arch, ircfg)
            modified |= remove_empty_assignblks(ircfg)
            modified |= merge_blocks(ircfg, entry_points)
        title += " (simplified)"

    if type_graph == TYPE_GRAPH_IR:
        graph = GraphMiasmIR(ircfg, title, None)
        graph.Show()
        return

    head = list(entry_points)[0]


    class IRAOutRegs(ira):
        def get_out_regs(self, block):
            regs_todo = super(IRAOutRegs, self).get_out_regs(block)
            out = {}
            for assignblk in block:
                for dst in assignblk:
                    reg = self.ssa_var.get(dst, None)
                    if reg is None:
                        continue
                    if reg in regs_todo:
                        out[reg] = dst
            return set(out.values())



    # Add dummy dependency to uncover out regs affectation
    for loc in ircfg.leaves():
        irblock = ircfg.blocks.get(loc)
        if irblock is None:
            continue
        regs = {}
        for reg in ir_arch.get_out_regs(irblock):
            regs[reg] = reg
        assignblks = list(irblock)
        new_assiblk = AssignBlock(regs, assignblks[-1].instr)
        assignblks.append(new_assiblk)
        new_irblock = IRBlock(irblock.loc_key, assignblks)
        ircfg.blocks[loc] = new_irblock

    ir_arch = IRAOutRegs(mdis.loc_db)
    ir_arch.ssa_var = {}
    modified = True
    ssa_forbidden_regs = set([
        ir_arch.pc,
        ir_arch.IRDst,
        ir_arch.arch.regs.exception_flags
    ])

    head = list(entry_points)[0]
    heads = set([head])
    all_ssa_vars = {}

    propagate_expr = PropagateExpr()

    ssa = SSADiGraph(ircfg)
    ssa.immutable_ids.update(ssa_forbidden_regs)
    ssa.ssa_variable_to_expr.update(all_ssa_vars)
    ssa.transform(head)
    all_ssa_vars.update(ssa.ssa_variable_to_expr)

    ir_arch.ssa_var.update(ssa.ssa_variable_to_expr)

    if simplify:

        while modified:
            ssa = SSADiGraph(ircfg)
            ssa.immutable_ids.update(ssa_forbidden_regs)
            ssa.ssa_variable_to_expr.update(all_ssa_vars)
            ssa.transform(head)
            all_ssa_vars.update(ssa.ssa_variable_to_expr)

            ir_arch.ssa_var.update(ssa.ssa_variable_to_expr)

            while modified:
                modified = False
                modified |= propagate_expr.propagate(ssa, head)
                modified |= ircfg.simplify(expr_simp)
                simp_modified = True
                while simp_modified:
                    simp_modified = False
                    simp_modified |= dead_simp(ir_arch, ircfg)
                    simp_modified |= remove_empty_assignblks(ircfg)
                    simp_modified |= load_from_int(ircfg, bs, is_addr_ro_variable)
                    modified |= simp_modified


    ssa = SSADiGraph(ircfg)
    ssa.immutable_ids.update(ssa_forbidden_regs)
    ssa.ssa_variable_to_expr.update(all_ssa_vars)
    ssa.transform(head)
    all_ssa_vars.update(ssa.ssa_variable_to_expr)

    if type_graph == TYPE_GRAPH_IRSSA:
        graph = GraphMiasmIR(ssa.graph, title, None)
        graph.Show()
        return

    if type_graph == TYPE_GRAPH_IRSSAUNSSA:

        cfg_liveness = DiGraphLivenessSSA(ssa.graph)
        cfg_liveness.init_var_info(ir_arch)
        cfg_liveness.compute_liveness()

        UnSSADiGraph(ssa, head, cfg_liveness)
        if simplify:
            modified = True
            while modified:
                modified = False
                modified |= ssa.graph.simplify(expr_simp)
                simp_modified = True
                while simp_modified:
                    simp_modified = False
                    simp_modified |= dead_simp(ir_arch, ssa.graph)
                    simp_modified |= remove_empty_assignblks(ssa.graph)
                    simp_modified |= merge_blocks(ssa.graph, heads)
                    modified |= simp_modified
        graph = GraphMiasmIR(ssa.graph, title, None)
        graph.Show()


def function_graph_ir():
    # Get settings
    settings = GraphIRForm()
    ret = settings.Execute()
    if not ret:
        return

    func = ida_funcs.get_func(idc.ScreenEA())
    func_addr = func.startEA

    build_graph(
        func_addr,
        settings.cScope.value,
        simplify=settings.cOptions.value & OPTION_GRAPH_CODESIMPLIFY,
        dontmodstack=settings.cOptions.value & OPTION_GRAPH_DONTMODSTACK,
        loadint=settings.cOptions.value & OPTION_GRAPH_LOADMEMINT,
        verbose=False
    )
    return

if __name__ == "__main__":
    function_graph_ir()
