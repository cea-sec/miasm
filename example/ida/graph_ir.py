import os
import tempfile

import idaapi
import idc
import idautils

from miasm2.core.bin_stream_ida import bin_stream_ida
from miasm2.core.asmblock import is_int
from miasm2.expression.simplifications import expr_simp

from miasm2.analysis.data_flow import dead_simp, DiGraphDefUse, \
    ReachingDefinitions, merge_blocks, remove_empty_assignblks, \
    PropagateExpr, replace_stack_vars, load_from_int, dead_simp, remove_empty_assignblks, \
    read_mem, get_memlookup

from miasm2.expression.simplifications import expr_simp
from miasm2.analysis.ssa import SSADiGraph, remove_phi
from miasm2.ir.ir import AssignBlock, IRBlock
from utils import guess_machine, expr2colorstr
from miasm2.expression.expression import ExprLoc, ExprMem, ExprId, ExprInt


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
    else:
        return "%s:%s" % (self.name, str(self.offset))



def color_irblock(irblock, ir_arch):
    out = []
    lbl = idaapi.COLSTR(ir_arch.loc_db.pretty_str(irblock.loc_key), idaapi.SCOLOR_INSN)
    out.append(lbl)
    for assignblk in irblock:
        for dst, src in sorted(assignblk.iteritems()):
            dst_f = expr2colorstr(dst, loc_db=ir_arch.loc_db)
            src_f = expr2colorstr(src, loc_db=ir_arch.loc_db)
            line = idaapi.COLSTR("%s = %s" % (dst_f, src_f), idaapi.SCOLOR_INSN)
            out.append('    %s' % line)
        out.append("")
    out.pop()
    dst = str('    Dst: %s' % irblock.dst)
    dst = idaapi.COLSTR(dst, idaapi.SCOLOR_RPTCMT)
    out.append(dst)
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

    def OnSelect(self, node_id):
        return True

    def OnClick(self, node_id):
        return True

    def Show(self):
        if not idaapi.GraphViewer.Show(self):
            return False
        return True


def build_graph(verbose=False, simplify=False, ssa=False, ssa_simplify=False):
    start_addr = idc.ScreenEA()

    machine = guess_machine(addr=start_addr)
    dis_engine, ira = machine.dis_engine, machine.ira


    if verbose:
        print "Arch", dis_engine

    fname = idc.GetInputFile()
    if verbose:
        print fname

    bs = bin_stream_ida()
    mdis = dis_engine(bs)
    ir_arch = ira(mdis.loc_db)

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
        print hex(addr)

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

    graph = GraphMiasmIR(ircfg, title, None)

    if ssa:
        if len(entry_points) != 1:
            raise RuntimeError("Your graph should have only one head")
        head = list(entry_points)[0]
        ssa = SSADiGraph(ircfg)
        ssa.transform(head)
        title += " (SSA)"
        graph = GraphMiasmIR(ssa.graph, title, None)

    if ssa_simplify:
        class IRAOutRegs(ira):
            def get_out_regs(self, block):
                regs_todo = super(self.__class__, self).get_out_regs(block)
                out = {}
                for assignblk in block:
                    for dst in assignblk:
                        reg = self.ssa_var.get(dst, None)
                        if reg is None:
                            continue
                        if reg in regs_todo:
                            out[reg] = dst
                return set(out.values())

        # Add dummy dependecy to uncover out regs affectation
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


        ir_arch.ssa_var = {}
        index = 0
        modified = True
        ssa_forbidden_regs = set([
            ir_arch.pc,
            ir_arch.IRDst,
            ir_arch.arch.regs.exception_flags
        ])

        head = list(entry_points)[0]
        heads = set([head])
        all_ssa_vars = set()

        propagate_expr = PropagateExpr()


        while modified:
            ssa = SSADiGraph(ircfg)
            ssa.immutable_ids.update(ssa_forbidden_regs)

            ssa.transform(head)

            all_ssa_vars.update(ssa._ssa_variable_to_expr)

            ssa_regs = [reg for reg in ssa.expressions if reg.is_id()]
            ssa_forbidden_regs.update(ssa_regs)


            ir_arch.ssa_var.update(ssa._ssa_variable_to_expr)

            while modified:
                index += 1
                modified = False
                modified |= propagate_expr.propagate(ssa, head)
                modified |= ircfg.simplify(expr_simp)
                simp_modified = True
                while simp_modified:
                    index += 1
                    simp_modified = False
                    simp_modified |= dead_simp(ir_arch, ircfg)
                    index += 1
                    simp_modified |= remove_empty_assignblks(ircfg)
                    simp_modified |= merge_blocks(ircfg, heads)
                    simp_modified |= load_from_int(ircfg, bs, is_addr_ro_variable)
                    modified |= simp_modified
                    index += 1


        merge_blocks(ircfg, heads)
        ssa = SSADiGraph(ircfg)
        ssa.immutable_ids.update(ssa_forbidden_regs)
        ssa.transform(head)
        all_ssa_vars.update(ssa._ssa_variable_to_expr)
        ssa._ssa_variable_to_expr = all_ssa_vars
        dead_simp(ir_arch, ssa.graph)

        title += " (SSA Simplified)"
        graph = GraphMiasmIR(ssa.graph, title, None)


    graph.Show()

if __name__ == "__main__":
    build_graph(verbose=True, simplify=False)
