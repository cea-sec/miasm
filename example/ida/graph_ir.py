import sys
import os
import tempfile

from idaapi import GraphViewer

from miasm2.core.bin_stream_ida import bin_stream_ida
from miasm2.core.asmblock import *
from miasm2.expression.simplifications import expr_simp
from miasm2.expression.expression import *
from miasm2.analysis.data_analysis import inter_bloc_flow, \
    intra_bloc_flow_symbexec
from miasm2.analysis.data_flow import dead_simp
from utils import guess_machine, expr2colorstr


def color_irbloc(irbloc):
    o = []
    lbl = '%s' % irbloc.label
    lbl = idaapi.COLSTR(lbl, idaapi.SCOLOR_INSN)
    o.append(lbl)
    for assignblk in irbloc.irs:
        for dst, src in sorted(assignblk.iteritems()):
            dst_f = expr2colorstr(ir_arch.arch.regs.all_regs_ids, dst)
            src_f = expr2colorstr(ir_arch.arch.regs.all_regs_ids, src)
            s = idaapi.COLSTR("%s = %s" % (dst_f, src_f), idaapi.SCOLOR_INSN)
            o.append('    %s' % s)
        o.append("")
    o.pop()
    i = len(irbloc.irs)
    s = str('    Dst: %s' % irbloc.dst)
    s = idaapi.COLSTR(s, idaapi.SCOLOR_RPTCMT)
    o.append(s)

    return "\n".join(o)


class GraphMiasmIR(GraphViewer):

    def __init__(self, ir_arch, title, result):
        GraphViewer.__init__(self, title)
        print 'init'
        self.ir_arch = ir_arch
        self.result = result
        self.names = {}

    def OnRefresh(self):
        print 'refresh'
        self.Clear()
        addr_id = {}
        for irbloc in self.ir_arch.blocks.values():
            id_irbloc = self.AddNode(color_irbloc(irbloc))
            addr_id[irbloc] = id_irbloc

        for irbloc in self.ir_arch.blocks.values():
            if not irbloc:
                continue
            dst = ir_arch.dst_trackback(irbloc)
            for d in dst:
                if not expr_is_label(d):
                    continue

                d = d.name
                if not d in self.ir_arch.blocks:
                    continue
                b = self.ir_arch.blocks[d]
                node1 = addr_id[irbloc]
                node2 = addr_id[b]
                self.AddEdge(node1, node2)
        return True

    def OnGetText(self, node_id):
        b = self[node_id]
        return str(b)

    def OnSelect(self, node_id):
        return True

    def OnClick(self, node_id):
        return True

    def OnCommand(self, cmd_id):
        if self.cmd_test == cmd_id:
            print 'TEST!'
            return
        print "command:", cmd_id

    def Show(self):
        if not GraphViewer.Show(self):
            return False
        self.cmd_test = self.AddCommand("Test", "F2")
        if self.cmd_test == 0:
            print "Failed to add popup menu item!"
        return True


machine = guess_machine()
mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira

print "Arch", dis_engine

fname = GetInputFile()
print fname

bs = bin_stream_ida()
mdis = dis_engine(bs)
ir_arch = ira(mdis.symbol_pool)

# populate symbols with ida names
for ad, name in Names():
    # print hex(ad), repr(name)
    if name is None:
        continue
    mdis.symbol_pool.add_label(name, ad)

print "start disasm"
ad = ScreenEA()
print hex(ad)

ab = mdis.dis_multibloc(ad)

print "generating graph"
open('asm_flow.dot', 'w').write(ab.dot())


print "generating IR... %x" % ad

for block in ab:
    print 'ADD'
    print block
    ir_arch.add_bloc(block)


print "IR ok... %x" % ad

for irb in ir_arch.blocks.values():
    for assignblk in irb.irs:
        for dst, src in assignblk.items():
            del(assignblk[dst])
            dst, src = expr_simp(dst), expr_simp(src)
            assignblk[dst] = src

out = ir_arch.graph.dot()
open(os.path.join(tempfile.gettempdir(), 'graph.dot'), 'wb').write(out)


# dead_simp(ir_arch)

g = GraphMiasmIR(ir_arch, "Miasm IR graph", None)


def mycb(*test):
    print test
    raise NotImplementedError('not fully functional')

g.cmd_a = g.AddCommand("cmd a", "x")
g.cmd_b = g.AddCommand("cmd b", "y")

g.Show()


def node2str(n):
    label, i, node = n
    print n
    # out = "%s,%s\n%s"%n
    out = "%s" % node
    return out


def get_node_name(label, i, n):
    # n_name = "%s_%d_%s"%(label.name, i, n)
    n_name = (label.name, i, n)
    return n_name


def get_modified_symbols(sb):
    # get modified IDS
    ids = sb.symbols.symbols_id.keys()
    ids.sort()
    out = {}
    for i in ids:
        if i in sb.arch.regs.regs_init and \
                i in sb.symbols.symbols_id and \
                sb.symbols.symbols_id[i] == sb.arch.regs.regs_init[i]:
            continue
        # print i, sb.symbols.symbols_id[i]
        out[i] = sb.symbols.symbols_id[i]

    # get mem IDS
    mems = sb.symbols.symbols_mem.values()
    for m, v in mems:
        # print m, v
        out[m] = v
    pp([(str(x[0]), str(x[1])) for x in out.items()])
    return out


def gen_bloc_data_flow_graph(ir_arch, in_str, ad):  # arch, attrib, pool_bin, bloc, symbol_pool):
    out_str = ""

    # dead_simp(ir_arch)

    irbloc_0 = None
    for irbloc in ir_arch.blocks.values():
        if irbloc.label.offset == ad:
            irbloc_0 = irbloc
            break
    assert(irbloc_0 is not None)
    flow_graph = DiGraph()
    done = set()
    todo = set([irbloc_0.label])

    bloc2w = {}

    for irbloc in ir_arch.blocks.values():
        intra_bloc_flow_symbexec(ir_arch, flow_graph, irbloc)
        # intra_bloc_flow_symb(ir_arch, flow_graph, irbloc)

    for irbloc in ir_arch.blocks.values():
        print irbloc
        print 'IN', [str(x) for x in irbloc.in_nodes]
        print 'OUT', [str(x) for x in irbloc.out_nodes]

    print '*' * 20, 'interbloc', '*' * 20
    inter_bloc_flow(ir_arch, flow_graph, irbloc_0.label, False)

    print 'Dataflow roots:'
    for node in flow_graph.roots():
        lbl, i, n = node
        if n in ir_arch.arch.regs.all_regs_ids:
            print node

    open('data.dot', 'w').write(flow_graph.dot())
    return flow_graph


class GraphMiasmIRFlow(GraphViewer):

    def __init__(self, flow_graph, title, result):
        GraphViewer.__init__(self, title)
        print 'init'
        self.flow_graph = flow_graph
        self.result = result
        self.names = {}

    def OnRefresh(self):
        print 'refresh'
        self.Clear()
        addr_id = {}
        for n in self.flow_graph.nodes():
            id_n = self.AddNode(node2str(self.flow_graph, n))
            addr_id[n] = id_n

        for a, b in self.flow_graph.edges():
                node1, node2 = addr_id[a], addr_id[b]
                self.AddEdge(node1, node2)
        return True

    def OnGetText(self, node_id):
        b = self[node_id]
        return str(b).lower()

    def OnSelect(self, node_id):
        return True

    def OnClick(self, node_id):
        return True

    def OnCommand(self, cmd_id):
        if self.cmd_test == cmd_id:
            print 'TEST!'
            return
        print "command:", cmd_id

    def Show(self):
        if not GraphViewer.Show(self):
            return False
        self.cmd_test = self.AddCommand("Test", "F2")
        if self.cmd_test == 0:
            print "Failed to add popup menu item!"
        return True


#print "gen bloc data flow"
#flow_graph = gen_bloc_data_flow_graph(ir_arch, bs, ad)
#def node2str(self, n):
#    return "%s, %s\\l%s" % n
#flow_graph.node2str = lambda n: node2str(flow_graph, n)
#open('data_flow.dot', 'w').write(flow_graph.dot())

# h =  GraphMiasmIRFlow(flow_graph, "Miasm IRFlow graph", None)
# h.Show()
