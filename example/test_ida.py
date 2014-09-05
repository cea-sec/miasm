import sys

# Set your path first!
sys.path.append("/home/serpilliere/tools/pyparsing/pyparsing-2.0.1/build/lib.linux-x86_64-2.7")
sys.path.append("/home/serpilliere/projet/m2_devel/build/lib.linux-x86_64-2.7")

from miasm2.core.bin_stream import bin_stream_str
from miasm2.core.asmbloc import *
from miasm2.expression.simplifications import expr_simp
from miasm2.expression.expression import *

from miasm2.analysis.data_analysis import intra_bloc_flow_raw, inter_bloc_flow
from miasm2.analysis.data_analysis import intra_bloc_flow_symbexec

from idaapi import *
import idautils


class bin_stream_ida(bin_stream_str):
    # ida should provide Byte function

    # dont generate xrange using address computation:
    # it can raise error on overflow 7FFFFFFF with 32 bit python
    def getbytes(self, start, l=1):
        o = ""
        for ad in xrange(l):
            o += chr(Byte(ad + start - self.shift))
        return o

    def readbs(self, l=1):
        if self.offset + l > self.l:
            raise IOError
        o = self.getbytes(self.offset)
        self.offset += l
        return p

    def writebs(self, l=1):
        raise ValueError('writebs unsupported')

    def __str__(self):
        raise NotImplementedError('not fully functional')
        out = self.bin[self.offset - self.shift:]
        return out

    def setoffset(self, val):
        self.offset = val

    def __len__(self):
        return 0x7FFFFFFF

    def getlen(self):
        return 0x7FFFFFFF - self.offset - self.shift


def expr2colorstr(ir_arch, e):
    # print "XXX", e
    if isinstance(e, ExprId):
        s = str(e)
        if e in ir_arch.arch.regs.all_regs_ids:
            s = idaapi.COLSTR(s, idaapi.SCOLOR_REG)
    elif isinstance(e, ExprInt):
        s = str(e)
        s = idaapi.COLSTR(s, idaapi.SCOLOR_NUMBER)
    elif isinstance(e, ExprMem):
        s = '@%d[%s]' % (e.size, expr2colorstr(ir_arch, e.arg))
    elif isinstance(e, ExprOp):
        out = []
        for a in e.args:
            s = expr2colorstr(ir_arch, a)
            if isinstance(a, ExprOp):
                s = "(%s)" % s
            out.append(s)
        if len(out) == 1:
            s = "%s %s" % (e.op, str(out[0]))
        else:
            s = (" " + e.op + " ").join(out)
    elif isinstance(e, ExprAff):
        s = "%s = %s" % (
            expr2colorstr(ir_arch, e.dst), expr2colorstr(ir_arch, e.src))
    elif isinstance(e, ExprCond):
        cond = expr2colorstr(ir_arch, e.cond)
        src1 = expr2colorstr(ir_arch, e.src1)
        src2 = expr2colorstr(ir_arch, e.src2)
        s = "(%s?%s:%s)" % (cond, src1, src2)
    elif isinstance(e, ExprSlice):
        s = "(%s)[%d:%d]" % (expr2colorstr(ir_arch, e.arg), e.start, e.stop)
    else:
        s = str(e)
    # print repr(s)
    return s


def color_irbloc(irbloc):
    o = []
    lbl = '%s' % irbloc.label
    lbl = idaapi.COLSTR(lbl, idaapi.SCOLOR_INSN)
    o.append(lbl)
    for i, expr in enumerate(irbloc.irs):
        for e in expr:
            s = expr2colorstr(ir_arch, e)
            s = idaapi.COLSTR(s, idaapi.SCOLOR_INSN)
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
        for irbloc in self.ir_arch.blocs.values():
            id_irbloc = self.AddNode(color_irbloc(irbloc))
            addr_id[irbloc] = id_irbloc

        for irbloc in self.ir_arch.blocs.values():
            if not irbloc:
                continue
            dst = ir_arch.dst_trackback(irbloc)
            for d in dst:
                if not self.ir_arch.ExprIsLabel(d):
                    continue

                d = d.name
                if not d in self.ir_arch.blocs:
                    continue
                b = self.ir_arch.blocs[d]
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


from miasm2.analysis.disasm_cb import guess_funcs, guess_multi_cb


processor_name = GetLongPrm(INF_PROCNAME)
dis_engine = None
if processor_name == "metapc":

    # HACK: check 32/64 using INF_START_SP
    max_size = GetLongPrm(INF_START_SP)
    if max_size == 0x80:  # TODO XXX check
        from miasm2.arch.x86.disasm import dis_x86_16 as dis_engine
        from miasm2.arch.x86.x86.ira import ir_a_x86_16 as ira
    elif max_size == 0xFFFFFFFF:
        from miasm2.arch.x86.disasm import dis_x86_32 as dis_engine
        from miasm2.arch.x86.ira import ir_a_x86_32 as ira

    elif max_size == 0xFFFFFFFFFFFFFFFF:
        from miasm2.arch.x86.disasm import dis_x86_64 as dis_engine
        from miasm2.arch.x86.ira import ir_a_x86_64 as ira

    else:
        raise ValueError('cannot guess 32/64 bit! (%x)' % max_size)
elif processor_name == "ARM":
    # TODO ARM/thumb
    # hack for thumb: place armt = True in globals :/
    is_armt = globals().get('armt', False)
    if is_armt:
        from miasm2.arch.arm.disasm import dis_armt as dis_engine
        from miasm2.arch.arm.ira import ir_a_armt as ira
    else:
        from miasm2.arch.arm.disasm import dis_arm as dis_engine
        from miasm2.arch.arm.ira import ir_a_arm as ira

    from miasm2.analysis.disasm_cb import arm_guess_subcall, arm_guess_jump_table
    guess_funcs.append(arm_guess_subcall)
    guess_funcs.append(arm_guess_jump_table)

elif processor_name == "msp430":
    # TODO ARM/thumb
    from miasm2.arch.msp430.disasm import dis_msp430 as dis_engine
    from miasm2.arch.msp430.ira import ir_a_msp430 as ira
elif processor_name == "mipsl":
    from miasm2.arch.mips32.disasm import dis_mips32l as dis_engine
    from miasm2.arch.mips32.ira import ir_a_mips32 as ira
elif processor_name == "mipsb":
    from miasm2.arch.mips32.disasm import dis_mips32b as dis_engine
    from miasm2.arch.mips32.ira import ir_a_mips32 as ira

else:
    print repr(processor_name)
    raise NotImplementedError('not fully functional')

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
g = bloc2graph(ab, True)
open('asm_flow.txt', 'w').write(g)


print "generating IR... %x" % ad

for b in ab:
    print 'ADD'
    print b
    ir_arch.add_bloc(b)


print "IR ok... %x" % ad

for irb in ir_arch.blocs.values():
    for irs in irb.irs:
        for i, e in enumerate(irs):
            e.dst, e.src = expr_simp(e.dst), expr_simp(e.src)

ir_arch.gen_graph()
out = ir_arch.graph()
open('/tmp/graph.txt', 'w').write(out)


# ir_arch.dead_simp()

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

    ir_arch.gen_graph()
    # ir_arch.dead_simp()

    irbloc_0 = None
    for irbloc in ir_arch.blocs.values():
        if irbloc.label.offset == ad:
            irbloc_0 = irbloc
            break
    assert(irbloc_0 is not None)
    flow_graph = DiGraph()
    done = set()
    todo = set([irbloc_0.label])

    bloc2w = {}

    for irbloc in ir_arch.blocs.values():
        # intra_bloc_flow_raw(ir_arch, flow_graph, irbloc)
        intra_bloc_flow_symbexec(ir_arch, flow_graph, irbloc)
        # intra_bloc_flow_symb(ir_arch, flow_graph, irbloc)

    for irbloc in ir_arch.blocs.values():
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

    open('data.txt', 'w').write(flow_graph.dot())
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
#open('data_flow.txt', 'w').write(flow_graph.dot())

# h =  GraphMiasmIRFlow(flow_graph, "Miasm IRFlow graph", None)
# h.Show()
