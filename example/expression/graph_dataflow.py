from argparse import ArgumentParser
from pdb import pm
from pprint import pprint

from miasm2.expression.expression import get_expr_mem
from miasm2.arch.x86.ira import ir_a_x86_32
from miasm2.arch.x86.disasm import dis_x86_32
from miasm2.analysis.data_analysis import intra_block_flow_raw, inter_block_flow
from miasm2.core.graph import DiGraph
from miasm2.ir.symbexec import SymbolicExecutionEngine
from miasm2.analysis.data_flow import dead_simp


parser = ArgumentParser("Simple expression use for generating dataflow graph")
parser.add_argument("filename", help="File to analyse")
parser.add_argument("addr", help="Function's address")
parser.add_argument("-s", "--symb", help="Symbolic execution mode",
                    action="store_true")
args = parser.parse_args()


def node_x_2_id(n, x):
    return hash(str(n) + str(x)) & 0xffffffffffffffff


def get_node_name(label, i, n):
    n_name = (label, i, n)
    return n_name


def intra_block_flow_symb(ir_arch, _, flow_graph, irblock, in_nodes, out_nodes):
    symbols_init = ir_arch.arch.regs.regs_init.copy()
    sb = SymbolicExecutionEngine(ir_arch, symbols_init)
    sb.eval_updt_irblock(irblock)
    print '*' * 40
    print irblock


    out = sb.modified(mems=False)
    current_nodes = {}
    # Gen mem arg to mem node links
    for dst, src in out:
        src = sb.eval_expr(dst)
        for n in [dst, src]:

            all_mems = set()
            all_mems.update(get_expr_mem(n))

        for n in all_mems:
            node_n_w = get_node_name(irblock.loc_key, 0, n)
            if not n == src:
                continue
            o_r = n.ptr.get_r(mem_read=False, cst_read=True)
            for i, n_r in enumerate(o_r):
                if n_r in current_nodes:
                    node_n_r = current_nodes[n_r]
                else:
                    node_n_r = get_node_name(irblock.loc_key, i, n_r)
                if not n_r in in_nodes:
                    in_nodes[n_r] = node_n_r
                flow_graph.add_uniq_edge(node_n_r, node_n_w)

    # Gen data flow links
    for dst in out:
        src = sb.eval_expr(dst)
        nodes_r = src.get_r(mem_read=False, cst_read=True)
        nodes_w = set([dst])
        for n_r in nodes_r:
            if n_r in current_nodes:
                node_n_r = current_nodes[n_r]
            else:
                node_n_r = get_node_name(irblock.loc_key, 0, n_r)
            if not n_r in in_nodes:
                in_nodes[n_r] = node_n_r

            flow_graph.add_node(node_n_r)
            for n_w in nodes_w:
                node_n_w = get_node_name(irblock.loc_key, 1, n_w)
                out_nodes[n_w] = node_n_w

                flow_graph.add_node(node_n_w)
                flow_graph.add_uniq_edge(node_n_r, node_n_w)


def node2str(self, node):
    out = "%s,%s\\l\\\n%s" % node
    return out


def gen_block_data_flow_graph(ir_arch, ircfg, ad, block_flow_cb):
    for irblock in ircfg.blocks.values():
        print irblock

    dead_simp(ir_arch, ircfg)


    irblock_0 = None
    for irblock in ircfg.blocks.values():
        loc_key = irblock.loc_key
        offset = ircfg.loc_db.get_location_offset(loc_key)
        if offset == ad:
            irblock_0 = irblock
            break
    assert(irblock_0 is not None)
    flow_graph = DiGraph()
    flow_graph.node2str = lambda n: node2str(flow_graph, n)


    irb_in_nodes = {}
    irb_out_nodes = {}
    for label in ircfg.blocks:
        irb_in_nodes[label] = {}
        irb_out_nodes[label] = {}

    for label, irblock in ircfg.blocks.iteritems():
        block_flow_cb(ir_arch, ircfg, flow_graph, irblock, irb_in_nodes[label], irb_out_nodes[label])

    for label in ircfg.blocks:
        print label
        print 'IN', [str(x) for x in irb_in_nodes[label]]
        print 'OUT', [str(x) for x in irb_out_nodes[label]]

    print '*' * 20, 'interblock', '*' * 20
    inter_block_flow(ir_arch, ircfg, flow_graph, irblock_0.loc_key, irb_in_nodes, irb_out_nodes)

    # from graph_qt import graph_qt
    # graph_qt(flow_graph)
    open('data.dot', 'w').write(flow_graph.dot())


data = open(args.filename).read()
ad = int(args.addr, 16)

print 'disasm...'
mdis = dis_x86_32(data)
mdis.follow_call = True
asmcfg = mdis.dis_multiblock(ad)
print 'ok'


print 'generating dataflow graph for:'
ir_arch = ir_a_x86_32(mdis.loc_db)
ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

for irblock in ircfg.blocks.values():
    print irblock


if args.symb:
    block_flow_cb = intra_block_flow_symb
else:
    block_flow_cb = intra_block_flow_raw

gen_block_data_flow_graph(ir_arch, ircfg, ad, block_flow_cb)

print '*' * 40
print """
 View with:
dotty dataflow.dot
 or
 Generate ps with pdf:
dot -Tps dataflow_xx.dot -o graph.ps
"""
