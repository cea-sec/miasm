from __future__ import print_function
from argparse import ArgumentParser

from future.utils import viewitems, viewvalues

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.expression.expression import get_expr_mem
from miasm.analysis.data_analysis import intra_block_flow_raw, inter_block_flow
from miasm.core.graph import DiGraph
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.analysis.data_flow import DeadRemoval
from miasm.core.locationdb import LocationDB


parser = ArgumentParser(description="Simple expression use for generating dataflow graph")
parser.add_argument("filename", help="File to analyse")
parser.add_argument("addr", help="Function's address")
parser.add_argument("-s", "--symb", help="Symbolic execution mode",
                    action="store_true")
args = parser.parse_args()


def get_node_name(label, i, n):
    n_name = (label, i, n)
    return n_name


def intra_block_flow_symb(lifter, _, flow_graph, irblock, in_nodes, out_nodes):
    symbols_init = lifter.arch.regs.regs_init.copy()
    sb = SymbolicExecutionEngine(lifter, symbols_init)
    sb.eval_updt_irblock(irblock)
    print('*' * 40)
    print(irblock)


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


def node2str(node):
    out = "%s,%s\\l\\\n%s" % node
    return out


def gen_block_data_flow_graph(lifter, ircfg, ad, block_flow_cb):
    for irblock in viewvalues(ircfg.blocks):
        print(irblock)

    deadrm(ircfg)


    irblock_0 = None
    for irblock in viewvalues(ircfg.blocks):
        loc_key = irblock.loc_key
        offset = ircfg.loc_db.get_location_offset(loc_key)
        if offset == ad:
            irblock_0 = irblock
            break
    assert irblock_0 is not None
    flow_graph = DiGraph()
    flow_graph.node2str = node2str


    irb_in_nodes = {}
    irb_out_nodes = {}
    for label in ircfg.blocks:
        irb_in_nodes[label] = {}
        irb_out_nodes[label] = {}

    for label, irblock in viewitems(ircfg.blocks):
        block_flow_cb(lifter, ircfg, flow_graph, irblock, irb_in_nodes[label], irb_out_nodes[label])

    for label in ircfg.blocks:
        print(label)
        print('IN', [str(x) for x in irb_in_nodes[label]])
        print('OUT', [str(x) for x in irb_out_nodes[label]])

    print('*' * 20, 'interblock', '*' * 20)
    inter_block_flow(lifter, ircfg, flow_graph, irblock_0.loc_key, irb_in_nodes, irb_out_nodes)

    # from graph_qt import graph_qt
    # graph_qt(flow_graph)
    open('data.dot', 'w').write(flow_graph.dot())


ad = int(args.addr, 16)
loc_db = LocationDB()
print('disasm...')
cont = Container.from_stream(open(args.filename, 'rb'), loc_db)
machine = Machine("x86_32")

mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
mdis.follow_call = True
asmcfg = mdis.dis_multiblock(ad)
print('ok')


print('generating dataflow graph for:')
lifter = machine.lifter_model_call(loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
deadrm = DeadRemoval(lifter)


for irblock in viewvalues(ircfg.blocks):
    print(irblock)


if args.symb:
    block_flow_cb = intra_block_flow_symb
else:
    block_flow_cb = intra_block_flow_raw

gen_block_data_flow_graph(lifter, ircfg, ad, block_flow_cb)

print('*' * 40)
print("""
 View with:
dotty data.dot
 or
xdot data.dot
 or
 Generate ps with pdf:
dot -Tps data.dot -o graph.ps
""")
