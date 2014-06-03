import os
import sys
from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp
from miasm2.arch.x86.ira import ir_a_x86_32
from miasm2.arch.x86.arch import mn_x86
from miasm2.core import asmbloc
from miasm2.core.bin_stream import bin_stream_str
from elfesteem import pe_init
from optparse import OptionParser
from pdb import pm
from miasm2.ir.ir import ir
from miasm2.arch.x86.regs import *
from miasm2.arch.x86.disasm import dis_x86_32

from miasm2.analysis.data_analysis import intra_bloc_flow_raw, inter_bloc_flow

from miasm2.core.graph import DiGraph
from miasm2.ir.symbexec import symbexec

from pprint import pprint as pp

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

print """
Simple expression use for generating dataflow graph
Exemple:
python manip_expression4.py  sc_connect_back.bin 0x2e
"""


parser = OptionParser(usage="usage: %prog [options] sc_connect_back.bin")

(options, args) = parser.parse_args(sys.argv[1:])
if len(args) != 2:
    parser.print_help()
    sys.exit(0)


def node_x_2_id(n, x):
    return hash(str(n) + str(x)) & 0xffffffffffffffff


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
        print m, v
        out[m] = v
    pp([(str(x[0]), str(x[1])) for x in out.items()])
    return out


def intra_bloc_flow_symb(my_ir, flow_graph, irbloc):
    symbols_init = {}
    for i, r in enumerate(all_regs_ids):
        symbols_init[r] = all_regs_ids_init[i]
    sb = symbexec(mn_x86, symbols_init)
    sb.emulbloc(irbloc)
    print '*' * 40
    print irbloc
    # sb.dump_mem()
    # sb.dump_id()
    in_nodes = {}
    out_nodes = {}

    out = get_modified_symbols(sb)
    current_nodes = {}
    # gen mem arg to mem node links
    for dst, src in out.items():
        for n in [dst, src]:

            all_mems = set()
            all_mems.update(get_expr_mem(n))

        for n in all_mems:
            node_n_w = get_node_name(irbloc.label, 0, n)
            if not n == src:
                continue
            o_r = n.arg.get_r(mem_read=False, cst_read=True)
            for n_r in o_r:
                if n_r in current_nodes:
                    node_n_r = current_nodes[n_r]
                else:
                    node_n_r = get_node_name(irbloc.label, i, n_r)
                if not n_r in in_nodes:
                    in_nodes[n_r] = node_n_r
                flow_graph.add_uniq_edge(node_n_r, node_n_w)

    # gen data flow links
    for dst, src in out.items():
        nodes_r = src.get_r(mem_read=False, cst_read=True)
        nodes_w = set([dst])
        for n_r in nodes_r:
            if n_r in current_nodes:
                node_n_r = current_nodes[n_r]
            else:
                node_n_r = get_node_name(irbloc.label, 0, n_r)
            if not n_r in in_nodes:
                in_nodes[n_r] = node_n_r

            flow_graph.add_node(node_n_r)
            for n_w in nodes_w:
                node_n_w = get_node_name(irbloc.label, 1, n_w)
                out_nodes[n_w] = node_n_w

                flow_graph.add_node(node_n_w)
                flow_graph.add_uniq_edge(node_n_r, node_n_w)

    irbloc.in_nodes = in_nodes
    irbloc.out_nodes = out_nodes


def node2str(self, n):
    label, i, node = n
    # print n
    out = "%s,%s\\l\\\n%s" % n
    return out


def gen_bloc_data_flow_graph(my_ir, in_str, ad):  # arch, attrib, pool_bin, bloc, symbol_pool):
    out_str = ""

    # my_ir = ir_x86_32(symbol_pool)

    for irbloc in my_ir.blocs.values():
        print irbloc

    my_ir.gen_graph()
    my_ir.dead_simp()

    irbloc_0 = None
    for irbloc in my_ir.blocs.values():
        if irbloc.label.offset == ad:
            irbloc_0 = irbloc
            break
    assert(irbloc_0 is not None)
    flow_graph = DiGraph()
    flow_graph.node2str = lambda n: node2str(flow_graph, n)
    done = set()
    todo = set([irbloc_0.label])

    bloc2w = {}

    for irbloc in my_ir.blocs.values():
        intra_bloc_flow_raw(my_ir, flow_graph, irbloc)
        # intra_bloc_flow_symb(my_ir, flow_graph, irbloc)

    for irbloc in my_ir.blocs.values():
        print irbloc
        print 'IN', [str(x) for x in irbloc.in_nodes]
        print 'OUT', [str(x) for x in irbloc.out_nodes]

    print '*' * 20, 'interbloc', '*' * 20
    inter_bloc_flow(my_ir, flow_graph, irbloc_0.label)

    # sys.path.append('/home/serpilliere/projet/m2_devel/miasm2/core')
    # from graph_qt import graph_qt
    # graph_qt(flow_graph)
    open('data.txt', 'w').write(flow_graph.dot())


data = open(args[0]).read()
ad = int(args[1], 16)

print 'disasm...'
mdis = dis_x86_32(data)
mdis.follow_call = True
ab = mdis.dis_multibloc(ad)
print 'ok'


print 'generating dataflow graph for:'
my_ir = ir_a_x86_32(mdis.symbol_pool)

blocs = ab
for bloc in blocs:
    print bloc
    my_ir.add_bloc(bloc)
for irbloc in my_ir.blocs.values():
    print irbloc
    if irbloc.label.offset != 0:
        continue


out_str = gen_bloc_data_flow_graph(my_ir, mdis.bs, ad)

print '*' * 40
print """
 View with:
dotty dataflow.txt
 or
 Generate ps with pdf:
dot -Tps dataflow_xx.txt -o graph.ps
"""
