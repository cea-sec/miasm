from miasm.arch.ia32_sem import *
from miasm.arch.ia32_arch import x86_mn
from miasm.core import asmbloc
from miasm.core.bin_stream import bin_stream
from miasm.tools.emul_helper import *

from elfesteem import pe_init
import sys

print 'simple expression use for generating dataflow graph'

def get_rw(exprs):
    o_r = set()
    o_w = set()
    for e in exprs:
        o_r.update(e.get_r(mem_read=True))
        if isinstance(e.dst, ExprMem):
            o_r.update(e.dst.arg.get_r(mem_read=True))
    for e in exprs:
        o_w.update(e.get_w())
    return o_r, o_w


def bloc2expr(b):
    out = []
    for i, l in enumerate(b.lines):
        print i, l
        args = []
        ex = get_instr_expr(l, ExprInt(uint32(l.offset)), args)
        out.append(ex)
    return out

def node_x_2_id(n, x):
    return hash(str(n)+str(x))& 0xffffffffffffffff

def gen_bloc_data_flow_graph(b):
    out_str = """
digraph asm_graph {
size="80,50";
node [
fontsize = "16",
shape = "box"
];

"""
    all_lines = bloc2expr(b)
    current_nodes = {}
    out = []
    all_nodes = {}
    out_str_2 = ""
    for i, exprs in enumerate(all_lines):
        n_r, n_w = get_rw(exprs)
        src = []
        for n in n_r:
            x = current_nodes.get(n, 0)
            current_nodes[n] = x
            src.append(((n, x), i))
        dst = []
        for n in n_w:
            x = current_nodes.get(n, 0) + 1
            current_nodes[n] = x
            dst.append((i, (n, x)))
        out.append((src, dst))
    for src, dst in out:
        #print "---"
        print src
        print dst
        for (n, x), i in src:
            #print node_x_2_id(n, x), i
            out_str_2 += "%s -> %s\n"%(node_x_2_id(n, x), i)
            all_nodes[node_x_2_id(n, x)] = (n, x)

        for i, (n, x) in dst:
            out_str_2 += "%s -> %s\n"%(i, node_x_2_id(n, x))
            all_nodes[node_x_2_id(n, x)] = (n, i)


    for n, v in all_nodes.items():
        out_str += '%s [label=\n"%s"\n];\n'%(n, str(v[1])+"_"+str(v[0]))
    for i, l in enumerate(b.lines):
        out_str += '%s [fillcolor=lightblue,style=filled,label=\n"%s"\n];\n'%(i, str(i)+" "+str(l))
    out_str += out_str_2
    out_str+="};\n"
    open('out.txt', 'w').write(out_str)

if len(sys.argv) != 2:
    print "%s sc_connect_back.bin"%sys.argv[0]
    sys.exit(-1)
data = open(sys.argv[1]).read()
in_str = bin_stream(data)

job_done = set()
symbol_pool = asmbloc.asm_symbol_pool()
l = asmbloc.asm_label('toto')
b = asmbloc.asm_bloc(l)

ad = 0x2E
asmbloc.dis_bloc(x86_mn, in_str, b, ad, job_done, symbol_pool)
print 'generating dataflow graph for:'
gen_bloc_data_flow_graph(b)

print """
Generate ps with pdf:
 dot -Tps out.txt -o graph.ps
or:
 dotty out.txt
"""
