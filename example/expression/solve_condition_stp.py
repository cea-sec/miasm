import sys
import subprocess
from collections import defaultdict
from optparse import OptionParser
from pdb import pm

from miasm2.arch.x86.arch import *
from miasm2.arch.x86.regs import *
from miasm2.arch.x86.sem import *
from miasm2.core.bin_stream import bin_stream_str
from miasm2.core import asmblock
from miasm2.expression.expression import get_rw
from miasm2.expression.modint import uint32
from miasm2.ir.symbexec import SymbolicExecutionEngine
from miasm2.expression.simplifications import expr_simp
from miasm2.expression import stp
from miasm2.core import parse_asm
from miasm2.arch.x86.disasm import dis_x86_32 as dis_engine


mn = mn_x86

parser = OptionParser(usage="usage: %prog [options] file")
parser.add_option('-a', "--address", dest="address", metavar="ADDRESS",
                  help="address to disasemble", default="0")

(options, args) = parser.parse_args(sys.argv[1:])
if not args:
    parser.print_help()
    sys.exit(0)


def get_block(ir_arch, mdis, ad):
    if isinstance(ad, asmblock.AsmLabel):
        l = ad
    else:
        l = mdis.symbol_pool.getby_offset_create(ad)
    if not l in ir_arch.blocks:
        ad = l.offset
        b = mdis.dis_bloc(ad)
        ir_arch.add_bloc(b)
    b = ir_arch.get_bloc(l)
    if b is None:
        raise LookupError('no block found at that address: %s' % l)
    return b


def emul_symb(ir_arch, mdis, states_todo, states_done):
    while states_todo:
        ad, symbols, conds = states_todo.pop()
        print '*' * 40, "addr", ad, '*' * 40
        if (ad, symbols, conds) in states_done:
            print 'skip', ad
            continue
        states_done.add((ad, symbols, conds))
        sb = SymbolicExecutionEngine(ir_arch, {})
        sb.symbols = symbols.copy()
        if ir_arch.pc in sb.symbols:
            del(sb.symbols[ir_arch.pc])
        b = get_block(ir_arch, mdis, ad)

        print 'run block'
        print b
        # print blocks[ad]
        ad = sb.emulbloc(b)
        print 'final state'
        sb.dump_id()
        print 'dataflow'
        # data_flow_graph_from_expr(sb)

        assert(ad is not None)
        print "DST", ad

        if isinstance(ad, ExprCond):
            # Create 2 states, each including complementary conditions
            p1 = sb.symbols.copy()
            p2 = sb.symbols.copy()
            c1 = {ad.cond: ExprInt(0, ad.cond.size)}
            c2 = {ad.cond: ExprInt(1, ad.cond.size)}
            print ad.cond
            p1[ad.cond] = ExprInt(0, ad.cond.size)
            p2[ad.cond] = ExprInt(1, ad.cond.size)
            ad1 = expr_simp(sb.eval_expr(ad.replace_expr(c1), {}))
            ad2 = expr_simp(sb.eval_expr(ad.replace_expr(c2), {}))
            if not (isinstance(ad1, ExprInt) or (isinstance(ad1, ExprId) and isinstance(ad1.name, asmblock.AsmLabel)) and
                    isinstance(ad2, ExprInt) or (isinstance(ad2, ExprId) and isinstance(ad2.name, asmblock.AsmLabel))):
                print str(ad1), str(ad2)
                raise ValueError("zarb condition")
            conds1 = list(conds) + c1.items()
            conds2 = list(conds) + c2.items()
            if isinstance(ad1, ExprId):
                ad1 = ad1.name
            if isinstance(ad2, ExprId):
                ad2 = ad2.name
            if isinstance(ad1, ExprInt):
                ad1 = ad1.arg
            if isinstance(ad2, ExprInt):
                ad2 = ad2.arg
            states_todo.add((ad1, p1, tuple(conds1)))
            states_todo.add((ad2, p2, tuple(conds2)))
        elif isinstance(ad, ExprInt):
            ad = int(ad.arg)
            states_todo.add((ad, sb.symbols.copy(), tuple(conds)))
        elif isinstance(ad, ExprId) and isinstance(ad.name, asmblock.AsmLabel):
            if isinstance(ad, ExprId):
                ad = ad.name
            states_todo.add((ad, sb.symbols.copy(), tuple(conds)))
        elif ad == ret_addr:
            print 'ret reached'
            continue
        else:
            raise ValueError("zarb eip")


if __name__ == '__main__':

    data = open(args[0]).read()
    bs = bin_stream_str(data)

    mdis = dis_engine(bs)

    ad = int(options.address, 16)

    symbols_init = {}
    for i, r in enumerate(all_regs_ids):
        symbols_init[r] = all_regs_ids_init[i]

    # config parser for 32 bit
    reg_and_id = dict(mn_x86.regs.all_regs_ids_byname)

    def my_ast_int2expr(a):
        return ExprInt(a, 32)

    # Modifify parser to avoid label creation in PUSH argc
    def my_ast_id2expr(string_parsed):
        if string_parsed in reg_and_id:
            return reg_and_id[string_parsed]
        else:
            return ExprId(string_parsed, size=32)

    my_var_parser = ParseAst(my_ast_id2expr, my_ast_int2expr)
    base_expr.setParseAction(my_var_parser)

    argc = ExprId('argc', 32)
    argv = ExprId('argv', 32)
    ret_addr = ExprId('ret_addr')
    reg_and_id[argc.name] = argc
    reg_and_id[argv.name] = argv
    reg_and_id[ret_addr.name] = ret_addr

    my_symbols = [argc, argv, ret_addr]
    my_symbols = dict([(x.name, x) for x in my_symbols])
    my_symbols.update(mn_x86.regs.all_regs_ids_byname)

    ir_arch = ir_x86_32(mdis.symbol_pool)

    sb = SymbolicExecutionEngine(ir_arch, symbols_init)

    blocks, symbol_pool = parse_asm.parse_txt(mn_x86, 32, '''
    PUSH argv
    PUSH argc
    PUSH ret_addr
    ''')


    b = list(blocks)[0]
    print b
    # add fake address and len to parsed instructions
    for i, line in enumerate(b.lines):
        line.offset, line.l = i, 1
    ir_arch.add_bloc(b)
    irb = get_block(ir_arch, mdis, 0)
    sb.emulbloc(irb)
    sb.dump_mem()

    # reset ir_arch blocks
    ir_arch.blocks = {}

    states_todo = set()
    states_done = set()
    states_todo.add((uint32(ad), sb.symbols, ()))

    # emul blocks, propagate states
    emul_symb(ir_arch, mdis, states_todo, states_done)

    all_info = []

    print '*' * 40, 'conditions to match', '*' * 40
    for ad, symbols, conds in sorted(states_done):
        print '*' * 40, ad, '*' * 40
        reqs = []
        for k, v in conds:
            print k, v
            reqs.append((k, v))
        all_info.append((ad, reqs))

    all_cases = set()

    sb = SymbolicExecutionEngine(ir_arch, symbols_init)
    for ad, reqs_cond in all_info:
        all_ids = set()
        for k, v in reqs_cond:
            all_ids.update(get_expr_ids(k))

        out = []

        # declare variables
        for v in all_ids:
            out.append(str(v) + ":" + "BITVECTOR(%d);" % v.size)

        all_csts = []
        for k, v in reqs_cond:
            cst = k.strcst()
            val = v.arg
            assert(val in [0, 1])
            inv = ""
            if val == 1:
                inv = "NOT "
            val = "0" * v.size
            all_csts.append("(%s%s=0bin%s)" % (inv, cst, val))
        if not all_csts:
            continue
        rez = " AND ".join(all_csts)
        out.append("QUERY(NOT (%s));" % rez)
        end = "\n".join(out)
        open('out.dot', 'w').write(end)
        try:
            cases = subprocess.check_output(["/home/serpilliere/tools/stp/stp",
                                             "-p",
                                             "out.dot"])
        except OSError:
            print "ERF, cannot find stp"
            break
        for c in cases.split('\n'):
            if c.startswith('ASSERT'):
                all_cases.add((ad, c))

    print '*' * 40, 'ALL COND', '*' * 40
    all_cases = list(all_cases)
    all_cases.sort(key=lambda x: (x[0], x[1]))
    for ad, val in all_cases:
        print 'address', ad, 'is reachable using argc', val
