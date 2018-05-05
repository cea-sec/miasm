import sys
import subprocess
from optparse import OptionParser
from pdb import pm

from miasm2.analysis.machine import Machine
from miasm2.expression.expression import ExprInt, ExprCond, ExprId, \
    get_expr_ids, ExprAff
from miasm2.core.bin_stream import bin_stream_str
from miasm2.core import asmblock
from miasm2.ir.symbexec import SymbolicExecutionEngine, get_block
from miasm2.expression.simplifications import expr_simp
from miasm2.core import parse_asm
from miasm2.arch.x86.disasm import dis_x86_32 as dis_engine
from miasm2.ir.translators.translator  import Translator


machine = Machine("x86_32")


parser = OptionParser(usage="usage: %prog [options] file")
parser.add_option('-a', "--address", dest="address", metavar="ADDRESS",
                  help="address to disasemble", default="0")

(options, args) = parser.parse_args(sys.argv[1:])
if not args:
    parser.print_help()
    sys.exit(0)


def emul_symb(ir_arch, mdis, states_todo, states_done):
    while states_todo:
        addr, symbols, conds = states_todo.pop()
        print '*' * 40, "addr", addr, '*' * 40
        if (addr, symbols, conds) in states_done:
            print 'Known state, skipping', addr
            continue
        states_done.add((addr, symbols, conds))
        symbexec = SymbolicExecutionEngine(ir_arch, {})
        symbexec.symbols = symbols.copy()
        if ir_arch.pc in symbexec.symbols:
            del symbexec.symbols[ir_arch.pc]
        irblock = get_block(ir_arch, mdis, addr)

        print 'Run block:'
        print irblock
        addr = symbexec.eval_updt_irblock(irblock)
        print 'Final state:'
        symbexec.dump(mems=False)

        assert addr is not None
        if isinstance(addr, ExprCond):
            # Create 2 states, each including complementary conditions
            cond_group_a = {addr.cond: ExprInt(0, addr.cond.size)}
            cond_group_b = {addr.cond: ExprInt(1, addr.cond.size)}
            addr_a = expr_simp(symbexec.eval_expr(addr.replace_expr(cond_group_a), {}))
            addr_b = expr_simp(symbexec.eval_expr(addr.replace_expr(cond_group_b), {}))
            if not (addr_a.is_int() or asmblock.expr_is_label(addr_a) and
                    addr_b.is_int() or asmblock.expr_is_label(addr_b)):
                print str(addr_a), str(addr_b)
                raise ValueError("Unsupported condition")
            if isinstance(addr_a, ExprInt):
                addr_a = int(addr_a.arg)
            if isinstance(addr_b, ExprInt):
                addr_b = int(addr_b.arg)
            states_todo.add((addr_a, symbexec.symbols.copy(), tuple(list(conds) + cond_group_a.items())))
            states_todo.add((addr_b, symbexec.symbols.copy(), tuple(list(conds) + cond_group_b.items())))
        elif addr == ret_addr:
            print 'Return address reached'
            continue
        elif isinstance(addr, ExprInt):
            addr = int(addr.arg)
            states_todo.add((addr, symbexec.symbols.copy(), tuple(conds)))
        elif asmblock.expr_is_label(addr):
            addr = addr.name
            states_todo.add((addr, symbexec.symbols.copy(), tuple(conds)))
        else:
            raise ValueError("Unsupported destination")


if __name__ == '__main__':

    translator_smt2 = Translator.to_language("smt2")
    data = open(args[0]).read()
    bs = bin_stream_str(data)

    mdis = dis_engine(bs)

    addr = int(options.address, 16)

    symbols_init = dict(machine.mn.regs.regs_init)

    ir_arch = machine.ir(mdis.symbol_pool)

    symbexec = SymbolicExecutionEngine(ir_arch, symbols_init)

    blocks, symbol_pool = parse_asm.parse_txt(machine.mn, 32, '''
    PUSH argv
    PUSH argc
    PUSH ret_addr
    ''',
    symbol_pool=mdis.symbol_pool)


    argc_lbl = symbol_pool.getby_name('argc')
    argv_lbl = symbol_pool.getby_name('argv')
    ret_addr_lbl = symbol_pool.getby_name('ret_addr')

    argc = ExprId(argc_lbl, 32)
    argv = ExprId(argv_lbl, 32)
    ret_addr = ExprId(ret_addr_lbl, 32)


    b = list(blocks)[0]
    print b
    # add fake address and len to parsed instructions
    for i, line in enumerate(b.lines):
        line.offset, line.l = i, 1
    ir_arch.add_block(b)
    irb = get_block(ir_arch, mdis, 0)
    symbexec.eval_updt_irblock(irb)
    symbexec.dump(ids=False)

    # reset ir_arch blocks
    ir_arch.blocks = {}

    states_todo = set()
    states_done = set()
    states_todo.add((addr, symbexec.symbols, ()))

    # emul blocks, propagate states
    emul_symb(ir_arch, mdis, states_todo, states_done)

    all_info = []

    print '*' * 40, 'conditions to match', '*' * 40
    for addr, symbols, conds in sorted(states_done):
        print '*' * 40, addr, '*' * 40
        reqs = []
        for k, v in conds:
            print k, v
            reqs.append((k, v))
        all_info.append((addr, reqs))

    all_cases = set()

    symbexec = SymbolicExecutionEngine(ir_arch, symbols_init)
    for addr, reqs_cond in all_info:
        out = ['(set-logic QF_ABV)',
               '(set-info :smt-lib-version 2.0)']

        conditions = []
        all_ids = set()
        for expr, value in reqs_cond:

            all_ids.update(get_expr_ids(expr))
            expr_test = ExprCond(expr,
                                 ExprInt(1, value.size),
                                 ExprInt(0, value.size))
            cond = translator_smt2.from_expr(ExprAff(expr_test, value))
            conditions.append(cond)

        for name in all_ids:
            out.append("(declare-fun %s () (_ BitVec %d))" % (name, name.size))
        if not out:
            continue

        out += conditions
        out.append('(check-sat)')
        open('out.dot', 'w').write('\n'.join(out))
        try:
            cases = subprocess.check_output(["/home/serpilliere/tools/stp/stp",
                                             "-p", '--SMTLIB2',
                                             "out.dot"])
        except OSError:
            print "Cannot find stp binary!"
            break
        for c in cases.split('\n'):
            if c.startswith('ASSERT'):
                all_cases.add((addr, c))

    print '*' * 40, 'ALL COND', '*' * 40
    all_cases = list(all_cases)
    all_cases.sort(key=lambda x: (x[0], x[1]))
    for addr, val in all_cases:
        print 'Address:', addr, 'is reachable using argc', val
