from __future__ import print_function
import sys
import subprocess
from optparse import OptionParser
from pdb import pm

from future.utils import viewitems

from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from miasm2.expression.expression import ExprInt, ExprCond, ExprId, \
    get_expr_ids, ExprAssign, ExprLoc
from miasm2.core.bin_stream import bin_stream_str
from miasm2.ir.symbexec import SymbolicExecutionEngine, get_block
from miasm2.expression.simplifications import expr_simp
from miasm2.core import parse_asm
from miasm2.ir.translators.translator  import Translator

machine = Machine("x86_32")


parser = OptionParser(usage="usage: %prog [options] file")
parser.add_option('-a', "--address", dest="address", metavar="ADDRESS",
                  help="address to disasemble", default="0")

(options, args) = parser.parse_args(sys.argv[1:])
if not args:
    parser.print_help()
    sys.exit(0)


def emul_symb(ir_arch, ircfg, mdis, states_todo, states_done):
    while states_todo:
        addr, symbols, conds = states_todo.pop()
        print('*' * 40, "addr", addr, '*' * 40)
        if (addr, symbols, conds) in states_done:
            print('Known state, skipping', addr)
            continue
        states_done.add((addr, symbols, conds))
        symbexec = SymbolicExecutionEngine(ir_arch)
        symbexec.symbols = symbols.copy()
        if ir_arch.pc in symbexec.symbols:
            del symbexec.symbols[ir_arch.pc]
        irblock = get_block(ir_arch, ircfg, mdis, addr)

        print('Run block:')
        print(irblock)
        addr = symbexec.eval_updt_irblock(irblock)
        print('Final state:')
        symbexec.dump(mems=False)

        assert addr is not None
        if isinstance(addr, ExprCond):
            # Create 2 states, each including complementary conditions
            cond_group_a = {addr.cond: ExprInt(0, addr.cond.size)}
            cond_group_b = {addr.cond: ExprInt(1, addr.cond.size)}
            addr_a = expr_simp(symbexec.eval_expr(addr.replace_expr(cond_group_a), {}))
            addr_b = expr_simp(symbexec.eval_expr(addr.replace_expr(cond_group_b), {}))
            if not (addr_a.is_int() or addr_a.is_loc() and
                    addr_b.is_int() or addr_b.is_loc()):
                print(str(addr_a), str(addr_b))
                raise ValueError("Unsupported condition")
            if isinstance(addr_a, ExprInt):
                addr_a = int(addr_a.arg)
            if isinstance(addr_b, ExprInt):
                addr_b = int(addr_b.arg)
            states_todo.add((addr_a, symbexec.symbols.copy(), tuple(list(conds) + list(viewitems(cond_group_a)))))
            states_todo.add((addr_b, symbexec.symbols.copy(), tuple(list(conds) + list(viewitems(cond_group_b)))))
        elif addr == ret_addr:
            print('Return address reached')
            continue
        elif addr.is_int():
            addr = int(addr.arg)
            states_todo.add((addr, symbexec.symbols.copy(), tuple(conds)))
        elif addr.is_loc():
            states_todo.add((addr, symbexec.symbols.copy(), tuple(conds)))
        else:
            raise ValueError("Unsupported destination")


if __name__ == '__main__':

    translator_smt2 = Translator.to_language("smt2")

    addr = int(options.address, 16)

    cont = Container.from_stream(open(args[0], 'rb'))
    mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)
    ir_arch = machine.ir(mdis.loc_db)
    ircfg = ir_arch.new_ircfg()
    symbexec = SymbolicExecutionEngine(ir_arch)

    asmcfg, loc_db = parse_asm.parse_txt(machine.mn, 32, '''
    init:
    PUSH argv
    PUSH argc
    PUSH ret_addr
    ''',
    loc_db=mdis.loc_db)


    argc_lbl = loc_db.get_name_location('argc')
    argv_lbl = loc_db.get_name_location('argv')
    ret_addr_lbl = loc_db.get_name_location('ret_addr')
    init_lbl = loc_db.get_name_location('init')

    argc_loc = ExprLoc(argc_lbl, 32)
    argv_loc = ExprLoc(argv_lbl, 32)
    ret_addr_loc = ExprLoc(ret_addr_lbl, 32)


    ret_addr = ExprId("ret_addr", ret_addr_loc.size)

    fix_args = {
        argc_loc: ExprId("argc", argc_loc.size),
        argv_loc: ExprId("argv", argv_loc.size),
        ret_addr_loc: ret_addr,
    }



    block = asmcfg.loc_key_to_block(init_lbl)
    for instr in block.lines:
        for i, arg in enumerate(instr.args):
            instr.args[i]= arg.replace_expr(fix_args)
    print(block)

    # add fake address and len to parsed instructions
    ir_arch.add_asmblock_to_ircfg(block, ircfg)
    irb = ircfg.blocks[init_lbl]
    symbexec.eval_updt_irblock(irb)
    symbexec.dump(ids=False)
    # reset ir_arch blocks
    ir_arch.blocks = {}

    states_todo = set()
    states_done = set()
    states_todo.add((addr, symbexec.symbols, ()))

    # emul blocks, propagate states
    emul_symb(ir_arch, ircfg, mdis, states_todo, states_done)

    all_info = []

    print('*' * 40, 'conditions to match', '*' * 40)
    for addr, symbols, conds in sorted(states_done, key=str):
        print('*' * 40, addr, '*' * 40)
        reqs = []
        for k, v in conds:
            print(k, v)
            reqs.append((k, v))
        all_info.append((addr, reqs))

    all_cases = set()

    symbexec = SymbolicExecutionEngine(ir_arch)
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
            cond = translator_smt2.from_expr(ExprAssign(expr_test, value))
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
            print("Cannot find stp binary!")
            break
        for c in cases.split('\n'):
            if c.startswith('ASSERT'):
                all_cases.add((addr, c))

    print('*' * 40, 'ALL COND', '*' * 40)
    all_cases = list(all_cases)
    all_cases.sort(key=lambda x: (x[0], x[1]))
    for addr, val in all_cases:
        print('Address:', addr, 'is reachable using argc', val)
