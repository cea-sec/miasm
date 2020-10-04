#! /usr/bin/env python2
#-*- coding:utf-8 -*-

from __future__ import print_function
import unittest
import logging

from future.utils import viewitems

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.arch.wasm.arch import mn_wasm as mn
from miasm.arch.wasm.arch import *
from miasm.arch.wasm.sem import ir_wasm as ir_arch
from miasm.arch.wasm.regs import *
from miasm.expression.expression import *
from miasm.core.locationdb import LocationDB

logging.getLogger('cpuhelper').setLevel(logging.ERROR)
#EXCLUDE_REGS = set([res, ir_arch().IRDst])
EXCLUDE_REGS = set([ir_arch().IRDst])

mode = None

def M(addr):
    return ExprMem(ExprInt(addr, 16), 16)


def compute(asm, inputstate={}, debug=False):
    loc_db = LocationDB()
    sympool = dict(regs_init)
    sympool.update({k: ExprInt(v, k.size) for k, v in viewitems(inputstate)})
    ir_tmp = ir_arch(loc_db)
    ircfg = ir_tmp.new_ircfg()
    symexec = SymbolicExecutionEngine(ir_tmp, sympool)
    instr = mn.fromstring(asm, loc_db, mode)
    code = mn.asm(instr)[0]
    instr = mn.dis(code, mode)
    instr.offset = inputstate.get(PC, 0)
    loc_key = ir_tmp.add_instr_to_ircfg(instr, ircfg)
    symexec.run_at(ircfg, loc_key)
    if debug:
        for k, v in viewitems(symexec.symbols):
            if regs_init.get(k, None) != v:
                print(k, v)
    print(symexec.symbols)
    #fds
    return None
    return {
        k: v.arg.arg for k, v in viewitems(symexec.symbols)
        if k not in EXCLUDE_REGS and regs_init.get(k, None) != v
    }

def computemany(asm_l, inputstate={}, debug=False):
    loc_db = LocationDB()
    sympool = dict(regs_init)
    sympool.update({k: ExprInt(v, k.size) for k, v in viewitems(inputstate)})
    ir_tmp = ir_arch(loc_db)
    ircfg = ir_tmp.new_ircfg()
    symexec = SymbolicExecutionEngine(ir_tmp, sympool)
    i = 0
    print('----------\n{}\n----------'.format('START'))
    print(symexec.symbols)
    for asm in asm_l:
        instr = mn.fromstring(asm, loc_db, mode)
        code = mn.asm(instr)[0]
        instr = mn.dis(code, mode)
        instr.offset = inputstate.get(PC, i*8)
        i += 1
        loc_key = ir_tmp.add_instr_to_ircfg(instr, ircfg)
        symexec.run_at(ircfg, loc_key)

        print('\n\n----------\n{}\n----------'.format(str(instr)))
        print(symexec.symbols)

        if debug:
            for k, v in viewitems(symexec.symbols):
                if regs_init.get(k, None) != v:
                    print(k, v)
    #fds
    return None
    return {
        k: v.arg.arg for k, v in viewitems(symexec.symbols)
        if k not in EXCLUDE_REGS and regs_init.get(k, None) != v
    }

class TestWasmSemantic(unittest.TestCase):
    def test_const(self):
        self.assertEqual(compute('i64.const 0x34'),
                         {})

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestWasmSemantic)
    #report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    #exit(len(report.errors + report.failures))
    print(computemany([
        'i64.const 0x12',
        'i32.const 0x34',
        'drop',
        'i64.const 0x10',
        'i64.const 0x56',
        'i64.add',
        'i64.xor',
        'i64.eqz',
        'drop', # No value on stack here
        'i32.const 0x1',
        'drop',
        'i32.const 0x2',
        'i32.eqz',
        'drop',
        'i64.const 0x1',
        'drop',
        'i32.const 0x2',
        'i32.eqz',
        'i32.const 0x0',
        'i32.eqz',
        'i32.const 0x4',
        'i32.const 0x3',
        'i32.le_u',
        'i32.const 0x4',
        'i32.const 0x5',
        'i32.le_u',
        'i32.const 0x4',
        'i32.const 0x4',
        'i32.lt_u',
        'drop',
        'drop',
        'drop',
        'drop',
        'drop', # No value on stack here
        'i64.const -0x2',
        'i64.popcnt',
        'drop',
        'i64.const -0x1',
        'i32.wrap_i64',
        'i64.extend_i32_s',
        'i32.wrap_i64',
        'i64.extend_i32_u',
        'drop', # No value on stack here
    ]))

