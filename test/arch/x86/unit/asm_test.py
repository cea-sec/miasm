#! /usr/bin/env python
import sys
import os

from miasm2.core.cpu import parse_ast
from miasm2.arch.x86.arch import mn_x86, base_expr, variable
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmbloc
from elfesteem.strpatchwork import StrPatchwork
from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import *
from pdb import pm


filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


reg_and_id = dict(mn_x86.regs.all_regs_ids_byname)


def my_ast_int2expr(a):
    return ExprInt32(a)


def my_ast_id2expr(t):
    return reg_and_id.get(t, ExprId(t, size=32))

my_var_parser = parse_ast(my_ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)


class Asm_Test(object):
    def __init__(self):
        self.myjit = Machine("x86_32").jitter()
        self.myjit.init_stack()

        self.myjit.jit.log_regs = False
        self.myjit.jit.log_mn = False


    def __call__(self):
        self.asm()
        self.run()
        self.check()


    def asm(self):
        blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 32, self.TXT,
                                                 symbol_pool = self.myjit.ir_arch.symbol_pool)
        # fix shellcode addr
        symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)
        s = StrPatchwork()
        resolved_b, patches = asmbloc.asm_resolve_final(
            mn_x86, '32', blocs[0], symbol_pool)
        for offset, raw in patches.items():
            s[offset] = raw

        s = str(s)
        self.assembly = s

    def run(self):
        run_addr = 0
        self.myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, self.assembly)

        self.myjit.push_uint32_t(0x1337beef)

        self.myjit.add_breakpoint(0x1337beef, lambda x:False)

        self.myjit.init_run(run_addr)
        self.myjit.continue_run()

        assert(self.myjit.pc == 0x1337beef)

    def check(self):
        raise NotImplementedError('abstract method')
