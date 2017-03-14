import sys
import os

from miasm2.core.cpu import ParseAst
from miasm2.arch.mips32.arch import mn_mips32, base_expr, variable
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmblock
from elfesteem.strpatchwork import StrPatchwork
from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import *


reg_and_id = dict(mn_mips32.regs.all_regs_ids_byname)

class Asm_Test(object):

    def __init__(self, jitter):
        self.myjit = Machine("mips32l").jitter(jitter)
        self.myjit.init_stack()

        self.myjit.jit.log_regs = False
        self.myjit.jit.log_mn = False

    def __call__(self):
        self.asm()
        self.run()
        self.check()

    def asm(self):
        blocks, symbol_pool = parse_asm.parse_txt(mn_mips32, 'l', self.TXT,
                                                  symbol_pool=self.myjit.ir_arch.symbol_pool)
        # fix shellcode addr
        symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)
        s = StrPatchwork()
        patches = asmblock.asm_resolve_final(mn_mips32, blocks, symbol_pool)
        for offset, raw in patches.items():
            s[offset] = raw

        s = str(s)
        self.assembly = s

    def run(self):
        run_addr = 0
        self.myjit.vm.add_memory_page(
            run_addr, PAGE_READ | PAGE_WRITE, self.assembly)

        self.myjit.cpu.RA = 0x1337beef

        self.myjit.add_breakpoint(0x1337beef, lambda x: False)

        self.myjit.init_run(run_addr)
        self.myjit.continue_run()

        assert(self.myjit.pc == 0x1337beef)

    def check(self):
        raise NotImplementedError('abstract method')
