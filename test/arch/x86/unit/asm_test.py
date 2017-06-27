import sys
import os

from miasm2.core.cpu import ParseAst
from miasm2.arch.x86.arch import mn_x86, base_expr, variable
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmblock
from elfesteem.strpatchwork import StrPatchwork
from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import *

reg_and_id = dict(mn_x86.regs.all_regs_ids_byname)

class Asm_Test(object):
    run_addr = 0x0

    def __init__(self, jitter_engine):
        self.myjit = Machine(self.arch_name).jitter(jitter_engine)
        self.myjit.init_stack()

        self.myjit.jit.log_regs = False
        self.myjit.jit.log_mn = False

    def test_init(self):
        pass

    def prepare(self):
        pass

    def __call__(self):
        self.prepare()
        self.asm()
        self.init_machine()
        self.test_init()
        self.run()
        self.check()

    def run(self):

        self.myjit.init_run(self.run_addr)
        self.myjit.continue_run()

        assert(self.myjit.pc == self.ret_addr)

    def asm(self):
        blocks, symbol_pool = parse_asm.parse_txt(mn_x86, self.arch_attrib, self.TXT,
                                                  symbol_pool = self.myjit.ir_arch.symbol_pool)
        # fix shellcode addr
        symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)
        s = StrPatchwork()
        patches = asmblock.asm_resolve_final(mn_x86, blocks, symbol_pool)
        for offset, raw in patches.items():
            s[offset] = raw

        s = str(s)
        self.assembly = s

    def check(self):
        raise NotImplementedError('abstract method')


class Asm_Test_32(Asm_Test):
    arch_name = "x86_32"
    arch_attrib = 32
    ret_addr = 0x1337beef

    def init_machine(self):
        self.myjit.vm.add_memory_page(self.run_addr, PAGE_READ | PAGE_WRITE, self.assembly)
        self.myjit.push_uint32_t(self.ret_addr)
        self.myjit.add_breakpoint(self.ret_addr, lambda x:False)


class Asm_Test_16(Asm_Test):
    arch_name = "x86_16"
    arch_attrib = 16
    ret_addr = 0x1337

    def __init__(self, jitter_engine):
        self.myjit = Machine(self.arch_name).jitter(jitter_engine)
        self.myjit.stack_base = 0x1000
        self.myjit.stack_size = 0x1000
        self.myjit.init_stack()

        self.myjit.jit.log_regs = False
        self.myjit.jit.log_mn = False


    def init_machine(self):
        self.myjit.vm.add_memory_page(self.run_addr, PAGE_READ | PAGE_WRITE, self.assembly)
        self.myjit.push_uint16_t(self.ret_addr)
        self.myjit.add_breakpoint(self.ret_addr, lambda x:False)

class Asm_Test_64(Asm_Test):
    arch_name = "x86_64"
    arch_attrib = 64
    ret_addr = 0x1337beef

    def init_machine(self):
        self.myjit.vm.add_memory_page(self.run_addr, PAGE_READ | PAGE_WRITE, self.assembly)
        self.myjit.push_uint64_t(self.ret_addr)
        self.myjit.add_breakpoint(self.ret_addr, lambda x:False)
