import sys
import os
from pdb import pm

from miasm2.core.cpu import ParseAst
from miasm2.arch.x86.arch import mn_x86, base_expr, variable
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmblock
from elfesteem.strpatchwork import StrPatchwork
from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import *
from miasm2.analysis.dse import DSEEngine

reg_and_id = dict(mn_x86.regs.all_regs_ids_byname)

class DSE_test(object):
    """Inspired from TEST/ARCH/X86

    Test the symbolic execution correctly follow generated labels
    """
    TXT = '''
    main:
        SHL         EDX, CL
        RET
    '''

    arch_name = "x86_32"
    arch_attrib = 32
    ret_addr = 0x1337beef

    run_addr = 0x0

    def __init__(self, jitter_engine):
        self.machine = Machine(self.arch_name)
        self.myjit = self.machine.jitter(jitter_engine)
        self.myjit.init_stack()

        self.myjit.jit.log_regs = False
        self.myjit.jit.log_mn = False

    def init_machine(self):
        self.myjit.vm.add_memory_page(self.run_addr, PAGE_READ | PAGE_WRITE, self.assembly)
        self.myjit.push_uint32_t(self.ret_addr)
        self.myjit.add_breakpoint(self.ret_addr, lambda x:False)

    def prepare(self):
        self.myjit.cpu.ECX = 4
        self.myjit.cpu.EDX = 5

        self.dse = DSEEngine(self.machine)
        self.dse.attach(self.myjit)

    def __call__(self):
        self.asm()
        self.init_machine()
        self.prepare()
        self.run()
        self.check()

    def run(self):

        self.myjit.init_run(self.run_addr)
        self.myjit.continue_run()

        assert(self.myjit.pc == self.ret_addr)

    def asm(self):
        blocks, symbol_pool = parse_asm.parse_txt(mn_x86, self.arch_attrib, self.TXT,
                                                  symbol_pool=self.myjit.ir_arch.symbol_pool)


        # fix shellcode addr
        symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)
        s = StrPatchwork()
        patches = asmblock.asm_resolve_final(mn_x86, blocks, symbol_pool)
        for offset, raw in patches.items():
            s[offset] = raw

        s = str(s)
        self.assembly = s

    def check(self):
        regs = self.dse.ir_arch.arch.regs
        value = self.dse.eval_expr(regs.EDX)
        # The expected value should contains '<<', showing it has been in the
        # corresponding generated label
        expected = ExprOp('<<', regs.EDX,
                          ExprCompose(regs.ECX[0:8],
                                      ExprInt(0x0, 24)) & ExprInt(0x1F, 32))
        assert value == expected

if __name__ == "__main__":
    [test(*sys.argv[1:])() for test in [DSE_test]]
