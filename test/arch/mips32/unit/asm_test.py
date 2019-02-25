import sys
import os

from future.utils import viewitems

from miasm2.arch.mips32.arch import mn_mips32
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

    def __call__(self):
        self.asm()
        self.run()
        self.check()

    def asm(self):
        blocks, loc_db = parse_asm.parse_txt(mn_mips32, 'l', self.TXT,
                                                  loc_db=self.myjit.ir_arch.loc_db)
        # fix shellcode addr
        loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)
        s = StrPatchwork()
        patches = asmblock.asm_resolve_final(mn_mips32, blocks, loc_db)
        for offset, raw in viewitems(patches):
            s[offset] = raw

        s = bytes(s)
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
