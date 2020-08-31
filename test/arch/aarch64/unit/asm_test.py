import sys
import os

from future.utils import viewitems

from miasm.arch.aarch64.arch import mn_aarch64, base_expr, variable
from miasm.core import parse_asm
from miasm.expression.expression import *
from miasm.core import asmblock
from miasm.loader.strpatchwork import StrPatchwork
from miasm.analysis.machine import Machine
from miasm.jitter.csts import *
from miasm.core.locationdb import LocationDB

reg_and_id = dict(mn_aarch64.regs.all_regs_ids_byname)

class Asm_Test(object):
    def __init__(self, jitter):
        self.loc_db = LocationDB()
        self.myjit = Machine("aarch64l").jitter(self.loc_db, jitter)
        self.myjit.init_stack()

    def __call__(self):
        self.asm()
        self.run()
        self.check()

    def asm(self):
        asmcfg = parse_asm.parse_txt(mn_aarch64, 'l', self.TXT, self.loc_db)
        # fix shellcode addr
        self.loc_db.set_location_offset(self.loc_db.get_name_location("main"), 0x0)
        s = StrPatchwork()
        patches = asmblock.asm_resolve_final(mn_aarch64, asmcfg)
        for offset, raw in viewitems(patches):
            s[offset] = raw

        self.assembly = bytes(s)

    def run(self):
        run_addr = 0
        self.myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, self.assembly)

        self.myjit.cpu.LR = 0x1337beef

        self.myjit.add_breakpoint(0x1337beef, lambda x:False)

        self.myjit.init_run(run_addr)
        self.myjit.continue_run()

        assert(self.myjit.pc == 0x1337beef)

    def check(self):
        raise NotImplementedError('abstract method')
