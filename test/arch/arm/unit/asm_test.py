from builtins import str
from builtins import object
import sys
import os

from future.utils import viewitems

from miasm.arch.arm.arch import mn_arm, base_expr, variable
from miasm.core import parse_asm
from miasm.expression.expression import *
from miasm.core import asmblock
from miasm.loader.strpatchwork import StrPatchwork
from miasm.analysis.machine import Machine
from miasm.jitter.csts import *

reg_and_id = dict(mn_arm.regs.all_regs_ids_byname)

class Asm_Test(object):
    run_addr = 0x0

    def __init__(self, jitter_engine):
        self.myjit = Machine(self.arch_name).jitter(jitter_engine)
        self.myjit.init_stack()

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
        blocks, loc_db = parse_asm.parse_txt(
            mn_arm, self.arch_attrib, self.TXT,
            loc_db = self.myjit.ir_arch.loc_db
        )
        # fix shellcode addr
        loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)
        s = StrPatchwork()
        patches = asmblock.asm_resolve_final(mn_arm, blocks, loc_db)
        for offset, raw in viewitems(patches):
            s[offset] = raw

        s = bytes(s)
        self.assembly = s

    def check(self):
        raise NotImplementedError('abstract method')


class Asm_Test(Asm_Test):
    arch_name = "arml"
    arch_attrib = "l"
    ret_addr = 0x1330

    def init_machine(self):
        self.myjit.vm.add_memory_page(self.run_addr, PAGE_READ | PAGE_WRITE, self.assembly)
        self.myjit.push_uint32_t(self.ret_addr)
        self.myjit.add_breakpoint(self.ret_addr, lambda x:False)

