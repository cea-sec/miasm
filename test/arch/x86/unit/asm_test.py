from builtins import str
from builtins import object
import sys
import os

from future.utils import viewitems

from miasm.arch.x86.arch import mn_x86, base_expr, variable
from miasm.core import parse_asm
from miasm.expression.expression import *
from miasm.core import asmblock
from miasm.loader.strpatchwork import StrPatchwork
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import *

reg_and_id = dict(mn_x86.regs.all_regs_ids_byname)
class Asm_Test(object):
    run_addr = 0x0

    def __init__(self, jitter_engine):
        self.loc_db = LocationDB()
        self.myjit = Machine(self.arch_name).jitter(self.loc_db, jitter_engine)
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
        asmcfg = parse_asm.parse_txt(mn_x86, self.arch_attrib, self.TXT, self.loc_db)
        # fix shellcode addr
        self.loc_db.set_location_offset(self.loc_db.get_name_location("main"), 0x0)
        s = StrPatchwork()
        patches = asmblock.asm_resolve_final(mn_x86, asmcfg)
        for offset, raw in viewitems(patches):
            s[offset] = raw

        s = bytes(s)
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
        self.loc_db = LocationDB()
        self.myjit = Machine(self.arch_name).jitter(self.loc_db, jitter_engine)
        self.myjit.stack_base = 0x1000
        self.myjit.stack_size = 0x1000
        self.myjit.init_stack()

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
