import sys
from pdb import pm

from future.utils import viewitems

from miasm.loader.strpatchwork import StrPatchwork
from miasm.core import parse_asm
from miasm.expression.expression import ExprCompose, ExprOp, ExprInt, ExprId
from miasm.core.asmblock import asm_resolve_final
from miasm.analysis.machine import Machine
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.dse import DSEEngine
from miasm.core.locationdb import LocationDB


class DSETest(object):

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
        self.loc_db = LocationDB()
        self.machine = Machine(self.arch_name)
        jitter = self.machine.jitter
        self.myjit = jitter(self.loc_db, jitter_engine)
        self.myjit.init_stack()

        self.myjit.set_trace_log()

        self.dse = None
        self.assembly = None

    def init_machine(self):
        self.myjit.vm.add_memory_page(self.run_addr,
                                      PAGE_READ | PAGE_WRITE,
                                      self.assembly)
        self.myjit.push_uint32_t(self.ret_addr)
        self.myjit.add_breakpoint(self.ret_addr, lambda x: False)

    def prepare(self):
        self.myjit.cpu.ECX = 4
        self.myjit.cpu.EDX = 5

        self.dse = DSEEngine(self.machine, self.loc_db)
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

        assert self.myjit.pc == self.ret_addr

    def asm(self):
        mn_x86 = self.machine.mn
        asmcfg = parse_asm.parse_txt(
            mn_x86,
            self.arch_attrib,
            self.TXT,
            self.loc_db
        )

        # fix shellcode addr
        self.loc_db.set_location_offset(self.loc_db.get_name_location("main"), 0x0)
        output = StrPatchwork()
        patches = asm_resolve_final(mn_x86, asmcfg)
        for offset, raw in viewitems(patches):
            output[offset] = raw

        self.assembly = bytes(output)

    def check(self):
        regs = self.dse.lifter.arch.regs
        value = self.dse.eval_expr(regs.EDX)
        # The expected value should contains '<<', showing it has been in the
        # corresponding generated label
        expected = ExprOp('<<', regs.EDX,
                          ExprCompose(regs.ECX[0:8],
                                      ExprInt(0x0, 24)) & ExprInt(0x1F, 32))
        assert value == expected


class DSEAttachInBreakpoint(DSETest):

    """
    Test that DSE is "attachable" in a jitter breakpoint
    """
    TXT = '''
    main:
        MOV    EAX, 5
        ADD    EBX, 6
        INC    EBX
        RET
    '''

    def __init__(self, *args, **kwargs):
        super(DSEAttachInBreakpoint, self).__init__(*args, **kwargs)
        self._dse = None
        lifter_cls = self.machine.lifter
        self._regs = lifter_cls(self.loc_db).arch.regs
        self._testid = ExprId("TEST", self._regs.EBX.size)

    def bp_attach(self, jitter):
        """Attach a DSE in the current jitter"""
        self.dse = DSEEngine(self.machine, self.loc_db)
        self.dse.attach(self.myjit)
        self.dse.update_state_from_concrete()
        self.dse.update_state({
            self._regs.EBX: self._testid,
        })

        # Additional call to the exec callback is necessary, as breakpoints are
        # honored AFTER exec callback
        jitter.exec_cb(jitter)

        return True

    def prepare(self):
        pass

    def init_machine(self):
        super(DSEAttachInBreakpoint, self).init_machine()
        self.myjit.add_breakpoint(5, self.bp_attach)  # On ADD EBX, 6

    def check(self):
        value = self.dse.eval_expr(self._regs.EBX)
        # EBX = TEST
        # ADD EBX, 6
        # INC EBX
        # -> EBX_final = TEST + 7
        assert value == self._testid + ExprInt(7, self._regs.EBX.size)


if __name__ == "__main__":
    jit_engine = sys.argv[1]
    for test in [
            DSETest,
            DSEAttachInBreakpoint,
    ]:
        test(jit_engine)()
