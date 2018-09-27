# BLX bit 0 indicates whether the destination code is interpreted as Thumb code.
# However, Thumb code or not, bit 0 should be ignored to compute the destination
# address.
# In this test, if bit 0 is not ignored, decoding the EOR instruction will fail
# because byte 0x80 will be skipped.

from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC

def bp_end(jitter):
    assert(jitter.cpu.R0 == 0)
    return False

machine = Machine("armtl")
jitter = machine.jitter("python")

jitter.vm.add_memory_page(0x1000, PAGE_READ | PAGE_EXEC, "\x00" * 0x10, "test")

jitter.cpu.R0 = 0x1003
jitter.vm.set_mem(0x1000, "\x80\x47") # BLX R0
jitter.vm.set_mem(0x1002, "\x80\xea\x00\x00") # EOR R0, R0

jitter.init_run(0x1000)
jitter.add_breakpoint(0x1006, bp_end)
jitter.add_breakpoint(0x1007, bp_end)
jitter.continue_run()
