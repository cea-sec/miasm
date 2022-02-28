from __future__ import print_function
import sys

from miasm.core.utils import decode_hex
from miasm.analysis.machine import Machine
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, \
    EXCEPT_BREAKPOINT_MEMORY, EXCEPT_ACCESS_VIOL
from miasm.core.locationdb import LocationDB
from miasm.jitter.jitload import JitterException

machine = Machine("x86_32")
loc_db = LocationDB()
jitter = machine.jitter(loc_db, sys.argv[1])

# Prepare stack and reset memory accesses to avoid an exception
jitter.vm.add_memory_page(0x10000, PAGE_READ|PAGE_WRITE, b"\x00"*0x1000, "stack")
print(jitter.vm)

jitter.cpu.ESP = 0x10000 + 0x1000
jitter.push_uint32_t(0x0)
jitter.push_uint32_t(0x1337beef)

jitter.vm.reset_memory_access()
print(hex(jitter.vm.get_exception()))

# Add code, and keep memory write pending
jitter.vm.add_memory_page(0x1000, PAGE_READ|PAGE_WRITE, b"\x00"*0x1000, "code page")

# MOV EAX, 0x11223344
# RET
jitter.vm.set_mem(0x1000, decode_hex("B844332211C3"))


jitter.set_trace_log()

def do_not_raise_me(jitter):
    raise ValueError("Should not be here")

jitter.add_exception_handler(EXCEPT_BREAKPOINT_MEMORY, do_not_raise_me)
jitter.vm.add_memory_breakpoint(0x11000-4, 4, PAGE_READ | PAGE_WRITE)

# The memory write pending will raise automod exception
# The RET should not re evaluate PC @ [ESP+4]
jitter.init_run(0x1000)
try:
    jitter.continue_run()
except JitterException:
    assert jitter.vm.get_exception() == EXCEPT_ACCESS_VIOL
