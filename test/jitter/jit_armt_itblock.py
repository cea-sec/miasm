import sys
from miasm.core.utils import decode_hex
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_UNK_MNEMO
from miasm.analysis.machine import Machine
from miasm.analysis.dse import DSEEngine

machine = Machine('armtl')

jitter = machine.jitter(sys.argv[1])

jitter.init_stack()

"""
CMP             R0, #0
IT NE
ADD             R0, #1
ADD             R0, #1
ADD             R0, #1
ADD             R0, #1
"""
data = decode_hex("002818bf0130013001300130")

run_addr = 0x40000000

def end_instruction(jitter):
    return False

jitter.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)
jitter.add_breakpoint(0x40000000 + 2 * 5, end_instruction)

jitter.set_trace_log()

dse = DSEEngine(machine)
dse.attach(jitter)

snapshot = dse.take_snapshot()

jitter.cpu.R0 = 1
# jitter.cpu.R0 = 0

dse.update_state_from_concrete()

jitter.init_run(run_addr)
jitter.continue_run()

assert jitter.cpu.R0 == 4

