from __future__ import print_function
import sys

from miasm.core.utils import decode_hex
from miasm.analysis.machine import Machine
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, \
    EXCEPT_BREAKPOINT_MEMORY, EXCEPT_ACCESS_VIOL
from miasm.core.locationdb import LocationDB
from miasm.jitter.jitload import JitterException

def mem_breakpoint_handler(jitter):
    print("======")
    print("Data access caught!")

    mem_r = jitter.vm.get_memory_read()
    if len(mem_r) > 0:
        for s, e in mem_r:
            print("%s - %s" % (hex(s), hex(e - s)))
    else:
        print("No read")

    mem_w = jitter.vm.get_memory_write()
    if len(mem_w) > 0:
        for s, e in mem_w:
            print("%s - %s" % (hex(s), hex(e - s)))
    else:
        print("No write")

    print("pc = %s" % (hex(jitter.cpu.PC)))
    print("[DBG] vm.exception = %d" % (jitter.vm.get_exception()))
    print("======")

    # Cleanup
    jitter.vm.set_exception(0)
    jitter.vm.reset_memory_access()

    return True

machine = Machine("aarch64l")
loc_db = LocationDB()
jitter = machine.jitter(loc_db, sys.argv[1])

start_addr = 0xFFFFFF8008080000
end_addr = start_addr + 0x8000000
jitter.vm.add_memory_page(start_addr, PAGE_READ|PAGE_WRITE, b"\x00"*(end_addr - start_addr), "code page")

jitter.vm.add_memory_page(0x10000000, PAGE_READ|PAGE_WRITE, b"\x00"*0x1000, "stack")
jitter.cpu.SP = 0x10000000 + 0x1000

jitter.vm.reset_memory_access()

'''
FFFFFF800901EBEC FD 7B BE A9                 STP             X29, X30, [SP,#var_20]!
FFFFFF800901EBF0 01 00 80 52                 MOV             W1, #0
FFFFFF800901EBF4 FD 03 00 91                 MOV             X29, SP
FFFFFF800901EBF8 A2 63 00 91                 ADD             X2, X29, #0x18
FFFFFF800901EBFC 00 00 80 52                 MOV             W0, 1
FFFFFF800901EC00 C0 00 00 35                 CBNZ            W0, loc_FFFFFF800901EC18
FFFFFF800901EC04 A0 0F 40 F9                 LDR             X0, [X29,#0x20+var_8]
FFFFFF800901EC08 1F 00 1F EB                 CMP             X0, XZR
FFFFFF800901EC0C 60 19 00 90                 ADRP            X0, #0xFFFFFF800934A6C4@PAGE
FFFFFF800901EC10 E1 07 9F 1A                 CSET            W1, NE
FFFFFF800901EC14 01 C4 06 B9                 STR             W1, [X0,#0xFFFFFF800934A6C4@PAGEOFF]
FFFFFF800901EC18 20 00 80 52                 MOV             W0, #1
FFFFFF800901EC1C FD 7B C2 A8                 LDP             X29, X30, [SP+0x20+var_20],#0x20
FFFFFF800901EC20 C0 03 5F D6                 RET
'''
jitter.vm.set_mem(0xFFFFFF800901EBEC, decode_hex("FD7BBEA901008052FD030091A263009100008052C0000035A00F40F91F001FEB60190090E1079F1A01C406B920008052FD7BC2A8C0035FD6"))

# print(jitter.vm)

jitter.set_trace_log()

jitter.add_exception_handler(EXCEPT_BREAKPOINT_MEMORY, mem_breakpoint_handler)
jitter.vm.add_memory_breakpoint(0xFFFFFF8009080000, 0x8000000, PAGE_READ | PAGE_WRITE)

jitter.init_run(0xFFFFFF800901EBEC)

try:
    jitter.continue_run()
except JitterException:
    assert jitter.vm.get_exception() == EXCEPT_ACCESS_VIOL

