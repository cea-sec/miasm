from miasm2.analysis.machine import Machine
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_BREAKPOINT_INTERN, EXCEPT_ACCESS_VIOL
import sys

machine = Machine("x86_32")
jitter = machine.jitter(sys.argv[1])

# Prepare stack and reset memory accesses to avoid an exception
jitter.vm.add_memory_page(0x10000, PAGE_READ|PAGE_WRITE, "\x00"*0x1000, "stack")
print jitter.vm

jitter.cpu.ESP = 0x10000 + 0x1000
jitter.push_uint32_t(0x0)
jitter.push_uint32_t(0x1337beef)

jitter.vm.reset_memory_access()
print hex(jitter.vm.get_exception())

# Add code, and keep memory write pending
jitter.vm.add_memory_page(0x1000, PAGE_READ|PAGE_WRITE, "\x00"*0x1000, "code page")

# MOV EAX, 0x11223344
# RET
jitter.vm.set_mem(0x1000, "B844332211C3".decode('hex'))

jitter.jit.log_mn = True
jitter.jit.log_regs = True

def do_not_raise_me(jitter):
    raise ValueError("Should not be here")

jitter.exceptions_handler.callbacks[EXCEPT_BREAKPOINT_INTERN] = []
jitter.add_exception_handler(EXCEPT_BREAKPOINT_INTERN,
                             do_not_raise_me)
jitter.vm.add_memory_breakpoint(0x11000-4, 4, 7)

# The memory write pending will raise automod execption
# The RET should not re evalueate PC @ [ESP+4]
jitter.init_run(0x1000)
try:
    jitter.continue_run()
except AssertionError:
    assert jitter.vm.get_exception() == EXCEPT_ACCESS_VIOL
except RuntimeError:
    assert sys.argv[1] == 'python'
    assert jitter.vm.get_exception() == EXCEPT_ACCESS_VIOL
