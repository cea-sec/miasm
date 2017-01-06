import os
from argparse import ArgumentParser
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.analysis.machine import Machine
from pdb import pm

parser = ArgumentParser(description="x86 32 basic Jitter")
parser.add_argument("-j", "--jitter",
                    help="Jitter engine. Possible values are : tcc (default), llvm",
                    default="tcc")
args = parser.parse_args()

# Shellcode

# main:
#       MOV EAX, 0x1
# loop_main:
#       CMP EAX, 0x10
#       JZ loop_end
# loop_inc:
#       INC EAX
#       JMP loop_main
# loop_end:
#       RET
data = "b80100000083f810740340ebf8c3".decode("hex")
run_addr = 0x40000000

def code_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True

def init_jitter():
    global data, run_addr
    # Create jitter
    myjit = Machine("x86_32").jitter(args.jitter)

    myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)

    # Init jitter
    myjit.init_stack()
    myjit.jit.log_regs = True
    myjit.jit.log_mn = True
    myjit.push_uint32_t(0x1337beef)

    myjit.add_breakpoint(0x1337beef, code_sentinelle)
    return myjit

# Test 'max_exec_per_call'
print "[+] First run, to jit blocks"
myjit = init_jitter()
myjit.init_run(run_addr)
myjit.continue_run()

assert myjit.run is False
assert myjit.cpu.EAX  == 0x10

## Let's specify a max_exec_per_call
## 5: main, loop_main, loop_inc, loop_main, loop_inc
myjit.jit.options["max_exec_per_call"] = 5

first_call = True
def cb(jitter):
    global first_call
    if first_call:
        # Avoid breaking on the first pass (before any execution)
        first_call = False
        return True
    return False

## Second run
print "[+] Second run"
myjit.push_uint32_t(0x1337beef)
myjit.cpu.EAX = 0
myjit.init_run(run_addr)
myjit.exec_cb = cb
myjit.continue_run()

assert myjit.run is True
# Use a '<=' because it's a 'max_...'
assert myjit.cpu.EAX <= 3
