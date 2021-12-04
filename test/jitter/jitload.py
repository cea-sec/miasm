import sys
from pdb import pm

from miasm.core.utils import decode_hex, encode_hex
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.machine import Machine
from miasm.expression.expression import ExprId, ExprAssign, ExprInt, ExprMem
from miasm.core.locationdb import LocationDB


# Initial data: from 'example/samples/x86_32_sc.bin'
data = decode_hex("8d49048d5b0180f90174058d5bffeb038d5b0189d8c3")
loc_db = LocationDB()

# Init jitter
myjit = Machine("x86_32").jitter(loc_db, sys.argv[1])
myjit.init_stack()

run_addr = 0x40000000
myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)

# Sentinelle called on terminate
def code_sentinelle(jitter):
    jitter.running = False
    jitter.pc = 0
    return True

myjit.push_uint32_t(0x1337beef)
myjit.add_breakpoint(0x1337beef, code_sentinelle)

# Run
myjit.init_run(run_addr)
myjit.continue_run()

# Check end
assert myjit.running is False

# Check resulting state / accessors
assert myjit.cpu.EAX == 0
assert myjit.cpu.ECX == 4

# Check eval_expr
eax = ExprId("RAX", 64)[:32]
imm0, imm4, imm4_64 = ExprInt(0, 32), ExprInt(4, 32), ExprInt(4, 64)
memdata = ExprMem(ExprInt(run_addr, 32), len(data) * 8)
assert myjit.eval_expr(eax) == imm0
## Due to ExprAssign construction, imm4 is "promoted" to imm4_64
assert myjit.eval_expr(ExprAssign(eax, imm4)) == imm4_64
assert myjit.eval_expr(eax) == imm4
## Changes must be passed on myjit.cpu instance
assert myjit.cpu.EAX == 4
## Memory
assert int(myjit.eval_expr(memdata)) == int(encode_hex(data[::-1]), 16)
