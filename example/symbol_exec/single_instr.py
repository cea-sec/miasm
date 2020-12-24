from __future__ import print_function
# Minimalist Symbol Exec example
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.core.locationdb import LocationDB

START_ADDR = 0
machine = Machine("x86_32")
loc_db = LocationDB()

# Assemble and disassemble a MOV
## Ensure that attributes 'offset' and 'l' are set
line = machine.mn.fromstring("MOV EAX, EBX", loc_db, 32)
asm = machine.mn.asm(line)[0]

# Get back block
cont = Container.from_string(asm, loc_db = loc_db)
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
mdis.lines_wd = 1
asm_block = mdis.dis_block(START_ADDR)

# Translate ASM -> IR
lifter_model_call = machine.lifter_model_call(mdis.loc_db)
ircfg = lifter_model_call.new_ircfg()
lifter_model_call.add_asmblock_to_ircfg(asm_block, ircfg)

# Instantiate a Symbolic Execution engine with default value for registers
symb = SymbolicExecutionEngine(lifter_model_call)

# Emulate one IR basic block
## Emulation of several basic blocks can be done through .emul_ir_blocks
cur_addr = symb.run_at(ircfg, START_ADDR)

# Modified elements
print('Modified registers:')
symb.dump(mems=False)
print('Modified memory (should be empty):')
symb.dump(ids=False)

# Check final status
eax, ebx = lifter_model_call.arch.regs.EAX, lifter_model_call.arch.regs.EBX
assert symb.symbols[eax] == ebx
assert eax in symb.symbols
