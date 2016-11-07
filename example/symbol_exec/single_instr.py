# Minimalist Symbol Exec example
from miasm2.core.bin_stream import bin_stream_str
from miasm2.ir.symbexec import symbexec
from miasm2.analysis.machine import Machine

START_ADDR = 0
machine = Machine("x86_32")

# Assemble and disassemble a MOV
## Ensure that attributes 'offset' and 'l' are set
line = machine.mn.fromstring("MOV EAX, EBX", 32)
asm = machine.mn.asm(line)[0]

# Get back block
bin_stream = bin_stream_str(asm)
mdis = machine.dis_engine(bin_stream)
asm_block = mdis.dis_bloc(START_ADDR)

# Translate ASM -> IR
ira = machine.ira(mdis.symbol_pool)
ira.add_bloc(asm_block)

# Instanciate a Symbolic Execution engine with default value for registers
## EAX = EAX_init, ...
symbols_init = ira.arch.regs.regs_init
symb = symbexec(ira, symbols_init)

# Emulate one IR basic block
## Emulation of several basic blocks can be done through .emul_ir_blocks
cur_addr = symb.emul_ir_block(START_ADDR)

# Modified elements
print 'Modified registers:'
symb.dump_id()
print 'Modified memory (should be empty):'
symb.dump_mem()

# Check final status
eax, ebx = ira.arch.regs.EAX, ira.arch.regs.EBX
assert symb.symbols[eax] == symbols_init[ebx]
assert eax in symb.modified()
