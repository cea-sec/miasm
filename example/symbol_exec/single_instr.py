# Minimalist Symbol Exec example
from miasm2.core.bin_stream                 import bin_stream_str
from miasm2.arch.x86.arch                   import mn_x86
from miasm2.arch.x86.ira                    import ir_a_x86_32
from miasm2.arch.x86.regs                   import regs_init
from miasm2.ir.symbexec                     import symbexec
from miasm2.arch.x86.disasm                 import dis_x86_32 as dis_engine
from miasm2.expression.expression           import ExprId

START_ADDR = 0

# Assemble and disassemble a MOV
## Ensure that attributes 'offset' and 'l' are set
line = mn_x86.fromstring("MOV EAX, EBX", 32)
asm = mn_x86.asm(line)[0]

# Get back block
bin_stream = bin_stream_str(asm)
mdis = dis_engine(bin_stream)
asm_block = mdis.dis_bloc(START_ADDR)

# Translate ASM -> IR
ir = ir_a_x86_32(mdis.symbol_pool)
ir.add_bloc(asm_block)

# Instanciate a Symbolic Execution engine with default value for registers
## EAX = EAX_init, ...
symb = symbexec(ir, regs_init)

# Emulate one IR basic block
## Emulation of several basic blocks can be done through .emul_ir_blocs
cur_addr = symb.emul_ir_bloc(ir, START_ADDR)

# Modified elements
print 'Modified registers:'
symb.dump_id()
print 'Modified memory (should be empty):'
symb.dump_mem()

# Check final status
eax, ebx = map(ExprId, ["EAX", "EBX"])
assert symb.symbols[eax] == regs_init[ebx]
assert eax in symb.modified()
