# Minimalist Symbol Exec example
from miasm2.core.bin_stream                 import bin_stream_str
from miasm2.arch.x86.arch                   import mn_x86
from miasm2.arch.x86.ira                    import ir_a_x86_32
from miasm2.arch.x86.regs                   import all_regs_ids, all_regs_ids_init
from miasm2.ir.symbexec                     import symbexec
from miasm2.arch.x86.disasm                 import dis_x86_32 as dis_engine
import miasm2.expression.expression as m2_expr

l = mn_x86.fromstring("MOV EAX, EBX", 32)
asm = mn_x86.asm(l)[0]

bin_stream = bin_stream_str(asm)

mdis = dis_engine(bin_stream)
disasm = mdis.dis_multibloc(0)

ir = ir_a_x86_32(mdis.symbol_pool)
for bbl in disasm: ir.add_bloc(bbl)

symbols_init =  {}
for i, r in enumerate(all_regs_ids):
    symbols_init[r] = all_regs_ids_init[i]
symb = symbexec(ir, symbols_init)

block = ir.get_bloc(0)

cur_addr = symb.emulbloc(block)
assert(symb.symbols[m2_expr.ExprId("EAX")] == symbols_init[m2_expr.ExprId("EBX")])
print 'modified registers:'
symb.dump_id()
