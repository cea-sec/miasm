from pdb import pm

from miasm2.arch.x86.arch import mn_x86
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmblock
from miasm2.arch.x86.ira import ir_a_x86_32
from miasm2.analysis.data_flow import dead_simp

# First, asm code
blocks, symbol_pool = parse_asm.parse_txt(mn_x86, 32, '''
main:
   MOV    EAX, 1
   MOV    EBX, 2
   MOV    ECX, 2
   MOV    DX, 2

loop:
   INC    EBX
   CMOVZ  EAX, EBX
   ADD    EAX, ECX
   JZ     loop
   RET
''')


symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)
for block in blocks:
    print block


print "symbols:"
print symbol_pool
patches = asmblock.asm_resolve_final(mn_x86, blocks, symbol_pool)

# Translate to IR
ir_arch = ir_a_x86_32(symbol_pool)
for block in blocks:
    print 'add block'
    print block
    ir_arch.add_bloc(block)

# Display IR
for lbl, irblock in ir_arch.blocks.items():
    print irblock

# Dead propagation
open('graph.dot', 'w').write(ir_arch.graph.dot())
print '*' * 80
dead_simp(ir_arch)
open('graph2.dot', 'w').write(ir_arch.graph.dot())

# Display new IR
print 'new ir blocks'
for lbl, irblock in ir_arch.blocks.items():
    print irblock
