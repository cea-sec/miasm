from __future__ import print_function
from pdb import pm

from future.utils import viewitems

from miasm2.arch.x86.arch import mn_x86
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmblock
from miasm2.arch.x86.ira import ir_a_x86_32
from miasm2.analysis.data_flow import dead_simp


# First, asm code
asmcfg, loc_db = parse_asm.parse_txt(mn_x86, 32, '''
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


loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)
for block in asmcfg.blocks:
    print(block)


print("symbols:")
print(loc_db)
patches = asmblock.asm_resolve_final(mn_x86, asmcfg, loc_db)

# Translate to IR
ir_arch = ir_a_x86_32(loc_db)
ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

# Display IR
for lbl, irblock in viewitems(ircfg.blocks):
    print(irblock)

# Dead propagation
open('graph.dot', 'w').write(ircfg.dot())
print('*' * 80)
dead_simp(ir_arch, ircfg)
open('graph2.dot', 'w').write(ircfg.dot())

# Display new IR
print('new ir blocks')
for lbl, irblock in viewitems(ircfg.blocks):
    print(irblock)
