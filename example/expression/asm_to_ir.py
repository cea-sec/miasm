from __future__ import print_function
from pdb import pm

from future.utils import viewitems

from miasm.arch.x86.arch import mn_x86
from miasm.core import parse_asm
from miasm.expression.expression import *
from miasm.core import asmblock
from miasm.arch.x86.lifter_model_call import LifterModelCall_x86_32
from miasm.analysis.data_flow import DeadRemoval
from miasm.core.locationdb import LocationDB


# First, asm code
loc_db = LocationDB()
asmcfg = parse_asm.parse_txt(
    mn_x86, 32, '''
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
''',
    loc_db
)


loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)
for block in asmcfg.blocks:
    print(block)


print("symbols:")
print(loc_db)
patches = asmblock.asm_resolve_final(mn_x86, asmcfg)

# Translate to IR
lifter = LifterModelCall_x86_32(loc_db)
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
deadrm = DeadRemoval(lifter)


# Display IR
for lbl, irblock in viewitems(ircfg.blocks):
    print(irblock)

# Dead propagation
open('graph.dot', 'w').write(ircfg.dot())
print('*' * 80)
deadrm(ircfg)
open('graph2.dot', 'w').write(ircfg.dot())

# Display new IR
print('new ir blocks')
for lbl, irblock in viewitems(ircfg.blocks):
    print(irblock)
