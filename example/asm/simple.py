from __future__ import print_function
from pdb import pm
from pprint import pprint

from miasm.arch.x86.arch import mn_x86
from miasm.core import parse_asm, asmblock
from miasm.core.locationdb import LocationDB

# Assemble code
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

# Set 'main' loc_key's offset
loc_db.set_location_offset(loc_db.get_name_location("main"), 0x0)

# Spread information and resolve instructions offset
patches = asmblock.asm_resolve_final(mn_x86, asmcfg)

# Show resolved asmcfg
for block in asmcfg.blocks:
    print(block)

# Print offset -> bytes
pprint(patches)
