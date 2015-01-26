from pdb import pm
from pprint import pprint

from miasm2.arch.x86.arch import mn_x86
from miasm2.core import parse_asm, asmbloc
import miasm2.expression.expression as m2_expr
from miasm2.core import asmbloc


# Assemble code
blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 32, '''
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

# Set 'main' label's offset
symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)

# Spread information and resolve instructions offset
resolved_b, patches = asmbloc.asm_resolve_final(mn_x86, blocs[0], symbol_pool)

# Show resolved blocs
for bloc in resolved_b:
    print bloc

# Print offset -> bytes
pprint(patches)
