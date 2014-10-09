#! /usr/bin/env python

from miasm2.core.cpu import parse_ast
from miasm2.arch.arm.arch import mn_arm, base_expr, variable
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmbloc
from elfesteem.strpatchwork import StrPatchwork

my_mn = mn_arm

reg_and_id = dict(mn_arm.regs.all_regs_ids_byname)


def my_ast_int2expr(a):
    return ExprInt32(a)


def my_ast_id2expr(t):
    return reg_and_id.get(t, ExprId(t, size=32))

my_var_parser = parse_ast(my_ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)

txt = '''
main:
  STMFD  SP!, {R4, R5, LR}
  MOV    R0, mystr & 0xffff
  ORR    R0, R0, mystr & 0xffff0000
  MOV    R4, R0
  MOV    R1, mystrend & 0xffff
  ORR    R1, R1, mystrend & 0xffff0000
xxx:
  LDRB    R2, [PC, key-$]
loop:
  LDRB   R3, [R0]
  EOR    R3, R3, R2
  STRB   R3, [R0], 1
  CMP    R0, R1
  BNE    loop
end:
  MOV    R0, R4
  LDMFD  SP!, {R4, R5, PC}
key:
.byte 0x11
mystr:
.string "test string"
mystrend:
.long 0
'''

blocs_b, symbol_pool_b = parse_asm.parse_txt(my_mn, "b", txt)
blocs_l, symbol_pool_l = parse_asm.parse_txt(my_mn, "l", txt)


# fix shellcode addr
symbol_pool_b.set_offset(symbol_pool_b.getby_name("main"), 0x0)
symbol_pool_l.set_offset(symbol_pool_l.getby_name("main"), 0x0)

# graph sc####
g = asmbloc.bloc2graph(blocs_l[0])
open("graph.txt", "w").write(g)

s_b = StrPatchwork()
s_l = StrPatchwork()

print "symbols"
print symbol_pool_l
# dont erase from start to shell code padading
resolved_b, patches_b = asmbloc.asm_resolve_final(
    my_mn, blocs_b[0], symbol_pool_b)
resolved_l, patches_l = asmbloc.asm_resolve_final(
    my_mn, blocs_l[0], symbol_pool_l)
print patches_b

for offset, raw in patches_b.items():
    s_b[offset] = raw
for offset, raw in patches_l.items():
    s_l[offset] = raw

open('demo_arm_b.bin', 'w').write(str(s_b))
open('demo_arm_l.bin', 'w').write(str(s_l))
