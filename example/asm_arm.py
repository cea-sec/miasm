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

blocs, symbol_pool = parse_asm.parse_txt(my_mn, "arm", '''
main:
  STMFD  SP!, {R4, R5, LR}
  MOV    R0, mystr & 0xffff
  ORR    R0, R0, mystr & 0xffff0000
  MOV    R1, mystrend & 0xffff
  ORR    R1, R1, mystrend & 0xffff0000
xxx:
  LDR    R2, [PC, key-(xxx+8)]
loop:
  LDRB   R3, [R0]
  EOR    R3, R3, R2
  STRB   R3, [R0], 1
  CMP    R0, R1
  BNE    loop
  EOR    R0, R0, R0
  BNE    end
  EOR    R1, R1, R1
  EOR    R2, R2, R2
  EORGE  R1, R1, R1
  EORGE  R2, R2, R2
  ADDLTS R2, R2, R2
  SUBEQ  R2, R2, R2
end:
  LDMFD  SP!, {R4, R5, PC}
key:
.long 0x11223344
mystr:
.string "test string"
mystrend:
.long 0
''')

# fix shellcode addr
symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)

for b in blocs[0]:
    print b
# graph sc####
g = asmbloc.bloc2graph(blocs[0])
open("graph.txt", "w").write(g)

s = StrPatchwork()

print "symbols"
print symbol_pool
# dont erase from start to shell code padading
resolved_b, patches = asmbloc.asm_resolve_final(
    my_mn, 'arm', blocs[0], symbol_pool)
print patches

for offset, raw in patches.items():
    s[offset] = raw

open('demo_arm.bin', 'wb').write(str(s))
