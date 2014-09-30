#! /usr/bin/env python

from miasm2.core.cpu import parse_ast
from miasm2.arch.arm.arch import mn_armt, base_expr, variable
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmbloc
from elfesteem.strpatchwork import StrPatchwork
from pdb import pm

my_mn = mn_armt

reg_and_id = dict(mn_armt.regs.all_regs_ids_byname)


def my_ast_int2expr(a):
    return ExprInt32(a)


def my_ast_id2expr(t):
    return reg_and_id.get(t, ExprId(t, size=32))

my_var_parser = parse_ast(my_ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)

blocs, symbol_pool = parse_asm.parse_txt(my_mn, "armt", '''
memcpy:
     PUSH    {R0-R3, LR}
     B       test_end
loop:
     LDRB    R3, [R1]
     STRB    R3, [R0]
     ADDS    R0, R0, 1
     ADDS    R1, R1, 1
     SUBS    R2, R2, 1
test_end:
     CMP     R2, 0
     BNE     loop
     POP     {R0-R3, PC}
main:
     PUSH    {LR}
     SUB     SP, 0x100
     MOV     R0, SP
     ADD     R1, PC, mystr-$+6
     MOV     R0, R0
     EORS    R2, R2
     ADDS    R2, R2, 0x4
     BL      memcpy
     ADD     SP, 0x100
     POP     {PC}

mystr:
.string "toto"
''')

# fix shellcode addr
symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x3a4b8)

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
    my_mn, 'armt', blocs[0], symbol_pool)
print patches



for offset, raw in patches.items():
    s[offset] = raw

open('demo_armt.bin', 'wb').write(str(s))
