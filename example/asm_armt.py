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

txt = '''
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
'''

blocs_b, symbol_pool_b = parse_asm.parse_txt(my_mn, "b", txt)
blocs_l, symbol_pool_l = parse_asm.parse_txt(my_mn, "l", txt)

# fix shellcode addr
symbol_pool_b.set_offset(symbol_pool_b.getby_name("main"), 0)
symbol_pool_l.set_offset(symbol_pool_l.getby_name("main"), 0)

# graph sc####
g = asmbloc.bloc2graph(blocs_b[0])
open("graph.txt", "w").write(g)

s_b = StrPatchwork()
s_l = StrPatchwork()

print "symbols"
print symbol_pool_b
# dont erase from start to shell code padading
resolved_b, patches_b = asmbloc.asm_resolve_final(
    my_mn, blocs_b[0], symbol_pool_b)
resolved__l, patches_l = asmbloc.asm_resolve_final(
    my_mn, blocs_l[0], symbol_pool_l)
print patches_b
print patches_l



for offset, raw in patches_b.items():
    s_b[offset] = raw
for offset, raw in patches_l.items():
    s_l[offset] = raw

open('demo_armt_b.bin', 'wb').write(str(s_b))
open('demo_armt_l.bin', 'wb').write(str(s_l))
