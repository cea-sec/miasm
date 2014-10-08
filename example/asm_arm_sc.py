#! /usr/bin/env python

from miasm2.core.cpu import parse_ast
from miasm2.arch.arm.arch import mn_arm, base_expr, variable
from miasm2.core.bin_stream import bin_stream
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from elfesteem.strpatchwork import StrPatchwork

from pdb import pm
from miasm2.core import asmbloc
import struct

reg_and_id = dict(mn_arm.regs.all_regs_ids_byname)


def my_ast_int2expr(a):
    return ExprInt32(a)


def my_ast_id2expr(t):
    return reg_and_id.get(t, ExprId(t, size=32))

my_var_parser = parse_ast(my_ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)


st = StrPatchwork()

blocs, symbol_pool = parse_asm.parse_txt(mn_arm, 'arm', '''
main:
    MOV R1, R0
    MOV R2, 0x100
    LDR R3, [PC, mykey1-$]
loop:
    ADD R2, R1, R2
    ADD R1, R1, 1
    LDR R3, [PC, mykey2-$]
    CMP R1, R3
    BEQ loop

    ADD R0, R1, R2
    BX LR
mykey1:
.long 0x1
mykey2:
.long 0x2
''')

# fix shellcode addr
symbol_pool.set_offset(symbol_pool.getby_name("main"), 0)

for b in blocs[0]:
    print b

resolved_b, patches = asmbloc.asm_resolve_final(
    mn_arm, blocs[0], symbol_pool)
print patches

for offset, raw in patches.items():
    st[offset] = raw

open('arm_sc.bin', 'wb').write(str(st))
