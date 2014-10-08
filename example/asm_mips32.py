#! /usr/bin/env python

from miasm2.core.cpu import parse_ast
from miasm2.arch.mips32.arch import mn_mips32, base_expr, variable
from miasm2.core.bin_stream import bin_stream
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from elfesteem.strpatchwork import StrPatchwork

from pdb import pm
from miasm2.core import asmbloc
import struct

reg_and_id = dict(mn_mips32.regs.all_regs_ids_byname)


def my_ast_int2expr(a):
    return ExprInt32(a)


def my_ast_id2expr(t):
    return reg_and_id.get(t, ExprId(t, size=32))

my_var_parser = parse_ast(my_ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)


st_l = StrPatchwork()
st_b = StrPatchwork()

txt = '''
main:
    ADDIU      A0, ZERO, 0x10
    ADDIU      A1, ZERO, 0
loop:
    ADDIU      A1, A1, 0x1
    BNE        A0, ZERO, loop
    ADDIU      A0, A0, 0xFFFFFFFF

    ADDIU      A2, A2, 0x1
    MOVN       A1, ZERO, ZERO
    JR         RA
    ADDIU      A2, A2, 0x1
'''

blocs_b, symbol_pool_b = parse_asm.parse_txt(mn_mips32, "b", txt)
blocs_l, symbol_pool_l = parse_asm.parse_txt(mn_mips32, "l", txt)

# fix shellcode addr
symbol_pool_b.set_offset(symbol_pool_b.getby_name("main"), 0)
symbol_pool_l.set_offset(symbol_pool_l.getby_name("main"), 0)

for b in blocs_b[0]:
    print b

resolved_b, patches_b = asmbloc.asm_resolve_final(
    mn_mips32, blocs_b[0], symbol_pool_b)
resolved_l, patches_l = asmbloc.asm_resolve_final(
    mn_mips32, blocs_l[0], symbol_pool_l)
print patches_b
print patches_l

for offset, raw in patches_b.items():
    st_b[offset] = raw
for offset, raw in patches_l.items():
    st_l[offset] = raw

open('mips32_sc_b.bin', 'wb').write(str(st_l))
open('mips32_sc_l.bin', 'wb').write(str(st_l))
