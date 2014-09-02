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


st = StrPatchwork()

blocs, symbol_pool = parse_asm.parse_txt(mn_mips32, "l", '''
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
''')

# fix shellcode addr
symbol_pool.set_offset(symbol_pool.getby_name("main"), 0)

for b in blocs[0]:
    print b

resolved_b, patches = asmbloc.asm_resolve_final(
    mn_mips32, 'l', blocs[0], symbol_pool)
print patches

for offset, raw in patches.items():
    st[offset] = raw

open('mips32_sc.bin', 'wb').write(str(st))
