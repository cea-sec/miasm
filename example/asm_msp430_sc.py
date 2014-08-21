#! /usr/bin/env python

from miasm2.core.cpu import parse_ast
from miasm2.arch.msp430.arch import mn_msp430, base_expr, variable
from miasm2.core.bin_stream import bin_stream
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from elfesteem.strpatchwork import StrPatchwork

from pdb import pm
from miasm2.core import asmbloc
import struct

reg_and_id = dict(mn_msp430.regs.all_regs_ids_byname)


def my_ast_int2expr(a):
    return ExprInt32(a)


def my_ast_id2expr(t):
    return reg_and_id.get(t, ExprId(t, size=32))

my_var_parser = parse_ast(my_ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)


st = StrPatchwork()

blocs, symbol_pool = parse_asm.parse_txt(mn_msp430, None, '''
main:
    mov.w      0x10, R10
    mov.w      0x0, R11
loop:
    add.w      1, R11
    sub.w      1, R10
    jnz        loop
    mov.w      @SP+, PC
''')

# fix shellcode addr
symbol_pool.set_offset(symbol_pool.getby_name("main"), 0)

for b in blocs[0]:
    print b

resolved_b, patches = asmbloc.asm_resolve_final(
    mn_msp430, None, blocs[0], symbol_pool)
print patches

for offset, raw in patches.items():
    st[offset] = raw

open('msp430_sc.bin', 'wb').write(str(st))
