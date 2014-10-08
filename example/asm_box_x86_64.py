#! /usr/bin/env python

from miasm2.core.cpu import parse_ast
from miasm2.arch.x86.arch import mn_x86, base_expr, variable
from miasm2.core.bin_stream import bin_stream
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from elfesteem import *
from pdb import pm
from miasm2.core import asmbloc
import struct

e = pe_init.PE(wsize=64)
s_text = e.SHList.add_section(name="text", addr=0x1000, rawsize=0x1000)
s_iat = e.SHList.add_section(name="iat", rawsize=0x100)
new_dll = [({"name": "USER32.dll",
             "firstthunk": s_iat.addr}, ["MessageBoxA"])]
e.DirImport.add_dlldesc(new_dll)
s_myimp = e.SHList.add_section(name="myimp", rawsize=len(e.DirImport))
e.DirImport.set_rva(s_myimp.addr)

reg_and_id = dict(mn_x86.regs.all_regs_ids_byname)


def my_ast_int2expr(a):
    return ExprInt64(a)


def my_ast_id2expr(t):
    return reg_and_id.get(t, ExprId(t, size=64))

my_var_parser = parse_ast(my_ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)

blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 64, '''
main:
    MOV R9, 0x0
    MOV R8, title
    MOV RDX, msg
    MOV RCX, 0x0
    MOV RAX, QWORD PTR [ MessageBoxA ]
    CALL RAX
    RET

title:
.string "Hello!"
msg:
.string "World!"
''')

# fix shellcode addr
symbol_pool.set_offset(symbol_pool.getby_name("main"), e.rva2virt(s_text.addr))
symbol_pool.set_offset(symbol_pool.getby_name_create("MessageBoxA"),
                       e.DirImport.get_funcvirt('MessageBoxA'))
e.Opthdr.AddressOfEntryPoint = s_text.addr

for b in blocs[0]:
    print b

resolved_b, patches = asmbloc.asm_resolve_final(
    mn_x86, blocs[0], symbol_pool,
    max_offset=0xFFFFFFFFFFFFFFFF)
print patches

for offset, raw in patches.items():
    e.virt[offset] = raw

open('box_x86_64.bin', 'wb').write(str(e))
