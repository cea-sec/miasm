#! /usr/bin/env python
from pdb import pm

from elfesteem import pe_init

from miasm2.core.cpu import parse_ast
from miasm2.arch.x86.arch import mn_x86, base_expr
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmbloc

pe = pe_init.PE()
s_text = pe.SHList.add_section(name="text", addr=0x1000, rawsize=0x1000)
s_iat = pe.SHList.add_section(name="iat", rawsize=0x100)
new_dll = [({"name": "USER32.dll",
             "firstthunk": s_iat.addr}, ["MessageBoxA"])]
pe.DirImport.add_dlldesc(new_dll)
s_myimp = pe.SHList.add_section(name="myimp", rawsize=len(pe.DirImport))
pe.DirImport.set_rva(s_myimp.addr)

reg_and_id = dict(mn_x86.regs.all_regs_ids_byname)


def my_ast_int2expr(a):
    return ExprInt32(a)


def my_ast_id2expr(t):
    return reg_and_id.get(t, ExprId(t, size=32))

my_var_parser = parse_ast(my_ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)

blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 32, '''
main:
    PUSH 0
    PUSH title
    PUSH msg
    PUSH 0
    CALL DWORD PTR [ MessageBoxA ]
    RET

title:
.string "Hello!"
msg:
.string "World!"
''')

# fix shellcode addr
symbol_pool.set_offset(symbol_pool.getby_name("main"), pe.rva2virt(s_text.addr))
symbol_pool.set_offset(symbol_pool.getby_name_create("MessageBoxA"),
                       pe.DirImport.get_funcvirt('MessageBoxA'))
pe.Opthdr.AddressOfEntryPoint = s_text.addr

for bloc in blocs[0]:
    print bloc

resolved_b, patches = asmbloc.asm_resolve_final(
    mn_x86, blocs[0], symbol_pool)
print patches

for offset, raw in patches.items():
    pe.virt[offset] = raw

open('box_x86_32.bin', 'wb').write(str(pe))
