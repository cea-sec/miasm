#! /usr/bin/env python

from miasm.core import parse_asm
from miasm.core import asmbloc
from miasm.arch.ia32_arch import *
from elfesteem import *
e = pe_init.PE()
s_text = e.SHList.add_section(name = "text ", addr = 0x1000, rawsize = 0x100)
s_iat = e.SHList.add_section(name = "iat" , rawsize = 0x100)
new_dll = [({ "name" : "USER32.dll",
              "firstthunk" : s_iat.addr},
            ["MessageBoxA"])]
e.DirImport.add_dlldesc(new_dll)
s_myimp = e.SHList.add_section(name = "myimp",rawsize = len(e.DirImport))
e.DirImport.set_rva(s_myimp.addr)
all_bloc, symbol_pool = parse_asm.parse_txt(x86_mn, r'''
main:
    push 0
    push title
    push msg
    push 0
    call [ MessageBoxA ]
    ret
title:
.string "Hello!"
msg:
.string "Word!"
''')
symbol_pool.add(asmbloc.asm_label('base_address', 0))
symbol_pool.getby_name("MessageBoxA").offset = e.DirImport.get_funcvirt('MessageBoxA')
symbol_pool.getby_name("main").offset = e.rva2virt(s_text.addr)
resolved_b, patches = asmbloc.asm_resolve_final(x86_mn, all_bloc[0], symbol_pool)
for p in patches:
    e.virt[p] = patches[p]
e.Opthdr.AddressOfEntryPoint = e.virt2rva(symbol_pool.getby_name("main").offset)
open('msg.exe', 'wb').write(str(e))
