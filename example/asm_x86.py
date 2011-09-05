#! /usr/bin/env python

from miasm.arch.ia32_arch  import *
from miasm.core.bin_stream import bin_stream
from miasm.core import parse_asm
from elfesteem import *

from miasm.core import asmbloc
import struct

my_mn = x86_mn




my_mn = x86_mn

e = pe_init.PE()
s_text = e.SHList.add_section(name = "text", addr = 0x1000, rawsize = 0x4000)

####filelogger sc####
all_bloc, symbol_pool = parse_asm.parse_txt(my_mn,r'''
main:
  jmp end
getstr:
  pop  ebp
  push  0xb
  pop	eax
  cdq

  push	edx
  mov  cx, 0x632d
  push	cx
  mov	edi, esp

  push	0xAA68732f
  push	0x6e69622f
  mov	ebx, esp
  push	edx

  push  ebp
  mov   byte ptr [ebp+eend-mystr], dl
  push	edi
  push	ebx
  mov   byte ptr [ebx+7], dl
  mov	ecx, esp
  int	0x80
end:
  call	getstr
mystr:
.string "cat /etc/passwd> /tmp/ooo; ls;"
eend:
  nop
''')

#fix shellcode addr
symbol_pool.add(asmbloc.asm_label('base_address', 0x400000))
symbol_pool.getby_name("main").offset = 0x401000
e.Opthdr.AddressOfEntryPoint = s_text.addr

for b in all_bloc[0]:
    print b
####graph sc####
g = asmbloc.bloc2graph(all_bloc[0])
open("graph.txt" , "w").write(g)

print "symbols"
print symbol_pool
#dont erase from start to shell code padading
resolved_b, patches = asmbloc.asm_resolve_final(my_mn, all_bloc[0], symbol_pool)
print patches

for offset, raw in patches.items():
    e.virt[offset] = raw

open('uu.bin', 'wb').write(str(e))

