#! /usr/bin/env python
import os
from elfesteem import *
from miasm.tools.pe_helper import *
from miasm.tools import seh_helper
from miasm.core import bin_stream
import inspect
from miasm.core import asmbloc
from miasm.core import parse_asm
from elfesteem import pe
from miasm.arch import ia32_arch
import pickle
import sys
fname = sys.argv[1]
dis_oep = True
print sys.argv
if len(sys.argv) >2:
    ad_to_dis = int(sys.argv[2], 16)
    dis_oep = False



dll_dyn_funcs = {}
data = open(fname, 'rb').read()
if data.startswith("MZ"):
    e = pe_init.PE(open(fname, 'rb').read())
    if dis_oep:
        ad_to_dis = e.rva2virt(e.Opthdr.AddressOfEntryPoint)
    in_str = bin_stream.bin_stream(e.virt)
    try:
        dll_dyn_funcs = get_import_address(e)
    except:
        print 'bug in import parsing'


elif data.startswith("\x7fELF") :
    e = elf_init.ELF(open(fname, 'rb').read())
    if dis_oep:
        ad_to_dis = e.Ehdr.entry
    in_str = bin_stream.bin_stream(e.virt)
    try:
        dll_dyn_funcs = get_import_address_elf(e)
    except:
        print 'bug in import parsing'

else:
    in_str = bin_stream.bin_stream(data)

print 'dis', fname, 'at', "0x%.8X"%ad_to_dis



symbol_pool = asmbloc.asm_symbol_pool()
# test qt
from miasm.graph.graph_qt import graph_blocs



#test symbols from ida
for (n,f), ad in dll_dyn_funcs.items():
    l = asmbloc.asm_label("%s_%s"%(n, f), ad)
    print l
    symbol_pool.add(l)


def my_disasm_callback(ad):
    all_bloc = asmbloc.dis_bloc_ia32(in_str, ad, symbol_pool = symbol_pool)
    for b in all_bloc:
        for l in b.lines:
            for i, a in enumerate(l.arg):
                if not ia32_arch.is_ad_lookup(a):
                    continue
                x = a[ia32_arch.x86_afs.imm]
                if x in symbol_pool.s_offset:
                    l.arg[i][x86_afs.symb] = symbol_pool.s_offset[x]
                    del(l.arg[i][ia32_arch.x86_afs.imm])
    return all_bloc

graph_blocs(ad_to_dis, all_bloc = [], dis_callback = my_disasm_callback)
