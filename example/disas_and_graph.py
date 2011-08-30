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
try:
    from miasm.arch.java_arch import java_mn
except ImportError:
    pass

import pickle
import sys


print sys.argv

fname = sys.argv[1]
ad_to_dis = None
if len(sys.argv) >2:
    ad_to_dis = sys.argv[2]



dll_dyn_funcs = {}
data = open(fname, 'rb').read()
if data.startswith("MZ"):
    e = pe_init.PE(open(fname, 'rb').read())
    if len(sys.argv) <=2:
        ad_to_dis = e.rva2virt(e.Opthdr.AddressOfEntryPoint)
    else:
        ad_to_dis = int(sys.argv[1], 16)
    in_str = bin_stream.bin_stream(e.virt)
    try:
        dll_dyn_funcs = get_import_address(e)
    except:
        print 'bug in import parsing'
    mnemo = ia32_arch.x86_mn

elif data.startswith("\x7fELF") :
    e = elf_init.ELF(open(fname, 'rb').read())
    if len(sys.argv) <=2:
        ad_to_dis = e.Ehdr.entry
    else:
        ad_to_dis = int(sys.argv[1], 16)
    in_str = bin_stream.bin_stream(e.virt)
    try:
        dll_dyn_funcs = get_import_address_elf(e)
    except:
        print 'bug in import parsing'
    mnemo = ia32_arch.x86_mn

elif data.startswith("\xca\xfe\xba\xbe"):
    e = jclass_init.JCLASS(data)
    methods = {}
    for m in e.description.methods:
        name = m.name_index.value
        descr = m.descriptor_index.value
        code = filter(lambda x: type(x) is jclass_init.CAttribute_code, m.attributes)[0].code
        print name, descr, len(code)
        methods[(name, descr)] = code
    if len(sys.argv) != 3:
        print 'usage:'
        print '%s methodname'%sys.argv[0]
        sys.exit(-1)

    method_todo = filter(lambda x: x[0] == sys.argv[2], methods)[0]
    if not method_todo:
        print 'unknown method', repr(sys.argv[2])
        sys.exit(-1)

    in_str = bin_stream.bin_stream(methods[filter(lambda x: x[0] == sys.argv[2], methods)[0]])
    ad_to_dis = 0
    mnemo = java_mn
    try:
        constants_pool = get_java_constant_pool(e)
    except:
        print 'bug in constant pool parsing'
        constants_pool = {}


else:
    in_str = bin_stream.bin_stream(data)
    ad_to_dis = 0
    mnemo = ia32_arch.x86_mn

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
    all_bloc = asmbloc.dis_bloc_all(mnemo, in_str, ad, set(),
                                    symbol_pool=symbol_pool,
                                    dont_dis_nulstart_bloc=True)
    if mnemo == ia32_arch.x86_mn:
        for b in all_bloc:
            for l in b.lines:
                for i, a in enumerate(l.arg):
                    if not ia32_arch.is_ad_lookup(a):
                        continue
                    x = a[ia32_arch.x86_afs.imm]
                    if x in symbol_pool.s_offset:
                        l.arg[i][x86_afs.symb] = symbol_pool.s_offset[x]
                        del(l.arg[i][ia32_arch.x86_afs.imm])
    elif mnemo == java_mn:
        for b in all_bloc:
            for l in b.lines:
                l.set_args_symbols(constants_pool)
    return all_bloc

graph_blocs(ad_to_dis, all_bloc = [], dis_callback = my_disasm_callback)
