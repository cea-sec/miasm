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
from miasm.arch import arm_arch
from optparse import OptionParser

try:
    from miasm.arch.java_arch import java_mn
except ImportError:
    pass

import pickle
import sys




print sys.argv


parser = OptionParser()
parser.add_option('-a', "--address", dest="address", metavar="ADDRESS",
                  help="address to disasemble")
parser.add_option('-m', "--architecture", dest="machine",metavar="MACHINE",
                  help="architecture to use for disasm: arm, x86, ppc, java")
parser.add_option('-M', "--architecture-options", dest="machine-options",
                  metavar="MACHINEOPTS",
                  help="architecture options (16/32/64 bits, ...)")
parser.add_option('-r', "--rawfile", dest="rawfile", action="store_true",
                  default=False, metavar=None,
                  help="dont use PE/ELF/CLASS autodetect, disasm raw file")

(options, args) = parser.parse_args(sys.argv[1:])
print options, args

fname = args[0]
ad_to_dis = options.address


dll_dyn_funcs = {}
data = open(fname, 'rb').read()

if options.rawfile:
    in_str = bin_stream.bin_stream(data)
    if ad_to_dis == None:
        ad_to_dis = 0
    else:
        ad_to_dis = int(ad_to_dis, 16)
    mnemo = ia32_arch.x86_mn
elif data.startswith("MZ"):
    e = pe_init.PE(open(fname, 'rb').read())
    if ad_to_dis == None:
        ad_to_dis = e.rva2virt(e.Opthdr.AddressOfEntryPoint)
    else:
        ad_to_dis = int(ad_to_dis, 16)
    in_str = bin_stream.bin_stream(e.virt)
    try:
        dll_dyn_funcs = get_import_address(e)
    except:
        print 'bug in import parsing'
    mnemo = ia32_arch.x86_mn

elif data.startswith("\x7fELF") :
    e = elf_init.ELF(open(fname, 'rb').read())
    if ad_to_dis == None:
        ad_to_dis = e.Ehdr.entry
    else:
        ad_to_dis = int(ad_to_dis, 16)
    in_str = bin_stream.bin_stream(e.virt)
    try:
        dll_dyn_funcs = get_import_address_elf(e)
    except:
        print 'bug in import parsing'
    mnemo = ia32_arch.x86_mn

elif data.startswith("\xca\xfe\xba\xbe"):
    def java_usage():
        print 'usage:'
        print '%s methodname methodtype'%sys.argv[0]
        print 'possible methods: (use -a N)'
        for i, ((c_name, c_type), code) in enumerate(methods):
            print i, "->", str(c_name), str(c_type)
        sys.exit(-1)

    e = jclass_init.JCLASS(data)
    methods = []
    for m in e.description.methods:
        name = m.name
        descr = m.descriptor
        c = filter(lambda x: type(x) is jclass_init.CAttribute_code, m.attributes)
        if not c:
            continue
        code = c[0].code
        methods.append(((name, descr), code))
    if ad_to_dis == None:
        java_usage()
    ad_to_dis = int(ad_to_dis)
    if not (0<=ad_to_dis<len(methods)):
        java_usage()
    in_str = bin_stream.bin_stream(methods[ad_to_dis][1])
    ad_to_dis = 0
    mnemo = java_mn
    try:
        constants_pool = get_java_constant_pool(e)
    except:
        print 'bug in constant pool parsing'
        constants_pool = {}


else:
    raise ValueError('cannot autodetect file type')


if options.machine:
    machine_dct = {"ia32":ia32_arch.x86_mn,
                   "arm":arm_arch.arm_mn,
                   "java":java_mn,
                   }
    if not options.machine in machine_dct:
        raise ValueError('unknown machine', options.machine)
    if mnemo:
        print "WARNING forcing machine disasm to ", options.machine

    mnemo = machine_dct[options.machine]

print 'dis', fname, 'at', "0x%.8X"%ad_to_dis, 'using', mnemo



symbol_pool = asmbloc.asm_symbol_pool()
# test qt
from miasm.graph.graph_qt import graph_blocs



#test symbols from ida
for (n,f), ad in dll_dyn_funcs.items():
    l = asmbloc.asm_label("%s_%s"%(n, f), ad)
    symbol_pool.add(l)


def my_disasm_callback(ad):
    all_bloc = asmbloc.dis_bloc_all(mnemo, in_str, ad, set(),
                                    symbol_pool=symbol_pool)
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
        o = {}
        for k, v in constants_pool.items():
            if hasattr(v, "pp"):
                o[k] = v.pp()
            else:
                o[k] = repr(v)
        for b in all_bloc:
            for l in b.lines:
                l.set_args_symbols(o)
    return all_bloc

graph_blocs(ad_to_dis, all_bloc = [], dis_callback = my_disasm_callback)
