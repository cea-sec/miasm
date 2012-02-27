import sys
from miasm.arch.ia32_arch import *
from miasm.tools.emul_helper import *
from miasm.core.bin_stream import bin_stream

print "symbolic execution & simplification demo"

def loop_emul(ad, machine, all_bloc):
    ad = ExprInt(uint32(ad))
    while isinstance(ad, ExprInt):
        b = asmbloc.getblocby_offset(all_bloc, ad.arg)
        if not b:
            raise ValueError('unknown bloc', repr(ad))
        print '*'*20, 'emul bloc:', '*'*20
        print b
        ad = emul_bloc(machine, b)
    return ad

if len(sys.argv) != 2:
    print "%s obf.bin"%sys.argv[0]
    sys.exit(-1)

data = open(sys.argv[1]).read()
in_str = bin_stream(data)

symbol_pool = asmbloc.asm_symbol_pool()
ad = 0

all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, ad, set(), symbol_pool, dontdis_retcall = True)

machine = x86_machine()
ad = loop_emul(ad, machine, all_bloc)
print
print "emulation result:"
print dump_reg(machine.pool)
print "eip", ad
print
print dump_mem(machine.pool)
