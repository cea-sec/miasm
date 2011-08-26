#! /usr/bin/env python
import os
from elfesteem import *
from miasm.core import asmbloc
from miasm.core import parse_asm
from miasm.tools.to_c_helper import *
from miasm.tools import emul_helper
from miasm.arch.ia32_arch import *
import sys



if len(sys.argv) <3:
    print 'usage:'
    print "%s rawfile address_to_exec"%sys.argv[0]
    sys.exit(0)
data = open(sys.argv[1], 'rb').read()
ad = sys.argv[2].lower()
if ad.startswith('0x'):
    ad = int(ad, 16)
else:
    ad = int(ad)


vm_init_regs()
init_memory_page_pool_py()
init_code_bloc_pool_py()
in_str = bin_stream_vm()

codenat_tcc_init()

code_ad = 0x40000000
vm_add_memory_page(code_ad, PAGE_READ|PAGE_WRITE|PAGE_EXEC, data)
stack_base_ad = 0x1230000
stack_size = 0x10000
vm_add_memory_page(stack_base_ad, PAGE_READ|PAGE_WRITE, "\x00"*stack_size)
dump_memory_page_pool_py()

regs = vm_get_gpreg()
regs['esp'] = stack_base_ad+stack_size
vm_set_gpreg(regs)
dump_gpregs_py()


vm_push_uint32_t(0x1337beef)
symbol_pool = asmbloc.asm_symbol_pool()
known_blocs = {}
code_blocs_mem_range = []




log_regs = True
log_mn = log_regs
def run_bin(my_eip, known_blocs, code_blocs_mem_range):
    global log_regs, log_mn
    while my_eip != 0x1337beef:

        if not my_eip in known_blocs:
            updt_bloc_emul(known_blocs, in_str, my_eip, symbol_pool, code_blocs_mem_range, log_regs = log_regs, log_mn = log_mn)
        try:
            my_eip = vm_exec_blocs(my_eip, known_blocs)
        except KeyboardInterrupt:
            break
        py_exception = vm_get_exception()
        if py_exception:
            if py_exception & EXCEPT_CODE_AUTOMOD:
                print 'automod code'
                dump_gpregs_py()
                known_blocs, code_blocs_mem_range = updt_automod_code(known_blocs)
            else:
                raise ValueError("except at", hex(my_eip))

print "start emulation"
run_bin(ad+code_ad, known_blocs, code_blocs_mem_range)
