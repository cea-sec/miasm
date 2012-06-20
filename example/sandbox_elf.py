import os
from elfesteem import *
from miasm.tools.pe_helper import *
from miasm.tools import seh_helper
import inspect
from miasm.core import asmbloc
from miasm.core import parse_asm
from miasm.tools.to_c_helper import *
from elfesteem import pe
import cProfile
import code
import sys
from miasm.tools import nux_api

from miasm.tools.nux_api import *


if len(sys.argv) != 2:
    print "to test:"
    print "python sandbox_elf.py md5"
    sys.exit(0)



fname = sys.argv[1]
e = elf_init.ELF(open(fname, 'rb').read())
in_str = bin_stream_vm()
vm_init_regs()
init_memory_page_pool_py()
init_code_bloc_pool_py()

codenat_tcc_init()

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

vm_load_elf(e)

runtime_dll, lib_dyn_funcs = preload_elf(e, patch_vm_imp = True, lib_base_ad = 0x77700000)
lib_dyn_ad2name = dict([(x[1], x[0]) for x in lib_dyn_funcs.items()])
dyn_func = {}


stack_base_ad = 0x1230000
stack_size = 0x10000
vm_add_memory_page(stack_base_ad, PAGE_READ|PAGE_WRITE, "\x00"*stack_size)
dump_memory_page_pool_py()


try:
    ep =  e.sh.symtab.symbols['main'].value
except:
    ep = e.Ehdr.entry

ptr_esp = stack_base_ad+stack_size-0x1000
vm_set_mem(ptr_esp, "/home/toto\x00")
ptr_arg0 = ptr_esp
ptr_esp -=0x100
ptr_args = ptr_esp
vm_set_mem(ptr_args, struct.pack('LL', ptr_arg0, 0))

regs = vm_get_gpreg()
regs['eip'] = ep
regs['esp'] = ptr_esp
vm_set_gpreg(regs)
dump_gpregs_py()

vm_push_uint32_t(ptr_args)
vm_push_uint32_t(1)
vm_push_uint32_t(0x1337beef)

dump_memory_page_pool_py()

symbol_pool = asmbloc.asm_symbol_pool()

my_eip = ep


known_blocs = {}
code_blocs_mem_range = []


log_regs = False
log_mn = log_regs
must_stop = False

ad_oep = None
segm_to_do = {}




def run_bin(my_eip, known_blocs, code_blocs_mem_range):
    global log_regs, log_mn
    may_end = None
    while my_eip != 0x1337beef:

        if my_eip == ad_oep:
            print 'reach ad_oep', hex(ad_oep)
            return
        #dyn dll funcs
        if my_eip in runtime_dll.fad2cname:
            my_eip = manage_runtime_func(my_eip, [globals(), nux_api], runtime_dll)
            continue

        my_eip, py_exception = do_bloc_emul(known_blocs, in_str, my_eip,
                                            symbol_pool, code_blocs_mem_range,
                                            log_regs = log_regs, log_mn = log_mn,
                                            segm_to_do = segm_to_do,
                                            dump_blocs = False)

        if py_exception:
            if py_exception & EXCEPT_CODE_AUTOMOD:
                known_blocs, code_blocs_mem_range = updt_automod_code(known_blocs)
            else:
                raise ValueError("except at", hex(my_eip))

print "start run"
run_bin(my_eip, known_blocs, code_blocs_mem_range)
