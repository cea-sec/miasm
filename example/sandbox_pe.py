import os
from elfesteem import *
from miasm.tools.pe_helper import *
import inspect
from miasm.core import asmbloc
from miasm.core import parse_asm
from miasm.tools.to_c_helper import *
from elfesteem import pe
import cProfile
import code
from miasm.tools import emul_helper
import sys
from miasm.tools import win_api
from miasm.arch.ia32_arch import *


def whoami():
    return inspect.stack()[1][3]


fname = sys.argv[1]
e = pe_init.PE(open(fname, 'rb').read())


# /!\ no seh set for this demo

vm_init_regs()
init_memory_page_pool_py()
init_code_bloc_pool_py()
in_str = bin_stream_vm()

codenat_tcc_init()

vm_load_pe(e)

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


runtime_dll = libimp(0x71111111)
dll_dyn_funcs = preload_lib(e, runtime_dll)
# set winapi to ours
win_api.runtime_dll = runtime_dll
win_api.current_pe = e
dll_dyn_ad2name = dict([(x[1], x[0]) for x in dll_dyn_funcs.items()])
dyn_func = {}


ep =  e.rva2virt(e.Opthdr.AddressOfEntryPoint)

stack_base_ad = 0x1230000
stack_size = 0x10000
vm_add_memory_page(stack_base_ad, PAGE_READ|PAGE_WRITE, "\x00"*stack_size)
dump_memory_page_pool_py()





regs = vm_get_gpreg()
regs['eip'] = ep
regs['esp'] = stack_base_ad+stack_size
vm_set_gpreg(regs)
dump_gpregs_py()

vm_push_uint32_t(0)
vm_push_uint32_t(0)
vm_push_uint32_t(0x1337beef)

symbol_pool = asmbloc.asm_symbol_pool()

known_blocs = {}
code_blocs_mem_range = []


def dump_raw_e(e):
    e.Opthdr.AddressOfEntryPoint = e.virt2rva(vm_get_gpreg()['eip'])
    str_e = StrPatchwork(str(e))
    for s in e.SHList:
        data = vm_get_str(e.rva2virt(s.addr), s.size)
        svad = e.rva2virt(s.addr)
        print hex(len(data))
        str_e[s.offset] = data
        e.virt[e.off2virt(s.offset)] = data
    open('out.bin', 'w').write(str(str_e))


log_regs = True
log_mn = log_regs
def run_bin(my_eip, known_blocs, code_blocs_mem_range):
    global log_regs, log_mn
    while my_eip != 0x1337beef:        

        #dyn dll funcs
        if my_eip in runtime_dll.fad2cname:
            fname = runtime_dll.fad2cname[my_eip]
            if not fname in win_api.__dict__:
                print repr(fname)
                raise ValueError('unknown api', hex(vm_pop_uint32_t()))
            win_api.__dict__[fname]()
            regs = vm_get_gpreg()
            my_eip = regs['eip']
            continue


        if not my_eip in known_blocs:
            updt_bloc_emul(known_blocs, in_str, my_eip, symbol_pool, code_blocs_mem_range, log_regs = log_regs, log_mn = log_mn)
            vm_reset_exception()

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
run_bin(ep, known_blocs, code_blocs_mem_range)
dump_raw_e(e)
