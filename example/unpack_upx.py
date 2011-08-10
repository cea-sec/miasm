import sys
import struct
from elfesteem import *
from miasm.tools.pe_helper import *
from elfesteem.strpatchwork import StrPatchwork
from miasm.tools.to_c_helper import *
from miasm.tools.codenat import *
from pdb import pm


# example for scrambled upx unpacking

fname = sys.argv[1]

e = pe_init.PE(open(fname, 'rb').read())
in_str = bin_stream(e.virt)

ep =  e.rva2virt(e.Opthdr.AddressOfEntryPoint)
decomp_func = ep




vm_init_regs()
init_memory_page_pool_py()
init_code_bloc_pool_py()

codenat_tcc_init()



job_done = set()
symbol_pool = asmbloc.asm_symbol_pool()
if e.Coffhdr.characteristics & (1<<13):
    # dll
    all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, decomp_func, job_done, symbol_pool, bloc_wd=2)
    b = all_bloc[1]
else:
    # binary
    all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, decomp_func, job_done, symbol_pool, bloc_wd=1)
    b = all_bloc[0]
    
print b


print "start emul..."
machine = x86_machine()
f_eip = emul_bloc(machine, b)

decomp_buf_ad_in =  int(machine.pool[esi].arg)
decomp_buf_ad_out = int( machine.pool[edi].arg)


decomp_buf_len_in = decomp_func - decomp_buf_ad_in
decomp_buf_len_out = decomp_buf_ad_in - decomp_buf_ad_out
print "in l", hex(decomp_buf_len_in), "out l", hex(decomp_buf_len_out)

dont_dis = [(decomp_buf_ad_out, decomp_buf_ad_in)]

g = asmbloc.bloc2graph(all_bloc)
open("graph.txt" , "w").write(g)


job_done = set()
symbol_pool = asmbloc.asm_symbol_pool()
all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, decomp_func, job_done, symbol_pool, dont_dis)


end_label = None
for b in all_bloc:
    if len(b.bto) == 1 and asmbloc.getblocby_label(all_bloc, b.bto[0].label)== None:
        end_label = b.bto[0].label.offset
        break
if not end_label:
    raise ValueError('cannot find final bloc')

print 'final label'
print hex(end_label)


    
base_imp = 0
offset_imp = 0
libbase_ad = 0x77700000
def myloadlibexa():
    global base_imp, offset_imp, libbase_ad, runtime_dll
    ret_ad = vm_pop_uint32_t()
    pname = vm_pop_uint32_t()
    print 'loadlib', hex(pname), hex(ret_ad)

    libname = vm_get_str(pname, 0x100)
    libname = libname[:libname.find('\x00')]

    print repr(libname)

    ad = runtime_dll.lib_get_add_base(libname)
        
    regs = vm_get_gpreg()
    
    if not base_imp:
        base_imp = regs["edi"]
    if not offset_imp:
        offset_imp = regs['eax']

    print hex(base_imp), hex(offset_imp)
    regs['eip'] = ret_ad
    regs['eax'] = ad
    vm_set_gpreg(regs)


    




def mygetproc():
    global runtime_dll
    ret_ad = vm_pop_uint32_t()
    libbase = vm_pop_uint32_t()
    fname = vm_pop_uint32_t()
    print 'getproc', hex(fname), hex(libbase), hex(ret_ad)
    
    regs = vm_get_gpreg()
    dst_ad = regs['ebx']
    print 'ebx', hex(dst_ad)

    if fname < 0x10000:
        fname = fname
    else:
        fname = vm_get_str(fname, 0x100)
        fname = fname[:fname.find('\x00')]
        print fname


    ad = runtime_dll.lib_get_add_func(libbase, fname, dst_ad)

    
    
    regs['eip'] = ret_ad
    regs['eax'] = ad
    vm_set_gpreg(regs)


stack_size = 0x10000
vm_add_memory_page(0x40000000, PAGE_READ|PAGE_WRITE, "\x00"*stack_size)

vm_load_pe(e)

runtime_dll = libimp(0x71111111)
dll_dyn_funcs = preload_lib(e, runtime_dll)
dll_dyn_ad2name = dict([(x[1], x[0]) for x in dll_dyn_funcs.items()])

from miasm.tools import win_api


dyn_func = {}
dyn_func[dll_dyn_funcs['kernel32_LoadLibraryA']] = myloadlibexa
dyn_func[dll_dyn_funcs['kernel32_GetProcAddress']] = mygetproc
dyn_func[dll_dyn_funcs['kernel32_VirtualProtect']] = win_api.kernel32_VirtualProtect




    
dump_memory_page_pool_py()


regs = vm_get_gpreg()
regs['eip'] = decomp_func
regs['esp'] = 0x40000000+stack_size

vm_set_gpreg(regs)

vm_push_uint32_t(1) #reason code if dll
vm_push_uint32_t(1) #reason code if dll
vm_push_uint32_t(0x1337beef)

known_blocs = {}
cpt =0
code_blocs_mem_range = []

def my_run():
    global cpt, my_eip, known_blocs, code_blocs_mem_range
    trace_on = {'log_mn':False, 'log_regs':False}
    
    print 'start'
    while True:
        cpt+=1
        #print 'eip', hex(my_eip)
        if my_eip in [ end_label]:
            e.Opthdr.AddressOfEntryPoint = e.virt2rva(my_eip)
            print 'updating binary', cpt
            for s in e.SHList:
                sdata = vm_get_str(e.rva2virt(s.addr), s.rawsize)
                e.virt[e.rva2virt(s.addr)] = sdata
            in_str = bin_stream(e.virt)
    
            open('uu.bin', 'wb').write(str(e))
            g = asmbloc.bloc2graph([x.b for x in known_blocs.values()], lines = False)
            open("graph.txt" , "w").write(g)
    
            break
        if my_eip in dyn_func:
            dyn_func[my_eip]()
            print 'call dyn func', hex(my_eip)
            regs = vm_get_gpreg()
            my_eip = regs['eip']
            continue
        if not my_eip in known_blocs:
            in_str = updt_pe_from_emul(e)
            updt_bloc_emul(known_blocs, in_str, my_eip, symbol_pool, code_blocs_mem_range, **trace_on)

        my_eip = known_blocs[my_eip].module_c.func()
        py_exception = vm_get_exception()
        if py_exception:
            if py_exception & EXCEPT_CODE_AUTOMOD:
                print 'automod code'
                dump_gpregs_py()
                known_blocs, code_blocs_mem_range = updt_automod_code(known_blocs)
            else:
                raise ValueError("zarb exception", hex(py_exception))


my_eip = decomp_func

my_run()

print "decomp end", hex(base_imp), hex(offset_imp)
regs = vm_get_gpreg()

for r, v in regs.items():
    print r, hex(v&0xFFFFFFFF)

oo = vm_get_str(decomp_buf_ad_out, decomp_func-decomp_buf_ad_out)

open('uu', 'w').write("A"*0x1000 + oo)
print repr(oo[:0x10])
print repr(oo[-0x10:])


print hex(len(oo))

###rebuild import table##########
print 'assing'
e.virt[decomp_buf_ad_out] = oo
e.SHList.align_sections(0x1000, 0x1000)
print repr(e.SHList)

ad_base = regs['esi']

ad_tmp = base_imp -8
print "imp addr", hex(ad_tmp)
print 'ad base:', hex(ad_base)
print "base imp", hex(offset_imp)
print 'decomp_buf_ad_out', hex(decomp_buf_ad_out)
new_dll = []

offset_imp = offset_imp - decomp_buf_ad_out - struct.unpack('I', e.virt[ad_tmp:ad_tmp+4])[0]
print "read ofset imp", hex(offset_imp)

#XXXXX 
ad_base = decomp_buf_ad_out

print repr(e.SHList)
st = StrPatchwork()
st[0] = e.content

# get back data from emulator
for s in e.SHList:
    ad1 = e.rva2virt(s.addr)
    ad2 =ad1 + len(s.data)
    st[s.offset] = e.virt[ad1:ad2]
e.content = str(st)

e.DirRes = pe_init.DirRes(e)
#e.DirImport.impdesc = None
print repr(e.DirImport.impdesc)
new_dll = runtime_dll.gen_new_lib(e)
print new_dll
e.DirImport.add_dlldesc(new_dll)
s_myimp = e.SHList.add_section(name = "myimp", rawsize = len(e.DirImport))
print repr(e.SHList)
e.DirImport.set_rva(s_myimp.addr)

e.Opthdr.AddressOfEntryPoint = e.virt2rva(end_label)
open('out.bin','w').write(str(e))
