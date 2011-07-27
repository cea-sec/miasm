import os, sys
from elfesteem import *
from miasm.tools.pe_helper import *
import inspect
from miasm.core import asmbloc
from miasm.core import parse_asm
from elfesteem import pe
from miasm.tools.to_c_helper import *


if len(sys.argv) < 2:
    print "%s dllfile"%sys.argv[0]
    sys.exit(0)
fname = sys.argv[1]
e = pe_init.PE(open(fname, 'rb').read())
in_str = bin_stream(e.virt)

# find gadget only in first section
section_code_name = e.SHList.shlist[0].name.strip("\x00")
s_code = e.getsectionbyname(section_code_name)


code_start = e.rva2virt(s_code.addr)
code_stop = e.rva2virt(s_code.addr+s_code.size)


print "run on", hex(code_start), hex(code_stop)
                           

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


def whoami():
    return inspect.stack()[1][3]



def mem_read_wrap(evaluator, e):
    return e


def mem_write_wrap(evaluator, dst, s, src, pool_out):
    return ExprTop()



min_addr = code_start
max_addr = code_stop

print hex(min_addr), hex(max_addr)
arg1 = ExprId('ARG1', 32, True)
arg2 = ExprId('ARG2', 32, True)
ret1 = ExprId('RET1', 32, True)

data1 = ExprId('DATA1', 32, True)
data2 = ExprId('DATA2', 32, True)
data3 = ExprId('DATA3', 32, True)
data4 = ExprId('DATA4', 32, True)
data5 = ExprId('DATA5', 32, True)
data6 = ExprId('DATA6', 32, True)
data7 = ExprId('DATA7', 32, True)
data8 = ExprId('DATA8', 32, True)
data9 = ExprId('DATA9', 32, True)
data10 = ExprId('DATA10', 32, True)

machine = eval_abs({esp:init_esp, ebp:init_ebp, eax:init_eax, ebx:init_ebx, ecx:init_ecx, edx:init_edx, esi:init_esi, edi:init_edi,
                cs:ExprInt(uint32(9)),
                zf :  ExprInt(uint32(0)), nf :  ExprInt(uint32(0)), pf : ExprInt(uint32(0)),
                of :  ExprInt(uint32(0)), cf :  ExprInt(uint32(0)), tf : ExprInt(uint32(0)),
                i_f:  ExprInt(uint32(1)), df :  ExprInt(uint32(0)), af : ExprInt(uint32(0)),
                iopl: ExprInt(uint32(0)), nt :  ExprInt(uint32(0)), rf : ExprInt(uint32(0)),
                vm :  ExprInt(uint32(0)), ac :  ExprInt(uint32(0)), vif: ExprInt(uint32(0)),
                vip:  ExprInt(uint32(0)), i_d:  ExprInt(uint32(0)),tsc1: ExprInt(uint32(0)),
                tsc2: ExprInt(uint32(0)),
                dr7:ExprInt(uint32(0)),
                cr0:init_cr0,
                
                },
               mem_read_wrap,
               mem_write_wrap,
               )


# add some info for example
machine.eval_instr(push(arg2))
machine.eval_instr(push(arg1))
machine.eval_instr(push(ret1))
machine.eval_instr(push(ebp))
machine.eval_instr(mov(ebp, esp))
machine.eval_instr(sub(esp, ExprInt(uint32(0x14))))
machine.eval_instr(mov(eax, ExprMem(ebp + ExprInt(uint32(8)))))
machine.eval_instr(mov(edx, ExprMem(eax + ExprInt(uint32(12)))))
machine.eval_instr(mov(eax, ExprMem(ebp + ExprInt(uint32(12)))))
machine.eval_instr(mov(ExprMem(esp), eax))
machine.eval_instr(push(ExprInt(uint32(0x1337beef))))

for k in machine.pool:
    machine.pool[k] = expr_simp(machine.pool[k])

print dump_reg(machine.pool)
init_mem = dict(machine.pool)


for f_ad in xrange(min_addr, max_addr):
    if f_ad %0x100 == 0:
        print hex(f_ad)
    machine.pool = dict(init_mem)
    start_ad = f_ad
    my_eip = ExprInt(uint32(f_ad))
    cycles = 0
    
    while True:
        cycles += 1
        # max 5 instructions chain
        if cycles> 5:
            break

        #final check
        if isinstance(my_eip, ExprCond):
            my_eip = my_eip.src1
        elif not isinstance(my_eip, ExprInt):
            break
        ad  = int(my_eip.arg)
        #if not e.is_in_virt_address(ad):
        if not (min_addr < ad< max_addr):
            break
        in_str.offset = ad
        
        l = x86_mn.dis(in_str)
        # print hex(my_eip.arg), l
        if not l:
            break
        
        args = []
        my_eip.arg+=uint32(l.l)
        try:
            ex = get_instr_expr(l, my_eip, args)
        except:
            break
        try:
            my_eip, mem_dst = emul_full_expr(ex, l, my_eip, None, machine)
        except:
            break
        
    for k in machine.pool:
        machine.pool[k] = expr_simp(machine.pool[k])

    if isinstance(my_eip, ExprCond):
        continue
    # we want eip controled by ARG* id or DATA
    # here, crappy test on str (not clean expression filtering)
    if not ("ARG" in str(my_eip) or "DATA" in str(my_eip)):
        continue

    # we want esp controled by ARG* id or DATA
    my_esp = machine.pool[esp]
    if not ("ARG" in str(my_esp) or "DATA" in str(my_esp)):
        continue

    # this should give stack pivot
    print "#"*0x80
    print 'constraint solved ad ', hex(start_ad)
    print "eip", my_eip
    print "esp", my_esp
