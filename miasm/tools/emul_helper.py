#!/usr/bin/env python
#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

from miasm.arch.ia32_sem import *
from miasm.expression.expression_helper import *
from miasm.core.memory_pool import *
from miasm.core import asmbloc
import StringIO
import zlib

from miasm.expression.expression_eval_abstract import *

log_emu_helper = logging.getLogger("emu.helper")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_emu_helper.addHandler(console_handler)
log_emu_helper.setLevel(logging.WARN)

def hexdump(a, offset = 0):
    out ="" 
    for i,c in enumerate(a):
        if i%0x10==0:
            out+="\n%.8X "%(offset+i)
            
        out+="%.2X "%ord(c)
    return out
      

def tohex(a):
        
    try:
        a = int(a)
    except:
        return a
    if a <0:
        a = struct.pack('l', a)
    else:
        a = struct.pack('L', a)
    a = struct.unpack('L', a)[0]
    return hex(a)
    

jcc = ['jz', 'je', 'jnz', 'jp', 'jnp', 'jg', 'jge', 'ja', 'jae', 'jb', 'jbe', 'jl', 'jle', 'js', 'jns', 'jo', 'jno', 'loop', 'loopne']

def dump_pool(p):
    log_emu_helper.error('/-------------\\')
    for x in p:
        log_emu_helper.error(str(x)+' '+tohex(str(p[x])))
    log_emu_helper.error('\\_____________/')

def dump_reg(p):
    out = " "*20
    for x in [eax, ebx, ecx, edx, esi, edi, esp, ebp, zf]:
        if isinstance(p[x], ExprInt):
            out+=str(x)+' %.8X  '%int(p[x].arg)
        else:
            out+=str(x)+' %s  '%p[x]
                      
    return out


def dump_mem(p):
    out = []
    todo = []
    kk = p.keys()
    kk.sort()
    for x in kk:
        if isinstance(x, ExprMem):
            todo.append(x)
    todo.sort()
    for x in todo:
        out.append('%s    %s'%(str(x), str(p[x])))
                      
    return "\n".join(out)

def mem_read(evaluator, env, src_address, mem_size):
    if not isinstance(src_address, ExprInt):
        dump_pool(evaluator.pool)
        raise "cannot read", str(src_address)
    src_address_l = int(src_address.arg)
    try:
        
        if mem_size == 32:
            ret = uint32(env.get_d(src_address_l))
        elif mem_size == 16:
            ret = uint16(env.get_w(src_address_l))
        elif mem_size == 8:
            ret = uint8(env.get_b(src_address_l))
        else:
            raise 'unknown size read', str(src_address.nbytes)
        log_emu_helper.debug("=>read @(%X)(%.8X)"%(src_address_l, int(ret)))
        return ExprInt(ret)
    except:
        dump_pool(evaluator.pool)
        raise ValueError('read bug at 0x%X'%int(src_address_l))

def mem_write(evaluator, env, mem_size, dst_address, src_val, pool_out = None):
    if not isinstance(dst_address, ExprInt) or not isinstance(src_val, ExprInt):
        dump_pool(evaluator.pool)
        raise ValueError("cannot write %s %s"%(str(dst_address), str(src_val)))
    dst_address_l = int(dst_address.arg)
    src_val = src_val.arg
    try:
        log_emu_helper.debug("=>write @(%X)(%.8X)"%(dst_address_l, int(src_val)))
        if mem_size == 32:
            env.set_d(dst_address_l, src_val&0xffffffff)
        elif mem_size == 16:
            env.set_w(dst_address_l, src_val&0xffff)
        elif mem_size == 8:
            env.set_b(dst_address_l, src_val&0xff)
        else:
            raise 'unknown size write', str(dst_address.nbytes)
    except:
        dump_pool(evaluator.pool)
        raise' write bug'

  
        
    
 
###XXX for eval int 
def get_instr_expr_args(name, modifs, mnemo_mode, args, my_eip):
    for a in args:
        if type(a) in [int, long]:
            raise ValueError('int deprec in args')


    if name in ['jmp']:
        if isinstance(args[0], ExprInt):
            e = mnemo_func[name](ExprOp('+', my_eip, args[0]))
        else:
            e = mnemo_func[name](*args)
    elif name in jcc:
        e = mnemo_func[name](my_eip, ExprOp('+', my_eip, args[0]))
    elif name in ['call']:
        if isinstance(args[0], ExprInt):# or is_imm(args[0]):
            e = mnemo_func[name](my_eip, ExprOp('+', my_eip, args[0]))
        else:
            e = mnemo_func[name](my_eip, args[0])
    else:
        e = mnemo_func[name](*args)
    return e

###XXX for eval int 
def get_instr_expr(l, my_eip, args = None):
    if args==None:args = []
    for x in l.arg:
        args.append(dict_to_Expr(x, l.m.modifs, l.mnemo_mode))
    l.arg_expr = args
    return get_instr_expr_args(l.m.name, l.m.modifs, l.mnemo_mode, args, my_eip)



###XXX for eval abs
def get_instr_expr_args(name, modifs, mnemo_mode, args, my_eip):
    for a in args:
        if type(a) in [int, long]:
            raise ValueError('int deprec in args')


    if name in ['jmp']:
        if isinstance(args[0], ExprInt):
            e = mnemo_func[name](args[0])
        else:
            e = mnemo_func[name](*args)
    elif name in jcc:
        e = mnemo_func[name](my_eip, args[0])
    elif name in ['call']:
        e = mnemo_func[name](my_eip, args[0])
    else:
        e = mnemo_func[name](*args)
    return e

###XXX for eval abs
def get_instr_expr(l, my_eip, args = None):
    if args==None:args = []
    for x in l.arg:
        args.append(dict_to_Expr(x, l.m.modifs, l.mnemo_mode))
    l.arg_expr = args
    return get_instr_expr_args(l.m.name, l.m.modifs, l.mnemo_mode, args, my_eip)





def emul_expr(machine, e, my_eip):
    mem_dst = machine.eval_instr(e)

    if eip in machine.pool:
        if isinstance(machine.pool[eip], ExprCond):
            pass
        my_eip = machine.eval_expr(eip, {})
        del machine.pool[eip]
    return my_eip, mem_dst

def emul_bloc(machine, bloc):
    return emul_lines(machine, bloc.lines)



def emul_lines(machine, lines):
    my_eip = None
    for l in lines:
        my_eip = ExprInt(uint32(l.offset))

        args = []
        my_eip.arg+=uint32(l.l)
        ex = get_instr_expr(l, my_eip, args)
        my_eip, mem_dst = emul_full_expr(ex, l, my_eip, None, machine)

        for k in machine.pool:
            machine.pool[k] = expr_simp(machine.pool[k])

    return my_eip



def emul_imp_init(machine, libbase = 0xCCC00000, malloc_next_ad = 0xEEE00000):
    #for loadlibrary & getprocaddress emul
    machine.lib_bases = {}
    machine.lib_bases_func_index = {}
    machine.lib_base = libbase    
    machine.func_loaded = {}

    #for malloc & free emul
    machine.malloc_next_ad = malloc_next_ad;
    
    
def emul_loadlibrary(machine, env):
    my_esp = machine.eval_expr(machine.pool[esp], {})
    libname_ad = env.get_d(my_esp+4)
    libname = ""
    l = 0
    while True:
        libname+=chr(env.get_b(libname_ad+l))
        l+=1
        if libname[-1]=='\x00':
            break

    machine.lib_bases[machine.lib_base] = libname
    machine.lib_bases_func_index[machine.lib_base] = machine.lib_base+1
    machine.eval_instr(mov(eax, ExprInt(uint32(machine.lib_base))))

    machine.lib_base+=0x1000
    print "emul loadlib %X, %s"%(libname_ad, libname[:-1])
    log.info("emul loadlib %X, %s"%(libname_ad, libname))
    machine.eval_instr(ret(ExprInt(uint32(4))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    return my_eip

def emul_getprocaddress(machine, env):
    my_esp = machine.eval_expr(machine.pool[esp], {})
    libbase_ad = env.get_d(my_esp+4)
    funcname_ad = env.get_d(my_esp+8)
    funcname = ""
    l = 0
    while True:
        funcname+=chr(env.get_b(funcname_ad+l))
        l+=1
        if funcname[-1]=='\x00':
            break

    log.info("emul getprocaddress %X, %s"%(libbase_ad, funcname))
    print "emul getprocaddress %X, %s"%(libbase_ad, funcname[:-1])

    if not libbase_ad in machine.lib_bases:
        log.debug(machine.lib_bases)
        raise 'unknown base lib! %s'%str(libbase_ad)
    func_ad = machine.lib_bases_func_index[libbase_ad]
    
    machine.lib_bases_func_index[libbase_ad]+=1
    machine.eval_instr(mov(eax, ExprInt(uint32(func_ad))))

    machine.func_loaded[func_ad] = funcname

    machine.eval_instr(ret(ExprInt(uint32(8))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    return my_eip

def hook_import_func(env, imported_func, start_address_hook = 0xAABB0000):
    func_hook_ptr = {}
    for f in imported_func:
        env.set_d(f, start_address_hook)
        func_hook_ptr[start_address_hook] = imported_func[f]
        start_address_hook+=0x10000
        
    return func_hook_ptr

def dump_imp(machine):

     log_emu_helper.warn('_'*10)
     for l in machine.lib_bases:
         log_emu_helper.warn("%.8X %s"%(l, machine.lib_bases[l]))

     log_emu_helper.warn('_'*10)
     for f in machine.func_loaded:
         log_emu_helper.warn("%.8X %s"%(f, machine.func_loaded[f]))


def emul_malloc(machine, env):
    my_esp = machine.get_reg(esp)
    pool_type =env.get_d(my_esp+0x4)
    alloc_size =env.get_d(my_esp+0x8)
    tag =env.get_d(my_esp+0xc)
    
    machine.eval_instr(ret(ExprInt(uint32(0xc))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    
    ret_alloc_ad = machine.malloc_next_ad
    m_data = mempool(machine.malloc_next_ad, machine.malloc_next_ad+alloc_size, 'RW', name = "malloc %.8X"%alloc_size)
    machine.malloc_next_ad += ((alloc_size+0xFFF)&(~0xFFF))
    
    log.warn('alloc(%X) tag %X poolt %X from %X esp %X ret %X:'%(int(alloc_size), int(tag), int(pool_type), int(my_eip), int(my_esp), int(machine.malloc_next_ad)))
    machine.eval_instr(mov(eax, ExprInt(uint32(ret_alloc_ad))))
    
    env.mems.append(m_data)
    log.warn(str(env))
    return my_eip

def emul_free(machine, env):
    my_esp = machine.get_reg(esp)
    address_free =env.get_d(my_esp+4)

    machine.eval_instr(ret(ExprInt(uint32(4))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]

    log.warn('free(%X) from %X esp %X:'%(int(address_free), int(my_eip), int(my_esp)))

    if address_free !=0:
        m = env.get_mem_pool(address_free)
        if not m:
            raise 'cannot find freeing mem!'
        env.mems.remove(m)
    log.warn(str(env))
    return my_eip


def emul_pitfall(machine, env):
    raise 'func not impl!'


def emul_heapcreate(machine, env):
    my_esp = machine.get_reg(esp)
    floptions =env.get_d(my_esp+4)
    dwinitialsize =env.get_d(my_esp+8)
    dwmaximumsize =env.get_d(my_esp+12)
    
    machine.eval_instr(ret(ExprInt(uint32(12))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    
    
    log.warn('heapcreate(%X %X %X) from %X esp %X ret %X:'%(floptions, dwinitialsize, dwmaximumsize, int(my_eip), my_esp, 0xdeadcafe))
    machine.eval_instr(mov(eax, ExprInt(uint32(0xdeadcafe))))
    
    return my_eip
    
def emul_heapalloc(machine, env):
    my_esp = machine.get_reg(esp)
    hheap =env.get_d(my_esp+4)
    dwflags =env.get_d(my_esp+8)
    alloc_size =env.get_d(my_esp+12) 
   
    machine.eval_instr(ret(ExprInt(uint32(12))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    
    ret_alloc_ad = machine.malloc_next_ad
    m_data = mempool(machine.malloc_next_ad, machine.malloc_next_ad+alloc_size, 'RW', name = "heapalloc %.8X"%alloc_size)
    machine.malloc_next_ad += ((alloc_size+0xFFF)&(~0xFFF))
    
    log.warn('heapalloc(%X %X %X) from %X esp %X ret %X:'%(hheap, dwflags, alloc_size, int(my_eip), my_esp, machine.malloc_next_ad))
    machine.eval_instr(mov(eax, ExprInt(uint32(ret_alloc_ad))))
    
    env.mems.append(m_data)
    log.warn(str(env))
    return my_eip

#VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
def emul_virtualprotect(machine, env):
    my_esp = machine.eval_expr(machine.pool[esp], {})
    lpaddress = env.get_d(my_esp+4)
    dwsize = env.get_d(my_esp+8)
    flnewprotect = env.get_d(my_esp+12)
    lpfloldprotect = env.get_d(my_esp+16)

    #XXX return 1??
    machine.eval_instr(mov(eax, ExprInt(uint32(1))))

    log.info("emul virtualprotect %X, %X %X %X"%(lpaddress, dwsize, flnewprotect, lpfloldprotect))
    machine.eval_instr(ret(ExprInt(uint32(16))))
    #dump_pool(machine.pool)
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    return my_eip

def emul_virtualalloc(machine, env):
    my_esp = machine.get_reg(esp)
    lpaddress =env.get_d(my_esp+4)
    alloc_size =env.get_d(my_esp+8)
    flallocationtype =env.get_d(my_esp+12) 
    flprotect =env.get_d(my_esp+16) 
   
    machine.eval_instr(ret(ExprInt(uint32(16))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    
    ret_alloc_ad = machine.malloc_next_ad
    m_data = mempool(machine.malloc_next_ad, machine.malloc_next_ad+alloc_size, 'RW', name = "virtualalloc %.8X"%alloc_size)
    machine.malloc_next_ad += ((alloc_size+0xFFF)&(~0xFFF))
    
    log.warn('virtualalloc(%X %X %X %X) from %X esp %X ret %X:'%(lpaddress, alloc_size, flallocationtype, flprotect, int(my_eip), my_esp, machine.malloc_next_ad))
    machine.eval_instr(mov(eax, ExprInt(uint32(ret_alloc_ad))))
    
    env.mems.append(m_data)
    log.warn(str(env))
    return my_eip


def emul_virtualfree(machine, env):
    my_esp = machine.get_reg(esp)
    address_free =env.get_d(my_esp+4)
    dwsize =env.get_d(my_esp+8)
    dwfreetype =env.get_d(my_esp+12)
    
    

    machine.eval_instr(ret(ExprInt(uint32(12))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]

    log.warn('virtualfree(%X %X %X) from %X esp %X:'%(address_free, dwsize, swfreetype, int(my_eip), my_esp))

    if address_free !=0:
        m = env.get_mem_pool(address_free)
        if not m:
            raise 'cannot find freeing mem!'
        env.mems.remove(m)
    log.warn(str(env))
    return my_eip



def emul_getmodulehandlea(machine, env):
    my_esp = machine.eval_expr(machine.pool[esp], {})
    libname_ad = env.get_d(my_esp+4)
    libname = ""
    l = 0
    while True:
        libname+=chr(env.get_b(libname_ad+l))
        l+=1
        if libname[-1]=='\x00':
            break


    machine.eval_instr(ret(ExprInt(uint32(4))))
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]


    log.info("emul loadlib (%X), %s from %X"%(libname_ad, libname, my_eip))

    if False:#libname.startswith("kernel32.dll"):
        machine.eval_instr(mov(eax, ExprInt(uint32(0x7C800000))))
    else:
        machine.eval_instr(mov(eax, ExprInt(uint32(0x0))))
        log.warn("unknown lib: %s"%str(libname))
        
    log.warn(str(env))

    return my_eip

def emul_kddisabledebugger(machine, env):
    my_esp = machine.get_reg(esp)
    
    machine.eval_instr(ret())
    my_eip = machine.eval_expr(machine.pool[eip], {})
    del machine.pool[eip]
    
    
    log.warn('emul_kddisabledebugger from %X esp %X '%(int(my_eip), int(my_esp)))
    machine.eval_instr(mov(eax, ExprInt(uint32(0))))
    
    log.warn(str(env))
    return my_eip
    
    
    
def sav_machine(machine, env, my_eip, snap_fmt_name):

    print 'SAVE**************tsc: %.10d***************'%machine.pool[tsc1].arg
    machine.pool[eip] = my_eip
    env_s = StringIO.StringIO()
    env.to_file(env_s)
    env_s.flush()
    fname = snap_fmt_name+".env" 
    open(fname%(machine.pool[tsc1].arg), 'wb').write(zlib.compress(env_s.getvalue(), 9))
    machine_s = StringIO.StringIO()
    machine.to_file(machine_s)
    machine_s.flush()
    fname = snap_fmt_name+".machine"
    open(fname%(machine.pool[tsc1].arg), 'wb').write(zlib.compress(machine_s.getvalue(), 9))
    del machine.pool[eip]
    
    
def load_machine(snap_fmt_name, step):

    fname = snap_fmt_name+".env" 
    env_s = StringIO.StringIO(zlib.decompress(open(fname%step, 'rb').read()))
    env = mempool_manager.from_file(env_s)
    fname = snap_fmt_name+".machine"        
    machine_s = StringIO.StringIO(zlib.decompress(open(fname%step, 'rb').read()))
    machine = eval_int.from_file(machine_s, globals())
    my_eip = machine.pool[eip]
    del machine.pool[eip]
    print 'LOAD**************tsc: %.10X***************'%machine.pool[tsc1].arg
    print "machine eip: %.8X"%int(my_eip.arg)
    
    return machine, env, my_eip
     
def emul_full_expr(e, l, my_eip, env, machine):
    if ((not 0xF2 in l.prefix) and (not 0xF3 in l.prefix)) or \
           not l.m.name[:-1] in ["ins", "outs", "movs", "lods", "stos", "cmps", "scas"]:
        my_eip, mem_dst = emul_expr(machine, e, my_eip)
    else:
        #rep mnemo
        #XXX HACK 16 bit
        if 0x66 in l.prefix and l.m.name[-1]== "d":
            raise "not impl 16 bit string"
        zf_w = zf in reduce(lambda x,y:x+y, [list(x.get_w()) for x in e], [])
        
        while True:

            my_ecx = machine.eval_expr(machine.pool[ecx], {})
            if not isinstance(my_ecx, ExprInt):# in tab_int_size:#[int, long]:
                raise "cannot eval counter....", str(machine.pool[ecx])
            if l.mnemo_mode== u16:
                my_ecx.arg&=0xFFFF
            if my_ecx.arg ==0:
                break

            my_esi = machine.eval_expr(machine.pool[esi], {})
            my_edi = machine.eval_expr(machine.pool[edi], {})
            tmp,mem_dst =  emul_expr(machine, e, my_eip)
            
            machine.eval_instr(mov(ecx, ExprOp('-', my_ecx, ExprInt(uint32(1)))))
            machine.eval_expr(machine.pool[ecx], {})

            if zf_w :
                my_zf = machine.eval_expr(machine.pool[zf], {})
                if 0xF3 in l.prefix and my_zf == 0:
                    break
                if 0xF2 in l.prefix and my_zf == 1:
                    break

            machine.pool[tsc1].arg+=uint32(1)

    return my_eip, mem_dst
    

def guess_func_destack(all_bloc):
    ret_destack = None
    for b in all_bloc:
        l = b.lines[-1]
        if not l.m.name.startswith('ret'):
            continue
        if len(l.arg) == 0:
            a = 0  
        elif len(l.arg) ==1:
            a = l.arg[0][x86_afs.imm]
        else:
            continue
        if ret_destack!=None:
            if a != ret_destack:
                print 'found diff ret unstack', ret_destack, a
                return None, None
            else:
                continue
        ret_destack = a


    if ret_destack !=None:
        return True, ret_destack

    #try func wrapper
    if len(all_bloc)!= 1:
        return None, None
    l = all_bloc[0].lines[-1]
    if not l.m.name.startswith('jmp') or len(l.arg) !=1:
        return None, None

    a = l.arg[0]
    print hex(l.offset), a, type(a)

    if not x86_afs.imm in a or not x86_afs.ad in a or not a[x86_afs.ad]:
        return None, None

    return False, a[x86_afs.imm]


def digest_allbloc_instr(all_bloc):
    instrs = {}
    g = asmbloc.bloc2graph(all_bloc)
    open("graph_b.txt" , "w").write(g)


    #test duplicated blocs
    unik_blobs = {}
    for b in all_bloc:
        if not b.label in unik_blobs:
            unik_blobs[b.label] = []
        unik_blobs[b.label].append(b)


    for lbl, blcs in unik_blobs.items():
        if len(blcs) ==1:
            continue
        tmp = blcs.pop()
        for b in blcs:
            if str(tmp) != str(b):
                print tmp
                print b
                raise ValueError('diff bloc in same label')
            all_bloc.remove(b)
        
    for b in all_bloc:
        for l in b.lines:
            if l.offset in instrs:
                log.warn(('zarb: dup instr', (hex(l.offset), str(l))))
                if str(instrs[l.offset][0]) != str(l):
                    raise ValueError('dup instr@ with different instr', (str(l), str(instrs[l.offset][0])))
            args = []
            ex = get_instr_expr(l, ExprInt(uint32(l.offset+l.l)), args)

                
            instrs[l.offset] = (l, ex)
    return instrs


def x86_machine():
    machine = eval_abs({esp:init_esp, ebp:init_ebp, eax:init_eax, ebx:init_ebx, ecx:init_ecx, edx:init_edx, esi:init_esi, edi:init_edi,
                        cs:ExprInt(uint32(9)),
                        zf :  init_zf,  nf :  init_nf, pf : init_pf,
                        of :  init_of, cf :  init_cf, tf : init_tf,
                        i_f:  init_i_f, df :  init_df, af : init_af,
                        iopl: init_iopl, nt :  init_nt, rf : init_rf,
                        vm :  init_vm, ac :  init_ac, vif: init_vif,
                        vip:  init_vip, i_d:  init_i_d,tsc1: init_tsc1,
                        tsc2: init_tsc2,
                        dr7:ExprInt(uint32(0)),
                        cr0:init_cr0,
                        #my_ret_addr:my_ret_addri
                        
                        },
                       #mem_read_wrap,
                       #mem_write_wrap,
                       
                       )
    return machine
