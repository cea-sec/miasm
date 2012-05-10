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
from miasm.core import asmbloc
from miasm.core.bin_stream import bin_stream
from miasm.arch.ia32_arch import *
from miasm.arch.ia32_sem import *
import struct

log_to_c_h = logging.getLogger("emu.to_c_helper")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_to_c_h.addHandler(console_handler)
log_to_c_h.setLevel(logging.WARN)

from elfesteem import *



from miasm.tools.emul_helper import *
from miasm.expression.expression_eval_abstract import eval_abs
from miasm.expression.expression_helper import *

from elfesteem.strpatchwork import StrPatchwork
import ctypes

def id2new(i):
    return str(i)+'_new'

mask_int = 0xffffffffffffffff


pfmem08_0 = ExprId("pfmem08_0", 8)
pfmem08_1 = ExprId("pfmem08_1", 8)
pfmem08_2 = ExprId("pfmem08_2", 8)
pfmem08_3 = ExprId("pfmem08_3", 8)
pfmem08_4 = ExprId("pfmem08_4", 8)
pfmem08_5 = ExprId("pfmem08_5", 8)
pfmem08_6 = ExprId("pfmem08_6", 8)
pfmem08_7 = ExprId("pfmem08_7", 8)

pfmem16_0 = ExprId("pfmem16_0", 16)
pfmem16_1 = ExprId("pfmem16_1", 16)
pfmem16_2 = ExprId("pfmem16_2", 16)
pfmem16_3 = ExprId("pfmem16_3", 16)
pfmem16_4 = ExprId("pfmem16_4", 16)
pfmem16_5 = ExprId("pfmem16_5", 16)
pfmem16_6 = ExprId("pfmem16_6", 16)
pfmem16_7 = ExprId("pfmem16_7", 16)

pfmem32_0 = ExprId("pfmem32_0", 32)
pfmem32_1 = ExprId("pfmem32_1", 32)
pfmem32_2 = ExprId("pfmem32_2", 32)
pfmem32_3 = ExprId("pfmem32_3", 32)
pfmem32_4 = ExprId("pfmem32_4", 32)
pfmem32_5 = ExprId("pfmem32_5", 32)
pfmem32_6 = ExprId("pfmem32_6", 32)
pfmem32_7 = ExprId("pfmem32_7", 32)

pfmem64_0 = ExprId("pfmem64_0", 64)
pfmem64_1 = ExprId("pfmem64_1", 64)
pfmem64_2 = ExprId("pfmem64_2", 64)
pfmem64_3 = ExprId("pfmem64_3", 64)
pfmem64_4 = ExprId("pfmem64_4", 64)
pfmem64_5 = ExprId("pfmem64_5", 64)
pfmem64_6 = ExprId("pfmem64_6", 64)
pfmem64_7 = ExprId("pfmem64_7", 64)


my_C_id = [
    eax,
    ebx,
    ecx,
    edx,
    esi,
    edi,
    esp,
    ebp,
    eip,
    zf,
    nf,
    pf,
    of,
    cf,
    af,
    df,
    #eax_new,
    #ebx_new,
    #ecx_new,
    #edx_new,
    #esi_new,
    #edi_new,
    #esp_new,
    #ebp_new,
    #eip_new,
    #zf_new,
    #nf_new,
    #pf_new,
    #of_new,
    #cf_new,
    #af_new,
    #df_new,
    tf,
    i_f,
    iopl,
    nt,
    rf,
    vm,
    ac,
    vif,
    vip,
    i_d,
    #tf_new,
    #i_f_new,
    #iopl_new,
    #nt_new,
    #rf_new,
    #vm_new,
    #ac_new,
    #vif_new,
    #vip_new,
    #i_d_new,
    #my_tick,
    float_control,
    float_eip ,
    float_cs ,
    float_address ,
    float_ds ,
    #cond,
    #vm_exception_flags,
    #vm_exception_flags_new,
    #vm_last_write_ad,
    #vm_last_write_size,
    tsc1,
    tsc2,


    es ,
    cs ,
    ss ,
    ds ,
    fs ,
    gs ,

    float_st0,
    float_st1,
    float_st2,
    float_st3,
    float_st4,
    float_st5,
    float_st6,
    float_st7,

    float_c0,
    float_c1,
    float_c2,
    float_c3,

    cr0,
    cr3,

    float_stack_ptr,
    pfmem08_0,
    pfmem08_1,
    pfmem08_2,
    pfmem08_3,
    pfmem08_4,
    pfmem08_5,
    pfmem08_6,
    pfmem08_7,

    pfmem16_0,
    pfmem16_1,
    pfmem16_2,
    pfmem16_3,
    pfmem16_4,
    pfmem16_5,
    pfmem16_6,
    pfmem16_7,

    pfmem32_0,
    pfmem32_1,
    pfmem32_2,
    pfmem32_3,
    pfmem32_4,
    pfmem32_5,
    pfmem32_6,
    pfmem32_7,

    pfmem64_0,
    pfmem64_1,
    pfmem64_2,
    pfmem64_3,
    pfmem64_4,
    pfmem64_5,
    pfmem64_6,
    pfmem64_7,

    ]

float_id_e = [
    float_st0,
    float_st1,
    float_st2,
    float_st3,
    float_st4,
    float_st5,
    float_st6,
    float_st7,
    ]

id2Cid = {}
for x in my_C_id:
    id2Cid[x] = ExprId('vmcpu.'+str(x), x.get_size())

def patch_c_id(e):
    return e.reload_expr(id2Cid)


code_deal_exception_at_instr = r"""
if (vmcpu.vm_exception_flags > EXCEPT_NUM_UDPT_EIP) {
    %s = 0x%X;
    return vmcpu.eip;
}
"""
code_deal_exception_post_instr = r"""
if (vmcpu.vm_exception_flags) {
    %s = (vmcpu.vm_exception_flags > EXCEPT_NUM_UDPT_EIP) ?  0x%X : 0x%X;
    return vmcpu.eip;
}
"""


tab_uintsize ={8:uint8,
               16:uint16,
               32:uint32,
               64:uint64
               }

def Exp2C(exprs, l = None, addr2label = None, gen_exception_code = False):
    my_size_mask = {1:1, 8:0xFF, 16:0xFFFF, 32:0xFFFFFFFF,  64:0xFFFFFFFFFFFFFFFFL,
                    2: 3}
    if not addr2label:
        addr2label = lambda x:x
    id_to_update = []
    out = []
    out_eip = []
    #print [str(x) for x in exprs]

    dst_dict = {}
    src_mem = {}

    prefect_mem_pool = {8: [pfmem08_0 ,pfmem08_1, pfmem08_2, pfmem08_3,
                            pfmem08_4, pfmem08_5, pfmem08_6, pfmem08_7],
                        16: [pfmem16_0 ,pfmem16_1, pfmem16_2, pfmem16_3,
                            pfmem16_4, pfmem16_5, pfmem16_6, pfmem16_7],
                        32: [pfmem32_0 ,pfmem32_1, pfmem32_2, pfmem32_3,
                            pfmem32_4, pfmem32_5, pfmem32_6, pfmem32_7],
                        64: [pfmem64_0 ,pfmem64_1, pfmem64_2, pfmem64_3,
                            pfmem64_4, pfmem64_5, pfmem64_6, pfmem64_7],}

    new_expr = []

    eip_is_dst = False

    for e in exprs:
        if not isinstance(e, ExprAff):
            raise ValueError('should be expr', str(e))

        if isinstance(e.dst, ExprId):
            if not e.dst in dst_dict:
                dst_dict[e.dst] = []
            dst_dict[e.dst].append(e)
        else:
            new_expr.append(e)
        # search mem lookup for generate mem read prefetch
        rs = e.src.get_r(mem_read=True)
        for r in rs:
            if (not isinstance(r, ExprMem)) or r in src_mem:
                continue
            pfmem = prefect_mem_pool[r.get_size()].pop(0)
            src_mem[r] = pfmem

    for dst, exs in dst_dict.items():
        if len(exs) ==1:
            new_expr += exs
            continue
        log_to_c_h.debug('warning: detected multi dst to same id')
        log_to_c_h.debug(str(l))
        new_expr+=exs
        #test if multi slice (for example xchg al, ah)
        if not False in [isinstance(e.src, ExprCompose) for e in exs]:
            #spotted multi affectation to same id
            e_colision = reduce(lambda x,y:x+y, [e.get_modified_slice() for e in exs])
            #print [str(x) for x in e_colision]
            known_intervals = [(x[1], x[2]) for x in e_colision]
            #print known_intervals
            missing_i = get_missing_interval(known_intervals)
            #print missing_i
            rest = [(ExprSlice(dst, r[0], r[1]), r[0], r[1]) for r in missing_i]
            final_dst = ExprCompose(e_colision+ rest)
            new_expr.append(ExprAff(dst, final_dst))
    out_mem = []

    # first, generate mem prefetch
    mem_k = src_mem.keys()
    mem_k.sort()
    for k in mem_k:
        str_src = patch_c_id(k).toC()
        str_dst = patch_c_id(src_mem[k]).toC()
        out.append('%s = %s;'%(str_dst, str_src))
    src_w_len = {}
    for k, v in src_mem.items():
        cast_int = tab_uintsize[k.get_size()]
        src_w_len[k] = v
    for e in new_expr:
        if True:#e.dst != eip:
            src, dst = e.src, e.dst
            # reload src using prefetch
            src = src.reload_expr(src_w_len)
            str_src = patch_c_id(src).toC()
            str_dst = patch_c_id(dst).toC()
            if isinstance(dst, ExprId):
                id_to_update.append(dst)
                str_dst = id2new(patch_c_id(dst))
                if dst in float_id_e:
                    # dont mask float affectation
                    out.append('%s = (%s);'%(str_dst, str_src))
                else:
                    out.append('%s = (%s)&0x%X;'%(str_dst, str_src,
                                                  my_size_mask[src.get_size()]))
            elif isinstance(dst, ExprMem):
                str_dst = str_dst.replace('MEM_LOOKUP', 'MEM_WRITE')
                out_mem.append('%s, %s);'%(str_dst[:-1], str_src))

        if e.dst == eip :
            eip_is_dst = True
            if isinstance(e.src, ExprCond):
                #out_eip.append("cond = %s;"%e.src.cond.toC())
                out.append("vmcpu.cond = %s;"%patch_c_id(e.src.cond).toC())
                out_eip+=["if (vmcpu.cond)",
                          "\tGOTO_STATIC(vmcpu.eip);//%s);"%(addr2label(e.src.src1.arg)),
                          "else",
                          "\tGOTO_STATIC(vmcpu.eip);//%s);"%(addr2label(e.src.src2.arg)),
                          ]
            else:
                if isinstance(e.src, ExprInt):
                    if l.is_subcall():
                        out_eip.append("GOTO_STATIC_SUB(%s);"%(addr2label(e.src.arg)))
                    else:
                        out_eip.append("GOTO_STATIC(0x%.16X);"%(e.src.arg))
                else:
                    if l.is_subcall():
                        out_eip.append("GOTO_DYN_SUB(%s);"%(patch_c_id(e.src).toC()))
                    else:
                        out_eip.append('GOTO_DYNAMIC; //(%s);'%patch_c_id(e.src).toC())


    #if len(id_to_update) != len(set(id_to_update)):
    #    raise ValueError('Not implemented: multi dst to same id!', str([str(x) for x in exprs]))

    out+=out_mem

    if gen_exception_code:
        out.append(code_deal_exception_at_instr % (patch_c_id(eip), (l.offset&mask_int)))

    for i in id_to_update:
        out.append('%s = %s;'%(patch_c_id(i), id2new(patch_c_id(i))))




    post_instr = []
    #### test stop exec ####
    if gen_exception_code:
        if eip_is_dst:
            #post_instr.append("if (vmcpu.vm_exception_flags) { /*eip = 0x%X; */return (unsigned int)vm_get_exception(vmcpu.vm_exception_flags); }"%(l.offset))
            post_instr.append("if (vmcpu.vm_exception_flags) { /*eip = 0x%X; */return vmcpu.eip; }"%(l.offset))
        else:
            post_instr.append(code_deal_exception_post_instr % (patch_c_id(eip), (l.offset&mask_int), (l.offset + l.l)&mask_int))
    
    """
    print "1"
    print out
    print "2"
    print out_eip
    print "3"
    print post_instr
    """
    
        

    #eip manip after all modifications
    return out+out_eip, post_instr


def bloc2C(all_bloc, addr2label = None, gen_exception_code = False, dbg_instr = False, dbg_reg = False, dbg_lbl = False, filtered_ad = None, tick_dbg = None, segm_to_do = {}):
    all_instrs = digest_allbloc_instr(all_bloc, segm_to_do)

    if not addr2label:
        addr2label = lambda x:"loc_%.16X"%(x&mask_int)


    out = []
    label_done = set()
    for b in all_bloc:
        #out.append("%s:"%str(b.label.name))
        if dbg_lbl or dbg_instr:
            if (not filtered_ad) or b.label.offset in filtered_ad:
                if tick_dbg!=None:
                    out.append('if (my_tick > %d)'%tick_dbg)
                out.append(r'fprintf(stdout, "%s\n");'%str(b.label.name))
        
        
        for l in b.lines:
            if l.offset in label_done:
                continue
            label_done.add(l.offset)
            l,ex = all_instrs[l.offset]
            if addr2label:
                out.append("%s:"%addr2label(l.offset))
            else:
                out.append("loc_%.16X:"%(l.offset&mask_int))
                
            o, post_instr = Exp2C(ex, l, addr2label, gen_exception_code)
            

            

            #if add_return:
            #    o.append('return;');
            #if add_call:
            #    o.append('%s();'%add_call);
    
            if (0xF2 in l.prefix or 0xF3 in l.prefix) and l.m.name in ["ins", "outs", "movsb", "movsw", "movsd", "lodsb", "lodsw", "lodsd", "stosb", "stosw", "stosd" ]+ [ "cmpsb", "cmpsw", "cmpsd", "scasb", "scasw", "scasd" ]:
                zf_w = zf in reduce(lambda x,y:x+y, [list(x.get_w()) for x in ex], [])
                my_o = ["while (1){"]
                #my_o.append("if (vmcpu.vm_exception_flags) { %s = 0x%X; return (PyObject*)vm_get_exception(vm_exception_flags); }"%(patch_c_id(eip), l.offset))
                #my_o.append(code_deal_exception_post_instr % (patch_c_id(eip), l.offset, l.offset + l.l))
                my_o.append(code_deal_exception_post_instr % (patch_c_id(eip), (l.offset&mask_int), (l.offset&mask_int)))


                #my_o.append(r'fprintf(stderr, "ecx %.8X\n", ecx );')            
                my_o+= ['if (%s==0) break;'%patch_c_id(ecx)]
                my_o+=o
                my_o+= ['%s--;'%patch_c_id(ecx)]
                if zf_w:
                    if 0xF3 in l.prefix:
                        my_o+= ['if (%s==0) break;'%patch_c_id(zf)]
                    if 0xF2 in l.prefix:
                        my_o+= ['if (%s==1) break;'%patch_c_id(zf)]


                my_o += ["}"]
    
                o = my_o

            o+= post_instr
            #print "\t"+"\n\t".join(o)

            if dbg_reg and ((not filtered_ad) or l.offset in filtered_ad):
                if tick_dbg!=None:
                    out.append(r'vmcpu.my_tick++;')
                    out.append('if (vmcpu.my_tick > %d)'%tick_dbg)
                out.append(r'printf("                                          eax %.8X ebx %.8X ecx %.8X edx %.8X esi %.8X edi %.8X esp %.8X ebp %.8X c%X p%X a%X z%X n%X d%X o%X\n", vmcpu.eax, vmcpu.ebx, vmcpu.ecx, vmcpu.edx, vmcpu.esi, vmcpu.edi, vmcpu.esp, vmcpu.ebp, vmcpu.cf, vmcpu.pf, vmcpu.af, vmcpu.zf, vmcpu.nf, vmcpu.df, vmcpu.of );')
            if dbg_instr and ((not filtered_ad) or l.offset in filtered_ad):
                if tick_dbg!=None:
                    out.append('if (vmcpu.my_tick > %d)'%tick_dbg)
                out.append(r'fprintf(stdout, "%s\n");'%str(l))
            else:
                out.append(r'//%s'%str(l))

            out+=o

        
        for c in b.bto:
            if c.c_t == asmbloc.asm_constraint.c_next:
                out.append("GOTO_STATIC(0x%.16X);"%(c.label.offset&mask_int))
        
        """
        #in case of bad disasm, no next, so default next instr
        #XXX BUG if  no line!!!
        
        if b.lines:
            l = b.lines[-1]
            out.append("GOTO_STATIC(%s);"%(addr2label(l.offset + l.l)))
        """


    return out



def bloc_gen_C_func(all_bloc, funcname, addr2label = None, gen_exception_code = False, dbg_instr = False, dbg_reg = False, dbg_lbl = False, filtered_ad = None, tick_dbg = None, segm_to_do = {}):
    f_dec = 'uint64_t %s(void)'%funcname
    out = []
    out+=[f_dec,
          '{',
          ]
    out += bloc2C(all_bloc, addr2label, gen_exception_code,
                  dbg_instr, dbg_reg, dbg_lbl,
                  filtered_ad, tick_dbg,
                  segm_to_do)
    out+=['}',
          ]
    return f_dec, out


def gen_x86_core():
    import os

    lib_dir = os.path.dirname(os.path.realpath(__file__))
    lib_dir = os.path.join(lib_dir, 'emul_lib')

    txt = ""
    txt += '#include "%s/queue.h"\n'%lib_dir
    txt += '#include "%s/libcodenat.h"\n'%lib_dir

    txt += r'''
    
//#define RAISE(errtype,msg) { PyErr_SetString(errtype,msg); RE_RAISE; }
//#define RE_RAISE           { return NULL; }

#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}



'''
    return txt
        

def gen_C_source(funcs_code, known_mems, dyn_dispatcher):
    c_source = dyn_dispatcher
    c_source+= "\n".join(funcs_code)
    
    kmems = gen_known_mems_code(known_mems)
    c_source = gen_x86_core()+"\n".join(kmems)+c_source
    return c_source


def blocs_to_memory_ranges(all_blocs):
    code_addr = []
    for b in all_blocs:
        # XXX no lines in bloc?
        if not b.lines:
            continue
        code_addr.append((b.lines[0].offset, b.lines[-1].offset + b.lines[-1].l))
    return code_addr

def del_bloc_in_range(all_blocs, ad1, ad2):
    bloc_out = []
    for b in all_blocs:
        # XXX no lines in bloc?
        if not b.lines:
            continue
        
        if b.lines[0].offset>=ad2 or b.lines[-1].offset + b.lines[-1].l <= ad1:
            bloc_out.append(b)
        else:
            #print 'inv bloc', b.label
            pass
    return bloc_out
    
def merge_memory_ranges(t):
    i = 0
    while i < len(t)-1:
        j = i+1
        rA1, rA2 = t[i]
        while j < len(t):
            rB1, rB2 = t[j]
            #print "uu", hex(rA1), hex(rA2)
            #print "vv", hex(rB1), hex(rB2)

            if rA1 >= rB1 and rA2 <= rB2:
                #print '#rA included in rB'
                rA1, rA2 = t[j]
                del(t[j])
                continue
            elif rA1 <= rB1 and rA2 >= rB2:
                #print '#rB included in rA'
                del(t[j])
                continue
            elif rA1 <= rB1 and rA2 >= rB1:
                #print '#rA ends in rB'
                rA2 = rB2
                del(t[j])
                continue
            elif rB1 <= rA1 and rB2 >= rA1:
                #print '#rB ends in rA'
                rA1 = rB1
                del(t[j])
                continue
            j+=1
        if t[i] != (rA1, rA2):
            t[i] = rA1, rA2
        else:
            i+=1
            

def gen_code_addr_tab(t):
    out = []

    out += ["#define CODE_ADDR_SIZE (2*%d)"%len(t)]
    out += ["unsigned int code_addr_tab[2*%d] = {"%len(t)]
    for r in t:
        out += ["\t0x%.8X, 0x%.8X,"%(r)]
        
    out += ['};']
    return '\n'.join(out)+'\n'
    
def asm2C(f_name, known_mems, dyn_func, in_str, x86_mn, symbol_pool, func_to_dis, dont_dis = [], follow_call = False, dontdis_retcall = False, log_mn = False, log_reg = False, log_lbl = False, filtered_ad = [], tick_dbg = None, code_addr = [], all_bloc_funcs = []):

    funcs_code = []
    funcs_dec = []

    all_bloc_funcs+=asmbloc.dis_multi_func(in_str, x86_mn, symbol_pool, func_to_dis, dont_dis, follow_call, dontdis_retcall)

    
        
    for b in all_bloc_funcs:
        if b.label.offset in dont_dis:
            continue

        #XXX no lines in bloc?
        if not b.lines:
            continue
        l = b.lines[-1]
        #if l.m.name.startswith('jmp') and not x86_afs.symb in l.arg[0]:
        #    raise ValueError('unsupported dst', str(l))
        '''
        if (l.m.name.startswith('call') or l.m.name.startswith('jmp')) and not x86_afs.symb in l.arg[0]:

            #print "TOTO", hex(l.offset), l, l.arg[0]
            
            #deal dyn call
            instr = x86_mn.dis(x86_mn.asm('mov eax, eax')[0])
            #XXX HACK to be unik address
            instr.offset = l.offset+1

            instr.arg = [{x86_afs.symb:{ExprId('dyn_dst'):1}}, dict(l.arg[0])]

            #print instr, str(instr)
            #instr.offset = 0x1337beef
            
            #b.lines[-1:-1] = [instr]
            #l.arg[0] = {x86_afs.symb:func_deal_dyn}


            #if dyn func is not in ref, add it (todo in gen C)
        '''
    
        for l in b.lines:
    
            #test imm redirect mem ad
            for a in l.arg:
                if not x86_afs.imm in a: continue
                i = a[x86_afs.imm]


                l_name = None
                for m_ad, m_val in known_mems.items():
                    if m_ad <= i < m_ad+len(m_val):
                        l_name = "(unsigned int)&tab_%.8X[0x%X]"%(m_ad, i-m_ad)
                        break

                for f in dyn_func:
                    if i == f:
                        l_name = "(unsigned int)0x%.8X"%(f)
                for f in func_to_dis:
                    if i == f:
                        l_name = "(unsigned int)0x%.8X"%(f)
                        break

                if not l_name:
                    continue
                
                label = asmbloc.asm_label(l_name, i)
                a[x86_afs.symb] = {label:1}
                del a[x86_afs.imm]
                

    code_addr += blocs_to_memory_ranges(all_bloc_funcs)
    merge_memory_ranges(code_addr)
    
    
    allb = all_bloc_funcs#reduce(lambda x,y:x+y, all_bloc_funcs.values(), [])
    f_dec, out = bloc_gen_C_func(allb, f_name, None, True, log_mn, log_reg, log_lbl, filtered_ad, tick_dbg)
    funcs_dec.append(f_dec)
    funcs_code+=out


    for f, f_code in dyn_func.items():
        l_name = "loc_%.16X"%(f&mask_int)
        funcs_code[-1:-1] = [l_name+":"]
        funcs_code[-1:-1] = f_code.split('\n')
        l = asmbloc.asm_label(l_name, f)
        b = asmbloc.asm_bloc(l)
        #all_bloc_funcs[f] = [b]
        all_bloc_funcs += [b]

    funcs_code[2:2] = ["FUNC_DYNAMIC;"]
    funcs_code[3:3] = ["GOTO_DYNAMIC;"]

    funcs_code[0:0] = [gen_code_addr_tab(code_addr)]
    #funcs_dec = ["void func_%.8X(void)"%x for x in all_bloc_funcs]


    #test return direct dyn dispatch
    dispatch_table = dispatch_table_from_f_blocs(all_bloc_funcs)
    dyn_dispatcher = gen_dynamic_dispatcher(dispatch_table)

    return funcs_code, dyn_dispatcher


def gen_C_from_asmbloc(in_str, offset, symbol_pool, dont_dis = [], job_done = None, log_mn = False, log_reg = False, log_lbl = False, filtered_ad = [], tick_dbg = None, code_addr = [], all_bloc_funcs = [], segm_to_do = {}, **kargs):
    if job_done == None:
        job_done = set()

    f_name = "bloc_%.16X"%(offset&mask_int)
    l = symbol_pool.getby_offset_create(offset)
    cur_bloc = asmbloc.asm_bloc(l)
    asmbloc.dis_bloc(x86_mn, in_str, cur_bloc, offset, job_done, symbol_pool,[],
                     follow_call = False, patch_instr_symb = True,
                     dontdis_retcall = False,lines_wd = None,
                     **kargs)
    f_dec, out = bloc_gen_C_func([cur_bloc], f_name, None, True,
                                 log_mn, log_reg, log_lbl,
                                 filtered_ad, tick_dbg, segm_to_do)
    #print "\n".join(out)
    return f_name, f_dec, out, cur_bloc


def dispatch_table_from_f_blocs(all_f_b):
    dispatch_table = {}
    #for b in all_f_b:
    #    dispatch_table[b.label.offset] = b.label.name
    for b in all_f_b:
        dispatch_table[b.label.offset] = b.label.name
        for l in b.lines:
            dispatch_table[l.offset] = "loc_%.16X"%(l.offset&mask_int)

    return dispatch_table


def gen_dynamic_dispatcher(dispatch_table):
    offsets = dispatch_table.keys()
    offsets.sort()
    
    out1 = []
    out1 += ["#define FUNC_DYNAMIC"]
    out1 += ['void* tab_eip_label[(%d+1)*2] = '%len(dispatch_table)]
    out1 += ['{']
    for o in offsets:
        out1+=['\t(void*)0x%.8X, (void*)&&%s,'%(o, dispatch_table[o])]
    out1+=['\t(void*)0x%.8X, (void*)0x0,'%(0)]

    out1 += ['};']

    out2 = []
    out2 += ["void * get_label_from_eip(void** tab_eip_label)"]
    out2 += ['{']
    
    out2 += ['\tvoid *labelref = NULL;']
    
    out2 += ['\tunsigned int i = 0;']
    out2 += ['\twhile (tab_eip_label[2*i]!= NULL && tab_eip_label[2*i+1]!=NULL){']
    out2 += ['\t\tif (tab_eip_label[i*2] == (void*)vmcpu.eip){']
    out2 += ['\t\t\tlabelref = tab_eip_label[i*2+1];']
    out2 += ['\t\t\treturn labelref;']
    out2 += ['\t\t}']
    out2 += ['\ti++;']
    out2 += ['\t}']
    out2 += [r'fprintf(stderr, "Unkown destination! 0x%.8X\n", vmcpu.eip);']
    out2 += [r'vmcpu.vm_exception_flags |= EXCEPT_UNK_EIP;']
    #out2 += [r'exit(0);']
    out2 += ['return labelref;']
    out2 += ['}']
    

    out = []

    out += ["#define GOTO_DYNAMIC"]
    out += ["labelref = get_label_from_eip();"]
    out += ["if (labelref == NULL) {"]
    out += [r'fprintf(stderr, "Unkown destination! 0x%.8X\n", vmcpu.eip);']
    out += [r'vmcpu.vm_exception_flags |= EXCEPT_UNK_EIP;']
    out += ["return (PyObject*)vm_get_exception(vm_exception_flags);"]
    out += ['}']
    out += ['goto *labelref;']
    
    """
    out += ['{']
    #out += [r'fprintf(stderr, "search dst: %X\n", eip);']
    
    out += ['switch(eip){']
    for o in offsets:
        out+=['case 0x%.8X:'%o]
        out+=['goto %s;'%dispatch_table[o]]
        out+=['break;']
    
    out += ['case 0x1337beef:']
    out += [r'fprintf(stderr, "return reached %X\n", eip);']
    out += ['return NULL;']
    out += ['default:']
    out += [r'fprintf(stderr, "Unkown destination! 0x%.8X\n", eip);']
    out += [r'vm_exception_flags |= EXCEPT_UNK_EIP;']
    out += ["return (PyObject*)vm_get_exception(vm_exception_flags);"]
    out += ['break;']
    out += ['}']
    out += ['}']
    """    
    return out1, out2
        
def gen_dyn_func_manager(dyn_func, dis_func):
    total_func_num = len(dyn_func)+len(dis_func)
    out = "int (*tab_func[%d][2])(void) = {"%(total_func_num)
    dec_f_ptr = ""
    init_f_ptr = ""
    for f_ad, f_name in dyn_func.items():
        out+="{%s, %s},"%("0x%.8X"%f_ad, f_name)

        dec_f_ptr += "unsigned int dyn_func_%.8X;\n"%(f_ad)
        init_f_ptr+= "dyn_func_%.8X = (unsigned int)&%s;\n"%(f_ad, f_name)
           
    for f_ad in dis_func:
        out+="{0x%.8X, func_%.8X},"%(f_ad, f_ad)
    out+="};"
        
        
    code = "\n"
    code += "#define DYN_FUNC_NUM %d"%total_func_num
    code += r"""
/*
void func_dyn_manager(void)
{
    unsigned int i;
""" + out + r"""
    
    for (i=0;i<DYN_FUNC_NUM;i++){
        if (dyn_dst == tab_func[i][0]){
            fprintf(stderr, "i %d v@%X r@%X\n", i, tab_func[i][0], tab_func[i][1]);
            tab_func[i][1]();
            return;
        }
    }
    
    fprintf(stderr, "unknown dyn dst!\n");
    exit(0);
}
*/
    """
    return dec_f_ptr, init_f_ptr, code



def insert_printf(c_source, label):
    for i, l in enumerate(c_source):
        print l
        if l.startswith(label):
            c_source[i+1:i+1] = ['printf("reached %s\\n");'%label]
        



def gen_label_declaration(known_mems):
    lab_dec = []
    
    for m_ad, m_val in known_mems.items():
        dec_name = "char tab_%.8X[0x%X]"%(m_ad, len(m_val))
        data = m_val
        dec_name+=' = {'+', '.join(["0x%.2X"%ord(x) for x in data])+'};'
        lab_dec.append(dec_name)

    
    return lab_dec


def gen_call_func(funcname, args, precode = "", postcode = ""):
    out = ""
    
def gen_known_mems_code(known_mems):
    code = []
    for m_ad, m_val in known_mems.items():
        out = ""
        out += "char *tab_%.8X;"%(m_ad)
        out += "char tab_data_%.8X[0x%X] = "%(m_ad, len(m_val))
        out += '{'+', '.join(["0x%.2X"%ord(x) for x in m_val])+'};'
        out += 'unsigned int get_tab_%.8X() { return (unsigned int)tab_%.8X;}'%(m_ad, m_ad)
        code.append(out)

    #test transform tab_XX to dynamic allocated prod
    """
    code.append("void init_tab_mem(void)")
    code.append("{")
    code.append("unsigned int ret;")
    
    for m_ad, m_val in known_mems.items():
        #code.append("tab_%.8X = malloc(0x%.8X);\n"%(m_ad, len(m_val)))
        code.append("ret = posix_memalign(&tab_%.8X, 0x10000, 0x%.8X);"%(m_ad, len(m_val)))
        code.append("if (ret){")
        code.append(r'    fprintf(stderr, "cannot alloc");')
        code.append(r'    exit(-1);')
        code.append(r'}')
        

        code.append("memcpy(tab_%.8X, tab_data_%.8X, 0x%.8X);"%(m_ad, m_ad, len(m_val)))
    code.append("}\n")
    """
    
    

    return code

if __name__ == '__main__':
    e = dec(ExprMem(eax))
    for x in e:
        print x
    print '_'*80
    o = Exp2C(e)
    for x in o:
        print x
    print '#'*80

    new_e = [x.reload_expr({ExprMem(eax): ExprId('ioio')}) for x in e]
    for x in new_e:
        print x
    print '-'*80
    o = Exp2C(new_e)
    for x in o:
        print x
    print '#'*80

    


def _compile(self):
    import os
    from distutils.core import setup, Extension
    import os

    lib_dir = os.path.dirname(os.path.realpath(__file__))
    lib_dir = os.path.join(lib_dir, 'emul_lib')

    os.chdir(self._buildDir)
    ext = Extension(self._moduleName,
                    [self._srcFileName],
                    library_dirs=self._options.get('library_dirs'),
                    libraries=self._options.get('libraries'),
                    define_macros=self._options.get('define_macros'),
                    undef_macros=self._options.get('undef_macros'),
                    extra_link_args = ['-Wl,-rpath,'+lib_dir]
                    )
    try:
        setup(name = self._moduleName,
              version = self._moduleVersion,
              ext_modules = [ext],
              script_args = ["build"] + (self._options.get('distutils_args') or []),
              script_name="C.py",
              package_dir=self._buildDir,
              )
    except SystemExit, e:
        raise BuildError(e)
        
    os.chdir(self._homeDir)
    

    


from miasm.tools.codenat import *
'''
def updt_bloc_emul(known_blocs, in_str, my_eip, symbol_pool, code_blocs_mem_range, dont_dis = [], log_mn = False, log_regs = False):

    f_dec, funcs_code, cur_bloc = gen_C_from_asmbloc(in_str, my_eip, symbol_pool, dont_dis, log_mn, log_regs)

    dyn_dispatcher = """
    #define GOTO_DYNAMIC do {return %s;} while(0)
    #define GOTO_STATIC(a) do {vmcpu.eip = a;return %s;} while(0)
    #define GOTO_STATIC_SUB(a) do {return %s;} while(0)
    #define GOTO_DYN_SUB(a) do {return %s;} while(0)
    #define vm_get_exception(a)  %s
    """%(patch_c_id(eip), patch_c_id(eip), patch_c_id(eip), patch_c_id(eip), patch_c_id(eip))

    c_source = gen_C_source(funcs_code, {}, dyn_dispatcher)
    c_source = "#include <Python.h>\n"+c_source

    a = gen_C_module(c_source)
    bn = bloc_nat(my_eip, cur_bloc, a, log_mn, log_regs)
    #f_dec = f_dec[10:-6]
    f_dec = f_dec[13:-6]
    a.func = a[f_dec]
    known_blocs[my_eip] = bn

    ###### update code ranges ###
    
    code_addr = blocs_to_memory_ranges([bn.b])
    code_blocs_mem_range += code_addr
    merge_memory_ranges(code_blocs_mem_range)
    reset_code_bloc_pool_py()
    for a, b in  code_blocs_mem_range:
            vm_add_code_bloc(a, b)
'''    

ttt = 0
def updt_bloc_emul(known_blocs, in_str, my_eip, symbol_pool, code_blocs_mem_range, dont_dis = [], job_done = None, log_mn = False, log_regs = False, segm_to_do = {}, **kargs):
    if job_done == None:
        job_done = set()
    fname, f_dec, funcs_code, cur_bloc = gen_C_from_asmbloc(in_str, my_eip, symbol_pool, dont_dis, job_done, log_mn, log_regs, segm_to_do = segm_to_do, **kargs)

    dyn_dispatcher = """
    #define GOTO_DYNAMIC do {return %s;} while(0)
    #define GOTO_STATIC(a) do {vmcpu.eip = a; return %s;} while(0)
    #define GOTO_STATIC_SUB(a) do {return %s;} while(0)
    #define GOTO_DYN_SUB(a) do {return %s;} while(0)
    #define vm_get_exception(a)  %s
    """%(patch_c_id(eip), patch_c_id(eip), patch_c_id(eip), patch_c_id(eip), patch_c_id(eip))

    c_source = gen_C_source(funcs_code, {}, dyn_dispatcher)
    c_source = "#include <Python.h>\n"+c_source
    #c_source = '#include "emul_lib/libcodenat.h"\n'+c_source
    #print c_source
    a = gen_C_module_tcc(fname, c_source)
    bn = bloc_nat(my_eip, cur_bloc, a, c_source, log_mn, log_regs)

    bn.c_source = c_source
    #f_dec = f_dec[10:-6]
    f_dec = f_dec[13:-6]
    #a.func = a[f_dec]
    known_blocs[my_eip] = bn
    ###### update code ranges ###
    code_addr = blocs_to_memory_ranges([bn.b])
    code_blocs_mem_range += code_addr
    merge_memory_ranges(code_blocs_mem_range)
    reset_code_bloc_pool_py()
    for a, b in  code_blocs_mem_range:
            vm_add_code_bloc(a, b)
#'''

def updt_pe_from_emul(e):
    for s in e.SHList:
        sdata = vm_get_str(e.rva2virt(s.addr), s.rawsize)
        e.virt[e.rva2virt(s.addr)] = sdata
    return bin_stream(e.virt)

def updt_automod_code(known_blocs):
    w_ad, w_size = vm_get_last_write_ad(), vm_get_last_write_size()
    log_to_c_h.debug("%X %X"%(w_ad, w_size))
    known_blocs = del_bloc_in_range(known_blocs, w_ad, w_ad+w_size/8)
    code_addr = blocs_to_memory_ranges([bn.b for bn in known_blocs.values()])
    merge_memory_ranges(code_addr)
    reset_code_bloc_pool_py()

    for a, b in  code_addr:
        vm_add_code_bloc(a, b)
    vm_reset_exception()

    return known_blocs, code_addr


def flush_all_blocs(known_blocs):
    for ad in known_blocs.keys():
        known_blocs = del_bloc_in_range(known_blocs, ad, ad+1)
    code_addr = blocs_to_memory_ranges([bn.b for bn in known_blocs.values()])
    merge_memory_ranges(code_addr)
    reset_code_bloc_pool_py()

    for a, b in  code_addr:
        vm_add_code_bloc(a, b)
    vm_reset_exception()
    return known_blocs, code_addr


def dump_stack():
    esp = vm_get_gpreg()['esp']
    print 'esp', hex(esp)
    a = vm_get_str(esp, 0x20)
    while a:
        x = struct.unpack('I', a[:4])[0]
        a = a[4:]
        print hex(x)

import random

def c_emul_bloc(known_blocs, my_eip):
    if not my_eip in known_blocs:
        raise ValueError('unknown bloc (should have been disasm...', hex(my_eip))
    return known_blocs[my_eip].module_c.func()


class bin_stream_vm():
    def __init__(self, offset = 0L):
        self.offset = offset

    def readbs(self, l=1):
        try:
            s = vm_get_str(self.offset, l)
        except:
            raise IOError('cannot get mem ad', hex(self.offset))
        self.offset+=l
        return s

    def writebs(self, l=1):
        raise 'writebs unsupported'

    def __str__(self):
        raise 'writebs unsupported'
    def setoffset(self, val):
        val = val & 0xFFFFFFFF
        self.offset = val



vm_read_dword = lambda a: struct.unpack('I', vm_get_str(a, 4))[0]
p = lambda addr: struct.pack('I', addr)
pdw = p
updw = lambda bbbb: struct.unpack('I', bbbb)[0]
pw = lambda x: struct.pack('H', x)
upw = lambda x: struct.unpack('H', x)[0]

#try:
if True:
    from emul_lib.libcodenat_interface import *
    
    #vm_init_regs = libcodenat.vm_init_regs
#except:
#    print "WARNING! unable to build libcodenat C interface!!"



