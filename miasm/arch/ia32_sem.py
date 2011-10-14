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
from miasm.expression.expression import *
from miasm.arch.ia32_reg import *
from miasm.arch.ia32_arch import *


EXCEPT_PRIV_INSN = 1<<7
reg_eax = 'eax'
reg_ebx = 'ebx'
reg_ecx = 'ecx'
reg_edx = 'edx'
reg_esp = 'esp'
reg_ebp = 'ebp'
reg_eip = 'eip'
reg_esi = 'esi'
reg_edi = 'edi'
reg_eflag = 'eflag'
reg_tmp1 = 'tmp1'

reg_zf = 'zf'
reg_nf = 'nf'
reg_pf = 'pf'
reg_of = 'of'
reg_cf = 'cf'
reg_tf = 'tf'
reg_if = 'i_f'
reg_df = 'df'
reg_af = 'af'
reg_iopl='iopl_f'
reg_nt = 'nt'
reg_rf = 'rf'
reg_vm = 'vm'
reg_ac = 'ac'
reg_vif= 'vif'
reg_vip= 'vip'
reg_id = 'i_d'


reg_es = "es"
reg_cs = "cs"
reg_ss = "ss"
reg_ds = "ds"
reg_fs = "fs"
reg_gs = "gs"

reg_dr0 = 'dr0'
reg_dr1 = 'dr1'
reg_dr2 = 'dr2'
reg_dr3 = 'dr3'
reg_dr4 = 'dr4'
reg_dr5 = 'dr5'
reg_dr6 = 'dr6'
reg_dr7 = 'dr7'

reg_cr0 = 'cr0'
reg_cr1 = 'cr1'
reg_cr2 = 'cr2'
reg_cr3 = 'cr3'
reg_cr4 = 'cr4'
reg_cr5 = 'cr5'
reg_cr6 = 'cr6'
reg_cr7 = 'cr7'


reg_tsc1 = "tsc1"
reg_tsc2 = "tsc2"

reg_float_c0 = 'float_c0'
reg_float_c1 = 'float_c1'
reg_float_c2 = 'float_c2'
reg_float_c3 = 'float_c3'
reg_float_stack_ptr = "float_stack_ptr"
reg_float_control = 'reg_float_control'


reg_float_st0 = 'float_st0'
reg_float_st1 = 'float_st1'
reg_float_st2 = 'float_st2'
reg_float_st3 = 'float_st3'
reg_float_st4 = 'float_st4'
reg_float_st5 = 'float_st5'
reg_float_st6 = 'float_st6'
reg_float_st7 = 'float_st7'



#commonly used
init_eax = ExprId("init_eax", is_term=True)
init_ebx = ExprId("init_ebx", is_term=True)
init_ecx = ExprId("init_ecx", is_term=True)
init_edx = ExprId("init_edx", is_term=True)
init_esi = ExprId("init_esi", is_term=True)
init_edi = ExprId("init_edi", is_term=True)
init_esp = ExprId("init_esp", is_term=True)
init_ebp = ExprId("init_ebp", is_term=True)




init_tsc1 = ExprId("init_tsc1")
init_tsc2 = ExprId("init_tsc2")

init_cr0 = ExprId("init_cr0")


init_zf    = ExprId("init_zf")
init_nf    = ExprId("init_nf")
init_pf    = ExprId("init_pf")
init_of    = ExprId("init_of")
init_cf    = ExprId("init_cf")
init_tf    = ExprId("init_tf")
init_i_f   = ExprId("init_i_f")
init_df    = ExprId("init_df")
init_af    = ExprId("init_af")
init_iopl  = ExprId("init_iopl")
init_nt    = ExprId("init_nt")
init_rf    = ExprId("init_rf")
init_vm    = ExprId("init_vm")
init_ac    = ExprId("init_ac")
init_vif   = ExprId("init_vif")
init_vip   = ExprId("init_vip")
init_i_d   = ExprId("init_i_d")
init_tsc1  = ExprId("init_tsc1")
init_tsc2  = ExprId("init_tsc2")



eax = ExprId(reg_eax)
ebx = ExprId(reg_ebx)
ecx = ExprId(reg_ecx)
edx = ExprId(reg_edx)
esp = ExprId(reg_esp)
ebp = ExprId(reg_ebp)
eip = ExprId(reg_eip)
esi = ExprId(reg_esi)
edi = ExprId(reg_edi)


r_al = eax[:8]
r_cl = ecx[:8]
r_dl = edx[:8]
r_bl = ebx[:8]
r_ah = eax[8:16]
r_ch = ecx[8:16]
r_dh = edx[8:16]
r_bh = ebx[8:16]

r_ax = eax[:16]
r_bx = ebx[:16]
r_cx = ecx[:16]
r_dx = edx[:16]
r_sp = esp[:16]
r_bp = ebp[:16]
r_ip = eip[:16]
r_si = esi[:16]
r_di = edi[:16]


dr0 = ExprId(reg_dr0)
dr1 = ExprId(reg_dr1)
dr2 = ExprId(reg_dr2)
dr3 = ExprId(reg_dr3)
dr4 = ExprId(reg_dr4)
dr5 = ExprId(reg_dr5)
dr6 = ExprId(reg_dr6)
dr7 = ExprId(reg_dr7)

cr0 = ExprId(reg_cr0)
cr1 = ExprId(reg_cr1)
cr2 = ExprId(reg_cr2)
cr3 = ExprId(reg_cr3)
cr4 = ExprId(reg_cr4)
cr5 = ExprId(reg_cr5)
cr6 = ExprId(reg_cr6)
cr7 = ExprId(reg_cr7)


eflag= ExprId(reg_eflag)
tmp1= ExprId(reg_tmp1)
zf = ExprId(reg_zf, size=1)
nf = ExprId(reg_nf, size=1)
pf = ExprId(reg_pf, size=1)
of = ExprId(reg_of, size=1)
cf = ExprId(reg_cf, size=1)
tf = ExprId(reg_tf , size=1)
i_f= ExprId(reg_if , size=1)
df = ExprId(reg_df , size=1)
af = ExprId(reg_af , size=1)
iopl=ExprId(reg_iopl,size=2)
nt = ExprId(reg_nt , size=1)
rf = ExprId(reg_rf , size=1)
vm = ExprId(reg_vm , size=1)
ac = ExprId(reg_ac , size=1)
vif= ExprId(reg_vif, size=1)
vip= ExprId(reg_vip, size=1)
i_d= ExprId(reg_id , size=1)

es = ExprId(reg_es, size = 16)
cs = ExprId(reg_cs, size = 16)
ss = ExprId(reg_ss, size = 16)
ds = ExprId(reg_ds, size = 16)
fs = ExprId(reg_fs, size = 16)
gs = ExprId(reg_gs, size = 16)

tsc1 = ExprId(reg_tsc1, size = 32)
tsc2 = ExprId(reg_tsc2, size = 32)

float_c0 = ExprId(reg_float_c0)
float_c1 = ExprId(reg_float_c1)
float_c2 = ExprId(reg_float_c2)
float_c3 = ExprId(reg_float_c3)
float_stack_ptr = ExprId(reg_float_stack_ptr)
float_control = ExprId(reg_float_control)
                          
float_st0 = ExprId(reg_float_st0, 64)
float_st1 = ExprId(reg_float_st1, 64)
float_st2 = ExprId(reg_float_st2, 64)
float_st3 = ExprId(reg_float_st3, 64)
float_st4 = ExprId(reg_float_st4, 64)
float_st5 = ExprId(reg_float_st5, 64)
float_st6 = ExprId(reg_float_st6, 64)
float_st7 = ExprId(reg_float_st7, 64)



init_regs = {
eax:init_eax,
ebx:init_ebx,
ecx:init_ecx,
edx:init_edx,
esi:init_esi,
edi:init_edi,
esp:init_esp,
ebp:init_ebp,
zf:init_zf,
nf:init_nf,
pf:init_pf,
of:init_of,
cf:init_cf,
tf:init_tf,
i_f:init_i_f,
df:init_df,
af:init_af,
iopl:init_iopl,
nt:init_nt,
rf:init_rf,
vm:init_vm,
ac:init_ac,
vif:init_vif,
vip:init_vip,
i_d:init_i_d,
tsc1:init_tsc1,
tsc2:init_tsc2,
}

all_registers = [
    eax ,
    ebx ,
    ecx ,
    edx ,
    esp ,
    ebp ,
    eip ,
    esi ,
    edi ,
    dr0, 
    dr1, 
    dr2, 
    dr3, 
    dr4, 
    dr5, 
    dr6, 
    dr7, 
    
    eflag,
    tmp1,
    zf ,
    nf ,
    pf ,
    of ,
    cf ,
    tf ,
    i_f,
    df ,
    af ,
    iopl,
    nt ,
    rf ,
    vm ,
    ac ,
    vif,
    vip,
    i_d,
    
    es ,
    cs ,
    ss ,
    ds ,
    fs ,
    gs ,
    
    tsc1 ,
    tsc2 ,
    
    float_c0 ,
    float_c1 ,
    float_c2 ,
    float_c3 ,
    float_stack_ptr ,
    float_control ,
    
    float_st0 ,
    float_st1 ,
    float_st2 ,
    float_st3 ,
    float_st4 ,
    float_st5 ,
    float_st6 ,
    float_st7 ,

    ]

tab_intsize = {8:int8,
               16:int16,
               32:int32,
               64:int64
               }
tab_uintsize ={8:uint8,
               16:uint16,
               32:uint32,
               64:uint64
               }

tab_afs_int ={x86_afs.u08:uint8,
              x86_afs.u16:uint16,
              x86_afs.u32:uint32,
              }
"""
http://www.emulators.com/docs/nx11_flags.htm

CF(A+B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND NOT (A XOR B)) < 0)
CF(A-B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND (A XOR B)) < 0)

OF(A+B) = ((A XOR D) AND NOT (A XOR B)) < 0
OF(A-B) = ((A XOR D) AND (A XOR B)) < 0
"""

def get_op_msb(a):
    cast_int = tab_uintsize[a.get_size()]
    return ExprOp('==', ExprInt(cast_int(1)), ExprOp('>>', a, ExprInt(cast_int(a.get_size()-1))))


def update_flag_zf(a):
    cast_int = tab_uintsize[a.get_size()]
    return [ExprAff(zf, ExprOp('==', a, ExprInt(cast_int(0))))]

def update_flag_nf(a):
    return [ExprAff(nf, ExprOp('&', get_op_msb(a), ExprInt(tab_uintsize[a.get_size()](1))))]

def update_flag_pf(a):
    return [ExprAff(pf, ExprOp('parity', a))]

def update_flag_af(a):
    return [ExprAff(af, ExprOp('==', ExprOp('&', a, ExprInt(tab_uintsize[a.get_size()](0x10))), ExprInt(tab_uintsize[a.get_size()](0x10))))]

def update_flag_znp(a):
    e = []
    e+=update_flag_zf(a)
    e+=update_flag_nf(a)
    e+=update_flag_pf(a)
    return e

def update_flag_logic(a):
    e = []
    e+=update_flag_znp(a)
    e.append(ExprAff(of, ExprInt(uint32(0))))
    e.append(ExprAff(cf, ExprInt(uint32(0))))
    return e

def update_flag_arith(a):
    e = []
    e+=update_flag_znp(a)
    return e


def check_ops_msb(a, b, c):
    if not a or not b or not c or a!=b or a!=c:
        raise 'bad ops size %s %s %s'%(str(a), str(b), str(c))

def arith_flag(a, b, c):
    a_s, b_s, c_s = a.get_size(), b.get_size(), c.get_size()
    check_ops_msb(a_s, b_s, c_s)
    a_s, b_s, c_s = get_op_msb(a), get_op_msb(b), get_op_msb(c)
    return a_s, b_s, c_s


#checked: ok for adc add because of b & c before +cf
def update_flag_add_cf(cast_int, a, b, c):
    return ExprAff(cf, get_op_msb((a ^ b) ^ c) ^ get_op_msb((a ^ c) & ExprOp('!', (a ^ b))))

def update_flag_add_of(cast_int, a, b, c):
    return ExprAff(of, get_op_msb(((a ^ c) & ExprOp('!', (a ^ b)))))



#checked: ok for sbb add because of b & c before +cf
def update_flag_sub_cf(cast_int, a, b, c):
    return ExprAff(cf, get_op_msb((a ^ b) ^ c) ^ get_op_msb((a ^ c) & (a ^ b)))


def update_flag_sub_of(cast_int, a, b, c):
    return ExprAff(of, get_op_msb(((a ^ c) & (a ^ b))))


    


#z = x+y (+cf?)
def update_flag_add(x, y, z):
    cast_int = tab_uintsize[z.get_size()]
    e = []
    e.append(update_flag_add_cf(cast_int, x, y, z))
    e.append(update_flag_add_of(cast_int, x, y, z))    
    return e

#z = x-y (+cf?)
def update_flag_sub(x, y, z):
    cast_int = tab_uintsize[z.get_size()]
    e = []
    e.append(update_flag_sub_cf(cast_int, x, y, z))
    e.append(update_flag_sub_of(cast_int, x, y, z))
    return e


def mov(a, b):
    return [ExprAff(a, b)]

def xchg(a, b):
    e = []
    e.append(ExprAff(a, b))
    e.append(ExprAff(b, a))
    return e

def movzx(a, b):
    return [ExprAff(a, ExprCompose([ExprSliceTo(ExprInt(uint32(0)), b.get_size(), a.get_size()), ExprSliceTo(b, 0, b.get_size())]))]

def movsx(a, b):
    return [ExprAff(a, ExprCompose([ExprSliceTo(ExprCond(ExprOp('==', get_op_msb(b), ExprInt(uint32(1))),
                                                         ExprInt(uint32(0xffffffff)),
                                                         ExprInt(uint32(0))),
                                                b.get_size(), a.get_size()),
                                    ExprSliceTo(b,
                                                0, b.get_size())]))]

def lea(a, b):
    return [ExprAff(a, b.arg)]

def add(a, b):
    e= []
    c = ExprOp('+', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_add(a, b, c)
    e.append(ExprAff(a, c))
    return e

def xadd(a, b):
    e= []
    c = ExprOp('+', b, a)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_add(b, a, c)
    e.append(ExprAff(b, a))
    e.append(ExprAff(a, c))
    return e

def adc(a, b):
    e= []
    c = ExprOp('+',
               a,
               ExprOp('+',
                      b,
                      ExprCompose([ExprSliceTo(ExprInt(uint32(0)), 1, a.get_size()), ExprSliceTo(cf, 0, 1)])))
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_add(a, b, c)
    e.append(ExprAff(a, c))
    return e

def sub(a, b):
    e= []
    c = ExprOp('-', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_sub(a, b, c)
    e.append(ExprAff(a, c))
    return e

#a-(b+cf)
def sbb(a, b):
    e= []
    c = ExprOp('-',
               a,
               ExprOp('+',
                      b,
                      ExprCompose([ExprSliceTo(ExprInt(uint32(0)), 1, a.get_size()), ExprSliceTo(cf, 0, 1)])))
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_sub(a, b, c)
    e.append(ExprAff(a, c))
    return e

def neg(b):
    e= []
    cast_int = tab_uintsize[b.get_size()]
    a = ExprInt(cast_int(0))
    
    c = ExprOp('-', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_sub(a, b, c)
    e+=update_flag_af(c)
    e.append(ExprAff(b, c))
    return e

def l_not(b):
    e= []
    cast_int = tab_uintsize[b.get_size()]
    c = ExprOp('!', b)
    e.append(ExprAff(b, c))
    return e


def l_cmp(a, b):
    e= []
    c = ExprOp('-', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_sub(a, b, c)
    e+=update_flag_af(c)
    return e

def xor(a, b):
    e= []
    c = ExprOp('^', a, b)
    e+=update_flag_logic(c)
    e.append(ExprAff(a, c))
    return e

def l_or(a, b):
    e= []
    c = ExprOp('|', a, b)
    e+=update_flag_logic(c)
    e.append(ExprAff(a, c))
    return e

def l_and(a, b):
    e= []
    c = ExprOp('&', a, b)
    e+=update_flag_logic(c)
    e.append(ExprAff(a, c))
    return e

def l_test(a, b):
    e= []
    c = ExprOp('&', a, b)
    e+=update_flag_logic(c)
    return e

def l_rol(a, b):
    e= []
    cast_int = tab_uintsize[a.get_size()]
    c = ExprOp('<<<', a, b)
    
    new_cf = ExprOp("&", c ,ExprInt(cast_int(1)))
    e.append(ExprAff(cf, new_cf))
    ### hack (only valid if b=1)
    e.append(ExprAff(of, ExprOp("^", get_op_msb(c), new_cf)))
    e.append(ExprAff(a, c))
    return e

def l_ror(a, b):
    e= []
    c = ExprOp('>>>', a, b)
    
    e.append(ExprAff(cf, get_op_msb(c)))
    ### hack (only valid if b=1): when count == 1: a = msb-1(dest)
    e.append(ExprAff(of, ExprOp("^", get_op_msb(c), get_op_msb(a))))
    e.append(ExprAff(a, c))
    return e

def rcl(a, b):
    e= []
    c = ExprOp('<<<c_rez', a, b, cf)
    new_cf = ExprOp('<<<c_cf', a, b, cf)

    e.append(ExprAff(cf, new_cf))
    ### hack (only valid if b=1)
    e.append(ExprAff(of, ExprOp("^", get_op_msb(c), new_cf)))
    e.append(ExprAff(a, c))
    return e

def rcr(a, b):
    e= []
    c = ExprOp('>>>c_rez', a, b, cf)
    new_cf = ExprOp('>>>c_cf', a, b, cf)

    e.append(ExprAff(cf, new_cf))
    ### hack (only valid if b=1)
    e.append(ExprAff(of, ExprOp("^", get_op_msb(a), get_op_msb(c))))
    e.append(ExprAff(a, c))
    
    return e

def sar(a, b):
    e= []
    cast_int = tab_uintsize[a.get_size()]
    cast_intb = tab_uintsize[b.get_size()]
    
    shifter = ExprOp('&',b, ExprInt(cast_intb(0x1f)))
    c = ExprOp('a>>', a, shifter)

    new_cf = ExprOp('&',
                    ExprInt(cast_int(1)),
                    ExprOp('a>>',
                           a,
                           ExprOp('-',
                                  shifter,
                                  ExprInt(cast_intb(1))
                                  )
                           
                           )
                    )
    
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e.append(ExprAff(of, ExprInt(cast_int(0))))
    e+=update_flag_znp(c)
    e.append(ExprAff(a, c))
    return e

def shr(a, b):
    e= []
    cast_int = tab_uintsize[a.get_size()]
    cast_intb = tab_uintsize[b.get_size()]
    shifter = ExprOp('&',b, ExprInt(cast_intb(0x1f)))
    c = ExprOp('>>', a, shifter)

    new_cf = ExprOp('&',
                    ExprInt(cast_int(1)),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  shifter,
                                  ExprInt(cast_intb(1))
                                  )
                           
                           )
                    )
    
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    
    e.append(ExprAff(of, get_op_msb(a)))
    e+=update_flag_znp(c)
    e.append(ExprAff(a, c))
    return e

def shrd_cl(a, b):
    e= []
    cast_int = tab_uintsize[a.get_size()]
    cast_intb = tab_uintsize[b.get_size()]

    shifter = ExprOp('&',ecx, ExprInt(cast_intb(0x1f)))
    
    c = ExprOp('|',
                ExprOp('>>', a, shifter),
                ExprOp('<<', b, ExprOp('-',
                                        ExprInt(cast_int(a.get_size())),
                                        shifter)
                                        )
              )

    new_cf = ExprOp('&',
                    ExprInt(cast_int(1)),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  shifter,
                                  ExprInt(cast_intb(1))
                                  )
                           
                           )
                    )
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e.append(ExprAff(of, get_op_msb(a)))
    e+=update_flag_znp(c)
    e.append(ExprAff(a, c))
    return e

def shrd(a, b, c):
    e= []
    cast_int = tab_uintsize[a.get_size()]
    cast_intb = tab_uintsize[b.get_size()]

    shifter = c

    d = ExprOp('|',
                ExprOp('>>', a, shifter),
                ExprOp('<<', b, ExprOp('-',
                                        ExprInt(cast_int(a.get_size())),
                                        shifter)
                                        )
              )

    new_cf = ExprAff(cf, ExprOp('&',
                                ExprInt(cast_int(1)),
                                ExprOp('>>',
                                       a,
                                       ExprOp('-',
                                              shifter,
                                              ExprInt(cast_intb(1))
                                              )
                                       )
                                )
                     )
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e.append(ExprAff(of, get_op_msb(a)))
    e+=update_flag_znp(d)
    e.append(ExprAff(a, d))
    return e

def sal(a, b):
    e= []
    cast_int = tab_uintsize[a.get_size()]
    cast_intb = tab_uintsize[b.get_size()]
    shifter = ExprOp('&',b, ExprInt(cast_intb(0x1f)))
    
    c = ExprOp('a<<', a, shifter)
    new_cf = ExprOp('&',
                    ExprInt(cast_int(1)),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  ExprInt(cast_intb(a.get_size())),
                                  shifter
                                  )
                           
                           )
                    )
    
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e+=update_flag_znp(c)
    e.append(ExprAff(of, ExprOp('^', get_op_msb(c), new_cf)))
    e.append(ExprAff(a, c))
    return e

def shl(a, b):
    e= []
    cast_int = tab_uintsize[a.get_size()]
    cast_intb = tab_uintsize[b.get_size()]
    shifter = ExprOp('&',b, ExprInt(cast_intb(0x1f)))
    
    c = ExprOp('<<', a, shifter)
    new_cf = ExprOp('&',
                    ExprInt(cast_int(1)),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  ExprInt(cast_intb(a.get_size())),
                                  shifter
                                  )
                           
                           )
                    )
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e+=update_flag_znp(c)
    e.append(ExprAff(of, ExprOp('^', get_op_msb(c), new_cf)))
    e.append(ExprAff(a, c))
    return e

def shld_cl(a, b):
    e= []
    cast_int = tab_uintsize[a.get_size()]
    cast_intb = tab_uintsize[b.get_size()]
    shifter = ExprOp('&',ecx, ExprInt(cast_int(0x1f)))
    
    c = ExprOp('|',
            ExprOp('<<', a, shifter),
            ExprOp('>>', b, ExprOp('-',
                                    ExprInt(cast_int(a.get_size())),
                                    shifter)
                                    )
          )

    new_cf = ExprOp('&',
                    ExprInt(cast_int(1)),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  ExprInt(cast_intb(a.get_size())),
                                  shifter
                                  )
                           
                           )
                    )
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e+=update_flag_znp(c)
    e.append(ExprAff(of, ExprOp('^', get_op_msb(c), new_cf)))
    e.append(ExprAff(a, c))
    return e


#XXX todo ###
def cmc():
    return     [ExprAff(cf, ExprOp('==', cf, ExprInt(uint32(0))))]

def clc():
    return     [ExprAff(cf, ExprInt(uint32(0)))]

def stc():
    return     [ExprAff(cf, ExprInt(uint32(1)))]

def cld():
    return     [ExprAff(df, ExprInt(uint32(0)))]

def std():
    return     [ExprAff(df, ExprInt(uint32(1)))]

def cli():
    return     [ExprAff(i_f, ExprInt(uint32(0)))]

def sti():
    return     [ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt(uint32(1<<7)))]

def inc(a):
    e= []
    b = ExprInt(tab_uintsize[a.get_size()](1))
    c = ExprOp('+', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)

    cast_int = tab_uintsize[c.get_size()]
    e.append(update_flag_add_of(cast_int, a, b, c))    
    e.append(ExprAff(a, c))
    return e


def dec(a):
    e= []
    b = ExprInt(tab_uintsize[a.get_size()](-1))
    c = ExprOp('+', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)

    cast_int = tab_uintsize[c.get_size()]
    e.append(update_flag_add_of(cast_int, a, b, c))    
    e.append(ExprAff(a, c))
    return e

def push(a):
    e= []
    s = a.get_size()
    if not s in [16,32]:
        raise 'bad size stacker!'
    c = ExprOp('-', esp, ExprInt(uint32(s/8)))
    e.append(ExprAff(esp, c))
    e.append(ExprAff(ExprMem(c, s), a))
    return e
    
def pop(a):
    e= []
    s = a.get_size()
    if not s in [16,32]:
        raise 'bad size stacker!'
    new_esp = ExprOp('+', esp, ExprInt(uint32(s/8)))
    e.append(ExprAff(esp, new_esp))
    #XXX FIX XXX for pop [esp]
    if isinstance(a, ExprMem):
        a =a.reload_expr({esp:new_esp})
    e.append(ExprAff(a, ExprMem(esp, s)))
    return e

def sete(a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('==', zf, ExprInt(uint32(1))), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e

def setnz(a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('==', zf, ExprInt(uint32(0))), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e

def setl(a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('==', ExprOp('==', nf, of), ExprInt(uint32(0))), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e

def setg(a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp("&", ExprOp('==', zf, ExprInt(uint32(0))), ExprOp('==', nf, of)), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e

def setge(a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('==', nf, of), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e


def seta(a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('&', ExprOp('==', cf, ExprInt(uint32(0))), ExprOp('==', zf, ExprInt(uint32(0)))), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e

def setb(a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('==', cf, ExprInt(uint32(1))), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e

def setns(a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('==', nf, ExprInt(uint32(0))), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e

def sets(a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('==', nf, ExprInt(uint32(1))), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e


def seto(a): 
    e= []
    e.append(ExprAff(a, ExprCond(ExprOp('==', of, ExprInt(uint32(1))), ExprInt(tab_uintsize[a.get_size()](1)), ExprInt(tab_uintsize[a.get_size()](0)))))
    return e


def bswap(a):
    e = []
    c = ExprCompose([ExprSliceTo(ExprOp('&', ExprInt(tab_uintsize[a.get_size()](0xFF)), a),                                 24, 32),
                     ExprSliceTo(ExprOp('>>', ExprOp('&', ExprInt(tab_uintsize[a.get_size()](0xFF00)), a), ExprInt(uint32(8))),     16, 24),
                     ExprSliceTo(ExprOp('>>', ExprOp('&', ExprInt(tab_uintsize[a.get_size()](0xFF0000)), a), ExprInt(uint32(16))),  8 , 16),
                     ExprSliceTo(ExprOp('>>', ExprOp('&', ExprInt(tab_uintsize[a.get_size()](0xFF000000)), a), ExprInt(uint32(24))),0 , 8 ),
                     ])
    e.append(ExprAff(a, c))
    return e

def cmpsb():
    e= []
    e+=l_cmp(ExprMem(esi, 8), ExprMem(edi, 8))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(1))), ExprOp('+', edi, ExprInt(uint32(1))))))
    e.append(ExprAff(esi, ExprCond(df, ExprOp('-', esi, ExprInt(uint32(1))), ExprOp('+', esi, ExprInt(uint32(1))))))
    return e

def cmpsw():
    e= []
    e+=l_cmp(ExprMem(esi, 16), ExprMem(edi, 16))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(2))), ExprOp('+', edi, ExprInt(uint32(2))))))
    e.append(ExprAff(esi, ExprCond(df, ExprOp('-', esi, ExprInt(uint32(2))), ExprOp('+', esi, ExprInt(uint32(2))))))
    return e

def cmpsd():
    e= []
    e+=l_cmp(ExprMem(esi), ExprMem(edi))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(4))), ExprOp('+', edi, ExprInt(uint32(4))))))
    e.append(ExprAff(esi, ExprCond(df, ExprOp('-', esi, ExprInt(uint32(4))), ExprOp('+', esi, ExprInt(uint32(4))))))
    return e

def scasb():
    e= []
    e+=l_cmp(eax[0:8], ExprMem(edi, 8))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(1))), ExprOp('+', edi, ExprInt(uint32(1))))))
    return e

def scasw():
    e= []
    e+=l_cmp(eax[0:16], ExprMem(edi, 16))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(2))), ExprOp('+', edi, ExprInt(uint32(2))))))
    return e

def scasd():
    e= []
    e+=l_cmp(eax, ExprMem(edi))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(4))), ExprOp('+', edi, ExprInt(uint32(4))))))
    return e


def compose_eflag(s = 32):
    args = []

    regs = [cf, ExprInt(uint32(1)), pf, ExprInt(uint32(0)), af, ExprInt(uint32(0)), zf, nf, tf, i_f, df, of]
    for i in xrange(len(regs)):
        args.append(ExprSliceTo(regs[i],i, i+1))

    args.append(ExprSliceTo(iopl,12, 14))

    if s == 32:
        regs = [nt, ExprInt(uint32(0)), rf, vm, ac, vif, vip, i_d]
    elif s == 16:
        regs = [nt, ExprInt(uint32(0))]
    else:
        raise ValueError('unk size')
    for i in xrange(len(regs)):
        args.append(ExprSliceTo(regs[i],i+14, i+15))
    if s == 32:
        args.append(ExprSliceTo(ExprInt(uint32(0)),22, 32))
                
    return ExprCompose(args)

    

def pushfd():
    return push(compose_eflag())

def pushfw():
    return push(compose_eflag(16))
    
def popfd():
    tmp = ExprMem(esp)
    e = []
    e.append(ExprAff(cf, ExprSlice(tmp, 0, 1)))
    e.append(ExprAff(pf, ExprSlice(tmp, 2, 3)))
    e.append(ExprAff(af, ExprSlice(tmp, 4, 5)))
    e.append(ExprAff(zf, ExprSlice(tmp, 6, 7)))
    e.append(ExprAff(nf, ExprSlice(tmp, 7, 8)))
    e.append(ExprAff(tf, ExprSlice(tmp, 8, 9)))
    e.append(ExprAff(i_f,ExprSlice(tmp, 9, 10)))
    e.append(ExprAff(df, ExprSlice(tmp, 10, 11)))
    e.append(ExprAff(of, ExprSlice(tmp, 11, 12)))
    e.append(ExprAff(iopl, ExprSlice(tmp, 12, 14)))
    e.append(ExprAff(nt, ExprSlice(tmp, 14, 15)))
    e.append(ExprAff(rf, ExprSlice(tmp, 16, 17)))
    e.append(ExprAff(vm, ExprSlice(tmp, 17, 18)))
    e.append(ExprAff(ac, ExprSlice(tmp, 18, 19)))
    e.append(ExprAff(vif,ExprSlice(tmp, 19, 20)))
    e.append(ExprAff(vip,ExprSlice(tmp, 20, 21)))
    e.append(ExprAff(i_d,ExprSlice(tmp, 21, 22)))
    e.append(ExprAff(esp, ExprOp('+', esp, ExprInt(uint32(4)))))
         
    return e

def pushad():
    e = []
    s = 32
    if not s in [16,32]:
        raise 'bad size stacker!'
    
    regs = [eax, ecx, edx, ebx, esp, ebp, esi, edi]
    for i in xrange(len(regs)):
        c = ExprOp('+', esp, ExprInt(uint32(-(s/8)*(i+1))))
        e.append(ExprAff(ExprMem(c, s), regs[i]))
    e.append(ExprAff(esp, c))
    return e

def popad():
    e = []
    s = 32
    if not s in [16,32]:
        raise 'bad size stacker!'
    regs = [eax, ecx, edx, ebx, esp, ebp, esi, edi]
    regs.reverse()
    for i in xrange(len(regs)):
        if regs[i] == esp:
            continue
        c = ExprOp('+', esp, ExprInt(uint32((s/8)*i)))
        e.append(ExprAff(regs[i], ExprMem(c, s)))
        
    c = ExprOp('+', esp, ExprInt(uint32((s/8)*(i+1))))
    e.append(ExprAff(esp, c))
    
    return e


def call(a, b): 
    e= []
    c = ExprOp('+', esp, ExprInt(uint32(-4)))    
    e.append(ExprAff(esp, c))
    e.append(ExprAff(ExprMem(c), a))
    e.append(ExprAff(eip, b))
    return e

def ret(a = ExprInt(uint32(0))):
    e = []
    e.append(ExprAff(esp, ExprOp('+', esp, ExprOp('+', ExprInt(uint32(4)), a))))
    e.append(ExprAff(eip, ExprMem(esp)))

    
    return e

def leave():
    e = []
    e.append(ExprAff(ebp, ExprMem(ebp)))
    e.append(ExprAff(esp, ExprOp('+', ExprInt(uint32(4)), ebp)))
    return e

def enter(a,b):
    #XXX 32 bit...
    e = []
    e.append(ExprAff(ExprMem(esp), ebp))
    e.append(ExprAff(ebp, ExprOp("-", esp, ExprInt(uint32(4)))))
    e.append(ExprAff(esp, ExprOp('-', esp, 
                                      ExprOp("+", a, ExprInt(uint32(4)))
                                )
                    )
            )
    return e

def jmp(a): 
    e= []
    e.append(ExprAff(eip, a))
    return e

def jz(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', zf, ExprInt(uint32(1))), b, a)))
    return e

def jnz(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', zf, ExprInt(uint32(0))), b, a)))
    return e

def jp(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', pf, ExprInt(uint32(1))), b, a)))
    return e

def jnp(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', pf, ExprInt(uint32(0))), b, a)))
    return e

def ja(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('&', ExprOp('==', cf, ExprInt(uint32(0))), ExprOp('==', zf, ExprInt(uint32(0)))), b, a)))
    return e

def jae(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', cf, ExprInt(uint32(0))), b, a)))
    return e

def jb(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', cf, ExprInt(uint32(1))), b, a)))
    return e

def jbe(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('|', ExprOp('==', cf, ExprInt(uint32(1))), ExprOp('==', zf, ExprInt(uint32(1)))), b, a)))
    return e

def jge(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', nf, of), b, a)))
    return e

def jg(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('&', ExprOp('==', zf, ExprInt(uint32(0))), ExprOp('==', nf, of)), b, a)))
    return e

def jl(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', ExprOp('==', nf, of), ExprInt(uint32(0))), b, a)))
    return e

def jle(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('|', zf, ExprOp('==', ExprOp('==', nf, of), ExprInt(uint32(0)))), b, a)))
    return e

def js(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', nf, ExprInt(uint32(1))), b, a)))
    return e

def jns(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', nf, ExprInt(uint32(0))), b, a)))
    return e

def jo(a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(of, b, a)))
    return e

def jno(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', of, ExprInt(uint32(0))), b, a)))
    return e

def jecxz(a, b): 
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('==', ecx, ExprInt(uint32(0))), b, a)))
    return e


def loop(a, b): 
    e= []
    c = ExprOp('-', ecx, ExprInt(uint32(1)))
    e.append(ExprAff(ecx, c))
    e.append(ExprAff(eip, ExprCond(ExprOp('==', ExprInt(uint32(0)), ExprOp('==', c, ExprInt(uint32(0)))), b, a)))
    return e

def loopne(a, b): 
    e= []
    c = ExprOp('-', ecx, ExprInt(uint32(1)))
    e.append(ExprAff(ecx, c))
    cond = ExprOp('&',
                  ExprOp('==', ExprInt(uint32(0)), ExprOp('==', c, ExprInt(uint32(0)))),
                  ExprOp('==', zf, ExprInt(uint32(0))),
                  )
    e.append(ExprAff(eip, ExprCond(cond, b, a)))
    return e

#XXX size to do; eflag
def div(a):
    e= []

    s = a.get_size()
    if s == 8:
        s1,s2 = r_ah, r_al
    elif s == 16:
        s1,s2 = ExprSlice(edx, 0, 16), ExprSlice(eax, 0, 16)
    elif s == 32:
        s1,s2 = edx, eax
    else:
        raise ValueError('div arg not impl', a)

    c_d = ExprOp('div%d'%s, s1, s2, a)
    c_r = ExprOp('rem%d'%s, s1, s2, a)

    #if 8 bit div, only ax is affected
    if s == 8:
        e.append(ExprAff(eax[0:16], ExprCompose([ExprSliceTo(c_d, 0, 8), ExprSliceTo(c_r, 8, 16)])))
    else:
        e.append(ExprAff(s1, c_r))
        e.append(ExprAff(s2, c_d))
    return e

#XXX size to do; eflag
def idiv(a):
    e= []

    s = a.get_size()

    if s == 8:
        s1,s2 = r_ah, r_al
    elif s == 16:
        s1,s2 = r_dx, r_ax
    elif s == 32:
        s1,s2 = edx, eax
    else:
        raise ValueError('div arg not impl', a)


    c_d = ExprOp('idiv%d'%s, s1, s2, a)
    c_r = ExprOp('irem%d'%s, s1, s2, a)

    e.append(ExprAff(s1, c_r))
    e.append(ExprAff(s2, c_d))
    return e

#XXX size to do; eflag
def mul(a):
    e= []
    if a.get_size() == 32:
        c_hi = ExprOp('umul32_hi', eax, a)
        c_lo = ExprOp('umul32_lo', eax, a)
        e.append(ExprAff(edx, c_hi))
        e.append(ExprAff(eax, c_lo))

        e.append(ExprAff(of, ExprCond(ExprOp("==", c_hi, ExprInt(uint32(0))),
                                      ExprInt(uint32(0)),
                                      ExprInt(uint32(1)))))
        e.append(ExprAff(cf, ExprCond(ExprOp("==", c_hi, ExprInt(uint32(0))),
                                      ExprInt(uint32(0)),
                                      ExprInt(uint32(1)))))

        
        
    elif a.get_size() == 16:
        c_hi = ExprOp('umul16_hi', r_ax, a)
        c_lo = ExprOp('umul16_lo', r_ax, a)
        e.append(ExprAff(r_dx, c_hi))
        e.append(ExprAff(r_ax, c_lo))

        e.append(ExprAff(of, ExprCond(ExprOp("==", c_hi, ExprInt(uint32(0))),
                                      ExprInt(uint32(0)),
                                      ExprInt(uint32(1)))))
        e.append(ExprAff(cf, ExprCond(ExprOp("==", c_hi, ExprInt(uint32(0))),
                                      ExprInt(uint32(0)),
                                      ExprInt(uint32(1)))))

    elif a.get_size() == 8:
        c = ExprOp('umul08', eax, a)
        e.append(ExprAff(eax[:16], c))
        e.append(ExprAff(of, ExprCond(ExprOp("==", eax[8:16], ExprInt(uint32(0))),
                                      ExprInt(uint32(0)),
                                      ExprInt(uint32(1)))))
        e.append(ExprAff(cf, ExprCond(ExprOp("==", eax[8:16], ExprInt(uint32(0))),
                                      ExprInt(uint32(0)),
                                      ExprInt(uint32(1)))))



    
    return e

#XXX size to do; eflag
def imul(a, b = None, c = None):
    e= []
    if b == None:
        if a.get_size() == 32:
            c_hi = ExprOp('imul32_hi', eax, a)
            c_lo = ExprOp('imul32_lo', eax, a)
            e.append(ExprAff(edx, c_hi))
            e.append(ExprAff(eax, c_lo))
        elif a.get_size() == 16:
            c_hi = ExprOp('imul16_hi', r_ax, a)
            c_lo = ExprOp('imul16_lo', r_ax, a)
            e.append(ExprAff(r_dx, c_hi))
            e.append(ExprAff(r_ax, c_lo))
        elif a.get_size() == 8:
            c = ExprOp('imul08', eax, a)
            e.append(ExprAff(eax[:16], c))
            
    else:
        if c == None:
            c = b
            b = a
        c = ExprOp('*', b, c)
        e.append(ExprAff(a, c))
    return e


#XXX 16 bit bug
def cdq():
    e = []
    e.append(ExprAff(edx,
                     ExprCond(ExprOp('==', ExprOp('&', eax, ExprInt(uint32(0x80000000))), ExprInt(uint32(0))),
                              ExprInt(uint32(0x0)),
                              ExprInt(uint32(0xffffffff)))
                     )
             )
    return e

def stosb():
    e = []
    e.append(ExprAff(ExprMem(edi, 8), eax[0:8]))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(1))), ExprOp('+', edi, ExprInt(uint32(1))))))
    return e

def stosw():
    e = []
    e.append(ExprAff(ExprMem(edi, 16), eax[0:16]))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(2))), ExprOp('+', edi, ExprInt(uint32(2))))))
    return e

def stosd():
    e = []
    e.append(ExprAff(ExprMem(edi), eax))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(4))), ExprOp('+', edi, ExprInt(uint32(4))))))
    return e

def lodsb():
    e = []
    e.append(ExprAff(eax[0:8], ExprMem(esi, 8)))
    e.append(ExprAff(esi, ExprCond(df, ExprOp('-', esi, ExprInt(uint32(1))), ExprOp('+', esi, ExprInt(uint32(1))))))
    return e

def lodsw():
    e = []
    e.append(ExprAff(eax[0:16], ExprMem(esi, 16)))
    e.append(ExprAff(esi, ExprCond(df, ExprOp('-', esi, ExprInt(uint32(2))), ExprOp('+', esi, ExprInt(uint32(2))))))
    return e

def lodsd():
    e = []
    e.append(ExprAff(eax, ExprMem(esi)))
    e.append(ExprAff(esi, ExprCond(df, ExprOp('-', esi, ExprInt(uint32(4))), ExprOp('+', esi, ExprInt(uint32(4))))))
    return e

def movsb():
    e = []
    e.append(ExprAff(ExprMem(edi, 8), ExprMem(esi, 8)))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(1))), ExprOp('+', edi, ExprInt(uint32(1))))))
    e.append(ExprAff(esi, ExprCond(df, ExprOp('-', esi, ExprInt(uint32(1))), ExprOp('+', esi, ExprInt(uint32(1))))))
    return e

def movsw():
    e = []
    e.append(ExprAff(ExprMem(edi, 16), ExprMem(esi, 16)))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(2))), ExprOp('+', edi, ExprInt(uint32(2))))))
    e.append(ExprAff(esi, ExprCond(df, ExprOp('-', esi, ExprInt(uint32(2))), ExprOp('+', esi, ExprInt(uint32(2))))))
    return e

def movsd():
    e = []
    e.append(ExprAff(ExprMem(edi), ExprMem(esi)))
    e.append(ExprAff(edi, ExprCond(df, ExprOp('-', edi, ExprInt(uint32(4))), ExprOp('+', edi, ExprInt(uint32(4))))))
    e.append(ExprAff(esi, ExprCond(df, ExprOp('-', esi, ExprInt(uint32(4))), ExprOp('+', esi, ExprInt(uint32(4))))))
    return e


def float_pop(avoid_flt = None):
    e= []
    if avoid_flt != float_st0:
        e.append(ExprAff(float_st0, float_st1))
    if avoid_flt != float_st1:
        e.append(ExprAff(float_st1, float_st2))
    if avoid_flt != float_st2:
        e.append(ExprAff(float_st2, float_st3))
    if avoid_flt != float_st3:
        e.append(ExprAff(float_st3, float_st4))
    if avoid_flt != float_st4:
        e.append(ExprAff(float_st4, float_st5))
    if avoid_flt != float_st5:
        e.append(ExprAff(float_st5, float_st6))
    if avoid_flt != float_st6:
        e.append(ExprAff(float_st6, float_st7))
    if avoid_flt != float_st7:
        e.append(ExprAff(float_st7, ExprInt(uint32(0))))
    e.append(ExprAff(float_stack_ptr, ExprOp('-', float_stack_ptr, ExprInt(uint32(1)))))
    return e

# XXX TODO
def fcom(a):
    e = []
    """
    if isinstance(a, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%a.get_size(), a)
    else:
        src = a
    """
    src = a
    e.append(ExprAff(float_c0, ExprOp('fcom_c0', float_st0, src)))
    e.append(ExprAff(float_c1, ExprOp('fcom_c1', float_st0, src)))
    e.append(ExprAff(float_c2, ExprOp('fcom_c2', float_st0, src)))
    e.append(ExprAff(float_c3, ExprOp('fcom_c3', float_st0, src)))
    return e

def ficom(a):
    return []

def fcomp(a):
    e= fcom(a)
    e+=float_pop()
    return e

def fld(a):
    if isinstance(a, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%a.get_size(), a)
    else:
        src = a

    e= []
    e.append(ExprAff(float_st7, float_st6))
    e.append(ExprAff(float_st6, float_st5))
    e.append(ExprAff(float_st5, float_st4))
    e.append(ExprAff(float_st4, float_st3))
    e.append(ExprAff(float_st3, float_st2))
    e.append(ExprAff(float_st2, float_st1))
    e.append(ExprAff(float_st1, float_st0))
    e.append(ExprAff(float_st0, src))
    e.append(ExprAff(float_stack_ptr, ExprOp('+', float_stack_ptr, ExprInt(uint32(1)))))
    return e

def fst(a):
    e = []
    if isinstance(a, ExprMem):
        src = ExprOp('double_to_mem_%2d'%a.get_size(), float_st0)
    else:
        src = float_st0

    
    e.append(ExprAff(a, src))
    return e

def fstp(a):
    e = fst(a)
    e+=float_pop(a)
    return e

def fist(a):
    e = []
    e.append(ExprAff(a, ExprOp('double_to_int_32', float_st0)))
    return e

def fistp(a):
    e = fist(a)
    e+=float_pop(a)
    return e

def fild(a):

    #XXXXX
    src = ExprOp('int_%.2d_to_double'%a.get_size(), a)
    return fld(src)

def fldz():
    #XXX
    return fld(ExprOp('int_32_to_double', ExprInt(uint32(0))))
    
def fadd(a):
    e = []
    if isinstance(a, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%a.get_size(), a)
    else:
        src = a
    e.append(ExprAff(float_st0, ExprOp('fadd', float_st0, src)))
    return e

def fdiv(a):
    e = []
    if isinstance(a, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%a.get_size(), a)
    else:
        src = a
    e.append(ExprAff(float_st0, ExprOp('fdiv', float_st0, src)))
    return e


def fnstsw():
    dst = eax
    return [ExprAff(dst, ExprCompose([ExprSliceTo(ExprInt(uint32(0)), 0, 8),
                                      ExprSliceTo(float_c0, 8, 9),
                                      ExprSliceTo(float_c1, 9, 10),
                                      ExprSliceTo(float_c2, 10, 11),
                                      ExprSliceTo(float_stack_ptr, 11, 14),
                                      ExprSliceTo(float_c3, 14, 15),
                                      ExprSliceTo(ExprInt(uint32(0)), 15, 16),
                                      ExprSliceTo(ExprSlice(dst, 16, dst.get_size()), 16, dst.get_size())
                                      ]))]

def fnstcw(a):
    e = []
    e.append(ExprAff(a, float_control))
    return e

def fldcw(a):
    e = []
    e.append(ExprAff(float_control, a))
    return e

def fwait():
    return []

def nop():
    return []

def hlt():
    return []

def rdtsc():
    e = []
    e.append(ExprAff(eax, tsc1))
    e.append(ExprAff(edx, tsc2))
    return e

def cbw(a):
    e = []
    cast_int = tab_uintsize[a.get_size()]
    b = ExprOp('<<', ExprInt(cast_int(-1)),
                     ExprInt(cast_int(a.get_size()/2)))

    e.append(ExprAff(a, ExprCond( 
                         ExprOp('==', ExprInt(cast_int(0)),
                                     ExprOp('&', a, ExprOp('<<',ExprInt(cast_int(1)), 
                                                                ExprOp('-', ExprInt(cast_int(a.get_size()/2)), 
                                                                            ExprInt(cast_int(1))
                                                                      )
                                                    )
                                           )
                               ), 
                         a,
                         ExprOp('|', a, b),
                         )
            ))
                   
    return e
    
# XXX TODO
def daa():
	return []

def aam(a):
	return []

def aad(a):
	return []

def aaa():
	return []

def bsf(a, b):
    e = []
    cast_int = tab_uintsize[b.get_size()]
    e.append(ExprAff(a, ExprOp('bsf', a, b)))
    e.append(ExprAff(zf, ExprOp('==', ExprInt(cast_int(0)), b)))
    return e
    
def bsr(a, b):
    e = []
    cast_int = tab_uintsize[b.get_size()]
    e.append(ExprAff(a, ExprOp('bsr', a, b)))
    e.append(ExprAff(zf, ExprOp('==', ExprInt(cast_int(0)), b)))
    return e

def arpl(a, b):
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt(uint32(1<<7))))
    return e

def ins():
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt(uint32(1<<7))))
    return e

def sidt(a):
    e = []
    if not isinstance(a, ExprMem) or a.size!=32:
      raise 'not exprmem 32bit instance!!'
    b = a.arg
    cast_int = tab_uintsize[a.get_size()]
    print "DEFAULT SIDT ADDRESS %s!!"%str(a)
    e.append(ExprAff(ExprMem(b, 32), ExprInt(uint32(0xe40007ff))))
    e.append(ExprAff(ExprMem(ExprOp("+", b, ExprInt(uint32(4))), 32), ExprInt(uint32(0x8245))))
    return e


def cmovz(a, b):
    e= []
    e.append(ExprAff(a, ExprCond(ExprOp('==', zf, ExprInt(uint32(1))), b, a)))
    return e
def cmovnz(a, b):
    e= []
    e.append(ExprAff(a, ExprCond(ExprOp('==', zf, ExprInt(uint32(0))), b, a)))
    return e

#XXX
def l_int(a):
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt(uint32(1<<1)))) #SOFT BP
    return e

def l_sysenter():
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt(uint32(EXCEPT_PRIV_INSN))))
    return e

#XXX
def l_outs():
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt(uint32(EXCEPT_PRIV_INSN)))) #SOFT BP
    return e

# XXX actually, xlat performs al = (ds:[e]bx + ZeroExtend(al))
def xlat():
    e= []
    a = ExprCompose([ExprSliceTo(ExprInt(uint32(0)), 8, 32), ExprSliceTo(eax[0:8], 0, 8)])
    b = ExprMem(ExprOp('+', ebx, a), 8)
    e.append(ExprAff(eax[0:8], b))
    return e

def cpuid():
    e = []
    e.append(ExprAff(eax, ExprOp('cpuid', eax, ExprInt(uint32(0)))))
    e.append(ExprAff(ebx, ExprOp('cpuid', eax, ExprInt(uint32(1)))))
    e.append(ExprAff(ecx, ExprOp('cpuid', eax, ExprInt(uint32(2)))))
    e.append(ExprAff(edx, ExprOp('cpuid', eax, ExprInt(uint32(3)))))
    return e

def bt(a, b):
    cast_int = tab_uintsize[a.get_size()]
    e= []
    c= ExprOp('&', b, ExprInt(cast_int(b.get_size() - 1)))
    d= ExprOp('>>', a, c)
    e.append(ExprAff(cf, ExprOp('&', d, ExprInt(cast_int(1)))))
    return e

def btc(a, b):
    cast_int = tab_uintsize[a.get_size()]
    e= []
    c= ExprOp('&', b, ExprInt(cast_int(b.get_size() - 1)))
    d= ExprOp('>>', a, c)
    m= ExprOp('<<', ExprInt(cast_int(1)), b)
    e.append(ExprAff(cf, ExprOp('&', d, ExprInt(cast_int(1)))))
    e.append(ExprAff(a, ExprOp('^', a, m)))
    return e

def bts(a, b):
    cast_int = tab_uintsize[a.get_size()]
    e= []
    c= ExprOp('&', b, ExprInt(cast_int(b.get_size() - 1)))
    d= ExprOp('>>', a, c)
    m= ExprOp('<<', ExprInt(cast_int(1)), b)
    e.append(ExprAff(cf, ExprOp('&', d, ExprInt(cast_int(1)))))
    e.append(ExprAff(a, ExprOp('|', a, m)))
    return e

def btr(a, b):
    cast_int = tab_uintsize[a.get_size()]
    e= []
    c= ExprOp('&', b, ExprInt(cast_int(b.get_size() - 1)))
    d= ExprOp('>>', a, c)
    m= ExprOp('!', ExprOp('<<', ExprInt(cast_int(1)), b))
    e.append(ExprAff(cf, ExprOp('&', d, ExprInt(cast_int(1)))))
    e.append(ExprAff(a, ExprOp('&', a, m)))
    return e


def into():
    return []

def l_in(a, b):
    return []

def cmpxchg(a, b, c):
    e = []
    cast_int = tab_uintsize[a.get_size()]

    cond = ExprOp('==', a, c )
    e.append(ExprAff(zf, cond))
    e.append(ExprAff(c, ExprCond(cond,
                                 b,
                                 c)
                     ))
    e.append(ExprAff(a, ExprCond(cond,
                                 a,
                                 c)
                     ))
    return e
    
    
    
mnemo_func = {'mov': mov,
              'xchg': xchg,
              'movzx': movzx,
              'movsx': movsx,
              'lea': lea,
              'add':add,
              'xadd':xadd,
              'adc':adc,
              'sub':sub,
              'sbb':sbb,
              'neg':neg,
              'not':l_not,
              'cmp':l_cmp,
              'xor':xor,
              'or':l_or,
              'and':l_and,
              'test':l_test,
              'rol':l_rol,
              'ror':l_ror,
              'rcl':rcl,
              'rcr':rcr,
              'sar':sar,
              'shr':shr,
              'shrd_cl':shrd_cl,              
              'sal':sal,
              'shl':shl,
              'shld_cl':shld_cl,
              'cmc':cmc,
              'clc':clc,
              'stc':stc,
              'cld':cld,
              'std':std,
              'cli':cli,
              'sti':sti,
              'bsf':bsf,
              'bsr':bsr,
              'inc':inc,
              'dec':dec,
              'push':push,
              'pop':pop,
              'sete':sete,
              'setnz':setnz,
              'setl':setl,
              'setg':setg,
              'setge':setge,
              'seta':seta,
              'setb':setb,
              'setns':setns,
              'sets':sets,
              'seto':seto,
              'bswap':bswap,
              'cmpsb':cmpsb,
              'cmpsw':cmpsw,
              'cmpsd':cmpsd,
              'scasb':scasb,
              'scasw':scasw,
              'scasd':scasd,
              'pushfd':pushfd,
              'pushfw':pushfw,
              'popfd':popfd,
              'pushad':pushad,
              'popad':popad,
              'call':call,
              'ret':ret,
              'leave':leave,
              'enter':enter,
              'jmp':jmp,
              'jz':jz,
              'je':jz,
              'jnz':jnz,
              'jp':jp,
              'jnp':jnp,
              'ja':ja,
              'jae':jae,
              'jb':jb,
              'jbe':jbe,
              'jg':jg,
              'jge':jge,
              'jl':jl,
              'jle':jle,
              'js':js,
              'jns':jns,
              'jo':jo,
              'jno':jno,
              'jecxz':jecxz,
              'loop':loop,
              'loopne':loopne,
              'div':div,
              'mul':mul,
              'imul':imul,
              'idiv':idiv,
              'cdq':cdq,
              'cbw':cbw,
              'daa':daa,
              'aam':aam,
              'aad':aad,
              'aaa':aaa,
              'shrd':shrd,
              'stosb':stosb,
              'stosw':stosw,
              'stosd':stosd,
              'lodsb':lodsb,
              'lodsw':lodsw,
              'lodsd':lodsd,
              'movsb':movsb,
              'movsw':movsw,
              'movsd':movsd,
              'fcomp':fcomp,
              'nop':nop,
              'fnop':nop, #XXX
              'hlt':hlt,
              'rdtsc':rdtsc,
              'fst':fst,
              'fstp':fstp,
              'fist':fist,
              'fistp':fistp,
              'fld':fld,
              'fldz':fldz,
              'fild':fild,
              'fadd':fadd,
              'fdiv':fdiv,
              'fnstsw':fnstsw,
              'fnstcw':fnstcw,
              'fldcw':fldcw,
              'fwait':fwait,
              'sidt':sidt,
              'arpl':arpl,
              'cmovz':cmovz,
              'cmove':cmovz,
              'cmovnz':cmovnz,
              'int':l_int,
              'xlat': xlat,
              'bt':bt,
              'cpuid':cpuid,
              'jo': jo,
              'fcom':fcom,
              'ficom':ficom,
              'ins':ins,
              'btc':btc,
              'bts':bts,
              'btr':btr,
              'into':into,
              'in':l_in,
              'outs':l_outs,
              "sysenter":l_sysenter,
              "cmpxchg":cmpxchg,
              }



class ia32_rexpr:

    noad = "no_ad"
    ad = "ad"

    ad8 = "ad8"
    ad16 = "ad16"
    ad32 = "ad32"
    segm = "segm"

    size = "size"

    symb = "symb__intern__"

    imm = "imm"
    s08 = "s08"
    u08 = "u08"
    u16 = "u16"
    s16 = "s16"
    u32 = "u32"
    s32 = "s32"

    f32 = "f32"
    f64 = "f64"

    im1 = "im1"
    im3 = "im3"
    ims = "ims"
    mim = "mim"


    dict_size = {imm:'imm',
                      s08:'b',
                      u08:'B',
                      s16:'h',
                      u16:'H',
                      s32:'i',
                      u32:'I',
                      }
                      

    
    r_eax = eax
    r_ecx = ecx
    r_edx = edx
    r_ebx = ebx
    r_esp = esp
    r_ebp = ebp
    r_esi = esi
    r_edi = edi
    
    r_dr0 = dr0
    r_dr1 = dr1
    r_dr2 = dr2
    r_dr3 = dr3
    r_dr4 = dr4
    r_dr5 = dr5
    r_dr6 = dr6
    r_dr7 = dr7
    
    r_cr0 = cr0
    r_cr1 = cr1
    r_cr2 = cr2
    r_cr3 = cr3
    r_cr4 = cr4
    r_cr5 = cr5
    r_cr6 = cr6
    r_cr7 = cr7
    
    r_ax = r_eax[:16]
    r_cx = r_ecx[:16]
    r_dx = r_edx[:16]
    r_bx = r_ebx[:16]
    r_sp = r_esp[:16]
    r_bp = r_ebp[:16]
    r_si = r_esi[:16]
    r_di = r_edi[:16]
         
    r_al = r_eax[:8]
    r_cl = r_ecx[:8]
    r_dl = r_edx[:8]
    r_bl = r_ebx[:8]
    r_ah = r_eax[8:16]
    r_ch = r_ecx[8:16]
    r_dh = r_edx[8:16]
    r_bh = r_ebx[8:16]


    r_es = es
    r_cs = cs
    r_ss = ss
    r_ds = ds
    r_fs = fs
    r_gs = gs

    reg_list8 =[r_al,  r_cl,  r_dl,  r_bl,
                     r_ah,  r_ch,  r_dh,  r_bh]
    reg_list16=[r_ax,  r_cx,  r_dx,  r_bx,
                     r_sp,  r_bp,  r_si,  r_di]
    reg_list32=[r_eax, r_ecx, r_edx, r_ebx,
                     r_esp, r_ebp, r_esi, r_edi]

    reg_listsg=[r_es,  r_cs,  r_ss,  r_ds,
                     r_fs,  r_gs]
    reg_listdr=[r_dr0, r_dr1, r_dr2, r_dr3, r_dr4, r_dr5, r_dr6, r_dr7]
    reg_listcr=[r_cr0, r_cr1, r_cr2, r_cr3, r_cr4, r_cr5, r_cr6, r_cr7]

    reg_flt = [float_st0, float_st1, float_st2, float_st3, float_st4, float_st5, float_st6, float_st7]

    reg_dict = {}
    for i in range(8):
        reg_dict[reg_list8[i]] = i
    for i in range(8):
        reg_dict[reg_list16[i]] = i
    for i in range(8):
        reg_dict[reg_list32[i]] = i
    for i in range(8):
        reg_dict[reg_flt[i]] = i



def dict_to_Expr(d, modifs = {}, mnemo_mode = x86_afs.u32):
    size = [x86_afs.u32, x86_afs.u08][modifs[w8]==True]
    #overwrite w8
    if modifs[sd]!=None:
        size = [x86_afs.f32, x86_afs.f64][modifs[sd]==True]
    if modifs[wd]:
        size = x86_afs.u16

                
    tab32 = {ia32_rexpr.u08:ia32_rexpr.reg_list8, ia32_rexpr.u16:ia32_rexpr.reg_list16, ia32_rexpr.u32:ia32_rexpr.reg_list32,ia32_rexpr.f32:ia32_rexpr.reg_flt}
    tab16 = {ia32_rexpr.u08:ia32_rexpr.reg_list8, ia32_rexpr.u16:ia32_rexpr.reg_list32, ia32_rexpr.u32:ia32_rexpr.reg_list16}
    ad_size = {ia32_rexpr.u08:ia32_rexpr.u08, ia32_rexpr.u16:ia32_rexpr.u16, ia32_rexpr.u32:ia32_rexpr.u32, ia32_rexpr.f32:ia32_rexpr.u32, ia32_rexpr.f64:ia32_rexpr.u32}

    if is_reg(d):
        n = [x for x in d if type(x) in [int, long]]
        if len(n)!=1:
            raise "bad reg! %s"%str(d)
        n = n[0]
        if x86_afs.size in d and d[x86_afs.size] == x86_afs.size_seg :
            t = ia32_rexpr.reg_listsg
        elif ia32_rexpr.size in d:
            my_s = d[x86_afs.size]
            if my_s == x86_afs.f64:
                my_s = x86_afs.u32
            t = tab32[my_s]
        else:
            if mnemo_mode == u32:
                t = tab32[size]
            else:
                t = tab16[size]
        if modifs[dr] and n>0x7:
            t = ia32_rexpr.reg_listdr
            n&=7
        if modifs[cr] and n>0x7:
            t = ia32_rexpr.reg_listcr
            n&=7
        if modifs[sg] and n>0x7:
            t = ia32_rexpr.reg_listsg
            n&=7
        if modifs[sd] is not None:
            t = tab32[size]
            n&=7
        
        out = t[n]
    elif is_imm(d):
        if ia32_rexpr.imm in d:
            #test bug imm 16b
            if mnemo_mode == x86_afs.u16:
                if size == x86_afs.u16:
                    size = x86_afs.u32
                else:
                    size = x86_afs.u16
        
            
            #print d
            out = ExprInt(tab_afs_int[size](d[ia32_rexpr.imm]))
        if ia32_rexpr.symb in d:
            if len(d[ia32_rexpr.symb])!=1:
                raise "not impl symb diff 1:x",str(d[ia32_rexpr.symb])
            myname = d[ia32_rexpr.symb].keys()[0]
            myval = myname.offset
            if myname.offset == None:
                return ExprId(myname.name)


            #XXX todo hack gen C
            return ExprInt(uint32(myval))
            if type(myname)!=str:
                return ExprId(myname.name)
            return ExprInt(uint32(myval))
    elif is_address(d):
        
        size = {ia32_rexpr.u08:8, ia32_rexpr.u16:16, ia32_rexpr.u32:32, ia32_rexpr.f32:32, ia32_rexpr.f64:64}[size]
        
        if ia32_rexpr.size in d:
            size = d[ia32_rexpr.size]
        msize = {ia32_rexpr.u08:8, ia32_rexpr.u16:16, ia32_rexpr.u32:32, ia32_rexpr.f32:32, ia32_rexpr.f64:64}
        if size in msize:
            size = msize[size]
        if ia32_rexpr.segm in d:
            pass
        out = []
        for k in d:
            if k in [ia32_rexpr.ad, ia32_rexpr.size]:
                continue
            elif k in [ia32_rexpr.segm]:
                if d[k] == 4:
                    out.append(ExprInt(uint32(0x7FF70000)))
            elif k == ia32_rexpr.imm:
                out.append(ExprInt(d[k]))
            elif type(k) in [int, long]:
                if d[k] ==1:
                    out.append(ia32_rexpr.reg_list32[k])
                else:
                    out.append(ExprOp('*', ExprInt(uint32(d[k])), ia32_rexpr.reg_list32[k]))
            elif k == ia32_rexpr.symb:
                print 'warning: symbol.. in mem look', d[k]
                out.append(ExprId(str(d[k].items()[0][0].name)))
            else:
                raise 'strange ad componoant: %s'%str(d)
        if not out:
            raise 'arg zarb expr %s'%str(d)
        e = out[0]
        for o in out[1:]:
            e = ExprOp('+', e, o)
        out = ExprMem(e, size)
        
    else:
        raise 'unknown arg %s'%str(d)
    return out



