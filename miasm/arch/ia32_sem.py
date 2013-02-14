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
import math

# interrupt with eip update after instr
EXCEPT_CODE_AUTOMOD = (1<<0)
EXCEPT_SOFT_BP = (1<<1)

EXCEPT_BREAKPOINT_INTERN = (1<<2)

EXCEPT_NUM_UDPT_EIP = (1<<5)
# interrupt with eip at instr
EXCEPT_UNK_MEM_AD = (1<<6)
EXCEPT_THROW_SEH = (1<<7)
EXCEPT_UNK_EIP = (1<<8)
EXCEPT_ACCESS_VIOL = (1<<9)
EXCEPT_INT_DIV_BY_ZERO = (1<<10)
EXCEPT_PRIV_INSN = (1<<11)
EXCEPT_ILLEGAL_INSN = (1<<12)


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
reg_float_eip = 'reg_float_eip'
reg_float_cs = 'reg_float_cs'
reg_float_address = 'reg_float_address'
reg_float_ds = 'reg_float_ds'


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


init_zf    = ExprId("init_zf", size=1)
init_nf    = ExprId("init_nf", size=1)
init_pf    = ExprId("init_pf", size=1)
init_of    = ExprId("init_of", size=1)
init_cf    = ExprId("init_cf", size=1)
init_tf    = ExprId("init_tf", size=1)
init_i_f   = ExprId("init_i_f", size=1)
init_df    = ExprId("init_df", size=1)
init_af    = ExprId("init_af", size=1)
init_iopl  = ExprId("init_iopl", size=2)
init_nt    = ExprId("init_nt", size=1)
init_rf    = ExprId("init_rf", size=1)
init_vm    = ExprId("init_vm", size=1)
init_ac    = ExprId("init_ac", size=1)
init_vif   = ExprId("init_vif", size=1)
init_vip   = ExprId("init_vip", size=1)
init_i_d   = ExprId("init_i_d", size=1)
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

segm_dict = {
    reg_es:es,
    reg_cs:cs,
    reg_ss:ss,
    reg_ds:ds,
    reg_fs:fs,
    reg_gs:gs,
    }

tsc1 = ExprId(reg_tsc1, size = 32)
tsc2 = ExprId(reg_tsc2, size = 32)

float_c0 = ExprId(reg_float_c0)
float_c1 = ExprId(reg_float_c1)
float_c2 = ExprId(reg_float_c2)
float_c3 = ExprId(reg_float_c3)
float_stack_ptr = ExprId(reg_float_stack_ptr)
float_control = ExprId(reg_float_control)
float_eip = ExprId(reg_float_eip)
float_cs = ExprId(reg_float_cs, size=16)
float_address = ExprId(reg_float_address)
float_ds = ExprId(reg_float_ds, size=16)

float_st0 = ExprId(reg_float_st0, 64)
float_st1 = ExprId(reg_float_st1, 64)
float_st2 = ExprId(reg_float_st2, 64)
float_st3 = ExprId(reg_float_st3, 64)
float_st4 = ExprId(reg_float_st4, 64)
float_st5 = ExprId(reg_float_st5, 64)
float_st6 = ExprId(reg_float_st6, 64)
float_st7 = ExprId(reg_float_st7, 64)

float_list = [
    float_st0 ,
    float_st1 ,
    float_st2 ,
    float_st3 ,
    float_st4 ,
    float_st5 ,
    float_st6 ,
    float_st7 ,
    ]



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
    float_eip ,
    float_cs ,
    float_address ,
    float_ds ,

    float_st0 ,
    float_st1 ,
    float_st2 ,
    float_st3 ,
    float_st4 ,
    float_st5 ,
    float_st6 ,
    float_st7 ,

    ]

tab_uintsize ={8:uint8,
               16:uint16,
               32:uint32,
               64:uint64
               }

tab_mode ={'u16':uint16,
           'u32':uint32,
           }

tab_mode_size ={'u16':16,
                'u32':32,
                }

tab_afs_int ={x86_afs.u08:uint8,
              x86_afs.u16:uint16,
              x86_afs.u32:uint32,
              }

class ia32info:
    opmode = "u32"
    admode = "u32"
    # offset

"""
http://www.emulators.com/docs/nx11_flags.htm

CF(A+B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND NOT (A XOR B)) < 0)
CF(A-B) = (((A XOR B) XOR D) < 0) XOR (((A XOR D) AND (A XOR B)) < 0)

OF(A+B) = ((A XOR D) AND NOT (A XOR B)) < 0
OF(A-B) = ((A XOR D) AND (A XOR B)) < 0
"""


# XXX TODO make default check against 0 or not 0 (same eq as in C)
def get_op_msb(a):
    return a[a.get_size()-1:a.get_size()]


def update_flag_zf(a):
    return [ExprAff(zf, ExprCond(a, ExprInt_from(zf, 0), ExprInt_from(zf, 1)))]

def update_flag_nf(a):
    return [ExprAff(nf, get_op_msb(a))]

def update_flag_pf(a):
    return [ExprAff(pf, ExprOp('parity', a))]

def update_flag_af(a):
    return [ExprAff(af, ExprCond(ExprOp('&', a, ExprInt_from(a, 0x10)),
                                 ExprInt_from(af, 1), ExprInt_from(af, 0)))]

def update_flag_znp(a):
    e = []
    e+=update_flag_zf(a)
    e+=update_flag_nf(a)
    e+=update_flag_pf(a)
    return e

def update_flag_logic(a):
    e = []
    e+=update_flag_znp(a)
    e.append(ExprAff(of, ExprInt32(0)))
    e.append(ExprAff(cf, ExprInt32(0)))
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
def update_flag_add_cf(a, b, c):
    return ExprAff(cf, get_op_msb((a ^ b) ^ c) ^ get_op_msb((a ^ c) & (~(a ^ b))))

def update_flag_add_of(a, b, c):
    return ExprAff(of, get_op_msb(((a ^ c) & (~(a ^ b)))))


#checked: ok for sbb add because of b & c before +cf
def update_flag_sub_cf(a, b, c):
    return ExprAff(cf, get_op_msb((a ^ b) ^ c) ^ get_op_msb((a ^ c) & (a ^ b)))


def update_flag_sub_of(a, b, c):
    return ExprAff(of, get_op_msb(((a ^ c) & (a ^ b))))


#z = x+y (+cf?)
def update_flag_add(x, y, z):
    e = []
    e.append(update_flag_add_cf(x, y, z))
    e.append(update_flag_add_of(x, y, z))
    return e

#z = x-y (+cf?)
def update_flag_sub(x, y, z):
    e = []
    e.append(update_flag_sub_cf(x, y, z))
    e.append(update_flag_sub_of(x, y, z))
    return e

def set_float_cs_eip(info):
    e = []
    # XXX TODO check float updt
    cast_int = tab_mode[info.opmode]
    e.append(ExprAff(float_eip, ExprInt(cast_int(info.offset))))
    e.append(ExprAff(float_cs, cs))
    return e

def mov(info, a, b):
    return [ExprAff(a, b)]

def xchg(info, a, b):
    e = []
    e.append(ExprAff(a, b))
    e.append(ExprAff(b, a))
    return e

def movzx(info, a, b):
    return [ExprAff(a, ExprCompose([(ExprInt32(0), b.get_size(), a.get_size()),
                                    (b, 0, b.get_size())]))]

def movsx(info, a, b):
    return [ExprAff(a, ExprCompose([(b, 0, b.get_size()),
                                    (ExprCond(get_op_msb(b),
                                              ExprInt32(0xffffffff),
                                              ExprInt32(0)),
                                     b.get_size(), a.get_size())
                                    ]))]

def lea(info, a, b):
    return [ExprAff(a, b.arg)]

def add(info, a, b):
    e= []
    c = ExprOp('+', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_add(a, b, c)
    e.append(ExprAff(a, c))
    return e

def xadd(info, a, b):
    e= []
    c = ExprOp('+', b, a)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_add(b, a, c)
    e.append(ExprAff(b, a))
    e.append(ExprAff(a, c))
    return e

def adc(info, a, b):
    e= []
    c = ExprOp('+',
               a,
               ExprOp('+',
                      b,
                      ExprCompose([(ExprInt32(0), 1, a.get_size()),
                                   (cf, 0, 1)])))
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_add(a, b, c)
    e.append(ExprAff(a, c))
    return e

def sub(info, a, b):
    e= []
    c = ExprOp('-', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_sub(a, b, c)
    e.append(ExprAff(a, c))
    return e

#a-(b+cf)
def sbb(info, a, b):
    e= []
    c = ExprOp('-',
               a,
               ExprOp('+',
                      b,
                      ExprCompose([(ExprInt32(0), 1, a.get_size()),
                                   (cf, 0, 1)])))
    e+=update_flag_arith(c)
    e+=update_flag_af(c)
    e+=update_flag_sub(a, b, c)
    e.append(ExprAff(a, c))
    return e

def neg(info, b):
    e= []
    a = ExprInt_from(b, 0)

    c = ExprOp('-', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_sub(a, b, c)
    e+=update_flag_af(c)
    e.append(ExprAff(b, c))
    return e

def l_not(info, b):
    e= []
    c = ~b
    e.append(ExprAff(b, c))
    return e


def l_cmp(info, a, b):
    e= []
    c = ExprOp('-', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_sub(a, b, c)
    e+=update_flag_af(c)
    return e

def xor(info, a, b):
    e= []
    c = ExprOp('^', a, b)
    e+=update_flag_logic(c)
    e.append(ExprAff(a, c))
    return e

def l_or(info, a, b):
    e= []
    c = ExprOp('|', a, b)
    e+=update_flag_logic(c)
    e.append(ExprAff(a, c))
    return e

def l_and(info, a, b):
    e= []
    c = ExprOp('&', a, b)
    e+=update_flag_logic(c)
    e.append(ExprAff(a, c))
    return e

def l_test(info, a, b):
    e= []
    c = ExprOp('&', a, b)
    e+=update_flag_logic(c)
    return e

def l_rol(info, a, b):
    e= []
    c = ExprOp('<<<', a, b)

    new_cf = ExprOp("&", c ,ExprInt_from(a, 1))
    e.append(ExprAff(cf, new_cf))
    ### hack (only valid if b=1)
    e.append(ExprAff(of, ExprOp("^", get_op_msb(c), new_cf)))
    e.append(ExprAff(a, c))
    return e

def l_ror(info, a, b):
    e= []
    c = ExprOp('>>>', a, b)

    e.append(ExprAff(cf, get_op_msb(c)))
    ### hack (only valid if b=1): when count == 1: a = msb-1(dest)
    e.append(ExprAff(of, ExprOp("^", get_op_msb(c), get_op_msb(a))))
    e.append(ExprAff(a, c))
    return e

def rcl(info, a, b):
    e= []
    c = ExprOp('<<<c_rez', a, b, cf)
    new_cf = ExprOp('<<<c_cf', a, b, cf)

    e.append(ExprAff(cf, new_cf))
    ### hack (only valid if b=1)
    e.append(ExprAff(of, ExprOp("^", get_op_msb(c), new_cf)))
    e.append(ExprAff(a, c))
    return e

def rcr(info, a, b):
    e= []
    c = ExprOp('>>>c_rez', a, b, cf)
    new_cf = ExprOp('>>>c_cf', a, b, cf)

    e.append(ExprAff(cf, new_cf))
    ### hack (only valid if b=1)
    e.append(ExprAff(of, ExprOp("^", get_op_msb(a), get_op_msb(c))))
    e.append(ExprAff(a, c))

    return e

def sar(info, a, b):
    e= []

    shifter = ExprOp('&',b, ExprInt_from(b, 0x1f))
    c = ExprOp('a>>', a, shifter)

    new_cf = ExprOp('&',
                    ExprInt_from(a, 1),
                    ExprOp('a>>',
                           a,
                           ExprOp('-',
                                  shifter,
                                  ExprInt_from(b, 1)
                                  )
                           )
                    )
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    e.append(ExprAff(of, ExprInt_from(a, 0)))
    e+=update_flag_znp(c)
    e.append(ExprAff(a, c))
    return e

def shr(info, a, b):
    e= []
    shifter = ExprOp('&',b, ExprInt_from(b, 0x1f))
    c = ExprOp('>>', a, shifter)

    new_cf = ExprOp('&',
                    ExprInt_from(a, 1),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  shifter,
                                  ExprInt_from(b, 1)
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

def shrd_cl(info, a, b):
    e= []
    shifter = ExprOp('&',ecx, ExprInt_from(b, 0x1f))
    c = ExprOp('|',
                ExprOp('>>', a, shifter),
                ExprOp('<<', b, ExprOp('-',
                                        ExprInt_from(a, a.get_size()),
                                        shifter)
                                        )
              )

    new_cf = ExprOp('&',
                    ExprInt_from(a, 1),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  shifter,
                                  ExprInt_from(b, 1)
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

def shrd(info, a, b, c):
    e= []
    shifter = c

    d = ExprOp('|',
                ExprOp('>>', a, shifter),
                ExprOp('<<', b, ExprOp('-',
                                        ExprInt_from(a, a.get_size()),
                                        shifter)
                                        )
              )

    new_cf = ExprAff(cf, ExprOp('&',
                                ExprInt_from(a, 1),
                                ExprOp('>>',
                                       a,
                                       ExprOp('-',
                                              shifter,
                                              ExprInt_from(b, 1)
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

def sal(info, a, b):
    e= []
    shifter = ExprOp('&',b, ExprInt_from(b, 0x1f))

    c = ExprOp('a<<', a, shifter)
    new_cf = ExprOp('&',
                    ExprInt_from(a, 1),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  ExprInt_from(b, a.get_size()),
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

def shl(info, a, b):
    e= []
    shifter = ExprOp('&',b, ExprInt_from(b, 0x1f))

    c = ExprOp('<<', a, shifter)
    new_cf = ExprOp('&',
                    ExprInt_from(a, 1),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  ExprInt_from(b, a.get_size()),
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

def shld_cl(info, a, b):
    return shld(info, a, b, ecx)

def shld(info, a, b, c):
    e= []
    shifter = ExprOp('&',c, ExprInt_from(a, 0x1f))
    c = ExprOp('|',
            ExprOp('<<', a, shifter),
            ExprOp('>>', b, ExprOp('-',
                                    ExprInt_from(a, a.get_size()),
                                    shifter)
                                    )
          )

    new_cf = ExprOp('&',
                    ExprInt_from(a, 1),
                    ExprOp('>>',
                           a,
                           ExprOp('-',
                                  ExprInt_from(b, a.get_size()),
                                  shifter
                                  )
                           )
                    )
    e.append(ExprAff(cf, ExprCond(shifter,
                                  new_cf,
                                  cf)
                     )
             )
    # XXX todo: don't update flag if shifter is 0
    e+=update_flag_znp(c)
    e.append(ExprAff(of, ExprOp('^', get_op_msb(c), new_cf)))
    e.append(ExprAff(a, ExprCond(shifter,
                                 c,
                                 a)))
    return e


#XXX todo ###
def cmc(info):
    return     [ExprAff(cf, ExprCond(cf, ExprInt_from(cf, 0), ExprInt_from(cf, 1)))]

def clc(info):
    return     [ExprAff(cf, ExprInt32(0))]

def stc(info):
    return     [ExprAff(cf, ExprInt32(1))]

def cld(info):
    return     [ExprAff(df, ExprInt32(0))]

def std(info):
    return     [ExprAff(df, ExprInt32(1))]

def cli(info):
    return     [ExprAff(i_f, ExprInt32(0))]

def sti(info):
    return     [ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt32(EXCEPT_PRIV_INSN))]

def inc(info, a):
    e= []
    b = ExprInt_from(a, 1)
    c = ExprOp('+', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)

    e.append(update_flag_add_of(a, b, c))
    e.append(ExprAff(a, c))
    return e


def dec(info, a):
    e= []
    b = ExprInt_from(a, -1)
    c = ExprOp('+', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_af(c)

    e.append(update_flag_add_of(a, b, c))
    e.append(ExprAff(a, c))
    return e

def push(info, a):
    e= []
    s = a.get_size()
    # special case segment regs
    if a in [es, cs, ss, ds, fs, gs]:
        opmode, admode = info.opmode, info.admode
        s = {u16:16, u32:32}[opmode]
    if not s in [16, 32]:
        raise ValueError('bad size stacker!')
    c = ExprOp('-', esp, ExprInt32(s/8))
    e.append(ExprAff(esp, c))
    e.append(ExprAff(ExprMem(c, a.get_size()), a))
    return e

def pop(info, a):
    e= []
    s = a.get_size()
    # special case segment regs
    if a in [es, cs, ss, ds, fs, gs]:
        opmode, admode = info.opmode, info.admode
        s = {u16:16, u32:32}[opmode]
    if not s in [16,32]:
        raise ValueError('bad size stacker!')
    new_esp = ExprOp('+', esp, ExprInt32(s/8))
    e.append(ExprAff(esp, new_esp))
    # XXX FIX XXX for pop [esp]
    if isinstance(a, ExprMem):
        a =a.replace_expr({esp:new_esp})
    e.append(ExprAff(a, ExprMem(esp, a.get_size())))
    return e

def sete(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(zf, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return e

def setnz(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(zf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return e

def setl(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(nf-of, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return e

def setg(info, a):
    e = []
    a0 = ExprInt_from(a, 0)
    a1 = ExprInt_from(a, 1)
    e.append(ExprAff(a, ExprOp("&",
                               ExprCond(zf, a0, a1),
                               ExprCond(nf-of, a0, a1)))
             )
    return e

def setge(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(nf-of, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return e


def seta(info, a):
    e = []
    a0 = ExprInt_from(a, 0)
    a1 = ExprInt_from(a, 1)
    e.append(ExprAff(a, ExprOp('&',
                               ExprCond(cf, a0, a1),
                               ExprCond(zf, a0, a1)))
             )
    return e

def setae(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(cf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return e

def setb(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(cf, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return e

def setbe(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('|',cf,zf),
                                 ExprInt_from(a, 1),
                                 ExprInt_from(a, 0)))
             )
    return e

def setns(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(nf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return e

def sets(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(nf, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return e


def seto(info, a):
    e= []
    e.append(ExprAff(a, ExprCond(of, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return e

def setp(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(pf, ExprInt_from(a, 1), ExprInt_from(a, 0))))
    return e

def setnp(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(pf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return e

def setle(info, a):
    e = []
    a0 = ExprInt_from(a, 0)
    a1 = ExprInt_from(a, 1)
    e.append(ExprAff(a, ExprOp("&",
                               ExprCond(zf, a1, a0),
                               ExprCond(nf-of, a1, a0)))
             )
    return e

def setna(info, a):
    e = []
    a0 = ExprInt_from(a, 0)
    a1 = ExprInt_from(a, 1)
    e.append(ExprAff(a, ExprOp('&',
                               ExprCond(cf, a1, a0),
                               ExprCond(zf, a1, a0)))
             )
    return e

def setnbe(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(ExprOp('|',cf,zf),
                                 ExprInt_from(a, 0),
                                 ExprInt_from(a, 1)))
             )
    return e

def setno(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(of, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return e

def setnb(info, a):
    e = []
    e.append(ExprAff(a, ExprCond(cf, ExprInt_from(a, 0), ExprInt_from(a, 1))))
    return e

def setalc(info):
    a = eax[0:8]
    e = []
    e.append(ExprAff(a, ExprCond(cf, ExprInt_from(a, 0xff), ExprInt_from(a, 0))))
    return e


def bswap(info, a):
    e = []
    c = ExprCompose([(ExprOp('&', ExprInt_from(a, 0xFF), a),                                         24, 32),
                     (ExprOp('>>', ExprOp('&', ExprInt_from(a, 0xFF00), a), ExprInt32(8)),     16, 24),
                     (ExprOp('>>', ExprOp('&', ExprInt_from(a, 0xFF0000), a), ExprInt32(16)),  8 , 16),
                     (ExprOp('>>', ExprOp('&', ExprInt_from(a, 0xFF000000), a), ExprInt32(24)),0 , 8 ),
                     ])
    e.append(ExprAff(a, c))
    return e

def cmps(info, a, b):
    e= []
    e+=l_cmp(info, a, b)
    off = a.get_size()/8
    e.append(ExprAff(a.arg, ExprCond(df,
                                     ExprOp('-', a.arg, ExprInt_from(a.arg, off)),
                                     ExprOp('+', a.arg, ExprInt_from(a.arg, off)))))
    e.append(ExprAff(b.arg, ExprCond(df,
                                     ExprOp('-', b.arg, ExprInt_from(a.arg, off)),
                                     ExprOp('+', b.arg, ExprInt_from(a.arg, off)))))
    return e

def scas(info, a):
    e= []
    off = a.get_size()/8
    e+=l_cmp(info, eax[0:a.get_size()], a)
    e.append(ExprAff(a.arg, ExprCond(df,
                                     ExprOp('-', a.arg, ExprInt_from(a.arg, off)),
                                     ExprOp('+', a.arg, ExprInt_from(a.arg, off)))))
    return e


def compose_eflag(s = 32):
    args = []

    regs = [cf, ExprInt32(1), pf, ExprInt32(0), af, ExprInt32(0), zf, nf, tf, i_f, df, of]
    for i in xrange(len(regs)):
        args.append((regs[i],i, i+1))

    args.append((iopl,12, 14))

    if s == 32:
        regs = [nt, ExprInt32(0), rf, vm, ac, vif, vip, i_d]
    elif s == 16:
        regs = [nt, ExprInt32(0)]
    else:
        raise ValueError('unk size')
    for i in xrange(len(regs)):
        args.append((regs[i],i+14, i+15))
    if s == 32:
        args.append((ExprInt32(0),22, 32))
    return ExprCompose(args)

def pushfd(info):
    return push(info, compose_eflag())

def pushfw(info):
    return push(info, compose_eflag(16))

def popfd(info):
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
    e.append(ExprAff(esp, ExprOp('+', esp, ExprInt32(4))))
    return e

def popfw(info):
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
    e.append(ExprAff(esp, ExprOp('+', esp, ExprInt32(2))))
    return e

def pushad(info):
    e = []
    opmode, admode = info.opmode, info.admode
    if opmode == u16:
        s = 16
        regs = [eax[:16], ecx[:16], edx[:16], ebx[:16],
                esp[:16], ebp[:16], esi[:16], edi[:16]]
    else:
        s = 32
        regs = [eax, ecx, edx, ebx, esp, ebp, esi, edi]
    for i in xrange(len(regs)):
        c = ExprOp('+', esp, ExprInt32(-(s/8)*(i+1)))
        e.append(ExprAff(ExprMem(c, s), regs[i]))
    e.append(ExprAff(esp, c))
    return e

def popad(info):
    e = []
    opmode, admode = info.opmode, info.admode
    if opmode == u16:
        s = 16
        myesp = esp[:16]
        regs = [eax[:16], ecx[:16], edx[:16], ebx[:16],
                esp[:16], ebp[:16], esi[:16], edi[:16]]
    else:
        s = 32
        myesp = esp
        regs = [eax, ecx, edx, ebx, esp, ebp, esi, edi]
    regs.reverse()
    for i in xrange(len(regs)):
        if regs[i] == myesp:
            continue
        c = ExprOp('+', esp, ExprInt32((s/8)*i))
        e.append(ExprAff(regs[i], ExprMem(c, s)))

    c = ExprOp('+', esp, ExprInt32((s/8)*(i+1)))
    e.append(ExprAff(esp, c))

    return e


def call(info, a, b):
    e= []
    opmode, admode = info.opmode, info.admode
    if opmode == u16:
        s = 16
        myesp = esp[:16]
    else:
        s = 32
        myesp = esp
    int_cast = tab_uintsize[s]

    c = ExprOp('+', myesp, ExprInt(int_cast(-s/8)))
    e.append(ExprAff(myesp, c))
    e.append(ExprAff(ExprMem(c, size=s), a))
    e.append(ExprAff(eip, b))
    return e

def ret(info, a = ExprInt32(0)):
    e = []
    opmode, admode = info.opmode, info.admode
    if opmode == u16:
        s = 16
        myesp = esp[:16]
    else:
        s = 32
        myesp = esp
    int_cast = tab_uintsize[s]
    e.append(ExprAff(myesp, ExprOp('+', myesp, ExprOp('+', ExprInt(int_cast(s/8)), a))))
    e.append(ExprAff(eip, ExprMem(myesp, size = s)))
    return e

def retf(info, a = ExprInt32(0)):
    e = []
    opmode, admode = info.opmode, info.admode
    if opmode == u16:
        s = 16
        myesp = esp[:16]
    else:
        s = 32
        myesp = esp
    int_cast = tab_uintsize[s]
    e.append(ExprAff(myesp, ExprOp('+', myesp, ExprOp('+', ExprInt(int_cast(s/8 + 2)), a))))
    e.append(ExprAff(eip, ExprMem(myesp, size = s)))
    e.append(ExprAff(cs, ExprMem(ExprOp('+', myesp, ExprInt(int_cast(s/8))),
                                 size=16)))


    return e

def leave(info):
    opmode, admode = info.opmode, info.admode
    if opmode == u16:
        s = 16
        myesp = esp[:16]
        myebp = ebp[:16]
    else:
        s = 32
        myesp = esp
        myebp = ebp
    int_cast = tab_uintsize[s]

    e = []
    e.append(ExprAff(myebp, ExprMem(myebp, size = s)))
    e.append(ExprAff(myesp, ExprOp('+', ExprInt(int_cast(s/8)), myebp)))
    return e

def enter(info, a,b):
    opmode, admode = info.opmode, info.admode
    if opmode == u16:
        s = 16
        myesp = esp[:16]
        myebp = ebp[:16]
    else:
        s = 32
        myesp = esp
        myebp = ebp
    int_cast = tab_uintsize[s]

    e = []
    esp_tmp = ExprOp("-", myesp, ExprInt(int_cast(s/8)))
    e.append(ExprAff(ExprMem(esp_tmp,
                             size = s),
                     myebp))
    e.append(ExprAff(myebp, esp_tmp))
    e.append(ExprAff(myesp, ExprOp('-', myesp,
                                      ExprOp("+", a, ExprInt(int_cast(s/8)))
                                )
                    )
            )
    return e

def jmp(info, a):
    e= []
    e.append(ExprAff(eip, a))
    return e

def jmpf(info, a, seg):
    e= []
    e.append(ExprAff(eip, a))
    e.append(ExprAff(cs, seg))
    return e


def jz(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(zf, b, a)))
    return e

def jnz(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(zf, a, b)))
    return e

def jp(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(pf, b, a)))
    return e

def jnp(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(pf, a, b)))
    return e

def ja(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('|', cf, zf), a, b)))
    return e

def jae(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(cf, a, b)))
    return e

def jb(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(cf, b, a)))
    return e

def jbe(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('|', cf, zf), b, a)))
    return e

def jge(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(nf-of, a, b)))
    return e

def jg(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('|', zf, nf-of), a, b)))
    return e

def jl(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(nf-of, b, a)))
    return e

def jle(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(ExprOp('|', zf, nf-of), b, a)))
    return e

def js(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(nf, b, a)))
    return e

def jns(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(nf, a, b)))
    return e

def jo(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(of, b, a)))
    return e

def jno(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(of, a, b)))
    return e

def jecxz(info, a, b):
    e= []
    e.append(ExprAff(eip, ExprCond(ecx, a, b)))
    return e


def loop(info, a, b):
    e= []
    c = ExprOp('-', ecx, ExprInt32(1))
    e.append(ExprAff(ecx, c))
    e.append(ExprAff(eip, ExprCond(c, b, a)))
    return e

def loopne(info, a, b):
    e= []
    c = ExprOp('-', ecx, ExprInt32(1))
    e.append(ExprAff(ecx, c))

    cond = ExprOp('|',
                  ExprCond(c, ExprInt_from(c, 0), ExprInt_from(c, 1)),
                  ExprCond(zf, ExprInt_from(c, 1), ExprInt_from(c, 0))
                  )
    e.append(ExprAff(eip, ExprCond(cond, a, b)))
    return e


def loope(info, a, b):
    e= []
    c = ExprOp('-', ecx, ExprInt32(1))
    e.append(ExprAff(ecx, c))

    cond = ExprOp('|',
                  ExprCond(c, ExprInt_from(c, 0), ExprInt_from(c, 1)),
                  ExprCond(zf, ExprInt_from(c, 0), ExprInt_from(c, 1))
                  )
    e.append(ExprAff(eip, ExprCond(cond, a, b)))
    return e


#XXX size to do; eflag
def div(info, a):
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
        e.append(ExprAff(eax[0:16], ExprCompose([(c_d, 0, 8),
                                                 (c_r, 8, 16)])))
    else:
        e.append(ExprAff(s1, c_r))
        e.append(ExprAff(s2, c_d))
    return e

#XXX size to do; eflag
def idiv(info, a):
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
def mul(info, a):
    e= []
    if a.get_size() == 32:
        c_hi = ExprOp('umul32_hi', eax, a)
        c_lo = ExprOp('umul32_lo', eax, a)
        e.append(ExprAff(edx, c_hi))
        e.append(ExprAff(eax, c_lo))

        e.append(ExprAff(of, ExprCond(c_hi,
                                      ExprInt32(1),
                                      ExprInt32(0))))
        e.append(ExprAff(cf, ExprCond(c_hi,
                                      ExprInt32(1),
                                      ExprInt32(0))))

    elif a.get_size() == 16:
        c_hi = ExprOp('umul16_hi', r_ax, a)
        c_lo = ExprOp('umul16_lo', r_ax, a)
        e.append(ExprAff(r_dx, c_hi))
        e.append(ExprAff(r_ax, c_lo))

        e.append(ExprAff(of, ExprCond(c_hi,
                                      ExprInt32(1),
                                      ExprInt32(0))))
        e.append(ExprAff(cf, ExprCond(c_hi,
                                      ExprInt32(1),
                                      ExprInt32(0))))

    elif a.get_size() == 8:
        c = ExprOp('umul08', eax, a)
        e.append(ExprAff(eax[:16], c))
        e.append(ExprAff(of, ExprCond(eax[8:16],
                                      ExprInt32(1),
                                      ExprInt32(0))))
        e.append(ExprAff(cf, ExprCond(eax[8:16],
                                      ExprInt32(1),
                                      ExprInt32(0))))



    return e

def imul(info, a, b = None, c = None):
    e= []
    if b == None:
        if a.get_size() == 32:
            c_hi = ExprOp('imul32_hi', eax, a)
            c_lo = ExprOp('imul32_lo', eax, a)
            e.append(ExprAff(edx, c_hi))
            e.append(ExprAff(eax, c_lo))
            e.append(ExprAff(cf, ExprCond(c_hi, ExprInt32(1), ExprInt32(0))))
            e.append(ExprAff(of, ExprCond(c_hi, ExprInt32(1), ExprInt32(0))))
        elif a.get_size() == 16:
            c_hi = ExprOp('imul16_hi', r_ax, a)
            c_lo = ExprOp('imul16_lo', r_ax, a)
            e.append(ExprAff(r_dx, c_hi))
            e.append(ExprAff(r_ax, c_lo))
            e.append(ExprAff(cf, ExprCond(c_hi, ExprInt32(1), ExprInt32(0))))
            e.append(ExprAff(of, ExprCond(c_hi, ExprInt32(1), ExprInt32(0))))
        elif a.get_size() == 8:
            c = ExprOp('imul08', eax, a)
            e.append(ExprAff(eax[:16], c))
            e.append(ExprAff(cf, ExprCond(c-eax[:16], ExprInt32(1), ExprInt32(0))))
            e.append(ExprAff(of, ExprCond(c-eax[:16], ExprInt32(1), ExprInt32(0))))
    else:
        if c == None:
            c = b
            b = a
        c = ExprOp('*', b, c)
        e.append(ExprAff(a, c))
        e.append(ExprAff(cf, ExprCond(c[16:], ExprInt32(1), ExprInt32(0))))
        e.append(ExprAff(of, ExprCond(c[16:], ExprInt32(1), ExprInt32(0))))
    return e

def cdq(info):
    # XXX to check
    opmode, admode = info.opmode, info.admode
    if opmode == u32:
        e = []
        e.append(ExprAff(edx,
                         ExprCond(get_op_msb(eax),
                                  ExprInt32(0xffffffff),
                                  ExprInt32(0x0))
                         )
                 )
    else:
        e = []
        e.append(ExprAff(edx[0:16],
                         ExprCond(get_op_msb(eax[:16]),
                                  ExprInt16(0xffff),
                                  ExprInt16(0x0))
                         )
                 )
    return e

def stos(info, a):
    e = []
    off = a.get_size()/8
    e.append(ExprAff(a, eax[0:a.get_size()]))
    e.append(ExprAff(a.arg, ExprCond(df,
                                     ExprOp('-', a.arg, ExprInt_from(a.arg, off)),
                                     ExprOp('+', a.arg, ExprInt_from(a.arg, off)))))
    return e

def lods(info, a):
    e = []
    off = a.get_size()/8
    e.append(ExprAff(eax[0:a.get_size()], a))
    e.append(ExprAff(a.arg, ExprCond(df,
                                     ExprOp('-', a.arg, ExprInt_from(a.arg, off)),
                                     ExprOp('+', a.arg, ExprInt_from(a.arg, off)))))
    return e

def movs(info, a, b):
    e = []
    off = a.get_size()/8
    e.append(ExprAff(a, b))
    e.append(ExprAff(a.arg, ExprCond(df,
                                     ExprOp('-', a.arg, ExprInt_from(a.arg, off)),
                                     ExprOp('+', a.arg, ExprInt_from(a.arg, off)))))
    e.append(ExprAff(b.arg, ExprCond(df,
                                     ExprOp('-', b.arg, ExprInt_from(b.arg, off)),
                                     ExprOp('+', b.arg, ExprInt_from(b.arg, off)))))

    return e

def float_prev(flt):
    if not flt in float_list:
        return None
    i = float_list.index(flt)
    if i == 0:
        fds
    flt = float_list[i-1]
    return flt

def float_pop(avoid_flt = None):
    avoid_flt = float_prev(avoid_flt)
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
        e.append(ExprAff(float_st7, ExprInt32(0)))
    e.append(ExprAff(float_stack_ptr, ExprOp('-', float_stack_ptr, ExprInt32(1))))
    return e

# XXX TODO
def fcom(info, a):
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

    e += set_float_cs_eip(info)
    return e

def ficom(info, a):
    e = []
    e += set_float_cs_eip(info)
    return e

def fcomi(info, a):
    # Invalid emulation
    InvalidEmulation
def fcomip(info, a):
    # Invalid emulation
    InvalidEmulation
def fucomi(info, a):
    # Invalid emulation
    InvalidEmulation
def fucomip(info, a):
    # Invalid emulation, only read/write analysis is valid
    cond = ExprOp('fcomp', float_st0, a)
    e = []
    e.append(ExprAff(zf, ExprCond(cond, ExprInt_from(zf, 0), ExprInt_from(zf, 1))))
    e.append(ExprAff(pf, ExprCond(cond, ExprInt_from(zf, 0), ExprInt_from(zf, 1))))
    e.append(ExprAff(cf, ExprCond(cond, ExprInt_from(zf, 0), ExprInt_from(zf, 1))))
    return e

def fcomp(info, a):
    e= fcom(info, a)
    e+=float_pop()

    e += set_float_cs_eip(info)
    return e

def fld(info, a):
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
    e.append(ExprAff(float_stack_ptr, ExprOp('+', float_stack_ptr, ExprInt32(1))))

    e += set_float_cs_eip(info)
    return e

def fst(info, a):
    e = []
    if isinstance(a, ExprMem):
        src = ExprOp('double_to_mem_%2d'%a.get_size(), float_st0)
    else:
        src = float_st0
    e.append(ExprAff(a, src))

    e += set_float_cs_eip(info)
    return e

def fstp(info, a):
    e = fst(info, a)
    e+=float_pop(a)
    return e

def fist(info, a):
    e = []
    e.append(ExprAff(a, ExprOp('double_to_int_32', float_st0)))

    e += set_float_cs_eip(info)
    return e

def fistp(info, a):
    e = fist(info, a)
    e+=float_pop(a)
    return e

def fild(info, a):
    #XXXXX
    src = ExprOp('int_%.2d_to_double'%a.get_size(), a)
    e = []
    e += set_float_cs_eip(info)
    e += fld(info, src)
    return e

def fldz(info):
    return fld(info, ExprOp('int_32_to_double', ExprInt32(0)))

def fld1(info):
    return fld(info, ExprOp('int_32_to_double', ExprInt32(1)))

def fldl2e(info):
    x = struct.pack('d', 1/math.log(2))
    x = struct.unpack('Q', x)[0]
    return fld(info, ExprOp('mem_64_to_double', ExprInt64(x)))

def fldlg2(info):
    x = struct.pack('d', math.log10(2))
    x = struct.unpack('Q', x)[0]
    return fld(info, ExprOp('mem_64_to_double', ExprInt64(x)))


def fadd(info, a, b = None):
    if b == None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%b.get_size(), b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fadd', a, src)))

    e += set_float_cs_eip(info)
    return e

def faddp(info, a, b = None):
    if b == None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%b.get_size(), b)
    else:
        src = b
    e.append(ExprAff(float_prev(a), ExprOp('fadd', a, src)))
    e += set_float_cs_eip(info)
    e += float_pop(a)
    return e

def fninit(info):
    e = []
    e += set_float_cs_eip(info)
    return e

def fnstenv(info, a):
    e = []
    # XXX TODO tag word, ...
    status_word = ExprCompose([(ExprInt32(0), 0, 8),
                               (float_c0,           8, 9),
                               (float_c1,           9, 10),
                               (float_c2,           10, 11),
                               (float_stack_ptr,    11, 14),
                               (float_c3,           14, 15),
                               (ExprInt32(0), 15, 16),
                               ])

    w_size = tab_mode_size[info.opmode]
    ad = ExprMem(a.arg, size=16)
    e.append(ExprAff(ad, float_control))
    ad = ExprMem(a.arg+ExprInt32(w_size/8*1), size = 16)
    e.append(ExprAff(ad, status_word))
    ad = ExprMem(a.arg+ExprInt32(w_size/8*3), size = w_size)
    e.append(ExprAff(ad, float_eip[:w_size]))
    ad = ExprMem(a.arg+ExprInt32(w_size/8*4), size = 16)
    e.append(ExprAff(ad, float_cs))
    ad = ExprMem(a.arg+ExprInt32(w_size/8*5), size = w_size)
    e.append(ExprAff(ad, float_address[:w_size]))
    ad = ExprMem(a.arg+ExprInt32(w_size/8*6), size = 16)
    e.append(ExprAff(ad, float_ds))
    return e

def fsub(info, a, b = None):
    if b == None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%b.get_size(), b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fsub', a, src)))
    e += set_float_cs_eip(info)
    return e

def fmul(info, a, b = None):
    if b == None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%b.get_size(), b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fmul', a, src)))
    e += set_float_cs_eip(info)
    return e

def fdiv(info, a, b = None):
    if b == None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%b.get_size(), b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fdiv', a, src)))
    e += set_float_cs_eip(info)
    return e

def fdivr(info, a, b = None):
    if b == None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%b.get_size(), b)
    else:
        src = b
    e.append(ExprAff(a, ExprOp('fdiv', src, a)))
    e += set_float_cs_eip(info)
    return e

def fdivp(info, a):
    # Invalid emulation
    if b == None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%b.get_size(), b)
    else:
        src = b
    e.append(ExprAff(float_prev(a), ExprOp('fdiv', a, src)))
    e += set_float_cs_eip(info)
    e += float_pop(a)
    return e

def fmulp(info, a, b):
    # Invalid emulation
    if b == None:
        b = a
        a = float_st0
    e = []
    if isinstance(b, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%b.get_size(), b)
    else:
        src = b
    e.append(ExprAff(float_prev(a), ExprOp('fmul', a, src)))
    e += set_float_cs_eip(info)
    e += float_pop(a)
    return e

def ftan(info, a):
    e = []
    if isinstance(a, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%a.get_size(), a)
    else:
        src = a
    e.append(ExprAff(float_st0, ExprOp('ftan', src)))
    e += set_float_cs_eip(info)
    return e

def fxch(info, a):
    e = []
    if isinstance(a, ExprMem):
        src = ExprOp('mem_%.2d_to_double'%a.get_size(), a)
    else:
        src = a
    e.append(ExprAff(float_st0, src))
    e.append(ExprAff(src, float_st0))
    e += set_float_cs_eip(info)
    return e

def fptan(info):
    e= []
    e.append(ExprAff(float_st7, float_st6))
    e.append(ExprAff(float_st6, float_st5))
    e.append(ExprAff(float_st5, float_st4))
    e.append(ExprAff(float_st4, float_st3))
    e.append(ExprAff(float_st3, float_st2))
    e.append(ExprAff(float_st2, float_st1))
    e.append(ExprAff(float_st1, ExprOp('ftan', float_st0)))
    e.append(ExprAff(float_st0, ExprOp('int_32_to_double', ExprInt32(1))))
    e.append(ExprAff(float_stack_ptr, ExprOp('+', float_stack_ptr, ExprInt32(1))))
    return e


def frndint(info):
    e = []
    e.append(ExprAff(float_st0, ExprOp('frndint', float_st0)))
    e += set_float_cs_eip(info)
    return e

def fsin(info):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fsin', float_st0)))
    e += set_float_cs_eip(info)
    return e

def fcos(info):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fcos', float_st0)))
    e += set_float_cs_eip(info)
    return e

def fscale(info):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fscale', float_st0, float_st1)))
    e += set_float_cs_eip(info)
    return e

def f2xm1(info):
    e = []
    e.append(ExprAff(float_st0, ExprOp('f2xm1', float_st0)))
    e += set_float_cs_eip(info)
    return e

def fsqrt(info):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fsqrt', float_st0)))
    e += set_float_cs_eip(info)
    return e

def fabs(info):
    e = []
    e.append(ExprAff(float_st0, ExprOp('fabs', float_st0)))
    e += set_float_cs_eip(info)
    return e


def fnstsw(info):
    dst = eax
    return [ExprAff(dst, ExprCompose([(ExprInt32(0), 0, 8),
                                      (float_c0,           8, 9),
                                      (float_c1,           9, 10),
                                      (float_c2,           10, 11),
                                      (float_stack_ptr,    11, 14),
                                      (float_c3,           14, 15),
                                      (ExprInt32(0), 15, 16),
                                      (dst[16:dst.get_size()], 16, dst.get_size())
                                      ]))]

def fnstcw(info, a):
    e = []
    e.append(ExprAff(a, float_control))
    return e

def fldcw(info, a):
    e = []
    e.append(ExprAff(float_control, a))
    return e

def fwait(info):
    return []

def nop(info):
    return []

def hlt(info):
    e = []
    except_int = EXCEPT_PRIV_INSN
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt32(except_int)))
    return e

def rdtsc(info):
    e = []
    e.append(ExprAff(tsc1, ExprOp('+', tsc1, ExprInt32(1))))
    e.append(ExprAff(eax, tsc1))
    e.append(ExprAff(edx, tsc2))
    return e

def cbw(info, a):
    opmode, admode = info.opmode, info.admode
    if opmode == u16:
        s = 16
        src = a[:8]
        dst = a[:16]

    else:
        s = 32
        src = a[:16]
        dst = a[:32]
    int_cast = tab_uintsize[s]

    byte_h_0 = ExprInt(int_cast(0))
    byte_h_f = ExprInt(int_cast(((1<<(s/2))-1)))

    mask = ExprCond(get_op_msb(src), byte_h_f, byte_h_0)
    e = []
    e.append(ExprAff(a, ExprCompose([(a,    0, s/2),
                                     (mask, s/2, s)])))
    return e

# XXX TODO
def daa(info):
    return []

def aam(info, a):
    return []

def aad(info, a):
    return []

def aaa(info, ):
    return []

def bsf(info, a, b):
    e = []
    e.append(ExprAff(a, ExprOp('bsf', a, b)))
    e.append(ExprAff(zf, ExprCond(b, ExprInt_from(zf, 0), ExprInt_from(zf, 1))))
    return e

def bsr(info, a, b):
    e = []
    e.append(ExprAff(a, ExprOp('bsr', a, b)))
    e.append(ExprAff(zf, ExprCond(b, ExprInt_from(zf, 0), ExprInt_from(zf, 1))))
    return e

def arpl(info, a, b):
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt32(1<<7)))
    return e

def ins(info):
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'), ExprInt32(1<<7)))
    return e

def sidt(info, a):
    e = []
    if not isinstance(a, ExprMem) or a.size!=32:
      raise 'not exprmem 32bit instance!!'
    b = a.arg
    print "DEFAULT SIDT ADDRESS %s!!"%str(a)
    e.append(ExprAff(ExprMem(b, 32), ExprInt32(0xe40007ff)))
    e.append(ExprAff(ExprMem(ExprOp("+", b, ExprInt32(4)), 32), ExprInt32(0x8245)))
    return e


def cmovz(info, a, b):
    e= []
    e.append(ExprAff(a, ExprCond(zf, b, a)))
    return e
def cmovnz(info, a, b):
    e= []
    e.append(ExprAff(a, ExprCond(zf, a, b)))
    return e
def cmovge(info, a, b):
    e= []
    e.append(ExprAff(a, ExprCond( ExprOp('^', nf, of) , a, b)))
    return e
def cmovl(info, a, b):
    e= []
    e.append(ExprAff(a, ExprCond( ExprOp('^', nf, of) , b, a)))
    return e
def cmovle(info, a, b):
    e= []
    e.append(ExprAff(a, ExprCond( ExprOp('|', ExprOp('^', nf, of), zf) , b, a)))
    return e
def cmovo(info, a, b):
    e= []
    e.append(ExprAff(a, ExprCond(of , b, a)))
    return e
def cmovno(info, a, b):
    e= []
    e.append(ExprAff(a, ExprCond(of , a, b)))
    return e
def cmovs(info, a, b):
    e= []
    # SF is called nf in miasm
    e.append(ExprAff(a, ExprCond(nf , b, a)))
    return e
def cmovns(info, a, b):
    e= []
    # SF is called nf in miasm
    e.append(ExprAff(a, ExprCond(nf , a, b)))
    return e

#XXX
def l_int(info, a):
    e= []
    # XXX
    if a.arg in [1, 3]:
        except_int = EXCEPT_SOFT_BP
    else:
        except_int = EXCEPT_PRIV_INSN

    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'),
                     ExprInt32(except_int)))
    return e

def l_sysenter(info):
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'),
                     ExprInt32(EXCEPT_PRIV_INSN)))
    return e

#XXX
def l_out(info, a, b):
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'),
                     ExprInt32(EXCEPT_PRIV_INSN)))
    return e

#XXX
def l_outs(info):
    e= []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'),
                     ExprInt32(EXCEPT_PRIV_INSN)))
    return e

# XXX actually, xlat performs al = (ds:[e]bx + ZeroExtend(al))
def xlat(info):
    e= []
    a = ExprCompose([(ExprInt32(0), 8, 32),
                     (eax[0:8], 0, 8)])
    b = ExprMem(ExprOp('+', ebx, a), 8)
    e.append(ExprAff(eax[0:8], b))
    return e

def cpuid(info):
    e = []
    e.append(ExprAff(eax, ExprOp('cpuid', eax, ExprInt32(0))))
    e.append(ExprAff(ebx, ExprOp('cpuid', eax, ExprInt32(1))))
    e.append(ExprAff(ecx, ExprOp('cpuid', eax, ExprInt32(2))))
    e.append(ExprAff(edx, ExprOp('cpuid', eax, ExprInt32(3))))
    return e

def bt(info, a, b):
    e= []
    c= ExprOp('&', b, ExprInt_from(a, b.get_size() - 1))
    d= ExprOp('>>', a, c)
    e.append(ExprAff(cf, ExprOp('&', d, ExprInt_from(a, 1))))
    return e

def btc(info, a, b):
    e= []
    c= ExprOp('&', b, ExprInt_from(a, b.get_size() - 1))
    d= ExprOp('>>', a, c)
    m= ExprOp('<<', ExprInt_from(a, 1), b)
    e.append(ExprAff(cf, ExprOp('&', d, ExprInt_from(a, 1))))
    e.append(ExprAff(a, ExprOp('^', a, m)))
    return e

def bts(info, a, b):
    e= []
    c= ExprOp('&', b, ExprInt_from(a, b.get_size() - 1))
    d= ExprOp('>>', a, c)
    m= ExprOp('<<', ExprInt_from(a, 1), b)
    e.append(ExprAff(cf, ExprOp('&', d, ExprInt_from(a, 1))))
    e.append(ExprAff(a, ExprOp('|', a, m)))
    return e

def btr(info, a, b):
    e= []
    c= ExprOp('&', b, ExprInt_from(a, b.get_size() - 1))
    d= ExprOp('>>', a, c)
    m= ~ExprOp('<<', ExprInt_from(a, 1), b)
    e.append(ExprAff(cf, ExprOp('&', d, ExprInt_from(a, 1))))
    e.append(ExprAff(a, ExprOp('&', a, m)))
    return e


def into(info):
    return []

def l_in(info, a, b):
    e = []
    e.append(ExprAff(ExprId('vmcpu.vm_exception_flags'),
                     ExprInt32(EXCEPT_PRIV_INSN)))
    return e

def cmpxchg(info, a, b, c):
    e = []

    cond = a-c
    e.append(ExprAff(zf, ExprCond(cond, ExprInt_from(zf, 0), ExprInt_from(zf, 1))))
    e.append(ExprAff(c, ExprCond(cond,
                                 c,
                                 b)
                     ))
    e.append(ExprAff(a, ExprCond(cond,
                                 c,
                                 a)
                     ))
    return e

def lds(info, a, b):
    e = []
    e.append(ExprAff(a, ExprMem(b.arg, size = a.get_size())))
    e.append(ExprAff(ds, ExprMem(ExprOp('+', b.arg, ExprInt_from(a, 2)),
                                 size=16)))
    return e

def les(info, a, b):
    e = []
    e.append(ExprAff(a, ExprMem(b.arg, size = a.get_size())))
    e.append(ExprAff(es, ExprMem(ExprOp('+', b.arg, ExprInt_from(a, 2)),
                                 size=16)))
    return e

def lss(info, a, b):
    e = []
    e.append(ExprAff(a, ExprMem(b.arg, size = a.get_size())))
    e.append(ExprAff(ss, ExprMem(ExprOp('+', b.arg, ExprInt_from(a, 2)),
                                 size=16)))
    return e

def lahf(info):
    e = []
    args = []
    regs = [cf, ExprInt32(1), pf, ExprInt32(0), af, ExprInt32(0), zf, nf]
    for i in xrange(len(regs)):
        args.append((regs[i],i, i+1))
    e.append(ExprAff(eax[8:16], ExprCompose(args)))
    return e

def sahf(info):
    tmp = eax[8:16]
    e = []
    e.append(ExprAff(cf, ExprSlice(tmp, 0, 1)))
    e.append(ExprAff(pf, ExprSlice(tmp, 2, 3)))
    e.append(ExprAff(af, ExprSlice(tmp, 4, 5)))
    e.append(ExprAff(zf, ExprSlice(tmp, 6, 7)))
    e.append(ExprAff(nf, ExprSlice(tmp, 7, 8)))
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
              'shld':shld,
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
              'setae':setae,
              'setb':setb,
              'setbe':setbe,
              'setns':setns,
              'sets':sets,
              'seto':seto,
              'setp':setp,
              'setpe':setp,
              'setnp':setnp,
              'setpo':setnp,
              'setle':setle,
              'setng':setle,
              'setna':setna,
              'setnbe':setnbe,
              'setno':setno,
              'setnc':setnb,
              'setz':sete,
              'setne':setnz,
              'setnb':setae,
              'setnae':setb,
              'setc':setb,
              'setnge':setl,
              'setnl':setge,
              'setnle':setg,
              'setalc':setalc,
              'bswap':bswap,
              'cmpsb':cmps,
              'cmpsw':cmps,
              'cmpsd':cmps,
              'scasb':scas,
              'scasw':scas,
              'scasd':scas,
              'pushfd':pushfd,
              'pushfw':pushfw,
              'popfd':popfd,
              'popfw':popfw,
              'pushad':pushad,
              'popad':popad,
              'call':call,
              'ret':ret,
              'retf':retf,
              'leave':leave,
              'enter':enter,
              'jmp':jmp,
              'jmpf':jmpf,
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
              'loope':loope,
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
              'stosb':stos,
              'stosw':stos,
              'stosd':stos,
              'lodsb':lods,
              'lodsw':lods,
              'lodsd':lods,
              'movsb':movs,
              'movsw':movs,
              'movsd':movs,
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
              'fld1':fld1,
              'fldl2e':fldl2e,
              'fldlg2':fldlg2,
              'fild':fild,
              'fadd':fadd,
              'fninit':fninit,
              'faddp':faddp,
              'fsub':fsub,
              'fmul':fmul,
              'fmulp':fmulp,
              'fdiv':fdiv,
              'fdivr':fdivr,
              'fdivp':fdivp,
              'fxch':fxch,
              'fptan':fptan,
              'frndint':frndint,
              'fsin':fsin,
              'fcos':fcos,
              'fscale':fscale,
              'f2xm1':f2xm1,
              'fsqrt':fsqrt,
              'fabs':fabs,
              'fnstsw':fnstsw,
              'fnstcw':fnstcw,
              'fldcw':fldcw,
              'fwait':fwait,
              'fnstenv':fnstenv,
              'sidt':sidt,
              'arpl':arpl,
              'cmovz':cmovz,
              'cmove':cmovz,
              'cmovnz':cmovnz,
              'cmovge':cmovge,
              'cmovnl':cmovge,
              'cmovl':cmovl,
              'cmovnge':cmovl,
              'cmovle':cmovle,
              'cmovng':cmovle,
              'cmovo':cmovo,
              'cmovno':cmovno,
              'cmovs':cmovs,
              'cmovns':cmovns,
              'int':l_int,
              'xlat': xlat,
              'bt':bt,
              'cpuid':cpuid,
              'jo': jo,
              'fcom':fcom,
              'ficom':ficom,
              'fcomi':fcomi,
              'fcomip':fcomip,
              'fucomi':fucomi,
              'fucomip':fucomip,
              'ins':ins,
              'btc':btc,
              'bts':bts,
              'btr':btr,
              'into':into,
              'in':l_in,
              'outs':l_outs,
              'out':l_out,
              "sysenter":l_sysenter,
              "cmpxchg":cmpxchg,
              "lds": lds,
              "les": les,
              "lss": lss,
              "lahf": lahf,
              "sahf": sahf,
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



def dict_to_Expr(d, modifs = {}, opmode = u32, admode = u32, segm_to_do = set()):
    size = [x86_afs.u32, x86_afs.u08][modifs[w8]==True]
    #overwrite w8
    if modifs[sd]!=None:
        size = [x86_afs.f32, x86_afs.f64][modifs[sd]==True]
    elif modifs[wd]:
        size = x86_afs.u16

    tab32 = {ia32_rexpr.u08:ia32_rexpr.reg_list8, ia32_rexpr.u16:ia32_rexpr.reg_list16, ia32_rexpr.u32:ia32_rexpr.reg_list32,ia32_rexpr.f32:ia32_rexpr.reg_flt,ia32_rexpr.f64:ia32_rexpr.reg_flt}
    tab16 = {ia32_rexpr.u08:ia32_rexpr.reg_list8, ia32_rexpr.u16:ia32_rexpr.reg_list32, ia32_rexpr.u32:ia32_rexpr.reg_list16}
    ad_size = {ia32_rexpr.u08:ia32_rexpr.u08, ia32_rexpr.u16:ia32_rexpr.u16, ia32_rexpr.u32:ia32_rexpr.u32, ia32_rexpr.f32:ia32_rexpr.u32, ia32_rexpr.f64:ia32_rexpr.u32}

    if is_reg(d):
        n = [x for x in d if type(x) in [int, long]]
        if len(n)!=1:
            raise ValueError("bad reg! %s"%str(d))
        n = n[0]
        if x86_afs.size in d and d[x86_afs.size] == x86_afs.size_seg :
            t = ia32_rexpr.reg_listsg
        elif ia32_rexpr.size in d:
            my_s = d[x86_afs.size]
            if my_s == x86_afs.f64:
                my_s = x86_afs.u32
            t = tab32[my_s]
        else:
            if opmode == u32:
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
            if opmode == x86_afs.u16:
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
            return ExprInt32(myval)
            if type(myname)!=str:
                return ExprId(myname.name)
            return ExprInt32(myval)
    elif is_address(d):
        int_cast = tab_afs_int[admode]
        #segm = None
        # XXX test
        segm = x86_afs.r_ds
        segm = segm_dict[segm]


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
                if d[k] in segm_to_do:
                    segm = x86_afs.reg_sg[d[k]]
                    segm =  segm_dict[segm]
            elif k == ia32_rexpr.imm:
                out.append(ExprInt(d[k]))
            elif type(k) in [int, long]:
                if d[k] ==1:
                    if admode == u16:
                        out.append(ia32_rexpr.reg_list16[k])
                    else:
                        out.append(ia32_rexpr.reg_list32[k])
                else:
                    if admode == u16:
                        out.append(ExprOp('*', ExprInt(int_cast(d[k])), ia32_rexpr.reg_list16[k]))
                    else:
                        out.append(ExprOp('*', ExprInt(int_cast(d[k])), ia32_rexpr.reg_list32[k]))

            elif k == ia32_rexpr.symb:
                #print 'warning: symbol.. in mem look', d[k]
                out.append(ExprId(str(d[k].items()[0][0].name)))
            else:
                raise 'strange ad componoant: %s'%str(d)
        if not out:
            raise 'arg zarb expr %s'%str(d)
        e = out[0]
        for o in out[1:]:
            e = ExprOp('+', e, o)
        out = ExprMem(e, size, segm)
    else:
        raise 'unknown arg %s'%str(d)
    return out



