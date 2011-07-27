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
from miasm.arch.arm_arch import *
from miasm.core.asmbloc import *


reg_r0 = 'R0'
reg_r1 = 'R1'
reg_r2 = 'R2'
reg_r3 = 'R3'
reg_r4 = 'R4'
reg_r5 = 'R5'
reg_r6 = 'R6'
reg_r7 = 'R7'
reg_r8 = 'R8'
reg_r9 = 'R9'
reg_r10 = 'R10'
reg_r11 = 'R11'
reg_r12 = 'R12'
reg_sp = 'SP'
reg_lr = 'LR'
reg_pc = 'PC'

reg_zf = 'zf'
reg_nf = 'nf'
reg_of = 'of'
reg_cf = 'cf'

zf = ExprId(reg_zf, size=1)
nf = ExprId(reg_nf, size=1)
of = ExprId(reg_of, size=1)
cf = ExprId(reg_cf, size=1)

R0  = ExprId(reg_r0)
R1  = ExprId(reg_r1)
R2  = ExprId(reg_r2)
R3  = ExprId(reg_r3)
R4  = ExprId(reg_r4)
R5  = ExprId(reg_r5)
R6  = ExprId(reg_r6)
R7  = ExprId(reg_r7)
R8  = ExprId(reg_r8)
R9  = ExprId(reg_r9)
R10 = ExprId(reg_r10)
R11 = ExprId(reg_r11)
R12 = ExprId(reg_r12)
SP = ExprId(reg_sp)
LR  = ExprId(reg_lr)
PC  = ExprId(reg_pc)


all_registers = [
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    SP,
    LR,
    PC,
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

str2regid = dict([(x.name,x) for x in all_registers])




def get_op_msb(a):
    cast_int = tab_uintsize[a.get_size()]
    return ExprOp('==', ExprInt(cast_int(1)), ExprOp('>>', a, ExprInt(cast_int(a.get_size()-1))))


def update_flag_zf(a):
    cast_int = tab_uintsize[a.get_size()]
    return [ExprAff(zf, ExprOp('==', a, ExprInt(cast_int(0))))]

def update_flag_nf(a):
    return [ExprAff(nf, ExprOp('&', get_op_msb(a), ExprInt(tab_uintsize[a.get_size()](1))))]


def update_flag_zn(a):
    e = []
    e+=update_flag_zf(a)
    e+=update_flag_nf(a)
    return e

def update_flag_logic(a):
    e = []
    e+=update_flag_zn(a)
    e.append(ExprAff(of, ExprInt(uint32(0))))
    e.append(ExprAff(cf, ExprInt(uint32(0))))
    return e

def update_flag_arith(a):
    e = []
    e+=update_flag_zn(a)
    return e

def check_ops_msb(a, b, c):
    if not a or not b or not c or a!=b or a!=c:
        raise 'bad ops size %s %s %s'%(str(a), str(b), str(c))

def arith_flag(a, b, c):
    a_s, b_s, c_s = a.get_size(), b.get_size(), c.get_size()
    check_ops_msb(a_s, b_s, c_s)
    a_s, b_s, c_s = get_op_msb(a), get_op_msb(b), get_op_msb(c)
    return a_s, b_s, c_s

#z = x+y (+cf?)
def update_flag_add(x, y, z):
    a, b, c = arith_flag(x, y, z)
    cast_int = tab_uintsize[z.get_size()]
    e = []
    e.append(update_flag_add_cf(cast_int, a, b, c))
    e.append(update_flag_add_of(cast_int, a, b, c))    
    return e

#z = x-y (+cf?)
def update_flag_sub(x, y, z):
    a, b, c = arith_flag(x, y, z)
    cast_int = tab_uintsize[z.get_size()]
    e = []
    e.append(update_flag_sub_cf(cast_int, a, b, c))
    e.append(update_flag_sub_of(cast_int, a, b, c))
    return e

def update_flag_sub_cf(cast_int, a, b, c):
    return ExprAff(cf, ExprOp('|',
                              ExprOp('&', ExprOp('==', a, ExprInt(cast_int(0))), b),
                              ExprOp('&', c, ExprOp('|', ExprOp('==', a, ExprInt(cast_int(0))), b)
                                     )
                              )
                   )


def update_flag_sub_of(cast_int, a, b, c):
    return ExprAff(of, ExprOp('|',
                              ExprOp('&',
                                     ExprOp('==', c, ExprInt(cast_int(1))),
                                     ExprOp('&', ExprOp('==', a, ExprInt(cast_int(0))), b)
                                     ),
                              ExprOp('&',
                                     ExprOp('==', c, ExprInt(cast_int(0))),
                                     ExprOp('&', a, ExprOp('==', b, ExprInt(cast_int(0))))
                                     )
                              )
                   )




def get_cf_shifter(a):
    e = []
    if not isinstance(a, ExprOp):
        return e
    if not a.op in ['<<', '>>', 'a>>', '>>>']:
        return e
    #int shift amount
    shifter = a.args[1]
    source = a.args[0]
    if isinstance(shifter, ExprInt) and shifter.arg == 0:
        if a.op == '<<':
            #cf is old cf
            return e
        elif a.op in  ['>>', 'a>>']:
            e.append(ExprAff(cf, get_op_msb(source)))                
            return e
        elif a.op == '>>>':
            new_cf = ExprOp('&',
                            ExprInt(cast_int(1)),
                            source
                            )
            e.append(ExprAff(cf, new_cf))
            return e
        raise ValueError('bad op')
        
            
    if a.op == '<<':            
        new_cf = ExprOp('&',
                        ExprInt(uint32(1)),
                        ExprOp('>>',
                               source,
                               ExprOp('-',
                                      ExprInt(uint32(source.get_size())),
                                      shifter
                                      )
                               
                               )
                        )
        
    elif a.op in ['>>', 'a>>']:
        new_cf = ExprOp('&',
                        ExprInt(uint32(1)),
                        ExprOp(a.op,
                               source,
                               ExprOp('-',
                                      shifter,
                                      ExprInt(uint32(1))
                                      )
                               
                               )
                        )
    elif a.op == '>>>':
        c = ExprOp('>>>', source, shifter)
        new_cf = get_op_msb(c)

    if isinstance(shifter, ExprInt):
        e.append(ExprAff(cf, new_cf))
    else:
        e.append(ExprAff(cf, ExprCond(shifter,
                                      new_cf,
                                      cf))
                 )
    return e
    
        


def add(x, a, b):
    e = []
    c = ExprOp('+', a, b)
    e.append(ExprAff(x, c))    
    return e

def adds(x, a, b):
    e = []
    c = ExprOp('+', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_add(a, b, c)
    e.append(ExprAff(x, c))    
    return e

def sub(x, a, b):
    e = []
    c = ExprOp('-', a, b)
    e.append(ExprAff(x, c))    
    return e

def subs(x, a, b):
    e = []
    c = ExprOp('-', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_sub(a, b, c)
    e.append(ExprAff(x, c))    
    return e

def eor(x, a, b):
    e= []
    c = ExprOp('^', a, b)
    e.append(ExprAff(x, c))
    return e

def eors(x, a, b):
    e= []
    c = ExprOp('^', a, b)
    e+=update_flag_logic(c)
    e.append(ExprAff(x, c))
    return e

def l_and(x, a, b):
    e= []
    c = ExprOp('&', a, b)
    e.append(ExprAff(x, c))
    return e

def l_ands(x, a, b):
    e= []
    c = ExprOp('&', a, b)
    e+=update_flag_logic(c)
    e.append(ExprAff(x, c))
    return e

def rsb(x, a, b):
    return sub(x, b, a)

def rsbs(x, a, b):
    return subs(x, b, a)

def adc(x, a, b):
    e= []
    c = ExprOp('+', a, ExprOp('+', b, ExprCompose([ExprSliceTo(ExprInt(uint32(0)), 1, a.get_size()), ExprSliceTo(cf, 0, 1)])))
    e.append(ExprAff(x, c))
    return e

def adcs(x, a, b):
    e= []
    c = ExprOp('+', a, ExprOp('+', b, ExprCompose([ExprSliceTo(ExprInt(uint32(0)), 1, a.get_size()), ExprSliceTo(cf, 0, 1)])))
    e+=update_flag_arith(c)
    e+=update_flag_add(a, b, c)
    e.append(ExprAff(x, c))
    return e

def sbc(x, a, b):
    e= []
    c = ExprOp('-',
               ExprOp('+', a, ExprCompose([ExprSliceTo(ExprInt(uint32(0)), 1, a.get_size()), ExprSliceTo(cf, 0, 1)])),
               ExprOp('+', b, ExprInt(uint32(1)))
               )
    e.append(ExprAff(x, c))
    return e

def sbcs(x, a, b):
    e= []
    c = ExprOp('-',
               ExprOp('+', a, ExprCompose([ExprSliceTo(ExprInt(uint32(0)), 1, a.get_size()), ExprSliceTo(cf, 0, 1)])),
               ExprOp('+', b, ExprInt(uint32(1)))
               )
    e+=update_flag_arith(c)
    e+=update_flag_sub(a, b, c)
    e.append(ExprAff(x, c))
    return e

def rsc(x, a, b):
    return sbc(x, b, a)

def rscs(x, a, b):
    return sbcs(x, b, a)

def tst(a, b):
    e= []
    c = ExprOp('&', a, b)
    e+=update_flag_logic(c)
    return e

def teq(a, b):
    e= []
    c = ExprOp('^', a, b)
    e+=update_flag_logic(c)
    return e

def l_cmp(a, b):
    e= []
    c = ExprOp('-', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_sub(a, b, c)
    return e

def cmn(a, b):
    e= []
    c = ExprOp('+', a, b)
    e+=update_flag_arith(c)
    e+=update_flag_sub(a, b, c)
    return e

def orr(x, a, b):
    e= []
    c = ExprOp('|', a, b)
    e.append(ExprAff(x, c))
    return e

def orrs(x, a, b):
    e= []
    c = ExprOp('|', a, b)
    e+=update_flag_logic(c)
    e.append(ExprAff(x, c))
    return e

def mov(x, a):
    return [ExprAff(x, a)]

def bic(x, a, b):
    e= []
    c = ExprOp('&', a, ExprOp('^', b, ExprInt(uint32(0xFFFFFFFF))))
    e.append(ExprAff(x, c))
    return e

def bics(x, a, b):
    e= []
    c = ExprOp('&', a, ExprOp('^', b, ExprInt(uint32(0xFFFFFFFF))))
    e+=update_flag_logic(c)
    e.append(ExprAff(x, c))
    return e


def mla(x, a, b, c):
    e = []
    d = ExprOp('+',
               ExprOp('*', a, b),
               c)
    e.append(ExprAff(x, d))


def mlas(x, a, b, c):
    e = []
    d = ExprOp('+',
               ExprOp('*', a, b),
               c)
    e+=update_flag_zn(d)
    e.append(ExprAff(x, d))


def mul(x, a, b):
    e = []
    c = ExprOp('*', a, b)
    e.append(ExprAff(x, c))



def muls(x, a, b):
    e = []
    c = ExprOp('*', a, b)
    e+=update_flag_zn(c)
    e.append(ExprAff(x, c))


def branch(my_eip, a):
    e = []
    e.append(ExprAff(PC, a))
    return e



def branchl(my_eip, a):
    e = []
    l = ExprOp('+',
               my_eip,
               ExprInt(uint32(4)),
               )
    e.append(ExprAff(PC, a))
    e.append(ExprAff(LR, l))
    return e

mnemo_func = {'add': add,
              'adds': adds,
              'sub':sub,
              'subs':subs,
              'eor':eor,
              'eors':eors,
              'and':l_and,
              'ands':l_ands,
              'rsb':rsb,
              'rsbs':rsbs,
              'adc':adc,
              'adcs':adcs,
              'sbc':sbc,
              'sbcs':sbcs,
              'rsc':rsc,
              'rscs':rscs,
              'tst':tst,
              'tsts':tst,
              'teq':teq,
              'teqs':teq,
              'cmp':l_cmp,
              'cmps':l_cmp,
              'cmn':cmn,
              'cmns':cmn,
              'orr':orr,
              'orrs':orrs,
              'mov':mov,
              'movs':mov,
              'bic':bic,
              'bics':bics,
              'b':branch,
              'bl':branchl,
              }
              
              
              
shifts2op = {'LSL':'<<', 'LSR':'>>', 'ASR':'a>>', 'ROR':'>>>', '-':'-'}

def condition_expr(cond, exprs):
    if cond  == COND_AL:
        return exprs

    tab_cond = {COND_EQ:zf,
                COND_NE:ExprOp('==', zf, ExprInt(uint32(0))),
                COND_CS:cf,
                COND_CC:ExprOp('==', cf, ExprInt(uint32(0))),
                COND_MI:nf,
                COND_PL:ExprOp('==', nf, ExprInt(uint32(0))),
                COND_VS:of,
                COND_VC:ExprOp('==', of, ExprInt(uint32(0))),
                COND_HI:ExprOp('&', cf, ExprOp('==', zf, ExprInt(uint32(0)))),
                COND_LS:ExprOp('&', zf, ExprOp('==', cf, ExprInt(uint32(0)))),
                COND_GE:ExprOp('==', nf, of),
                COND_LT:ExprOp('^', nf, of),
                COND_GT:ExprOp('|',
                               ExprOp('&',
                                      ExprOp('==', zf, ExprInt(uint32(0))),
                                      ExprOp('|',nf, of)
                                      ),
                               ExprOp('&',
                                      ExprOp('==', nf, ExprInt(uint32(0))),
                                      ExprOp('==', of, ExprInt(uint32(0)))
                                      )
                               ),
                COND_LE:ExprOp('|',
                               zf,
                               ExprOp('^', nf, of)
                               ),
                }
    if not cond in tab_cond:
        raise 'unknown cond'
    cond = tab_cond[cond]
    out = []
    for e in exprs:
        src, dst = e.src, e.dst
        out.append(ExprAff(dst, ExprCond(cond, src, dst)))
    return out


def get_instr_expr_args(mn, args, my_eip):
    print args
    wback = False
    outa = []
    optmem = lambda x:x
    for a in args:
        l = len(a)
        if type(a) is str and a in str2regid:
            outa.append(str2regid[a])
            continue
        elif type(a) is str and is_imm(a):
            outa.append(ExprInt(uint32(str2imm(a))))
            continue
        elif type(a) is str and a == '!':
            wback = True
            continue
        elif not type(a) == list:
            print 'spot symb', a
            break
        if a[0] == '[' and a[-1] == ']':
            optmem = ExprMem
            a = a[1:-1]
            l-=2
            

        print a
        t = None
        a.reverse()
        u = a.pop()
        if not u in str2regid:
            raise ValueError('unknown1 arg', str(a))
        u1 = str2regid[u]
        if len(a) >1:
            u = a.pop()
            if not u in shifts2op:
                raise ValueError('unknown2 arg', str(a))
            t = shifts2op[u]

        if len(a)>0:
            u = a.pop()
            print u
            if is_imm(u):
                u2 = ExprInt(uint32(str2imm(u)))
            elif u in str2regid:
                u2 = str2regid[u]
            else:
                raise ValueError('unknown3 arg', str(a))
        if l==1:
            o = u1
        elif l == 2:
            o = ExprOp('+', u1, u2)
        elif l == 3:
            o = ExprOp(t, u1, u2)
        else:
            rezrezrezr
        o = optmem(o)
        outa.append(o)
    print args
    print [str(x) for x in outa]
    n = mn.name2str()

    exprs = []
    if isinstance(mn, arm_data):
        if n in ['mov', 'eor', 'and', 'tst', 'teq', 'cmp', 'orr', 'bic']:
            exprs += get_cf_shifter(outa[-1])
        n+=mn.scc2str()
    elif isinstance(mn, arm_br):
        d = mn.getdstflow()
        if len(d) !=1:
            raise ValueError("zarb dst", d)
        
        outa = [my_eip, ExprInt(uint32(d[0].offset))]
    else:
        print 'unimpl mnemo', str(n)
        return None

    
    print 'ARGS', [str(x) for x in outa]
    print n, args
    exprs += mnemo_func[n.lower()](*outa)

    exprs = condition_expr(mn.cond, exprs)
    print 'EXPR', [str(x) for x in exprs]
    return exprs
    
