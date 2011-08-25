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
from numpy import uint8, uint16, uint32, uint64, int8, int16, int32, int64
import shlex
import struct

from miasm.arch.ia32_reg import x86_afs
from miasm.core.bin_stream import bin_stream
import re

tab_int_size = {int8:8,
                uint8:8,
                int16:16,
                uint16:16,
                int32:32,
                uint32:32,
                int64:64,
                uint64:64
                }

def hex2bin(op):
    out = []
    for i in xrange(31, -1, -1):
        out.append(str((op>>i)&1))
    for i in xrange(32, -1,  -4):
        out[i:i] = ' '
    return "".join(out)

def myror(v, r):
    return ((v&0xFFFFFFFFL)>>r)  | ((v << (32-r))&0xFFFFFFFFL)
def myrol(v, r):
    return ((v&0xFFFFFFFFL)>>(32-r))  | ((v << r)&0xFFFFFFFFL)


def str2imm(i):
    if type(i) is list and len(i) == 1:
        i = i[0]
    if i.startswith('0x') or i.startswith('-0x'):
        d =16
    else:
        d = 10
    try:
        a = int(i, d)
    except:
        return False
    return a
    
def imm2str(i):
    if type(i) in [int, long]:
        if i<0:
            return "-0x%.x"%-i
        else:
            return "0x%.x"%i
    return str(i)

def is_imm(i):
    if type(i) is list and len(i) == 1:
        i = i[0]
    if type(i) is list:
        return False
    
    return type(str2imm(i)) is not bool



def split_args(args):
    t_enclosed = {'{':'}', '[':']', '(':')'}
    t_v = ','
    def get_until_t(args, lvl):
        o = []
        while args:
            x = args.pop(0)
            if x == lvl[-1]:
                if len(lvl) == 1:
                    break
                else:
                    lvl.pop()
                    if x != t_v:
                        o.append(x)
                    continue
            
            if x != t_v:
                o.append(x)
            if x in t_enclosed:
                lvl.append(t_enclosed[x])
                continue
            if x in t_enclosed.values():
                raise ValueError('unbalanced expr')
        if lvl and lvl != [',']:
            raise ValueError('unbalanced expr')
        return o
            
            
    o = []
    t = [x for x in shlex.shlex(args)]
    
    new_t = []
    i = 0
    while i < len(t):
        x = t[i]
        if i == len(t)-1:
            new_t.append(x)
        elif x == "-" and (re.match('\d+', t[i+1]) or re.match('0x[0-9a-fA-F]+', t[i+1])):
            new_t.append(x+t[i+1])
            i+=1
        else:
            new_t.append(x)
        i +=1

    t = new_t
    while t:
        a = get_until_t(t, [','])
        o.append(a)
    return o
        
            
    
    
class bm(object):
    class __metaclass__(type):
        def __new__(cls, name, bases, odct):
            if name is "bm":
                return type.__new__(cls, name, bases, odct)
            dct = {'fbits':None, 'l':None, "p_property":[], "checkinv" : False}
            dct.update(odct)

            pname = None
            if name.startswith('bm_'):
                pname = name[3:]
                dct["p_property"] = [pname]+dct["p_property"]
                

            
            b = bases[0]
            
            dct["check"] = b.check_no
            l = dct["l"]
            fbits = dct["fbits"]
            if fbits:
                l = len(fbits)
                allbits = list(fbits)
                allbits.reverse()
                fbits = 0
                fmask = 0
                while allbits:
                    a = allbits.pop()
                    if a in '01':
                        a = int(a)
                    fbits<<=1
                    fmask<<=1
                    fbits|=[0, a][type(a) is int]
                    fmask|=[0, 1][type(a) is int]
                dct["l"] = l
                dct["fbits"] = fbits
                #for bm int
                if pname:
                    dct[pname] = fbits
                dct['fmask'] = fmask
                if dct['checkinv']:
                    dct["check"] = b.check_fbits_inv
                else:
                    dct["check"] = b.check_fbits
                    
            p_property = dct["p_property"]
                
            for p in p_property:
                dct["get_"+p] = lambda self, p=p:getattr(self, p)
                dct["set_"+p] = lambda self, p=p:setattr(self, p)
            return type.__new__(cls, name, bases, dct)

    def __init__(self, parent, off, set_at = True):
        self.parent = parent
        self.off = off-self.l
    def __repr__(self):
        return "<W-"+str(self.__class__)+str(self.off+self.l-1)+" "+str(self.off)+">"
    def check_no(self, v):
        return True
    def check_fbits(self, v):
        return (v>>self.off) & self.fmask == self.fbits
    def check_fbits_inv(self, v):
        return (v>>self.off) & self.fmask != self.fbits

    def get_val(self, v):
        return (v>>self.off) & ((1<<self.l)-1)
    def set_val(self, v = None):
        
        if v == None and len(self.p_property) >= 1:
            p = self.p_property[0]
            v = getattr(self, p)
        return (v&((1<<self.l)-1))<<self.off 

    def bin(self):
        return self.set_val()
        
    def parse(self, v):
        if len(self.p_property) >= 1:
            p = self.p_property[0]
            val = self.get_val(v)
            setattr(self, p, val)
        return True
    def setprop(self, val = None):
        if len(self.p_property) >= 1:
            p = self.p_property[0]
            if not hasattr(self, p):
                setattr(self, p, None)


COND_EQ = 0
COND_NE = 1
COND_CS = 2
COND_CC = 3
COND_MI = 4
COND_PL = 5
COND_VS = 6
COND_VC = 7
COND_HI = 8
COND_LS = 9
COND_GE = 10
COND_LT = 11
COND_GT = 12
COND_LE = 13
COND_AL = 14
COND_NV = 15

class bm_cond(bm):
    l = 4
    p_property = ["cond2str", 'str2cond']
    n = ['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC', 'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'AL', 'NV']

    def cond2str(self):
        return self.n[self.cond]

    def str2cond(self, cond):
        if not cond in self.n:
            raise ValueError('unknown cond')
        self.cond = self.n.index(cond)    
    

class bm_int0(bm):
    fbits = '0'

class bm_int1(bm):
    fbits = '1'

class bm_int00(bm):
    fbits = '00'

class bm_int01(bm):
    fbits = '01'

class bm_int000(bm):
    fbits = '000'

class bm_int011(bm):
    fbits = '011'
class bm_int0111(bm):
    fbits = '0111'


class bm_int01101(bm):
    fbits = '01101'
class bm_int100(bm):
    fbits = '100'

class bm_int101(bm):
    fbits = '101'

class bm_int110(bm):
    fbits = '110'

class bm_int0000(bm):
    fbits = '0000'

class bm_int1001(bm):
    fbits = '1001'

class bm_int1110(bm):
    fbits = '1110'

class bm_int1111(bm):
    fbits = '1111'

class bm_int00001(bm):
    fbits = '00001'

class bm_int00010(bm):
    fbits = '00010'

class bm_int000000(bm):
    fbits = '000000'

class bm_accum(bm):
    l = 1
    n = ['MUL', 'MLA']
    def name2str(self):
        return self.n[self.accum]

    def str2name(self, name):
        if not name in self.n:
            raise ValueError('unknown name')
        self.accum = self.n.index(name)

class bm_immop(bm):
    l = 1

class bm_opc(bm):
    l = 4

class bm_opsz(bm):
    l = 1

class bm_szext(bm):
    l = 2

class bm_rot(bm):
    l = 2

class bm_scc(bm):
    l = 1
    p_property = ["scc2str"]
    def scc2str(self):
        return ['', 'S'][self.scc==1]

class bm_lnk(bm):
    l = 1
    p_property = ["lnk2str"]
    def lnk2str(self):
        return ['', 'L'][self.lnk==1]

class bm_offs(bm):
    l = 24

    def parse(self, v):
        val = self.get_val(v)
        val<<=2
        if val & (1<<25):
            val |=0xFC000000
        self.offs = val
        return True
    def bin(self):
        if not type(self.offs) in [int, long]:
            v = 0
        else:
            v = (self.offs>>2)&0xffffff
        return self.set_val(v)

class bm_cooff(bm):
    l = 8

    def parse(self, v):
        val = self.get_val(v)
        val<<=2
        self.cooff = val
        return True
    def bin(self):
        v = (self.cooff>>2)&0xff
        return self.set_val(v)

class bm_size(bm):
    l = 1
    p_property = ["size2str"]
    def size2str(self):
        return ['', 'B'][self.size==1]

class bm_tlen(bm):
    l = 1

class bm_ppndx(bm):
    l = 1

class bm_updown(bm):
    l = 1

class bm_psr(bm):
    l = 1

class bm_wback(bm):
    l = 1

class bm_ldst(bm):
    l = 1

class bm_reglist(bm):
    l = 16

    def parse(self, v):
        val = self.get_val(v)
        self.reglist = []
        for i in xrange(0x10):
            if val & (1<<i):
                self.reglist.append(i)
        return True
    def bin(self):
        v = 0
        for r in self.reglist:
            v|=(1<<r)
        return self.set_val(v)
            
class bm_rn(bm):
    l = 4

class bm_rd(bm):
    l = 4

class bm_rdh(bm):
    l = 4

class bm_rdl(bm):
    l = 4

class bm_rs(bm):
    l = 4

class bm_rm(bm):
    l = 4

class bm_crd(bm):
    l = 4

class bm_crn(bm):
    l = 4

class bm_crm(bm):
    l = 4

class bm_cpnum(bm):
    l = 4

class bm_cpopc(bm):
    l = 4

class bm_opmode(bm):
    l = 3

class bm_info(bm):
    l = 3

class bm_swint(bm):
    l = 24

class bm_op2(bm):
    l = 12
    p_property = ["rm", "rot", "imm", "rs", 'shiftt', 'sub_shift_type', 'amount']

    def parse(self, v):
        val = self.get_val(v)
        self.op2 = val

        if self.parent.immop:
            self.rot = val>>8
            self.imm = val&0xff
        else:
            self.rm = val&0xf
            self.shift = val>>4
            self.sub_shift_type = self.shift&1
            self.shift>>=1
            self.shiftt = self.shift&0x3
            self.shift>>=2
            
            if self.sub_shift_type:
                #sub shift type is reg
                if self.shift&1:
                    return False
                self.rs = self.shift>>1
                if self.rs==0:
                    return False
            else:
                #sub shift type is imm
                self.amount = self.shift
                
        return True

    def bin(self):
        if self.parent.immop:
            val = self.rot<<8
            val+=self.imm&0xff
        else:
            shift = self.sub_shift_type
            shift |= self.shiftt<<1
            if self.sub_shift_type:
                shift|=self.rs<<4
            else:
                shift|=self.amount<<3
            val = (shift<<4) | (self.rm&0xf)
            
        self.op2 = val
        return self.set_val()

class bm_opoff(bm):
    l = 12
    p_property = ["rm", "imm", 'shiftt', 'amount']

    def parse(self, v):
        val = self.get_val(v)
        self.opoff = val
        
        if self.parent.immop:
            self.shift = val>>4
            self.rm = val&0xf
            if self.shift&1:
                #no reg shift
                return False
            
            self.shift>>=1
            self.shiftt = self.shift&0x3
            self.amount = self.shift>>2
        else:
            self.imm = val&0xfff
            
        return True

    def bin(self):
        if self.parent.immop:
            shift = 0
            shift |= self.shiftt<<1
            shift|=self.amount<<3
            val = (shift<<4) | (self.rm&0xf)
        else:
            val = self.imm&0xfff
            
        self.opoff = val
        return self.set_val()

class bm_undef1(bm):
    l = 20

class bm_undef2(bm):
    l = 4

class bmi_int1XX1(bm):
    fbits = '0XXXXXXXXXXXXXXXXX1XX1'
    checkinv = True

class bmi_int1111(bm):
    fbits = '1111'
    checkinv = True

class bmi_intX00X(bm):
    fbits = '1XXXXXXXXXXXXXXXX1001'
    checkinv = True

class bmi_int11110XX1(bm):
    fbits = 'X0XXXXXXXXXXXXX11110XX1'
    checkinv = True

class bm_int000100101111111111110001(bm):
    fbits = '000100101111111111110001'

class bm_int0001001011111111111100(bm):
    fbits = '0001001011111111111100'
    
class bmi_int1XXXX1(bm):
    fbits = '1XXXXXXXXXXXXXXXXXXXX1'
    checkinv = True

class bm_sh(bm):
    l = 2

class bm_hdoff1(bm):
    l = 4

class bm_hdoff2(bm):
    l = 4

class bm_sign(bm):
    l = 1


class arm_mnemo_metaclass(type):
    rebuilt_inst = False

    def __call__(cls, op, offset = 0):
        if type(op) in [int, long]:
            cls = cls.class_from_op(op)
            i = cls.__new__(cls)
            i.__init__(op, offset)
        elif type(op) is str:
            cls = cls.asm(op)
            i = cls.__new__(cls)
            i.__init__(op, 0, False)
        else:
            raise ValueError('zarb arg')
        return i
        
    def class_from_op(cls, op):
        #print "dis", hex(op), hex2bin(op)
        tab_mn = [arm_data, arm_mul, arm_mull, arm_swp, arm_brxchg, arm_hdtreg, arm_hdtimm, arm_sdt, arm_bdt, arm_br, arm_codt, arm_cort, arm_codo, arm_swi, arm_szext]#, arm_undef]
        ret = filter(lambda x:x.check(op), tab_mn)
        if len(ret)==1:
            return ret[0]
        raise ValueError('ambiquity %s'%str(ret))


    def dis(cls, bin, amode = None, sex = None):
        if type(bin) == str:
            bin = bin_stream(bin)
        elif not isinstance(bin, bin_stream):
            raise ValueError('unknown input')

        op = bin.readbs(4)
        op = struct.unpack('<L', op)[0]
        return cls(op, bin.offset-4)
        
    def asm_instr(cls, txt):
        tab_mn = [arm_data, arm_mul, arm_mull, arm_swp, arm_brxchg, arm_hdtreg, arm_hdtimm, arm_sdt, arm_bdt, arm_br, arm_codt, arm_cort, arm_codo, arm_swi, arm_szext]#, arm_undef]

        t = [x for x in shlex.shlex(txt)]
        t.reverse()
        name = t.pop()
        ret = filter(lambda x:x.check_mnemo(name), tab_mn)
        if len(ret)!=1:
            raise ValueError('parse name err %s'%str(ret))
        cls = ret[0]
        i = cls.__new__(cls)
        i.__init__(txt, 0, False)
        return i

    def asm(cls, txt, symbol_reloc_off = {}):
        i = cls.asm_instr(txt)
        return [struct.pack('<L', i.bin())]
        
    def __new__(cls, name, bases, dct):
        ret_c = type.__new__(cls, name, bases, dct)
        if name is "arm_mn":
            return ret_c

        mask = []
        if 'mask' in dct:
            for off in dct['mask']:
                mc = dct['mask'][off](None, off+1)
                mask.append(mc)
            
        mask_orig = [bm_cond]+dct["mask_list"]
        ret_c.mask_orig = mask_orig
        off = 32
        for m in mask_orig:
            mc = m(None, off)
            off-=mc.l
            mask.append(mc)
            for pname in m.p_property:
                '''
                p = property(lambda self=ret_c, pname=pname:getattr(getattr(self, "bm_"+pname), pname),
                             lambda self=ret_c, val=None,pname=pname:setattr(getattr(self, "bm_"+pname), pname, val))
                '''
                p = property(lambda self, pname=pname:getattr(getattr(self, "bm_"+pname), pname),
                             lambda self, val=None,pname=pname:setattr(getattr(self, "bm_"+pname), pname, val))
                
                setattr(ret_c, pname, p)
                
        if off!=0:
            raise ValueError('invalid mnemonic %d'%off)
        ret_c.mask_chk = mask
        
        return ret_c
    
    def check(self, op):
        for m in self.mask_chk:
            if m.off<20 and m.fbits==None:
                continue
            if not m.check(op):
                return False
        return True

    def check_opts(self, rest):
        if rest:
            return False
        return True

    def check_mnemo(self, mnemo):
        found = False
        for n in self.namestr:
            if mnemo.startswith(n):
                found = True
                break
        if not found:
            return False
        
        rest = mnemo[len(n):]
        for c in bm_cond.n:
            if rest.startswith(c):
                rest = rest[len(c):]
                break
        return self.check_opts(rest)
        
    def pre_parse_mnemo(self, args):
        mn = [x for x in shlex.shlex(args)][0]
        t = split_args(args[args.index(mn)+len(mn):])
        t = [mn]+t
        t.reverse()
        return t

    def parse_mnemo(cls, args):
        t = cls.pre_parse_mnemo(args)
        mn = t.pop()
        t.reverse()
        

        return [], mn, t


    def parse_address(self, a):
        o = {}
        if len(a) != 1:
            return a
        if a[0] in regs_str+cop_str+copr_str:
            return a
        return {x86_afs.symb:{a[0]:1}}

    def prefix2hex(self, prefix):
        return ""

    def has_symb(cls, a):
        if type(a) in [int, long]+tab_int_size.keys():
            return False
        if x86_afs.symb in a:
            return True
        return False
    def get_symbols(cls, a):
        if x86_afs.symb in a:
            return a[x86_afs.symb].items()
        return []
    def names2symbols(cls, a, s_dict):
        all_s = a[x86_afs.symb]
        for name, s in s_dict.items():
            count = all_s[name]
            del(all_s[name])
            all_s[s] = count
    def fix_symbol(cls, a, symbol_pool = None):
        pass
    def is_mem(cls, a):
        pass

    def get_label(cls, a):
        if x86_afs.ad in a and a[x86_afs.ad]:
            return None
        if x86_afs.imm in a:
            return None
        if not x86_afs.symb in a:
            return None
        n = a[x86_afs.symb]
        if len(n)!=1:
            return None
        k = n.keys()[0]
        if n[k] != 1:
            return None
        return k
    
regs_str = ['R%d'%r for r in xrange(0x10)]
regs_str[13] = 'SP'
regs_str[14] = 'LR'
regs_str[15] = 'PC'

cop_str = ['P%d'%r for r in xrange(0x10)]
copr_str = ['C%d'%r for r in xrange(0x10)]

def reg2str(r):
    return regs_str[r]
def str2reg(r):
    if type(r) is list and len(r) == 1:
        r = r[0]
    return regs_str.index(r)

def cop2str(r):
    return cop_str[r]
def str2cop(r):
    if type(r) is list and len(r) == 1:
        r = r[0]    
    return cop_str.index(r)

def copr2str(r):
    return copr_str[r]
def str2copr(r):
    if type(r) is list and len(r) == 1:
        r = r[0]    
    return copr_str.index(r)

def reglist2str(rlist):
        out = []
        i = 0
        while i < len(rlist):
            j = i+1
            while j < len(rlist) and rlist[j] <13 and rlist[j]  == rlist[j-1]+1:
                j+=1
            j-=1
            if j < i+2:
                out.append(reg2str(rlist[i]))
                i+=1
            else:
                out.append(reg2str(rlist[i])+'-'+reg2str(rlist[j]))
                i = j+1

        return "{"+", ".join(out)+'}'


def str2reglist(rlist):
    r_start = None
    out = []
    rlist.pop()
    while rlist:
        tmp = rlist.pop()
        if tmp =='-':
            r_end = str2reg(rlist.pop())
            for i in xrange(r_start, r_end+1):
                out.append(i)
            r_start = None
        elif tmp == '}':
            if r_start!=None:
                out.append(r_start)
            break
        elif r_start==None:
            r_start = str2reg(tmp)
        else:
            out.append(r_start)
            r_start = str2reg(tmp)
    return out
            
def args2reduce(args):
    out = []
    for a in args:
        if type(a) is list:
            out+=args2reduce(a)
        else:
            out.append(a)
    return out

def arglist2str(args):
    out = ""
    for a in args:
        if a in ['[', ']', 'LSL', 'LSR', 'ASR', 'ROR']:
            out+=a+' '
        else:
            out+=str(a)
            out+=', '
    if out.endswith(', '):
        out = out[:-2]
    return out


def args2str(args):
    return arglist2str(args2reduce(args))
            
       
class arm_mn(object):
    mask_list = []
    __metaclass__ = arm_mnemo_metaclass
    def __init__(self, op, offset = 0, dis = True):
        
        off=32
        mask = []
        self.offset = offset
        self.l = 4
        self.m = None
        self.arg = []



        for m in self.mask_orig:
            mc = m(self, off)
            off-=mc.l
            for pname in m.p_property:
                setattr(self, "bm_"+pname, mc)
            mask.append(mc)
        self.mask = mask
        
        if dis:
            for m in self.mask:
                ret = m.parse(op)
                if not ret:
                    raise ValueError('cannot parse %.8X'%op)
        else:
            for m in self.mask:
                ret = m.setprop()
            
            full_mnemo = arm_mn.pre_parse_mnemo(op)
            mnemo = full_mnemo.pop()
            name, cond, rest = self.parse_name_cond(mnemo)
            self.name = name
            self.cond = cond
            self.parse_opts(rest)
            self.str2name(name)

            self.parse_args(full_mnemo)

    def parse_opts(self, rest):
        pass
    def str2name(self, n):
        pass
    
    def getname(self):
        name = self.name2str()
        cond = self.cond2str()
        scc = ""
        if cond =="AL":cond = "" #XXX smart display
        
        return name+cond+scc

    def bin(self):
        v = 0
        for m in self.mask:
            if not m.checkinv:
                v|=m.bin()
        return v

    def parse_name_cond(self, mnemo):
        name, cond = None, None
        for i, n in enumerate(self.namestr):
            if mnemo.startswith(n):
                name = n
                break
        if name == None:
            raise ValueError('cannot parse name')

        rest = mnemo[len(n):]
        for i, c in enumerate(bm_cond.n):
            if rest.startswith(c):
                cond = i
                break
            
        if cond == None:
            cond = COND_AL         #default cond is AL
        else:
            rest = rest[len(c):]
        return name, cond, rest
    def breakflow(self):
        return False
    def splitflow(self):
        return False
    def dstflow(self):
        return False

    def getnextflow(self):
        return self.offset+self.l


MN_AND = 0
MN_EOR = 1
MN_SUB = 2
MN_RSB = 3
MN_ADD = 4
MN_ADC = 5
MN_SBC = 6
MN_RSC = 7
MN_TST = 8
MN_TEQ = 9
MN_CMP = 10
MN_CMN = 11
MN_ORR = 12
MN_MOV = 13
MN_BIC = 14
MN_MVN = 15


class arm_data(arm_mn):
    mask_list = [bm_int00, bm_immop, bm_opc, bm_scc, bm_rn, bm_rd, bm_op2]
    mask = {25:bmi_int1XX1, 26:bmi_int11110XX1}

    namestr = ['AND', 'EOR', 'SUB', 'RSB', 'ADD', 'ADC', 'SBC', 'RSC', 'TST', 'TEQ', 'CMP', 'CMN', 'ORR', 'MOV', 'BIC', 'MVN']
    allshifts = ['LSL', 'LSR', 'ASR', 'ROR']

    def name2str(self):
        return self.namestr[self.opc]
    def str2name(self, n):
        self.opc = self.namestr.index(n)

    @classmethod
    def check_opts(cls, rest):
        if rest in ['', 'S']:
            return True
        return False

    def args2str(self):
        args = []
        if self.opc in [MN_MOV, MN_MVN]:
            args.append(reg2str(self.rd))
        elif self.opc in [MN_CMP, MN_CMN, MN_TEQ, MN_TST]:
            args.append(reg2str(self.rn))
        else:
            args.append(reg2str(self.rd))
            args.append(reg2str(self.rn))
            
        if self.immop:
            #arg is pure imm
            imm = myror(self.imm, self.rot*2)
            args.append(imm2str(imm))
        else:
            a = reg2str(self.rm)
            if self.sub_shift_type:
                #shift with another reg
                a = [a, self.allshifts[self.shiftt], reg2str(self.rs)]
            elif self.amount: #if no amount, no display needed
                a = [a, self.allshifts[self.shiftt], imm2str(self.amount)]
            args.append(a)
        return args
    
    def __str__(self):
        name = self.getname()
        name+=self.scc2str()
        args = self.args2str()
        args = args2str(args)
        return name+" "+args

    def parse_opts(self, opts):
        self.scc = 0
        if not opts:
            return
        if opts[0] == "S":
            self.scc = 1

    def parse_args(self, args):
        if self.opc in [MN_MOV, MN_MVN]:
            self.rd = str2reg(args.pop())
            self.rn = 0 #default reg value
        elif self.opc in [MN_CMP, MN_CMN, MN_TEQ, MN_TST]:
            self.rn = str2reg(args.pop())
            self.rd = 0 #default reg value
        else:
            self.rd = str2reg(args.pop())
            self.rn = str2reg(args.pop())
        self.immop = [0,1][len(args) == 1 and is_imm(args[0])]
        self.sub_shift_type = 0
        if self.immop:
            #pure imm

            i = 0
            im = str2imm(args.pop())
            #find rol
            while myrol(im, 2*i) > 0xFF:
                i+=1
                if i > 16:
                    raise ValueError('cannot encod imm for shift!')
            self.rot = i
            self.imm = myrol(im, 2*i)
            return

        self.rm = str2reg(args.pop())

        #reg shift
        self.shiftt=0
        self.amount = 0

        if not args:
            return

        if len(args) != 1:
            raise ValueError('zarb arg1', args)
        args = args.pop()

        #reg shift shift
        if is_imm(args[-1]):
            #shift reg shift num
            self.sub_shift_type = 0
            self.amount = str2imm(args.pop())
        else:
            #shift reg shift reg
            self.sub_shift_type = 1
            self.rs = str2reg(args.pop())

        self.shiftt = self.allshifts.index(args.pop())
        if args:
            raise ValueError('zarb arg2', args)
            

            

class arm_mul(arm_mn):
    mask_list = [bm_int000000, bm_accum, bm_scc, bm_rd, bm_rn, bm_rs, bm_int1001, bm_rm]
    #cannot have pc in reg
    namestr = ['MUL', 'MLA']
    def name2str(self):
        return self.namestr[self.accum]
    def str2name(self, n):
        self.accum = self.namestr.index(n)

    @classmethod
    def check_opts(cls, rest):
        if rest in ['', 'S']:
            return True
        return False

    def args2str(self):
        args = []
        args.append(reg2str(self.rd))
        args.append(reg2str(self.rm))
        args.append(reg2str(self.rs))
        if self.accum:
            args.append(reg2str(self.rn))
        return args
    
    def __str__(self):
        name = self.getname()
        name+=self.scc2str()
        args = self.args2str()
        args = args2str(args)
        return name+" "+args

    def parse_opts(self, opts):
        self.scc = 0
        if not opts:
            return
        if opts[0] == "S":
            self.scc = 1

    def parse_args(self, args):
        self.rd = str2reg(args.pop())
        self.rm = str2reg(args.pop())
        self.rs = str2reg(args.pop())
        if self.accum:
            self.rn = str2reg(args.pop())
        else:
            self.rn = 0 #default reg value
        

class arm_mull(arm_mn):
    mask_list = [bm_int00001, bm_sign, bm_accum, bm_scc, bm_rdh, bm_rdl, bm_rs, bm_int1001, bm_rm]
    #cannot habe pc as reg
    namestr = ['UMULL', 'UMLAL', 'SMULL', 'SMLAL']
    def name2str(self):
        return self.namestr[self.sign*2+self.accum]
    def str2name(self, n):
        tmp = self.namestr.index(n)
        self.accum = tmp&1
        self.sign = tmp>>1

    @classmethod
    def check_opts(cls, rest):
        if rest in ['', 'S']:
            return True
        return False

    def args2str(self):
        args = []
        args.append(reg2str(self.rdh))
        args.append(reg2str(self.rdl))
        args.append(reg2str(self.rm))
        args.append(reg2str(self.rs))
        return args
    
    def __str__(self):
        name = self.getname()
        name+= self.scc2str()
        args = self.args2str()
        args = args2str(args)
        return name+" "+args

    def parse_opts(self, opts):
        self.scc = 0
        if not opts:
            return
        if opts[0] == "S":
            self.scc = 1

    def parse_args(self, args):
        self.rdh = str2reg(args.pop())
        self.rdl = str2reg(args.pop())
        self.rm = str2reg(args.pop())
        self.rs = str2reg(args.pop())
        

class arm_swp(arm_mn):
    mask_list = [bm_int00010, bm_size, bm_int00, bm_rn, bm_rd, bm_int0000, bm_int1001, bm_rm]
    mask = {19:bmi_int1111, 15:bmi_int1111, 3:bmi_int1111}
    #cannot have PC as reg
    namestr = ["SWP"]
    def name2str(self):
        return self.namestr[0]
    
    @classmethod
    def check_opts(cls, rest):
        if not rest or rest == 'B':
            return True
        return False

    def args2str(self):
        args = []
        args.append(reg2str(self.rd))
        args.append(reg2str(self.rm))
        args.append(['[', reg2str(self.rn), ']'])
        return args
    
    def __str__(self):
        name = self.getname()
        name+=self.size2str()
        args = self.args2str()
        args = args2str(args)
        return name+' '+args

    def parse_opts(self, opts):
        self.size = 0
        if not opts:
            return
        if opts[0] == "B":
            self.size = 1

    def parse_args(self, args):
        self.rd = str2reg(args.pop())
        self.rm = str2reg(args.pop())
        p1 = args.pop()
        self.rn = str2reg(args.pop())
        p2 = args.pop()
        if p1== '[' and p2 ==']':
            return
        raise ValueError('cannot parse %s %s'%(str(p1), str(p2)))

class arm_brxchg(arm_mn):
    mask_list = [bm_int0001001011111111111100, bm_lnk, bm_int1, bm_rn]

    namestr = ["BX", "BXL"]
    def name2str(self):
        return self.namestr[self.lnk]
    def str2name(self, n):
        self.lnk = self.namestr.index(n)

    def parse_name_cond(self, mnemo):
        name, cond = None, None
        if not mnemo.startswith('BX'):
            raise  ValueError('zarb mnemo %s'%str(mnemo))
        l = len(mnemo)
        if l in [2,4]:
            n = mnemo[:2]
        elif l in [3,4]:
            n = mnemo[:3]
        else:
            raise ValueError('zarb mnemo %s'%str(mnemo))
        name = n
        rest = mnemo[len(n):]
        for i, c in enumerate(bm_cond.n):
            if rest.startswith(c):
                cond = i
                break
        if cond == None:
            cond = COND_AL         #default cond is AL
        else:
            rest = rest[len(c):]
        return name, cond, rest

    @classmethod
    def check_mnemo(self, mnemo):
        if mnemo in self.namestr:
            return True
        return False


    def args2str(self):
        args = []
        args.append(reg2str(self.rn))
        return args

    def __str__(self):
        name = self.getname()
        args = self.args2str()
        args = args2str(args)
        return name+' '+args
    
    def parse_args(self, args):
        self.rn = str2reg(args.pop())

    def breakflow(self):
        return True
    def splitflow(self):
        return self.cond != COND_AL
    def dstflow(self):
        return True
    def getdstflow(self):
        return []
    def setdstflow(self, dst):
        return []
    def is_subcall(self):
        return self.lnk

class arm_hdtreg(arm_mn):
    mask_list = [bm_int000, bm_ppndx, bm_updown, bm_int0, bm_wback, bm_ldst, bm_rn, bm_rd, bm_int00001, bm_sh, bm_int1, bm_rm]
    #and XXX str cant be SB nor SH
    mask = {24:bmi_intX00X}
    
    typestr = ["XXX", "H", "SB", "SH"]
    namestr = ['STR', 'LDR']
    def name2str(self):
        return self.namestr[self.ldst]
    def str2name(self, n):
        self.ldst = self.namestr.index(n)

    @classmethod
    def check_opts(cls, rest):
        found = False
        for t in cls.typestr:
            if rest.startswith(t):
                found = True
                rest = rest[len(t):]
        if not found:
            return False
        #XXX check diff with hdreg TODO
        return True

    def args2str(self):
        args = []
        args.append(reg2str(self.rd))
        o = []
        o.append('[')
        o.append(reg2str(self.rn))
        if not self.ppndx:
            o.append(']')
        if not self.updown:
            o.append("-")
        o.append(reg2str(self.rm))
        if self.ppndx:
            o.append(']')
        
        args.append(o)
        return args
        
    def __str__(self):
        name = self.getname()
        #XXX XXX swp?? 
        name += self.typestr[self.sh]
        args = self.args2str()
        args = args2str(args)
        wb = ['', '!'][self.wback==1]
        return name+' '+args+wb

    def breakflow(self):
        if self.ldst == 0 or self.rd!=15:
            return False
        #XXX pc pp incremented
        return True
    def splitflow(self):
        if self.ldst == 0 or self.rd!=15:
            return False
        #XXX pc pp incremented
        return self.cond != COND_AL
    def dstflow(self):
        return True


class arm_hdtimm(arm_mn):
    mask_list = [bm_int000, bm_ppndx, bm_updown, bm_int1, bm_wback, bm_ldst, bm_rn, bm_rd, bm_hdoff1, bm_int1, bm_sh, bm_int1, bm_hdoff2]
    #and XXX str cant be SB nor SH
    mask = {24:bmi_intX00X}

    typestr = ["XXX", "H", "SB", "SH"]
    namestr = ['STR', 'LDR']
    def name2str(self):
        return self.namestr[self.ldst]
    def str2name(self, n):
        self.ldst = self.namestr.index(n)

    @classmethod
    def check_opts(cls, rest):
        found = False        
        for t in cls.typestr:
            if rest.startswith(t):
                found = True
                rest = rest[len(t):]
        if not found:
            return False
        #XXX check diff with hdreg TODO
        return True

    def args2str(self):
        args = []
        args.append(reg2str(self.rd))
        o = []
        o.append('[')
        o.append(reg2str(self.rn))
        if not self.ppndx:
            o.append(']')
        imm = [-1, 1][self.updown==1]*((self.hdoff1<<4)+self.hdoff2)
        o.append(imm2str(imm))
        if self.ppndx:
            o.append(']')
        
        args.append(o)
        return args

        
    def __str__(self):
        name = self.getname()
        #XXX XXX swp?? 
        name += self.typestr[self.sh]
        args = self.args2str()
        args = args2str(args)
        wb = ['', '!'][self.wback==1]

        return name+' '+args+wb


    def breakflow(self):
        if self.ldst == 0 or self.rd!=15:
            return False
        #XXX pc pp incremented
        return True
    def splitflow(self):
        if self.ldst == 0 or self.rd!=15:
            return False
        #XXX pc pp incremented
        return self.cond != COND_AL
    def dstflow(self):
        return True


class arm_sdt(arm_mn):
    mask_list = [bm_int01, bm_immop, bm_ppndx, bm_updown, bm_size, bm_wback, bm_ldst, bm_rn, bm_rd, bm_opoff]
    #cannot shift amount with immop
    mask = {25:bmi_int1XXXX1}
    
    namestr = ['STR', 'LDR']
    def name2str(self):
        return self.namestr[self.ldst]
    def str2name(self, n):
        self.ldst = self.namestr.index(n)

    allshifts = ['LSL', 'LSR', 'ASR', 'ROR']

    @classmethod
    def check_opts(cls, rest):
        if not rest:
            return True
        if rest[0] == "B":
            rest = rest[1:]
        if not rest:
            return True
        if rest[0] == "T":
            rest = rest[1:]
        if rest:
            return False
        return True

    def args2str(self):
        args = []
        args.append(reg2str(self.rd))
        o = []
        o.append('[')
        o.append(reg2str(self.rn))
        if not self.ppndx:
            o.append(']')

        if self.immop:
            if not self.updown:
                o.append("-")
            o.append([reg2str(self.rm), self.allshifts[self.shiftt], imm2str(self.amount)])
        else:
            imm = [-1, 1][self.updown==1]*self.imm
            o.append(imm2str(imm))
        if self.ppndx:
            o.append(']')
        args.append(o)
        return args
        
    
    def __str__(self):
        name = self.getname()
        name+=self.size2str()
        #XXX TODO T bit??? name+=['', 'T'][self.wback==1]
        wb = ['', '!'][self.wback==1]
        args = self.args2str()
        args = args2str(args)
        return name+' '+args+wb

    def parse_opts(self, opts):
        self.wback = 0
        self.size = 0
        if not opts:
            return
        if opts[0] == "B":
            self.size = 1

    def parse_args(self, args):
        self.rd = str2reg(args.pop())

        if len(args)!=1:
            raise ValueError("zarb arg3", args)
        args = args.pop()
        args = args[::-1]
        p1 = args.pop()
        self.rn = str2reg(args.pop())

        param = []
        if args[-1] == ']':
            self.ppndx = 0
            param = args[:-1]
            args = []
        else:
            self.ppndx = 1
            param = args[args.index(']')+1:]
            args = args[:args.index(']')]

        self.updown = 1
        tmp = param.pop()
        if tmp =='-':
            self.updown = 0
            tmp = param.pop()

        if is_imm(tmp):
            self.immop = 0
            self.imm = str2imm(tmp)
        else:
            self.immop = 1
            self.rm = str2reg(tmp)
            self.shiftt = self.allshifts.index(param.pop())
            tmp = param.pop()
            if not is_imm(tmp):
                raise ValueError('amount must be int')
            self.amount = str2imm(tmp)

        if args:
            tmp = args.pop()
            if tmp!= '!':
                raise "arg zarb %s"%str(tmp)
            self.wback = 1
        if args:
            raise ValueError('rest args...'%str(param))


    def breakflow(self):
        if self.ldst == 0 or self.rd!=15:
            return False
        #XXX pc pp incremented
        return True
    def splitflow(self):
        if self.ldst == 0 or self.rd!=15:
            return False
        #XXX pc pp incremented
        return self.cond != COND_AL
    def dstflow(self):
        return False
    def getdstflow(self):
        return []
    def setdstflow(self, dst):
        if len(dst)==0:
            return
        if len(dst)!=1:
            raise ValueError('should be 1 dst')
    def is_subcall(self):
        return False

class arm_undef(arm_mn):
    mask_list = [bm_int011, bm_undef1, bm_int1, bm_undef2]

    namestr = ["UNDEF"]
    def name2str(self):
        return self.namestr[0]

    def args2str(self):
        args = []
        args.append(imm2str(self.undef1))
        args.append(imm2str(self.undef2))
        return args
    
    def __str__(self):
        name = self.getname()
        args = self.args2str()
        args = args2str(args)
        
        return name+' '+args
    
    def parse_args(self, args):
        self.undef1 = str2imm(args.pop())
        self.undef2 = str2imm(args.pop())

class arm_bdt(arm_mn):
    mask_list = [bm_int100, bm_ppndx, bm_updown, bm_psr, bm_wback, bm_ldst, bm_rn, bm_reglist]
    
    ad_mode_nostack = ['DA', 'DB', 'IA', 'IB']
    ad_mode_stack = ['FA', 'EA', 'FD',  'ED']

    namestr = ['STM', 'LDM']
    def name2str(self):
        return self.namestr[self.ldst]
    def str2name(self, n):
        self.ldst = self.namestr.index(n)

    @classmethod
    def check_opts(cls, rest):
        for m in cls.ad_mode_stack+cls.ad_mode_nostack:
            if rest.startswith(m):
                rest = rest[len(m):]
                break
        if rest:
            return False
        return True

    def args2str(self):
        args = []
        args.append(reg2str(self.rn))
        if self.wback:
            args.append('!')
        args+=[reg2str(r) for r in self.reglist]
        if self.psr:
            args.append('^')
        return args

    def __str__(self):
        name = self.getname()
        tmp = (self.ppndx<<1)+self.updown
        if self.ldst!=0:
            tmp = 3-tmp
        if self.rn == 13:
            ad_mode = self.ad_mode_stack[tmp]
        else:
            ad_mode = self.ad_mode_nostack[tmp]

        name+=ad_mode
        args = []
        wb = ['', '!'][self.wback]
        psr = ['', '^'][self.psr]
        args.append(reg2str(self.rn)+wb)
        args.append(reglist2str(self.reglist))
        return name+" "+", ".join(args)+psr

    def parse_opts(self, opts):
        if opts in self.ad_mode_stack:
            self.stackattr = True
            self.bits = self.ad_mode_stack.index(opts)
        elif opts in self.ad_mode_nostack:
            self.stackattr = False
            self.bits = self.ad_mode_nostack.index(opts)
        else:
            raise ValueError('opt zarb %s'%str(opts))


    def parse_args(self, args):
        self.wback = 0
        a = args.pop()
        if len(a) >1:
            w = a.pop()
            if w == "!":
                self.wback = 1
            else:
                raise ValueError('zarb arg 4', (args, a, w))
        
            
        self.rn = str2reg(a.pop())
        if self.stackattr != (self.rn==13):
            raise ValueError('unmatch stack/nostack')

        if self.ldst!=0:
            self.bits = 3-self.bits

        self.updown = self.bits & 1
        self.ppndx = self.bits >> 1

        if len(args) !=1:
            raise ValueError('zarb arg 4', args)
        args = args.pop()
        args = args[::-1]
        self.reglist = str2reglist(args)

        self.psr = 0
        if args:
            tmp = args.pop()
            if tmp == '^':
                self.psr = 1
            else:
                raise ValueError('zarb last arg %s'%str(tmp))

    def breakflow(self):
        if self.ldst == 0 or not 15 in self.reglist:
            return False
        #XXX pc pp incremented
        return True
    def splitflow(self):
        if self.ldst == 0 or not 15 in self.reglist:
            return False
        #XXX pc pp incremented
        return self.cond != COND_AL
    def dstflow(self):
        return False
        
class arm_br(arm_mn):
    mask_list = [bm_int101, bm_lnk, bm_offs]

    namestr = ["B", "BL"]
    def name2str(self):
        return self.namestr[self.lnk]
    def str2name(self, n):
        self.lnk = self.namestr.index(n)

    @classmethod
    def check_mnemo(self, mnemo):
        if not mnemo.startswith('B'):
            return False
        l = len(mnemo)        
        if l==1 and mnemo in ['B']:
            return True
        elif l in [2,4] and mnemo.startswith('BL'):
            return True
        elif l == 3 and mnemo[1:] in bm_cond.n:
            return True
        return False

    def parse_name_cond(self, mnemo):
        name, cond = None, None
        if not mnemo.startswith('B'):
            raise  ValueError('zarb mnemo %s'%str(mnemo))
        l = len(mnemo)
        if l in [1,3]:
            n = mnemo[:1]
        elif l in [2,4]:
            n = mnemo[:2]
        else:
            raise ValueError('zarb mnemo %s'%str(mnemo))
        name = n
        rest = mnemo[len(n):]
        for i, c in enumerate(bm_cond.n):
            if rest.startswith(c):
                cond = i
                break
        if cond == None:
            cond = COND_AL         #default cond is AL
        else:
            rest = rest[len(c):]
        return name, cond, rest

    def args2str(self):
        if type(self.offs) in [int, long]:
            args = [imm2str(self.offs)]
        else:
            args = [self.offs]
        return args
    
    def __str__(self):
        name = self.getname()
        args = self.args2str()
        args = args2str(args)
        return name+' '+args

    def parse_args(self, args):
        ad = args.pop()
        if is_imm(ad):
            self.offs = str2imm(ad)
        else:
            self.offs = {x86_afs.symb:{ad[0]:1}}
    def breakflow(self):
        return True
    def splitflow(self):
        return self.cond != COND_AL or self.lnk
    def dstflow(self):
        return True

    def getdstflow(self):
        if type(self.offs) in [int, long]:
            dst = (self.offset+8+self.offs)&0xFFFFFFFF
        else:
            dst = self.arg[0]
        return [dst]

    def setdstflow(self, dst):
        if len(dst)==0:
            return
        if len(dst)!=1:
            raise ValueError('should be 1 dst')
        l = dst[0]
        #patch only known symbols
        if l.offset !=None:
            self.offs = l
    def is_subcall(self):
        return self.lnk

    def fixdst(self, lbls, my_offset, is_mem):
        l = self.offs[x86_afs.symb].keys()[0]
        offset = lbls[l]
        if is_mem:
            arg = {x86_afs.ad:is_mem, x86_afs.imm:offset}
        else:
            arg = {x86_afs.imm:offset-(my_offset)}
        self.arg = [arg]
        self.offs = lbls[l]-my_offset-4

class arm_codt(arm_mn):
    mask_list = [bm_int110, bm_ppndx, bm_updown, bm_tlen, bm_wback, bm_ldst, bm_rn, bm_crd, bm_cpnum, bm_cooff]

    namestr = ['STC', 'LDC']
    def name2str(self):
        return self.namestr[self.ldst]
    def str2name(self, n):
        self.ldst = self.namestr.index(n)

    @classmethod
    def check_opts(cls, rest):
        if not rest or rest == 'L':
            return True
        return False

    def args2str(self):
        args = []
        args.append(cop2str(self.cpnum))
        args.append(copr2str(self.crd))
        o = []
        o.append('[')
        o.append(reg2str(self.rn))
        if not self.ppndx:
            o.append(']')
        o.append(imm2str(self.cooff))
        if self.ppndx:
            o.append(']')
        args.append(o)
        return args
    
    def __str__(self):
        name = self.getname()
        if self.tlen:
            name+='L'
        args = self.args2str()
        args = args2str(args)
        wb = ['', '!'][self.wback]
        return name+' '+args+wb

    def parse_opts(self, opts):
        self.tlen = 0
        if not opts:
            return
        if opts =='L':
            self.tlen = 1
            return
        raise ValueError('opt zarb %s'%str(opts))

    def parse_args(self, args):
        self.wback = 0
        self.updown = 0
        self.cpnum = str2cop(args.pop())
        self.crd = str2copr(args.pop())
        if len(args) !=1:
            raise ValueError('zarb arg 6', str(args))
        args = args.pop()
        args = args[::-1]
        p1 = args.pop()
        self.rn = str2reg(args.pop())

        param = []
        if args[-1] == ']':
            self.ppndx = 0
            param = args[:-1]
            args = []
        else:
            self.ppndx = 1
            param = args[args.index(']')+1:]
            args = args[:args.index(']')]

        self.updown = 1
        tmp = param.pop()
        if tmp =='-':
            self.updown = 0
            tmp = param.pop()

        self.cooff = str2imm(tmp)
        
        if args:
            tmp = args.pop()
            if tmp!= '!':
                raise "arg zarb %s"%str(tmp)
            self.wback = 1
        if args:
            raise ValueError('rest args...'%str(param))
            


class arm_codo(arm_mn):
    mask_list = [bm_int1110, bm_cpopc, bm_crn, bm_crd, bm_cpnum, bm_info, bm_int0, bm_crm]

    namestr = ["CDP"]
    def name2str(self):
        return self.namestr[0]

    def args2str(self):
        args = []
        args.append(cop2str(self.cpnum))
        args.append(imm2str(self.cpopc))
        args.append(copr2str(self.crd))
        args.append(copr2str(self.crn))
        args.append(copr2str(self.crm))
        args.append(imm2str(self.info))
        return args
    
    def __str__(self):
        name = self.getname()
        args = self.args2str()
        args = args2str(args)
        return name+' '+args

    def parse_args(self, args):
        self.cpnum = str2cop(args.pop())
        self.cpopc = str2imm(args.pop())
        self.crd = str2copr(args.pop())
        self.crn = str2copr(args.pop())
        self.crm = str2copr(args.pop())
        self.info = str2imm(args.pop())
        
        


class arm_cort(arm_mn):
    mask_list = [bm_int1110, bm_opmode, bm_ldst, bm_crn, bm_rd, bm_cpnum, bm_info, bm_int1, bm_crm]

    namestr = ['MCR', 'MRC']
    def name2str(self):
        return self.namestr[self.ldst]
    def str2name(self, n):
        self.ldst = self.namestr.index(n)

    def args2str(self):
        args = []
        args.append(cop2str(self.cpnum))
        args.append(imm2str(self.opmode))
        args.append(reg2str(self.rd))
        args.append(copr2str(self.crn))
        args.append(copr2str(self.crm))
        args.append(imm2str(self.info))
        return args
    
    def __str__(self):
        name = self.getname()
        args = self.args2str()
        args = args2str(args)
        return name+' '+args


    def parse_args(self, args):
        self.cpnum = str2cop(args.pop())
        self.opmode = str2imm(args.pop())
        self.rd = str2reg(args.pop())
        self.crn = str2copr(args.pop())
        self.crm = str2copr(args.pop())
        self.info = str2imm(args.pop())

class arm_swi(arm_mn):
    mask_list = [bm_int1111, bm_swint]

    namestr = ["SWI"]
    def name2str(self):
        return self.namestr[0]

    def args2str(self):
        args = [imm2str(self.swint)]
        return args

    def __str__(self):
        name = self.getname()
        args = self.args2str()
        args = args2str(args)
        return name+' '+args

    def parse_args(self, args):
        self.swint = str2imm(args.pop())
        
    def breakflow(self):
        return True
    def splitflow(self):
        return True
    def dstflow(self):
        return False


class arm_szext(arm_mn):
    mask_list = [bm_int01101, bm_opsz, bm_szext, bm_rn, bm_rd, bm_rot, bm_int00, bm_int0111, bm_rm]
    #szext may not be 01
    namestr = ['SXT', 'UXT']
    szextname = ['B16', None, 'B', 'H']
    def name2str(self):
        return self.namestr[self.opsz]+['A', ''][self.rn==15]+self.szextname[self.szext]
    def str2name(self, n):
        self.opsz = self.namestr.index(n)

    @classmethod
    def check_mnemo(self, mnemo):
        if len(mnemo)<3:
            return False
        if not mnemo[:3] in self.namestr:
            return False
        rest = mnemo[3:]
        if rest[0] =='A':
            rest = rest[1:]
        found = False
        for n in self.szextname:
            if not n:
                continue
            if rest.startswith(n):
                found = True
        if not found:
            return False
        rest = rest[len(n):]
        if not rest or rest in bm_cond.n:
            return True
        return False

    def parse_name_cond(self, mnemo):
        name, szextname, cond = None, None, None
        for n in self.namestr:
            if mnemo.startswith(n):
                name = n
                break
        if not name:
            raise ValueError('zarb mnemo1 %s'%str(mnemo))
        rest = mnemo[len(n):]
        out = []
        if rest[0] =='A':
            rest = rest[1:]
            out.append('A')
            self.rn = 0
        else:
            self.rn=15
        for i, n in enumerate(self.szextname):
            if n and rest.startswith(n):
                szextname = n
                self.szext = i
                break
        if not szextname:
            raise ValueError('zarb mnemo2 %s'%str(mnemo))
        rest = rest[len(n):]
        
        for i, c in enumerate(bm_cond.n):
            if rest.startswith(c):
                cond = i
                break
        if cond == None:
            cond = COND_AL         #default cond is AL
        else:
            rest = rest[len(c):]
        if rest:
            raise ValueError("rest! %s"%str(rest))
        return name, cond, rest

    def parse_opts(self, opts):
        if not opts:
            return
        raise ValueError('opt zarb %s'%str(opts))

    def args2str(self):
        args = []
        args.append(reg2str(self.rd))
        if self.rn!=15:
            args.append(reg2str(self.rn))
        args.append(reg2str(self.rm))
        return args
    
    def __str__(self):
        name = self.getname()
        args = self.args2str()
        args = args2str(args)
        return name+' '+args


    def parse_args(self, args):
        
        self.rd = str2reg(args.pop())
        if self.rn!=15:
            self.rn = str2reg(args.pop())
        self.rm = str2reg(args.pop())
        self.rot = 0
    

    

if __name__ == "__main__":
 
    import struct
