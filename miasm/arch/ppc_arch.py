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
import shlex
import struct

from miasm.core.bin_stream import bin_stream


def hex2bin(op):
    out = []
    for i in xrange(31, -1, -1):
        out.append(str((op>>i)&1))
    for i in xrange(32, -1,  -4):
        out[i:i] = ' '
    return "".join(out)

def myrol(v, r):
    return ((v&0xFFFFFFFFL)>>r)  | ((v << (32-r))&0xFFFFFFFFL)

def str2imm(i):
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
            return "-0x%x"%-i
        else:
            return "0x%x"%i
    return str(i)

def is_imm(i):
    return type(str2imm(i)) is not bool

class bm_meta(type):
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


class bm(object):
    __metaclass__ = bm_meta
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


all_bm_int = []
for i in xrange(0x40):
    mask_str = hex2bin(i).replace(' ', '')[26:]
    while mask_str:
        bstr = "bm_int"+mask_str
        globals()[bstr] = bm_meta(bstr,(bm,),{"fbits":mask_str})
        if mask_str[0] !='0':
            break
        mask_str = mask_str[1:]


class bm_set_meta(type):
    def __new__(cls, name, bases, odct):
        if not 'l' in odct:
            odct['l'] = 9
        return type.__new__(cls, name, bases, odct)


class bm_set(object):
    __metaclass__ = bm_set_meta
    def __init__(self, parent, off):
        self.parent = parent
        self.off = 32-off-self.l
        self.fmask = (1<<self.l)-1
    def check(self, v):
        return (v>>self.off) & self.fmask in self.fbits


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

class bm_int000000000(bm):
    fbits = '000000000'

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


class bm_rt(bm):
    l = 5

class bm_rs(bm):
    l = 5

class bm_ra(bm):
    l = 5

class bm_bo(bm):
    l = 5

class bm_bi(bm):
    l = 5

class bm_bd(bm):
    l = 14

class bm_rb(bm):
    l = 5

class bm_oe(bm):
    l = 1

class bm_rc(bm):
    l = 1

class bm_opc5(bm):
    l = 5

class bm_opc9(bm):
    l = 9

class bm_opc10(bm):
    l = 10

class bm_nb(bm):
    l = 5

class bm_spr(bm):
    l = 10

class bm_sr(bm):
    l = 4

class bm_mb(bm):
    l = 5

class bm_me(bm):
    l = 5

class bm_sh(bm):
    l = 5

class bm_to(bm):
    l = 5

class bm_fra(bm):
    l = 5

class bm_frb(bm):
    l = 5

class bm_frc(bm):
    l = 5

class bm_frt(bm):
    l = 5






class bm_simm(bm):
    l = 16

class bm_uimm(bm):
    l = 16

class bm_li(bm):
    l = 24

class bm_aa(bm):
    l = 1

class bm_lk(bm):
    l = 1

class bm_bf(bm):
    l = 3

class bm_bfa(bm):
    l = 3

class bm_bt(bm):
    l = 5

class bm_ba(bm):
    l = 5

class bm_bb(bm):
    l = 5

class bm_rn(bm):
    l = 4


class bm_rdh(bm):
    l = 4

class bm_rdl(bm):
    l = 4


class ppc_mnemo_metaclass(type):
    global tab_mn
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
        ret = filter(lambda x:x.check(op), tab_mn)
        if len(ret)==1:
            return ret[0]
        raise ValueError('ambiquity %s'%str(ret))


    def dis(cls, bin, attrib = {}):
        if type(bin) == str:
            bin = bin_stream(bin)
        elif not isinstance(bin, bin_stream):
            raise ValueError('unknown input')

        op = bin.readbs(4)
        op = struct.unpack('>L', op)[0]
        return cls(op, bin.offset-4)


    def asm(cls, txt, symbol_reloc_off = []):
        print txt
        t = ppc_mn.pre_parse_mnemo(txt)
        name = t.pop()
        ret = filter(lambda x:x.check_mnemo(name), tab_mn)
        if len(ret)!=1:
            raise ValueError('parse name err %s'%str(ret))
        cls = ret[0]
        i = cls.__new__(cls)
        i.__init__(txt, 0, False)
        return [struct.pack('>L', i.bin())]

    def __new__(cls, name, bases, dct):
        ret_c = type.__new__(cls, name, bases, dct)
        if name is "ppc_mn":
            return ret_c

        mask = []
        if 'mask' in dct:
            for off in dct['mask']:
                mc = dct['mask'][off](None, off)#+1)
                mask.append(mc)

        mask_orig = dct["mask_list"]
        ret_c.mask_orig = mask_orig
        off = 32
        for m in mask_orig:
            mc = m(None, off)
            off-=mc.l
            mask.append(mc)
            for pname in m.p_property:
                pfunc = "get_"+pname
                p = property(lambda self=ret_c, pname=pname:getattr(getattr(self, "bm_"+pname), pname),
                             lambda self=ret_c,val=None,pname=pname:setattr(getattr(self, "bm_"+pname), pname, val))

                setattr(ret_c, pname, p)

        if off!=0:
            raise ValueError('invalid mnemonic %d'%off)
        ret_c.mask_chk = mask

        #gen arg parser/generator if present
        if 'do_args' in dct:
            ret_c.args_list = dct['do_args']

            args2str_f = None
            parse_args_f = None
            for tmp_cls in bases:
                if 'gen_args2str' in tmp_cls.__dict__:
                    args2str_f = tmp_cls.__dict__['gen_args2str']
                if 'gen_parse_args' in tmp_cls.__dict__:
                    parse_args_f = tmp_cls.__dict__['gen_parse_args']

            ret_c.args2str = args2str_f
            ret_c.parse_args = parse_args_f

        return ret_c

    def check(self, op):
        for m in self.mask_chk:
            if m.fbits==None:
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
        return self.check_opts(rest)

    def pre_parse_mnemo(cls, args):
        tmp = args.replace(',', ' ')
        t = []
        is_minux = False
        for x in shlex.shlex(tmp):
            if x == '-':
                is_minux = True
                continue
            if is_minux:
                x = '-'+x
                is_minux = False

            if x == '.':
                t[-1]+=x
            else:
                t.append(x)

        t.reverse()
        return t

    def parse_mnemo(cls, args):
        t = cls.pre_parse_mnemo(args)
        t.reverse()
        return [], t[0], t[1:]

    def parse_address(self, a):
        return parse_ad(a)
    def prefix2hex(self, p):
        return ""

regs_str = ['R%d'%r for r in xrange(0x20)]
regs_str[1] = 'SP'

cop_str = ['P%d'%r for r in xrange(0x10)]
copr_str = ['C%d'%r for r in xrange(0x10)]

crb_str = []
for i in xrange(0x8):
    for x in ['LT', 'GT', 'EQ', 'SO']:
        crb_str.append('CR%d_%s'%(i, x))

cr_str = ['CR%d'%r for r in xrange(0x8)]
fpr_str = ['FP%d'%r for r in xrange(0x20)]
spr_str = ['SPR%d'%r for r in xrange(0x400)]
spr_str[256] = 'LR'
spr_str[392] = 'BL'
spr_str[424] = 'BU'
spr_str[832] = 'SR0'
spr_str[864] = 'SR1'
spr_str[529] = 'IC_CSR'
spr_str[964] = 'ICTRL'
spr_str[288] = 'CTR'

sr_str = ['SR%d'%r for r in xrange(0x10)]

all_regs = regs_str+cop_str+copr_str+cr_str+crb_str+fpr_str+spr_str

from ia32_reg import x86_afs


def is_symbol(a):
    if is_imm(a) or a in all_regs:
        return False
    return True

def parse_ad(a):
    a = a.strip()
    if is_symbol(a):
        print 'SYMBOL!', a
        return {x86_afs.symb:{a:1}}
    else:
        return {0x1337:1}


def reg2str(r):
    return regs_str[r]
def str2reg(r):
    return regs_str.index(r)


def cr2str(r):
    return cr_str[r]
def str2cr(r):
    return cr_str.index(r)

def crb2str(r):
    return crb_str[r]
def str2crb(r):
    return crb_str.index(r)


def fpr2str(r):
    return fpr_str[r]
def str2fpr(r):
    return fpr_str.index(r)

def spr2str(r):
    return spr_str[r]
def str2spr(r):
    return spr_str.index(r)


def sr2str(r):
    return sr_str[r]
def str2sr(r):
    return sr_str.index(r)

class reg:
    @classmethod
    def str(cls, r):
        return reg2str(r)
    @classmethod
    def cls(cls, r):
        return str2reg(r)

class imm:
    @classmethod
    def str(cls, r):
        return imm2str(r)
    @classmethod
    def cls(cls, r):
        return str2imm(r)

class crb:
    @classmethod
    def str(cls, r):
        return crb2str(r)
    @classmethod
    def cls(cls, r):
        return str2crb(r)


class fpr:
    @classmethod
    def str(cls, r):
        return fpr2str(r)
    @classmethod
    def cls(cls, r):
        return str2fpr(r)


class cr:
    @classmethod
    def str(cls, r):
        return cr2str(r)
    @classmethod
    def cls(cls, r):
        return str2cr(r)

class spr:
    @classmethod
    def str(cls, r):
        return spr2str(r)
    @classmethod
    def cls(cls, r):
        return str2spr(r)

class sr:
    @classmethod
    def str(cls, r):
        return sr2str(r)
    @classmethod
    def cls(cls, r):
        return str2sr(r)

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
            out+=a
            out+=', '
    if out.endswith(', '):
        out = out[:-2]
    return out


def args2str(args):
    return arglist2str(args2reduce(args))


class ppc_mn(object):
    mask_list = []
    __metaclass__ = ppc_mnemo_metaclass


    def gen_args2str(self):
        args = []
        for r, t in self.args_list:
            args.append(t.str(getattr(self, r)))
        return args

    def gen_parse_args(self, args):
        for r, t in self.args_list:
            setattr(self, r, t.cls(args.pop()))

    def __init__(self, op, offset = 0, dis = True):
        off=32
        mask = []
        self.offset = offset
        self.l = 4
        self.m = None
        self.arg = []
        self.cmt = ""

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

            full_mnemo = ppc_mn.pre_parse_mnemo(op)
            mnemo = full_mnemo.pop()
            name, rest = self.parse_name_cond(mnemo)
            self.name = name
            self.parse_opts(rest)
            self.str2name(name)

            mnemo_nosymb = []
            for a in full_mnemo:
                if not is_symbol(a) or a in bm_cond.n:
                    mnemo_nosymb.append(a)
                    continue
                print "WARNING asm symb", a
                mnemo_nosymb.append("0")
            full_mnemo = mnemo_nosymb

            self.parse_args(full_mnemo)

    def get_attrib(self):
        return {}

    def parse_opts(self, rest):
        if rest:
            raise ValueError('should not have rest here ', rest)
        pass
    def str2name(self, n):
        pass

    def getname(self):
        name = self.name2str()+self.oe2str()+self.rc2str()
        return name

    def bin(self):
        v = 0
        for m in self.mask:
            if not m.checkinv:
                v|=m.bin()
        return v

    def args2str(self):
        args = ["NO ARGS"]
        return args

    def __str__(self):
        name = self.getname()
        args = self.args2str()
        args = args2str(args)
        return name+" "+args

    def parse_name_cond(self, mnemo):
        name = None
        for i, n in enumerate(self.namestr):
            if mnemo.startswith(n):
                name = n
                break
        if name == None:
            raise ValueError('cannot parse name')

        rest = mnemo[len(n):]
        return name, rest

    def oe2str(self):
        return ""
    def rc2str(self):
        return ""


    def breakflow(self):
        return False
    def splitflow(self):
        return False
    def dstflow(self):
        return False

    def getnextflow(self):
        return self.offset+self.l

    def fix_symbol(self, s):
        pass


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

class ppc_add(ppc_mn):
    mask_list = [bm_int011111, bm_rt, bm_ra, bm_rb, bm_oe, bm_opc9, bm_rc]
    namestr = ['ADDE', 'ADDC', 'ADD', 'DIVWU', "DIVW", 'MULLW', 'SUBFC', 'SUBFE', 'SUBF']
    namsdct = {'ADD':266, 'ADDC':10, 'ADDE':138, 'DIVWU':459, 'DIVW':491, 'MULLW':235, 'SUBFC':8, 'SUBF':40, 'SUBFE':136}
    mask = {22:bm_set_meta("bm_addopc",(bm_set,),{"fbits":namsdct.values()})}

    strname = dict((x[1], x[0]) for x in namsdct.items())

    do_args = [('rt',reg), ('ra',reg), ('rb',reg)]

    def name2str(self):
        return self.strname[self.opc9]
    def str2name(self, n):
        self.opc9 = self.namsdct[n]
    @classmethod
    def check_opts(cls, rest):
        if rest in ["", ".", "O", "O."]:
            return True
        return False


    def parse_opts(self, opts):
        self.oe = 0
        self.rc = 0
        if not opts:
            return
        if "O" in opts:
            self.oe = 1
        if "." in opts:
            self.rc = 1

    def oe2str(self):
        return ['','O'][self.oe==1]
    def rc2str(self):
        return ['','.'][self.rc==1]


class ppc_addi(ppc_mn):
    mask_list = [bm_int001110, bm_rt, bm_ra, bm_simm]
    namestr = ['ADDI', 'LI']

    def name2str(self):
        if self.ra == 0:
            return self.namestr[1]
        return self.namestr[0]

    def args2str(self):
        args = []
        args.append(reg2str(self.rt))
        if self.ra!=0:
            args.append(reg2str(self.ra))
        args.append(imm2str(self.simm))
        return args

    def parse_args(self, args):
        self.ra = 0
        self.rt = str2reg(args.pop())
        if len(args)==2:
            self.ra = str2reg(args.pop())
        self.simm = str2imm(args.pop())



class ppc_addic(ppc_addi):
    mask_list = [bm_int001100, bm_rt, bm_ra, bm_simm]
    namestr = ['ADDIC']


class ppc_addicp(ppc_addi):
    mask_list = [bm_int001101, bm_rt, bm_ra, bm_simm]
    namestr = ['ADDIC.']

class ppc_addis(ppc_addi):
    mask_list = [bm_int001111, bm_rt, bm_ra, bm_simm]
    namestr = ['ADDIS', 'LIS']


class ppc_adde(ppc_mn):
    mask_list = [bm_int011111, bm_rt, bm_ra, bm_int00000, bm_oe, bm_opc9, bm_rc]
    namestr = {'ADDME':234, 'ADDZE':202, 'NEG':104, 'SUBFME':232, 'SUBFZE':200}

    mask = {22:bm_set_meta("bm_addeopc",(bm_set,),{"fbits":namestr.values()})}

    strname = dict((x[1], x[0]) for x in namestr.items())

    do_args = [('rt',reg), ('ra',reg)]

    def name2str(self):
        return self.strname[self.opc9]
    def str2name(self, n):
        self.opc9 = self.namestr[n]
    @classmethod
    def check_opts(cls, rest):
        if rest in ["", ".", "O", "O."]:
            return True
        return False

    def oe2str(self):
        return ['','O'][self.oe==1]
    def rc2str(self):
        return ['','.'][self.rc==1]

    def parse_opts(self, opts):
        self.oe = 0
        self.rc = 0
        if not opts:
            return
        if "O" in opts:
            self.oe = 1
        if "." in opts:
            self.rc = 1


class ppc_and(ppc_mn):
    mask_list = [bm_int011111, bm_rs, bm_ra, bm_rb, bm_opc10, bm_rc]
    namestr = ['ANDC', 'AND', 'EQV', 'NAND', 'NOR', 'ORC', 'OR', 'SLW', 'SRAW', 'SRW', 'XOR']
    namedct = {'AND':28, 'ANDC':60, 'EQV':284, 'NAND':476, 'NOR':124, 'OR':444, 'ORC':412, 'SLW':24, 'SRAW':792, 'SRW':536, 'XOR':316}
    mask = {21:bm_set_meta("bm_andopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}

    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('ra',reg), ('rs',reg), ('rb',reg)]

    def name2str(self):
        return self.strname[self.opc10]
    def str2name(self, n):
        self.opc10 = self.namedct[n]
    @classmethod
    def check_opts(cls, rest):
        if rest in ["", "."]:
            return True
        return False

    def rc2str(self):
        return ['','.'][self.rc==1]


    def parse_opts(self, opts):
        self.rc = 0
        if not opts:
            return
        if "." in opts:
            self.rc = 1


class ppc_andip(ppc_mn):
    mask_list = [bm_int011100, bm_rs, bm_ra, bm_uimm]
    namestr = ['ANDI.']

    do_args = [('ra',reg), ('rs',reg), ('uimm',imm)]


    def name2str(self):
        return self.namestr[0]


class ppc_andisp(ppc_andip):
    mask_list = [bm_int011101, bm_rs, bm_ra, bm_uimm]
    namestr = ['ANDIS.']

class ppc_b(ppc_mn):
    mask_list = [bm_int010010, bm_li, bm_aa, bm_lk]
    namestr = ['B']
    def name2str(self):
        return self.namestr[0]

    @classmethod
    def check_opts(cls, rest):
        if rest in ["", "A", "L", "AL"]:
            return True
        return False

    def getname(self):
        name = "B"
        if self.aa:
            name+='A'
        if self.lk:
            name+='L'
        return name

    def args2str(self):
        args = []
        if type(self.li) in [int, long]:
            args.append(imm2str(self.li<<2))
        else:
            args.append(str(self.li))
        return args

    def parse_args(self, args):
        self.li = str2imm(args.pop())>>2

    def parse_opts(self, opts):
        self.aa = 0
        self.lk = 0
        if not opts:
            return
        if "A" in opts:
            self.aa = 1
        if "L" in opts:
            self.lk = 1



    def breakflow(self):
        return True
    def splitflow(self):
        return self.lk
    def dstflow(self):
        return True

    def getdstflow(self):
        if type(self.li) in [int, long]:
            li = self.li<<2
            if li &(0x1<<25):
                li |=0xFF000000
            li = struct.unpack('L', struct.pack('L', li))[0]
            if self.aa:
                print "absolute jmp! default abs ad  0"
                dst = (li)&0xFFFFFFFF
            else:
                dst = (self.offset+(li))&0xFFFFFFFF
        else:
            dst = self.li
        return [dst]

    def setdstflow(self, dst):
        if len(dst)==0:
            return
        if len(dst)!=1:
            raise ValueError('should be 1 dst')
        l = dst[0]
        self.li = l.name

    def is_subcall(self):
        return self.lk

    def fixdst(self, lbls, my_offset, is_mem = False):
        l = self.li
        if self.aa:
            self.li = lbls[l]>>2
        else:
            self.li = (lbls[l]+4-my_offset)>>2



class ppc_bc(ppc_mn):
    mask_list = [bm_int010000, bm_bo, bm_bi, bm_bd, bm_aa, bm_lk]
    namestr = ['B']
    all_tests = ['GE', 'LE', 'NE', 'NS', 'LT', 'GT', 'EQ', 'SO']
    def name2str(self):
        return self.namestr[0]

    @classmethod
    def check_opts(cls, rest):
        if not rest:
            return False
        if rest[0] == 'D':
            rest = rest[1:]
            if rest[0] == 'Z':
                rest = rest[1:]
            elif rest.startswith('NZ'):
                rest = rest[2:]
            else:
                return False
        elif rest[0] == 'C':
            rest = rest[1:]
        else:
            if len(rest)>1 and rest[:2] in ppc_bc.all_tests:
                rest = rest[2:]
            else:
                return False
        if rest in ["", "A", "L", "LA"]:
            return True
        return False

    def getname(self):
        self.bi_parsed = False
        name = "B"
        if not self.bo &4:
            name+="D"
            if self.bo & 2:
                name+='Z'
            else:
                name+='NZ'
        elif not self.bo &0x10:
            index = (self.bo&8)>>1
            index |= self.bi & 3
            name+=ppc_bc.all_tests[index]
            self.bi_parsed = True
        else:
            name+='C'
        if self.aa:
            name+='A'
        if self.lk:
            name+='L'

        return name


    def parse_opts(self, opts):
        self.bi_done = False

        self.bo = 0x14
        self.bi = 0
        self.aa = 0
        self.lk = 0
        if not opts:
            return
        if opts[0] == 'D':
            self.bo&=0x1B
            opts = opts[1:]
            if opts[0] == 'Z':
                self.bo|=2
                opts = opts[1:]
            elif opts.startswith('NZ'):
                self.bo&=0x1d
                opts = opts[2:]
        elif opts[0] =='C':
            pass
        else:
            if len(opts)>1 and opts[:2] in ppc_bc.all_tests:
                self.bi_done = True
                index = ppc_bc.all_tests.index(opts[:2])
                inv = index&0x4
                self.bi = index&0x3
                if inv:
                    self.bo|=8
                else:
                    self.bo&=0x17
                self.bo &=0xf
                opts = opts[2:]
        if opts == 'C':
            return
        if not opts:
            return
        if opts[0] == 'L':
            self.lk = 1
            opts = opts[1:]
        if not opts:
            return
        if not opts:
            return
        if opts == 'A':
            self.aa = 1
        return

    def args2str(self):
        args = []

        if not self.bi_parsed:
            if not self.bo & 0x10:
                index = (self.bo&8)>>1
                index |= self.bi & 3
                a = ppc_bc.all_tests[index]

                args.append(a)
            else:
                pass
        if self.bi>>2:
            args.append(cr2str(self.bi>>2))
        if type(self.bd) in [int, long]:
            args.append(imm2str(self.bd<<2))
        else:
            args.append(str(self.bd))
        return args

    def parse_args(self, args):
        if not self.bi_done:

            if args[-1] in ppc_bc.all_tests:
                self.bo &=0xF

                a = args.pop()
                index = ppc_bc.all_tests.index(a)
                inv = index&0x4
                self.bi = index&0x3
                if inv:
                    self.bo|=8
                else:
                    self.bo&=0x17
            else:
                self.bo |=0x10

                pass

        if len(args) >1:
            tmp = str2cr(args.pop())
            self.bi|=tmp<<2

        self.bd = str2imm(args.pop())>>2

    def breakflow(self):
        return True
    def splitflow(self):
        return True
    def dstflow(self):
        return True

    def getdstflow(self):
        if type(self.bd) in [int, long]:
            li = self.bd<<2
            if li &(0x1<<15):
                li |=0xFFFF0000
            li = struct.unpack('L', struct.pack('L', li))[0]
            if self.aa:
                dst = (li)&0xFFFFFFFF
            else:
                dst = (self.offset+(li))&0xFFFFFFFF
        else:
            dst = self.bd
        return [dst]

    def setdstflow(self, dst):
        if len(dst)==0:
            return
        if len(dst)!=1:
            raise ValueError('should be 1 dst')
        l = dst[0]
        self.bd = l.name

    def is_subcall(self):
        return self.lk

    def fixdst(self, lbls, my_offset, is_mem = False):
        l = self.bd
        if self.aa:
            self.bd = lbls[l]>>2
        else:
            self.bd = (lbls[l]+4-my_offset)>>2



class ppc_bctr(ppc_mn):
    mask_list = [bm_int010011, bm_bo, bm_bi, bm_int00000, bm_opc10, bm_lk]
    namestr = ['BLR', 'BCTR']
    namedct = {'BLR':16, 'BCTR':528}
    mask = {21:bm_set_meta("bm_cmpopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}

    strname = dict((x[1], x[0]) for x in namedct.items())
    def name2str(self):
        return self.strname[self.opc10]
    def str2name(self, n):
        self.opc10 = self.namedct[n]

    @classmethod
    def check_opts(cls, rest):
        if not rest:
            return True
        if rest[0] == 'D':
            rest = rest[1:]
            if rest[0] == 'Z':
                rest = rest[1:]
            elif rest.startswith('NZ'):
                rest = rest[2:]
            else:
                return False
        elif rest[0] == 'C':
            rest = rest[1:]
        else:
            if len(rest)>1 and rest[:2] in ppc_bc.all_tests:
                rest = rest[2:]
            else:
                return False
        if rest in ["", "L"]:
            return True
        return False

    def getname(self):
        self.bi_parsed = False
        name = self.name2str()
        if not self.bo &4:
            name+="D"
            if self.bo & 2:
                name+='Z'
            else:
                name+='NZ'
        elif not self.bo &0x10:
            index = (self.bo&8)>>1
            index |= self.bi & 3
            name+=ppc_bc.all_tests[index]
            self.bi_parsed = True
        else:
            pass

        return name



    def parse_opts(self, opts):
        self.bi_done = False

        self.bo = 0x14
        self.bi = 0
        self.aa = 0
        self.lk = 0
        if not opts:
            return
        if opts[0] == 'D':
            self.bo&=0x1B
            opts = opts[1:]
            if opts[0] == 'Z':
                self.bo|=2
                opts = opts[1:]
            elif opts.startswith('NZ'):
                self.bo&=0x1d
                opts = opts[2:]
        elif opts[0] =='C':
            pass
        else:
            if len(opts)>1 and opts[:2] in ppc_bc.all_tests:
                self.bi_done = True
                index = ppc_bc.all_tests.index(opts[:2])
                inv = index&0x4
                self.bi = index&0x3
                if inv:
                    self.bo|=8
                else:
                    self.bo&=0x17
                self.bo &=0xf
                opts = opts[2:]
        if opts == 'C':
            return
        if not opts:
            return
        if opts[0] == 'L':
            self.lk = 1
            opts = opts[1:]
        if not opts:
            return
        if not opts:
            return
        if opts == 'A':
            self.aa = 1
        return

    def args2str(self):
        args = []
        if not self.bi_parsed:
            if not self.bo & 0x10:

                index = (self.bo&8)>>1
                index |= self.bi & 3
                a = ppc_bc.all_tests[index]

                args.append(a)
            else:
                pass
        if self.bi>>2:
            args.append(cr2str(self.bi>>2))
        return args

    def parse_args(self, args):
        if not args:
            return
        if not self.bi_done:
            if args[-1] in ppc_bc.all_tests:
                self.bo &=0xF

                a = args.pop()
                index = ppc_bc.all_tests.index(a)
                inv = index&0x4
                self.bi = index&0x3
                if inv:
                    self.bo|=8
                else:
                    self.bo&=0x17
            else:
                self.bo |=0x10

                pass

        if len(args) >1:
            tmp = str2cr(args.pop())
            self.bi|=tmp<<2


    def breakflow(self):
        return True
    def splitflow(self):
        return False
    def dstflow(self):
        return False

    def getdstflow(self):
        return []

    def setdstflow(self, dst):
        pass
    def is_subcall(self):
        return self.lk

    def fixdst(self, lbls, my_offset, is_mem = False):
        pass


class ppc_cmp(ppc_mn):
    mask_list = [bm_int011111, bm_bf, bm_int00, bm_ra, bm_rb, bm_opc10, bm_int0]
    namestr = ['CMPL', 'CMP']
    namedct = {'CMP':0, 'CMPL':32}
    mask = {21:bm_set_meta("bm_cmpopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}

    strname = dict((x[1], x[0]) for x in namedct.items())
    def name2str(self):
        return self.strname[self.opc10]
    def str2name(self, n):
        self.opc10 = self.namedct[n]

    def args2str(self):
        args = []
        if self.bf!=0:
            args.append(cr2str(self.bf))
        args.append(reg2str(self.ra))
        args.append(reg2str(self.rb))
        return args

    def parse_args(self, args):
        self.bf = 0
        if len(args)==3:
            self.bf = str2cr(args.pop())
        self.ra = str2reg(args.pop())
        self.rb = str2reg(args.pop())



class ppc_cmpli(ppc_mn):
    mask_list = [bm_int001010, bm_bf, bm_int00, bm_ra, bm_uimm]
    namestr = ['CMPLI']

    def name2str(self):
        return self.namestr[0]

    def args2str(self):
        args = []
        if self.bf!=0:
            args.append(cr2str(self.bf))
        args.append(reg2str(self.ra))
        args.append(imm2str(self.uimm))
        return args

    def parse_args(self, args):
        self.bf = 0
        if len(args)==3:
            self.bf = str2cr(args.pop())

        self.ra = str2reg(args.pop())
        self.uimm = str2imm(args.pop())


class ppc_cmpi(ppc_mn):
    mask_list = [bm_int001011, bm_bf, bm_int00, bm_ra, bm_simm]
    namestr = ['CMPI']

    def name2str(self):
        return self.namestr[0]

    def args2str(self):
        args = []
        if self.bf!=0:
            args.append(cr2str(self.bf))
        args.append(reg2str(self.ra))
        args.append(imm2str(self.simm))
        return args

    def parse_args(self, args):
        self.bf = 0
        if len(args)==3:
            self.bf = str2cr(args.pop())
        self.ra = str2reg(args.pop())
        self.simm = str2imm(args.pop())

class ppc_cntlzw(ppc_mn):
    mask_list = [bm_int011111, bm_rs, bm_ra, bm_int00000, bm_opc10, bm_rc]
    mask = {21:bm_set_meta("bm_cntlzwopc",(bm_set,),{"fbits":[26], 'l':10})}

    namestr = ['CNTLZW']

    do_args = [('ra',reg), ('rs',reg)]

    def name2str(self):
        return self.namestr[0]

    def str2name(self, n):
        self.opc10 = 26

    @classmethod
    def check_opts(cls, rest):
        if rest in ["", "."]:
            return True
        return False

    def rc2str(self):
        return ['','.'][self.rc==1]

    def parse_opts(self, opts):
        self.rc = 0
        if not opts:
            return
        if "." in opts:
            self.rc = 1

class ppc_crand(ppc_mn):
    mask_list = [bm_int010011, bm_bt, bm_ba, bm_bb, bm_opc10, bm_int0]
    namestr = ['CRANDC', 'CRAND', "CREQV", "CRNAND", "CRNOR", "CRORC", "CROR", "CRXOR"]
    namedct = {'CRAND':257, 'CRANDC':129, "CREQV":289, "CRNAND":225, "CRNOR":33, "CROR":449, "CRORC":417,
               "CRXOR":193}
    mask = {21:bm_set_meta("bm_crandopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}

    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('bt',crb), ('ba',crb), ('bb',crb)]

    def name2str(self):
        return self.strname[self.opc10]
    def str2name(self, n):
        self.opc10 = self.namedct[n]


class ppc_dcb(ppc_crand, ppc_mn):
    mask_list = [bm_int011111, bm_int00000, bm_ra, bm_rb, bm_opc10, bm_int0]
    namestr = ['DCBTST', 'DCBST', 'DCBF', 'DCBI', 'DCBT', 'DCBZ', 'ICBI']
    namedct = {'DCBTST':246, 'DCBST':54, 'DCBF':86, 'DCBI':470, 'DCBT':278, 'DCBZ':1014, 'ICBI':982}
    mask = {21:bm_set_meta("bm_dcbopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}

    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('ra',reg), ('rb',reg)]
    @classmethod
    def check_opts(cls, rest):
        if rest in ["", "."]:
            return True
        return False


class ppc_eciw(ppc_crand, ppc_mn):
    mask_list = [bm_int011111, bm_rt, bm_ra, bm_rb, bm_opc10, bm_int0]
    namestr = ['ECIW', 'ECOW', 'LBZUX', 'LBZX', 'LHAUX', 'LHAX', 'LHBR', 'LHZUX', 'LHZUX', 'LHZX',
               'LSWX', 'STSWX', 'LWARX', 'LWBRX', 'STWBRX', 'LWZX', 'LWZUX', 'STWUX', 'STWX', 'STBUX',
               'STBX', 'STHBRX', 'STHX', 'STHUX']
    namedct = {'ECIW':310, 'ECOW':438, 'LBZUX':119, 'LBZX':87, 'LHAUX':375, 'LHAX':343, 'LHBR':790,
               'LHZUX':311, 'LHZX':279, 'LSWX':533, 'STSWX':661, 'LWARX':20, 'LWBRX':534, 'STWBRX':662,
               'LWZUX':55, 'LWZX':23, 'STWUX':183, 'STWX':151, 'STBUX':247, 'STBX':215, 'STHBRX':918,
               'STHX':407, 'STHUX':439}
    mask = {21:bm_set_meta("bm_eciwopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}

    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('rt',reg), ('ra',reg), ('rb',reg)]

class ppc_eieio(ppc_mn):
    mask_list = [bm_int011111, bm_int00000, bm_int00000, bm_int00000, bm_opc10, bm_int0]
    namestr = ['EIEIO']
    mask = {21:bm_set_meta("bm_eieioopc",(bm_set,),{"fbits":[854], 'l':10})}

    def name2str(self):
        return self.namestr[0]
    def str2name(self, n):
        self.opc10 = 854

    def __str__(self):
        name = self.getname()
        return name

    def parse_args(self, args):
        pass

class ppc_isync(ppc_eieio):
    mask_list = [bm_int010011, bm_int00000, bm_int00000, bm_int00000, bm_opc10, bm_int0]
    namestr = ['ISYNC', 'RFI']
    namedct = {'ISYNC':150, 'RFI':50}
    mask = {21:bm_set_meta("bm_isyncopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}
    strname = dict((x[1], x[0]) for x in namedct.items())
    def name2str(self):
        return self.strname[self.opc10]
    def str2name(self, n):
        self.opc10 = self.namedct[n]


class ppc_exts(ppc_crand, ppc_mn):
    mask_list = [bm_int011111, bm_rs, bm_ra, bm_int00000, bm_opc10, bm_rc]
    namestr = ['EXTSB', 'EXTSH', 'EXTSW']
    namedct = {'EXTSB':954, 'EXTSH':922, 'EXTSW':986}
    mask = {21:bm_set_meta("bm_extsopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}

    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('ra',reg), ('rs',reg)]

    def rc2str(self):
        return ['','.'][self.rc==1]

    def parse_opts(self, opts):
        self.rc = 0
        if not opts:
            return
        if "." in opts:
            self.rc = 1

class ppc_lbz(ppc_mn):
    mask_list = [bm_int100010, bm_rt, bm_ra, bm_simm]
    namestr = ['LBZ']

    do_args = [('rt',reg), ('ra',reg), ('simm',imm)]

    def name2str(self):
        return self.namestr[0]


class ppc_lbzu(ppc_lbz, ppc_mn):
    mask_list = [bm_int100011, bm_rt, bm_ra, bm_uimm]
    namestr = ['LBZU']

    do_args = [('rt',reg), ('ra',reg), ('uimm',imm)]

class ppc_lha(ppc_lbz):
    mask_list = [bm_int101010, bm_rt, bm_ra, bm_simm]
    namestr = ['LHA']

class ppc_lhau(ppc_lbzu):
    mask_list = [bm_int101011, bm_rt, bm_ra, bm_uimm]
    namestr = ['LHAU']

class ppc_lhz(ppc_lbz):
    mask_list = [bm_int101000, bm_rt, bm_ra, bm_simm]
    namestr = ['LHZ']

class ppc_lhzu(ppc_lbz):
    mask_list = [bm_int101001, bm_rt, bm_ra, bm_simm]
    namestr = ['LHZU']

class ppc_lmw(ppc_lbz):
    mask_list = [bm_int101110, bm_rt, bm_ra, bm_simm]
    namestr = ['LMW']

class ppc_lfd(ppc_lbz):
    mask_list = [bm_int110010, bm_rt, bm_ra, bm_simm]
    namestr = ['LFD']

class ppc_lfdu(ppc_lbz):
    mask_list = [bm_int110011, bm_rt, bm_ra, bm_simm]
    namestr = ['LFDU']

class ppc_lfs(ppc_lbz):
    mask_list = [bm_int110000, bm_rt, bm_ra, bm_simm]
    namestr = ['LFDS']

class ppc_lfsu(ppc_lbz):
    mask_list = [bm_int110001, bm_rt, bm_ra, bm_simm]
    namestr = ['LFSU']

class ppc_lwz(ppc_lbz):
    mask_list = [bm_int100000, bm_rt, bm_ra, bm_simm]
    namestr = ['LWZ']

class ppc_lwzu(ppc_lbz):
    mask_list = [bm_int100001, bm_rt, bm_ra, bm_simm]
    namestr = ['LWZU']

class ppc_stw(ppc_lbz):
    mask_list = [bm_int100100, bm_rt, bm_ra, bm_simm]
    namestr = ['STW']

class ppc_stwu(ppc_lbz):
    mask_list = [bm_int100101, bm_rt, bm_ra, bm_simm]
    namestr = ['STWU']

class ppc_stbu(ppc_lbz):
    mask_list = [bm_int100111, bm_rt, bm_ra, bm_simm]
    namestr = ['STBU']


class ppc_stb(ppc_lbz):
    mask_list = [bm_int100110, bm_rt, bm_ra, bm_simm]
    namestr = ['STB']

class ppc_stfd(ppc_lbz, ppc_mn):
    mask_list = [bm_int110110, bm_rt, bm_ra, bm_simm]
    namestr = ['STFD']

    do_args = [('rt',fpr), ('ra',reg), ('simm',imm)]

class ppc_stfdu(ppc_lbz, ppc_mn):
    mask_list = [bm_int110111, bm_rt, bm_ra, bm_simm]
    namestr = ['STFDU']

    do_args = [('rt',fpr), ('ra',reg), ('simm',imm)]

class ppc_wi(ppc_crand, ppc_mn):
    mask_list = [bm_int011111, bm_rt, bm_ra, bm_nb, bm_opc10, bm_int0]
    namestr = ['LSWI', 'STSWI']
    namedct = {'LSWI':597, 'STSWI':725}
    mask = {21:bm_set_meta("bm_wiopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}

    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('rt',reg), ('ra',reg), ('nb',imm)]


class ppc_stfdx(ppc_lbz):
    mask_list = [bm_int011111, bm_rt, bm_ra, bm_rb, bm_opc10, bm_int0]
    namestr = ['STFDUX', 'STFDX', 'STFIWX', 'STFSUX', 'STFSX']
    namsdct = {'STFDX':727, 'STFDUX':759, 'STFIWX':983, 'STFSX':663, 'STFSUX':695}
    mask = {21:bm_set_meta("bm_wiopc",(bm_set,),{"fbits":namsdct.values(), 'l':10})}
    strname = dict((x[1], x[0]) for x in namsdct.items())

    do_args = [('rt',fpr), ('ra',reg), ('simm',imm)]

class ppc_stfs(ppc_stfd):
    mask_list = [bm_int110100, bm_rt, bm_ra, bm_simm]
    namestr = ['STFS']

class ppc_stfsu(ppc_stfd):
    mask_list = [bm_int110101, bm_rt, bm_ra, bm_simm]
    namestr = ['STFSU']

class ppc_sth(ppc_lbz):
    mask_list = [bm_int101100, bm_rt, bm_ra, bm_simm]
    namestr = ['STH']

class ppc_sthu(ppc_lbz):
    mask_list = [bm_int101101, bm_rt, bm_ra, bm_simm]
    namestr = ['STHU']

class ppc_stmw(ppc_stw):
    mask_list = [bm_int101111, bm_rt, bm_ra, bm_simm]
    namestr = ['STMW']


class ppc_mcrf(ppc_crand, ppc_mn):
    mask_list = [bm_int010011, bm_bf, bm_int00, bm_bfa, bm_int00, bm_int00000, bm_opc10, bm_int0]
    namestr = ['MCRFS', 'MCRF' ]
    namedct = {'MCRFS':64, 'MCRF':0}
    mask = {21:bm_set_meta("bm_mcrfopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('bf',cr), ('bfa',cr)]

class ppc_mcrxr(ppc_crand, ppc_mn):
    mask_list = [bm_int011111, bm_bf, bm_int00, bm_int00000, bm_int00000, bm_opc10, bm_int0]
    namestr = ['MCRXR' ]
    mask = {21:bm_set_meta("bm_mcrxropc",(bm_set,),{"fbits":[512], 'l':10})}

    do_args = [('bf',cr)]



class ppc_mfcr(ppc_crand, ppc_mn):
    mask_list = [bm_int011111, bm_rt, bm_int00000, bm_int00000, bm_opc10, bm_int0]
    namestr = ['MFCR', 'MFMSR', 'MTMSR']
    namedct = {'MFCR':19, 'MFMSR':83, 'MTMSR':146}
    mask = {21:bm_set_meta("bm_mcrfopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('rt',reg)]


class ppc_mffsx(ppc_cntlzw, ppc_mfcr):
    mask_list = [bm_int111111, bm_rt, bm_int00000, bm_int00000, bm_opc10, bm_rc]
    namestr = ['MFFSR']
    mask = {21:bm_set_meta("bm_mcrxropc",(bm_set,),{"fbits":[583], 'l':10})}


class ppc_mtfsb(ppc_exts, ppc_mn):
    mask_list = [bm_int111111, bm_bt, bm_int00000, bm_int00000, bm_opc10, bm_rc] #XXX TODO bm_bt doc zarb
    namestr = ['MTFSB0', 'MTFSB1']
    namedct = {'MTFSB0':70, 'MTFSB1':38}
    mask = {21:bm_set_meta("bm_mcrfopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('bt',crb)]


class ppc_mfspr(ppc_crand, ppc_mn):
    mask_list = [bm_int011111, bm_rt, bm_spr, bm_opc10, bm_int0]
    namestr = ['MFSPR']
    mask = {21:bm_set_meta("bm_mfspropc",(bm_set,),{"fbits":[339, 371], 'l':10})}#XXX TODO ZARB RETRO COMPAT?

    do_args = [('rt',reg), ('spr',spr)]

    def name2str(self):
        return self.namestr[0]
    def str2name(self, n):
        self.opc10 = 339 #XXX TODO default mnemo

class ppc_mtspr(ppc_mfspr, ppc_mn):
    mask_list = [bm_int011111, bm_rt, bm_spr, bm_opc10, bm_int0]
    namestr = ['MTSPR']
    mask = {21:bm_set_meta("bm_mcrxropc",(bm_set,),{"fbits":[467], 'l':10})}  #XXX TODO ZARB RETRO COMPAT? , 210

    do_args = [('spr',spr), ('rt',reg)]
    def str2name(self, n):
        self.opc10 = 467

class ppc_mfsr(ppc_crand, ppc_mn):
    mask_list = [bm_int011111, bm_rt, bm_int0, bm_sr, bm_int00000, bm_opc10, bm_int0]
    namestr = ['MFSR', 'MTSR']
    namedct = {'MFSR':595, 'MTSR':210}
    mask = {21:bm_set_meta("bm_mcrfopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('sr',sr), ('rt',reg)]

class ppc_mulhw(ppc_mn):
    mask_list = [bm_int011111, bm_rt, bm_ra, bm_rb, bm_int0, bm_opc9, bm_rc]
    namestr = ['MULHWU', 'MULHW']
    namedct = {'MULHW':75, 'MULHWU':11}
    mask = {22:bm_set_meta("bm_addopc",(bm_set,),{"fbits":namedct.values()})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('rt',reg), ('ra',reg), ('rb',reg)]

    def name2str(self):
        return self.strname[self.opc9]
    def str2name(self, n):
        self.opc9 = self.namedct[n]
    def rc2str(self):
        return ['','.'][self.rc==1]

    def parse_opts(self, opts):
        self.rc = 0
        if not opts:
            return
        if "." in opts:
            self.rc = 1


class ppc_mulli(ppc_addi):
    mask_list = [bm_int000111, bm_rt, bm_ra, bm_simm]
    namestr = ['MULLI']

class ppc_ori(ppc_addi):
    mask_list = [bm_int011000, bm_rt, bm_ra, bm_simm]
    namestr = ['ORI']

class ppc_oris(ppc_addi):
    mask_list = [bm_int011001, bm_rt, bm_ra, bm_simm]
    namestr = ['ORIS']


class ppc_rlwimi(ppc_mn):
    mask_list = [bm_int010100, bm_rt, bm_ra, bm_sh, bm_mb, bm_me, bm_rc]
    namestr = ['RLWIMI']

    do_args = [('ra',reg), ('rt',reg), ('sh',imm), ('mb',imm), ('me',imm)]

    def name2str(self):
        return self.namestr[0]
    @classmethod
    def check_opts(cls, rest):
        if rest in ["", "."]:
            return True
        return False

    def rc2str(self):
        return ['','.'][self.rc==1]

    def parse_opts(self, opts):
        self.rc = 0
        if not opts:
            return
        if "." in opts:
            self.rc = 1

class ppc_rlwinm(ppc_rlwimi):
    mask_list = [bm_int010101, bm_rt, bm_ra, bm_sh, bm_mb, bm_me, bm_rc]
    namestr = ['RLWINM']

class ppc_rlwnm(ppc_mn):
    mask_list = [bm_int010111, bm_rt, bm_ra, bm_rb, bm_mb, bm_me, bm_rc]
    namestr = ['RLWNM']

    do_args = [('ra',reg), ('rt',reg), ('rb',reg), ('mb',imm), ('me',imm)]


class ppc_sc(ppc_mn):
    mask_list = [bm_int010001, bm_offs, bm_int1, bm_int0]
    namestr = ['SC']
    def name2str(self):
        return self.namestr[0]

    def args2str(self):
        args = []
        args.append(imm2str(self.offs))
        return args



    def parse_args(self, args):
        self.offs = 0
        pass

    def __str__(self):
        name = self.getname()
        args = self.args2str()
        args = args2str(args)

        return name+" "+args


class ppc_srawi(ppc_cntlzw, ppc_mn):
    mask_list = [bm_int011111, bm_rs, bm_ra, bm_sh, bm_opc10, bm_rc]
    namestr = ['SRAWI']
    mask = {21:bm_set_meta("bm_srawiopc",(bm_set,),{"fbits":[824], 'l':10})}

    do_args = [('ra',reg), ('rs',reg), ('sh',imm)]

    def str2name(self, n):
        self.opc10 = 824

class ppc_subfic(ppc_addi):
    mask_list = [bm_int001000, bm_rt, bm_ra, bm_simm]
    namestr = ['SUBFIC']


class ppc_sync(ppc_eieio):
    mask_list = [bm_int011111, bm_int00000, bm_int00000, bm_int00000, bm_opc10, bm_int0]
    namestr = ['SYNC', 'TLBSYNC']
    namedct = {'SYNC':598, 'TLBSYNC':566}
    mask = {21:bm_set_meta("bm_syncopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}
    strname = dict((x[1], x[0]) for x in namedct.items())
    def name2str(self):
        return self.strname[self.opc10]
    def str2name(self, n):
        self.opc10 = self.namedct[n]


class ppc_tlb(ppc_sync, ppc_mn):
    mask_list = [bm_int011111, bm_int00000, bm_int00000, bm_rb, bm_opc10, bm_int0]
    namestr = ['TLBIE', 'TLBID', 'TLBLI']
    namedct = {'TLBIE':306, 'TLBLD':978, 'TLBLI':1010}
    mask = {22:bm_set_meta("bm_addopc",(bm_set,),{"fbits":namedct.values()})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('rb',reg)]

class ppc_xori(ppc_addi):
    mask_list = [bm_int011010, bm_rt, bm_ra, bm_simm]
    namestr = ['XORI']

class ppc_xoris(ppc_addi):
    mask_list = [bm_int011011, bm_rt, bm_ra, bm_simm]
    namestr = ['XORIS']


class ppc_tw(ppc_crand, ppc_mn):
    mask_list = [bm_int011111, bm_to, bm_ra, bm_rb, bm_opc10, bm_int0]
    namestr = ['TW']
    namedct = {'TW':4}
    mask = {21:bm_set_meta("bm_wiopc",(bm_set,),{"fbits":[4], 'l':10})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('to',imm), ('ra',reg), ('rb',reg)]

class ppc_twi(ppc_mn):
    mask_list = [bm_int000011, bm_to, bm_ra, bm_simm]
    namestr = ['TWI']

    do_args = [('to',imm), ('ra',reg), ('simm',imm)]

    def name2str(self):
        return self.namestr[0]



#FPU

class ppc_fabs(ppc_and, ppc_mn):
    mask_list = [bm_int111111, bm_frt, bm_int00000, bm_frb, bm_opc10, bm_rc]
    namestr = ['FABS', 'FCTIWZ', 'FCTIW', 'FMR', 'FNABS', 'FNEG', 'FRSP']
    namedct = {'FABS':264, 'FCTIWZ':15, 'FCTIW':14, 'FMR':72, 'FMABS':136, 'FNEG':40, 'FRSP':12}
    mask = {21:bm_set_meta("bm_addopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('frt',fpr), ('frb',fpr)]


class ppc_fdiv(ppc_fabs, ppc_mn):
    mask_list = [bm_int111111, bm_frt, bm_fra, bm_frb, bm_int00000, bm_opc5, bm_rc]
    namestr = ['FDIV', 'FSUB', 'FADD']
    namedct = {'FDIV':18, 'FSUB':20, 'FADD':21}
    mask = {26:bm_set_meta("bm_fdivopc",(bm_set,),{"fbits":namedct.values(), 'l':5})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('frt',fpr), ('fra',fpr), ('frb',fpr)]

    def name2str(self):
        return self.strname[self.opc5]
    def str2name(self, n):
        self.opc5 = self.namedct[n]

class ppc_fcmp(ppc_fabs, ppc_mn):
    mask_list = [bm_int111111, bm_bf, bm_int00, bm_fra, bm_frb, bm_opc10, bm_rc]
    namestr = ['FCMPO', 'FCMPU']
    namedct = {'FCMPO':32, 'FCMPU':0}
    mask = {21:bm_set_meta("bm_fcmpopc",(bm_set,),{"fbits":namedct.values(), 'l':10})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('bf',cr), ('fra',fpr), ('frb',fpr)]


class ppc_fdivs(ppc_fdiv):
    mask_list = [bm_int111011, bm_frt, bm_fra, bm_frb, bm_int00000, bm_opc5, bm_rc]
    namestr = ['FDIVS', 'FSUBS', 'FADDS']
    namedct = {'FDIVS':18, 'FSUBS':20, 'FADDS':21}
    mask = {26:bm_set_meta("bm_fdivsopc",(bm_set,),{"fbits":namedct.values(), 'l':5})}
    strname = dict((x[1], x[0]) for x in namedct.items())


class ppc_fmadd(ppc_fdiv, ppc_mn):
    mask_list = [bm_int111111, bm_frt, bm_fra, bm_frb, bm_frc, bm_opc5, bm_rc]
    namestr = ['FMADD', 'FMSUB', 'FNMADD', 'FNMSUB', 'FSEL']
    namedct = {'FMADD':29, 'FMSUB':28, 'FNMADD':31, 'FNMSUB':30, 'FSEL':23}
    mask = {26:bm_set_meta("bm_fmaddopc",(bm_set,),{"fbits":namedct.values(), 'l':5})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('frt',fpr), ('fra',fpr), ('frb',fpr), ('frc',fpr)]

class ppc_fmadds(ppc_fdiv):
    mask_list = [bm_int111011, bm_frt, bm_fra, bm_frb, bm_frc, bm_opc5, bm_rc]
    namestr = ['FMADDS', 'FMSUBS', 'FNMADDS', 'FNMSUBS']
    namedct = {'FMADDS':29, 'FMSUBS':28, 'FNMADDS':31, 'FNMSUBS':30}
    mask = {26:bm_set_meta("bm_fmaddsopc",(bm_set,),{"fbits":namedct.values(), 'l':5})}
    strname = dict((x[1], x[0]) for x in namedct.items())


class ppc_fmul(ppc_fdiv, ppc_mn):
    mask_list = [bm_int111111, bm_frt, bm_fra, bm_int00000, bm_frc, bm_opc5, bm_rc]
    namestr = ['FMUL']
    namedct = {'FMUL':25}
    mask = {26:bm_set_meta("bm_fmulopc",(bm_set,),{"fbits":namedct.values(), 'l':5})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('frt',fpr), ('fra',fpr), ('frc',fpr)]


class ppc_fmuls(ppc_fmul):
    mask_list = [bm_int111011, bm_frt, bm_fra, bm_int00000, bm_frc, bm_opc5, bm_rc]
    namestr = ['FMULS']
    namedct = {'FMULS':25}
    mask = {26:bm_set_meta("bm_fmaddsopc",(bm_set,),{"fbits":namedct.values(), 'l':5})}
    strname = dict((x[1], x[0]) for x in namedct.items())


class ppc_fres(ppc_fdiv, ppc_mn):
    mask_list = [bm_int111011, bm_frt, bm_int00000, bm_frb, bm_int00000, bm_opc5, bm_rc]
    namestr = ['FRES']
    namedct = {'FRES':24}
    mask = {26:bm_set_meta("bm_fmulopc",(bm_set,),{"fbits":namedct.values(), 'l':5})}
    strname = dict((x[1], x[0]) for x in namedct.items())

    do_args = [('frt', fpr),('frb', fpr)]


class ppc_frsqrte(ppc_fres):
    mask_list = [bm_int111111, bm_frt, bm_fra, bm_int00000, bm_frc, bm_opc5, bm_rc]
    namestr = ['FRSQRTE']
    namedct = {'FRSQRTE':26}
    mask = {26:bm_set_meta("bm_fmaddsopc",(bm_set,),{"fbits":namedct.values(), 'l':5})}
    strname = dict((x[1], x[0]) for x in namedct.items())


#order is important
tab_mn = [ppc_addi, ppc_ori, ppc_oris, ppc_xori, ppc_xoris, ppc_addic, ppc_addicp, ppc_addis, ppc_adde, ppc_and,
          ppc_andip, ppc_andisp, ppc_bctr, ppc_bc, ppc_b, ppc_cmpli, ppc_cmpi, ppc_cmp, ppc_cntlzw,
          ppc_crand, ppc_dcb, ppc_eciw, ppc_eieio, ppc_exts, ppc_isync, ppc_lfsu, ppc_lfdu, ppc_lfs, ppc_lfd, ppc_lbzu,
          ppc_lbz, ppc_lhau, ppc_lha, ppc_lhzu, ppc_lhz, ppc_lmw, ppc_wi, ppc_lwzu,
          ppc_lwz, ppc_stwu, ppc_stw, ppc_stfdu, ppc_stfd, ppc_stfdx, ppc_stfsu,
          ppc_stfs, ppc_sthu, ppc_sth, ppc_stmw, ppc_stbu, ppc_stb, ppc_mcrxr, ppc_mcrf,
          ppc_mffsx, ppc_mfspr, ppc_mfcr, ppc_mtfsb, ppc_mtspr, ppc_mfsr, ppc_mulhw, ppc_mulli,
          ppc_rlwimi, ppc_rlwinm, ppc_rlwnm, ppc_sc, ppc_srawi, ppc_subfic,
          ppc_sync, ppc_tlb, ppc_add, ppc_twi, ppc_tw,

          ppc_fabs, ppc_fcmp, ppc_fdivs, ppc_fdiv, ppc_fmadds, ppc_fmadd, ppc_fmuls, ppc_fmul,
          ppc_frsqrte, ppc_fres]



if __name__ == "__main__":

    import struct


    for op in [0x7D4A5214, 0x7FAA4A14, 0x7D615A14]:

        m = ppc_mn(op)
        print m


    txt = """
    ADD R10, R10, R10
    ADDO. R10, R10, R10
    ADD R29, R10, R9
    ADD R11, SP, R11
    LI R10, 0x23
    LIS R10, 0x23
    ADDIS R10, R0, 0x23
    ADDI R10, R0, 0x23
    ADDI R0, R11, -0x7
    ADDIC R8, R6, -1
    ADDIC. R5, R5, -1
    ADDIS R4, R31, 1
    ADDME R7, R5
    AND R11, R11, R4
    ANDC R11, R11, R3
    AND. R5, R5, R4
    ANDI. R30, R30, 0x2e00
    ANDIS. R11, R3, 0x8000
    BA 0x1337
    BL 0x1337
    B 0x3
    CMPL CR0, R3, R4
    CMPL R3, R4
    CMP  CR0, R3, R4
    CMP  R3, R4
    CMPLI CR0, R0, 0x18
    CMPLI R0, 0x18
    CMPI CR0, R3, 1
    CMPI CR0, R28, -1
    CMPLI CR5, R11, 3
    CNTLZW R4, R9
    CRAND CR0_EQ, CR1_EQ, CR2_EQ
    CRNOR CR5_LT, CR5_LT, CR6_LT
    DCBT R4, R5
    DIVWU R0, R29, R10
    DIVW R0, R12, R11
    ECIW R0, R0, R0
    EIEIO
    EXTSH R11, R3
    ISYNC
    LBZ R11, R11, 0x70
    LBZX R12, R3, R12
    LHA R3, R31, 2
    LHAU R3, R31, 2
    LHZ R3, R5, 0xA
    LHZX R12, R4, R12
    LMW R27, SP, 0xC
    LSWI R7, R12, 4
    STSWI R7, R11, 4
    LWZ R0, SP, 0xC
    STW R0, SP, 8
    STWU SP, SP, -0x10
    LWZX R9, R3, R11
    STWX R7, R9, R8
    STBX R12, R31, R4
    STFD FP31, SP, 0x28
    STFS FP1, R8, 4
    STH R4, R6, 2
    STHX R11, R6, R7
    STMW R27, SP, 0xC
    MCRF CR0, CR1
    MFSR SR1, R0
    MTSR SR1, R0
    MULHWU R30, R12, R27
    MULLI R9, R25, 0x90
    MULLW R10, R26, R10
    ORI R4, R4, 0x60b6
    ORIS R3, R3, -1
    RFI
    RLWINM R30, R28, 26, 22, 25
    RLWINM. R10, R3, 0, 21, 21
    SLW R6, R6, R12
    SRAWI R11, R11, 1
    STB R12, SP, 0xC
    SUBF R4, R5, R4
    SUBFE R11, R30, R5
    SUBFIC R3, R7, 0xFF
    SUBFZE R30, R30
    SYNC
    XOR R6, R12, R11
    XORIS R11, R11, 0x8000
    FCTIWZ FP0, FP13
    FNEG FP3, FP1
    FMR FP1, FP31
    FRSP FP1, FP13
    FDIVS FP1, FP2, FP1
    FSUB FP13, FP13, FP12
    FSUBS FP11, FP2, FP11
    FADDS FP1, FP13, FP11
    FMADD FP1, FP2, FP3, FP4
    FMADD. FP1, FP2, FP3, FP4
    FMULS FP13, FP13, FP11
    FRES FP1, FP2
    BGE 0x10
    BLE 0x10
    BNE 0x10
    BNS 0x10
    BLT 0x10
    BGT 0x10
    BEQ 0x10
    BSO 0x10
    BGE CR1, 0x10
    BDNZ 0x10
    BDNZ LE, 0x10
    BDNZ LE, CR1, 0x10
    MFSPR R0, LR
    MTSPR LR, R0
    BC LE, CR1, 0x10
    BLE CR1, 0x10
    BLR
    BC 0x10
    FCMPU CR1, FP1, FP3
    MTFSB0 CR1_LT
    TW 1, R3, R4
    TWI 3, R4, 8
    SC"""


    #    UNDEF 0x1337, 1

    txt = txt.split('\n')[1:]
    for t in txt:
        print "___%s___"%t
        op1 = ppc_mn.asm(t)[0]
        h = struct.unpack('>L', op1)
        print "bin: %.8X"%h
        m = ppc_mn.dis(op1)
        print "dis:", str(m)
        token_a = [x for x in shlex.shlex(t)]
        token_b = [x for x in shlex.shlex(str(m))]
        token_a = filter(lambda x:not x in ['-', ',', 'CR0'] and not is_imm(x), token_a)
        token_b = filter(lambda x:not x in ['-', ',', 'CR0'] and not is_imm(x), token_b)
        print token_a
        print token_b

        op2 = ppc_mn.asm(str(m))[0]
        h = struct.unpack('>L', op2)
        print "%.8X"%h
        if op1 !=op2 or (token_a != token_b and not token_b[0] in ['BLE', 'ADDI', 'LI', 'ADDIS', 'LIS']):
            raise ValueError('bug in self test', t)


