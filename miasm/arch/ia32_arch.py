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
from miasm.tools.modint import uint1, uint8, uint16, uint32, uint64, int8, int16, int32, int64
import struct
import logging
from miasm.core.parse_ad import parse_ad, ad_to_generic
from miasm.arch.ia32_reg import x86_afs
import shlex


log = logging.getLogger("x86escape")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


tab_int_size = {int8:8,
                uint8:8,
                int16:16,
                uint16:16,
                int32:32,
                uint32:32,
                int64:64,
                uint64:64
                }

tab_size2int = {x86_afs.s08:int8,
                x86_afs.u08:uint8,
                x86_afs.s16:int16,
                x86_afs.u16:uint16,
                x86_afs.s32:int32,
                x86_afs.u32:uint32,
                }

tab_max_uint = {x86_afs.u08:0xFF, x86_afs.u16:0xFFFF, x86_afs.u32:0xFFFFFFFF, x86_afs.u64:0xFFFFFFFFFFFFFFFFL}



prefix_dic = {"lock":0xF0, "repnz":0xF2, "repne":0xF2, "repz":0xF3, "repe":0xF3, "rep":0xF3, }

prefix_dic_inv = dict(map(lambda x:(x[1],x[0]), prefix_dic.items()))

#'es'|'cs'|'ss'|'ds'|'fs'|'gs') ':' '''
prefix_seg = {0:0x26, 1:0x2E, 2:0x36, 3:0x3E, 4:0x64, 5:0x65}

prefix_seg_inv = dict(map(lambda x:(x[1],x[0]), prefix_seg.items()))

class mnemonic:
    def __init__(self, name, opc, afs, rm, modifs, modifs_orig, sem):
        self.name = name
        self.opc = opc

        self.afs = afs
        self.rm = rm

        self.modifs = modifs
        self.modifs_orig = modifs_orig

    def __str__(self):
        return self.name+' '+str(self.opc)+' '+str(self.afs)+' '+str(self.rm)+' '+str(self.modifs)+' '+str(self.modifs_orig)#+' '+str(self.sem)+' '


def mask_opc_to_i(mask, opc):
    log.debug("mask %x opc %x"%(mask, opc))
    return [i for i in range(0x100) if (i & mask) == opc]

mask_d = 0x38
mask_reg = 0xF8
mask_cond = 0xF0

d0 = 0<<3
d1 = 1<<3
d2 = 2<<3
d3 = 3<<3
d4 = 4<<3
d5 = 5<<3
d6 = 6<<3
d7 = 7<<3
reg = "reg"
noafs = "noafs"
cond = "cond"
cond_list = [["o"],
             ["no"],
             ["nae","c","b"],
             ["nb","nc","ae"],
             ["z","e"],
             ["ne","nz"],
             ["be"],
             ["a"],
             ["s"],
             ["ns"],
             ["pe","p"],
             ["po","np"],
             ["nge","l"],
             ["nl","ge"],
             ["ng","le"],
             ["nle","g"],
             ]
no_rm = []
rmr = "rmr"

imm = x86_afs.imm
ims = x86_afs.ims
mim = x86_afs.mim
u08 = x86_afs.u08
s08 = x86_afs.s08
u16 = x86_afs.u16
s16 = x86_afs.s16
u32 = x86_afs.u32
s32 = x86_afs.s32
im1 = x86_afs.im1
im3 = x86_afs.im3

r_eax = {x86_afs.r_eax:1, x86_afs.ad:False}
r_cl  = {x86_afs.reg_list8.index(x86_afs.r_cl):1, x86_afs.ad:False, x86_afs.size:x86_afs.u08}
r_dx  = {x86_afs.reg_list16.index(x86_afs.r_dx):1, x86_afs.ad:False, x86_afs.size:x86_afs.u16}

r_es = 'es'
r_ss = 'ss'
r_cs = 'cs'
r_ds = 'ds'
r_fs = 'fs'
r_gs = 'gs'

segm_regs = [r_es, r_ss, r_cs, r_ds, r_fs, r_gs]

w8 = "w8"
se = "se"
sw = "sw"
ww = "ww"
sg = "sg" # segment reg
dr = "dr" # debug reg
cr = "cr" # control reg
ft = "ft" # float
w64= "w64"
sd = "sd" # single/double
wd = "wd" # word/dword


bkf = "breakflow"
spf = "splitflow"
dtf = "dstflow"

seip = "seip" #seteip
stpeip = "stpeip" #stop eip

unsanity_mnemo = ['nop', 'monitor', 'mwait', 'fadd', 'faddp', 'fiadd', 'fcmovb', 'fcom', 'fcomp', 'fcomip',
                  'fdiv', 'fdivr', 'fidivr', 'fdivrp', 'ficom', 'ficomp', 'fild', 'fist', 'fistp', 'fisttp',
                  'fld', 'fldcw', 'fld1', 'fldl2t', "fldl2e", "fldpi", "fldlg2", "fldln2", "fldz", 'fldenv', 'fmul', 'fimul', 'fmulp', 'fst', 'fstp', 'fnstcw', 'fnstenv', 'f2xm1',
                  'fnstsw', 'fsub', 'fsubr', 'fisubr', 'fsubrp', 'ftst', 'fucom', 'fucompp', 'fxam', 'fxtract', 'fyl2x', 'fyl2xp1', 'fsqrt', 'fsincos', 'fsin', 'fscale',
                  'fcos', 'fdecstp', 'fnop', 'fpatan', 'fprem', 'fprem1', 'fptan', 'frndint', "shl", 'sal', 'sar', 'fabs',
                  "jmpff",
                  "fcomi", "fucomi", "fucomip", "fdivp"]


mask_drcrsg = {cr:0x100, dr:0x200, sg:0x400}

def hexdump(a):
    return reduce(lambda x,y:x+"%.2X"%ord(y), a, "")

def is_address(a):
    if x86_afs.ad in a and a[x86_afs.ad]:
        return True
    return False

def is_imm(a):
    if x86_afs.ad in a and a[x86_afs.ad]:
        return False
    if not (x86_afs.imm in a or x86_afs.symb in a) :
        return False
    for k in a:
        if not k in [x86_afs.imm, x86_afs.size, x86_afs.ad, x86_afs.symb]:
            return False
    return True

def is_ad_lookup(a):
    if not x86_afs.ad in a or not a[x86_afs.ad]:
        return False
    if not (x86_afs.imm in a or x86_afs.symb in a) :
        return False
    for k in a:
        if not k in [x86_afs.imm, x86_afs.size, x86_afs.ad, x86_afs.symb]:
            return False
    return True

def is_reg(a):
    if x86_afs.ad in a and a[x86_afs.ad]:
        return False
    if x86_afs.imm in a:
        return False
    if x86_afs.symb in a:
        return False

    return True

def get_label(a):
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



def check_imm_size(imm, size):
    i = int32(uint32(imm))
    if not size in [u08, s08, u16, s16, u32, s32]:
        raise ValueError("unknown size %s"%size)
    if size == u08 and imm >= 0 and imm < 0x100:
        return uint8(imm)
    elif size == s08 and i >=-0x80 and i < 0x80:
        return int8(i)
    elif size == u16 and imm >= 0 and imm < 0x10000:
        return uint16(imm)
    elif size == s16 and i >=-0x8000 and i < 0x8000:
        return int16(i)
    elif size == u32 and imm >=-0x100000000L and imm < 0x100000000L:
        return uint32(imm)
    elif size == s32 and i >=-0x80000000 and i < 0x80000000:
        return int32(i)
    return None

def dict_to_ad(d, modifs = {}, opmode = u32, admode = u32):
    size = [x86_afs.u32, x86_afs.u08][modifs[w8]==True]
    #overwrite w8
    if modifs[sd]!=None:
        size = [x86_afs.f32, x86_afs.f64][modifs[sd]==True]
    elif modifs[wd]:
        size = x86_afs.u16

    tab32 = {x86_afs.u08:x86_afs.reg_list8, x86_afs.u16:x86_afs.reg_list16, x86_afs.u32:x86_afs.reg_list32,x86_afs.f32:x86_afs.reg_flt, x86_afs.f64:x86_afs.reg_flt}
    tab16 = {x86_afs.u08:x86_afs.reg_list8, x86_afs.u16:x86_afs.reg_list32, x86_afs.u32:x86_afs.reg_list16}
    ad_size = {x86_afs.u08:"byte ptr", x86_afs.u16:"word ptr", x86_afs.u32:"dword ptr", x86_afs.f32:"single ptr", x86_afs.f64:"double ptr"}

    if is_reg(d):
        n = [x for x in d if type(x) in [int, long]]
        if len(n)!=1:
            raise ValueError("bad reg! %s"%str(d))
        n = n[0]
        if x86_afs.size in d and d[x86_afs.size] == x86_afs.size_seg :
            t = x86_afs.reg_sg
        elif x86_afs.size in d:
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
            t = x86_afs.reg_dr
            n&=7
        if modifs[cr] and n>0x7:
            t = x86_afs.reg_cr
            n&=7
        if modifs[sg] and n>0x7:
            t = x86_afs.reg_sg
            n&=7
        if modifs[sd] is not None:
            t = tab32[size]
            n&=7

        try:
            out = t[n]
        except:
            print 'WARNING!dict2ad', t, str(d)
            out = ""
    elif is_imm(d):
        out = ""
        if x86_afs.imm in d:
            imm_tmp = int(d[x86_afs.imm]) &0xffffffffL
            if imm_tmp<0:
                out+='-0x%.8X'%-imm_tmp
            else:
                out+='0x%.8X'%imm_tmp
        if x86_afs.symb in d:
            #XXX todo multiple ref
            if out!="": out+='+'
            for c in d[x86_afs.symb]:
                if d[x86_afs.symb][c]==1:
                    out += '%s'%str(c.name)
                else:
                    out += '%d,%s'%(int(d[x86_afs.symb][c]), str(c))
    elif is_address(d):
        if x86_afs.size in d:
            size = d[x86_afs.size]
        out = [ad_size[size]]
        segment = " "
        if x86_afs.segm in d:
            segment += x86_afs.reg_sg[d[x86_afs.segm]]+':'
        for k in d:
            if k in [x86_afs.ad, x86_afs.size, x86_afs.segm]:
                continue
            elif k == x86_afs.imm:
                if int(d[k])<0:
                    out.append('-0x%.8X'%-int(d[k]))
                else:
                    out.append('0x%.8X'%int(d[k]))
            elif type(k) in [int, long]:
                if d[k] ==1:
                    if admode == u32:
                        out.append(x86_afs.reg_list32[k])
                    else:
                        out.append(x86_afs.reg_list16[k])
                else:
                    if admode == u32:
                        out.append(str(int(d[k]))+'*'+x86_afs.reg_list32[k])
                    else:
                        out.append(str(int(d[k]))+'*'+x86_afs.reg_list16[k])

            elif k == x86_afs.symb:
                out.append(str(d[k]))
            else:
                raise ValueError('strange ad componoant: %s'%str(d))
        out = out[0]+segment+'['+ reduce(lambda x,y: x+"+"+y, out[1:], "")[1:] + ']'
    else:
        raise ValueError('unknown arg %s'%str(d))
    return out



class x86allmncs:
    def print_op(self, optab, decal):
        cpt = -1
        for i in optab:
            cpt+=1
            if type(i) == list:
                self.print_op(i, decal+1)
            elif i == None:
                pass
            else:
                print "%.3d "%cpt+"\t"*decal + str(i)

    def print_tab(self):
        for i in range(0x100):
            if type(self.db_afs[i]) == list:
                for j in range(0x100):
                    print "%.2X %.2X\t"%(i,j),
                    print self.db_afs[i][j]
            else:
                print "%.2X\t"%i+str(self.db_afs[i])

    def get_afs(self, bin, m, size_m):
        if size_m == u32:
            db_afs = self.db_afs
            my_uint = uint32
        else:
            db_afs = self.db_afs_16
            my_uint = uint16

        mod, re, rm = self.modrm(m)

        if type(db_afs[m])==list:
            a = dict(db_afs[m][ord(bin.readbs())])
        else:
            a = dict(db_afs[m])
        if x86_afs.imm in a:
            if a[x86_afs.imm] == x86_afs.u08:
                a[x86_afs.imm] = my_uint(struct.unpack('B', bin.readbs())[0])
            elif a[x86_afs.imm] == x86_afs.s08:
                a[x86_afs.imm] = my_uint(struct.unpack('b', bin.readbs())[0])
            elif a[x86_afs.imm] == x86_afs.u32:
                a[x86_afs.imm] = my_uint(struct.unpack('I', bin.readbs(4))[0])
            elif a[x86_afs.imm] == x86_afs.u16:
                a[x86_afs.imm] = my_uint(struct.unpack('H', bin.readbs(2))[0])
            else:
                raise ValueError('imple other afs ... ', str(a[x86_afs.imm]))
        return re, a

    def get_afs_re(self, re):
        return {x86_afs.ad:False, re:1}

    def get_im_fmt(self, modifs, mnemo_mode, im):
        if modifs[se]:
            fmt,t = ('b',s08)
        elif modifs[w8]:
            if im == x86_afs.imm:
                fmt,t = ('B',u08)
            elif im == x86_afs.ims:
                fmt,t = ('b',s08)
            else:
                raise ValueError("error encode %s"%str(im))
        else:
            if im == x86_afs.imm:
                if mnemo_mode == u32: fmt,t = ('I',u32)
                else:                 fmt,t = ('H',u16)
            elif im == x86_afs.ims:
                if mnemo_mode == u32: fmt,t = ('i',s32)
                else:                 fmt,t = ('h',s16)


        return struct.calcsize(fmt), fmt,t

    def modrm(self, c):
        return (c>>6)&3, (c>>3)&7, c&7
    def sib(self, c):
        return self.modrm(c)

    def init_pre_modrm(self):

        self.sib_rez_u08_ebp = [{x86_afs.ad:True} for i in range(0x100)]
        self.sib_rez_u32_ebp = [{x86_afs.ad:True} for i in range(0x100)]
        self.sib_rez_u32 = [{x86_afs.ad:True} for i in range(0x100)]

        for sib_rez in [self.sib_rez_u08_ebp,
                        self.sib_rez_u32_ebp,
                        self.sib_rez_u32
                        ]:
            for index in range(0x100):
                ss, i, r = self.modrm(index)

                if r == 5:
                    if sib_rez == self.sib_rez_u08_ebp:
                        sib_rez[index][x86_afs.imm] = x86_afs.s08
                        sib_rez[index][x86_afs.reg_dict[x86_afs.r_ebp]] = 1
                    elif sib_rez == self.sib_rez_u32_ebp:
                        sib_rez[index][x86_afs.imm] = x86_afs.u32
                        sib_rez[index][x86_afs.reg_dict[x86_afs.r_ebp]] = 1
                    elif sib_rez == self.sib_rez_u32:
                        sib_rez[index][x86_afs.imm] = x86_afs.u32
                else:
                    if sib_rez == self.sib_rez_u08_ebp:
                        sib_rez[index][r]=1
                        sib_rez[index][x86_afs.imm] = x86_afs.s08
                    elif sib_rez == self.sib_rez_u32_ebp:
                        sib_rez[index][r]=1
                        sib_rez[index][x86_afs.imm] = x86_afs.u32
                    elif sib_rez == self.sib_rez_u32:
                        sib_rez[index][r]=1


                if i == 4:
                    continue

                tmp = i
                if tmp in sib_rez[index]:
                    sib_rez[index][tmp]+=[1, 2, 4, 8][ss]
                else:
                    sib_rez[index][tmp] =[1, 2, 4, 8][ss]

        #32bit
        self.db_afs = [None for i in range(0x100)]
        for i in range(0x100):
            index = i
            mod, re, rm = self.modrm(i)

            if mod == 0:
                if rm == 4:
                    self.db_afs[index] = self.sib_rez_u32
                elif rm == 5:
                    self.db_afs[index] = {x86_afs.ad:True, x86_afs.imm:x86_afs.u32}
                else:
                    self.db_afs[index] = {x86_afs.ad:True, rm:1}
            elif mod == 1:
                if rm == 4:
                    self.db_afs[index] = self.sib_rez_u08_ebp
                    continue
                tmp = {x86_afs.ad:True, rm:1}
                if rm == 0:
                    tmp[x86_afs.imm] = x86_afs.s08
                else:
                    tmp[x86_afs.imm] = x86_afs.s08
                self.db_afs[index] = tmp

            elif mod == 2:
                if rm == 4:
                    self.db_afs[index] = self.sib_rez_u32_ebp
                else:
                    self.db_afs[index] = {x86_afs.ad:True, rm:1,x86_afs.imm:x86_afs.u32}
            elif mod == 3:
                self.db_afs[index] = {x86_afs.ad:False, rm:1}

        #16bit
        self.db_afs_16 = [None for i in range(0x100)]
        _si = x86_afs.reg_dict[x86_afs.r_si]
        _di = x86_afs.reg_dict[x86_afs.r_di]
        _bx = x86_afs.reg_dict[x86_afs.r_bx]
        _bp = x86_afs.reg_dict[x86_afs.r_bp]
        for i in range(0x100):
            index = i
            mod, re, rm = self.modrm(i)

            if mod == 0:
                if rm == 4:
                    self.db_afs_16[index] = {x86_afs.ad:True,_si:1}
                elif rm == 5:
                    self.db_afs_16[index] = {x86_afs.ad:True,_di:1}
                elif rm == 6:
                    self.db_afs_16[index] = {x86_afs.ad:True,x86_afs.imm:x86_afs.u16}#{x86_afs.ad:True,_bp:1}
                elif rm == 7:
                    self.db_afs_16[index] = {x86_afs.ad:True,_bx:1}
                else:
                    self.db_afs_16[index] = {x86_afs.ad:True,
                                             [_si, _di][rm%2]:1,
                                             [_bx, _bp][(rm>>1)%2]:1}
            elif mod in [1,2]:
                if mod==1:
                    if rm==0:
                        my_imm=x86_afs.s08
                    else:
                        my_imm=x86_afs.s08
                else:
                    my_imm=x86_afs.u16

                if rm==4:
                    self.db_afs_16[index] = {x86_afs.ad:True,_si:1, x86_afs.imm:my_imm}
                elif rm==5:
                    self.db_afs_16[index] = {x86_afs.ad:True,_di:1, x86_afs.imm:my_imm}
                elif rm==6:
                    self.db_afs_16[index] = {x86_afs.ad:True,_bp:1, x86_afs.imm:my_imm}
                elif rm==7:
                    self.db_afs_16[index] = {x86_afs.ad:True,_bx:1, x86_afs.imm:my_imm}
                else:
                    self.db_afs_16[index] = {x86_afs.ad:True,
                                             [_si, _di][rm%2]:1,
                                             [_bx, _bp][(rm>>1)%2]:1,
                                             x86_afs.imm:my_imm}

            elif mod == 3:
                self.db_afs_16[index] = {x86_afs.ad:False, rm:1}


    def addop(self, name, opc, afs, rm, modif_desc, prop_dict, sem):
        prop_dict.update(sem)
        modifs = dict([[x, True] for x in modif_desc])
        base_modif = dict([[x, None] for x in [w8, se, sw, ww, sg, dr, cr, ft, w64, sd, wd, bkf, spf, dtf]])
        base_modif.update(modifs)

        #update with forced properties
        base_modif.update(prop_dict)
        base_mnemo = [(opc, base_modif)]

        #XXX zarb: default se inverted?
        if se in modif_desc:
            tmp = base_mnemo[0][1]
            tmp[se] = False
            base_mnemo = [(base_mnemo[0][0], tmp)]

        log.debug(modifs)
        for modif in modifs:
            base_mnemo_add = []
            for opc, n_m in base_mnemo:
                n_m = dict(n_m)
                n_m[modif]= not n_m[modif]

                opc = opc[:]
                opc[modif_desc[modif][0]] |=(1<<modif_desc[modif][1])

                base_mnemo_add.append((opc, n_m))

            base_mnemo+=base_mnemo_add

        for opc, n_m in base_mnemo:
            #unassociable modifs XXX here cause structure generation
            if n_m[se] and n_m[w8]:
                continue

            if afs in [d0, d1, d2, d3, d4, d5, d6, d7]:
                opc+=[afs]
                mask = mask_d
            elif afs in [reg]:
                mask = mask_reg
            elif afs == noafs:
                mask = 0xFF
            elif afs == cond:
                mask = mask_cond
            else:
                raise ValueError('bug in %s %d'%(name, afs))

            #find mnemonic table
            insert_tab = self.db_mnemo
            log.debug(name)
            log.debug(opc )
            log.debug(mask)
            for i in opc[:-1]:
                if insert_tab[i] == None:
                    insert_tab[i] = [None for x in range(0x100)]
                insert_tab = insert_tab[i]

            keys = mask_opc_to_i(mask, opc[-1])
            if afs == cond:
                for k in keys:
                    opc_tmp = opc[:]
                    i_k = k&(mask_cond^0xFF)
                    opc_tmp[-1]|=i_k
                    for cond_suffix in cond_list[i_k]:
                        mnemo = mnemonic(name+cond_suffix, opc_tmp, afs, rm, n_m, modif_desc, sem)
                        #if insert_tab[k]!=None and not name in unsanity_mnemo:
                        #    raise ValueError("sanity check fail in mnemo affect %s"%str(insert_tab[k]))
                        insert_tab[k] = mnemo
                        #fast mnemo_lookup
                        if not mnemo.name in self.mnemo_lookup:
                            self.mnemo_lookup[mnemo.name] = [mnemo]
                        elif not mnemo in self.mnemo_lookup[mnemo.name]:
                            self.mnemo_lookup[mnemo.name].append(mnemo)

            else:
                mnemo = mnemonic(name, opc, afs, rm, n_m, modif_desc, sem)
                for k in keys:
                    if insert_tab[k]!=None and not name in unsanity_mnemo:
                        raise ValueError("sanity check fail in mnemo affect %s"%str(insert_tab[k]))
                    insert_tab[k] = mnemo
                    #fast mnemo_lookup
                    if not mnemo.name in self.mnemo_lookup:
                        self.mnemo_lookup[mnemo.name] = [mnemo]
                    elif not mnemo in self.mnemo_lookup[mnemo.name]:
                        self.mnemo_lookup[mnemo.name].append(mnemo)

    def find_mnemo(self, name, mnemo_list = None, candidate = None):
        if name in self.mnemo_lookup.keys():
            return self.mnemo_lookup[name]
        else:
            return []







    def get_address_afs(self, a):
        l = parse_ad(a)
        return ad_to_generic(l)

    def get_address_afs_hex(self, adprops):
        out = []
        for ad in adprops:
            candidate = []
            for i in range(0x100):
                index = i&0xC7
                if type(self.db_afs[index])==list:
                    for j in range(0x100):
                        if self.db_afs[index][j] == ad:
                            if not (index, j)  in candidate:
                                candidate.append((index, j) )

                else:
                    if self.db_afs[index] == ad:
                        if not (index, None)  in candidate:
                            candidate.append((index, None) )

            out.append(candidate)
        return out

    def forge_opc(self, out_opc, a, a2 = None):
        if a2!=None :
            k = [x for x in a2.keys() if type(x) in [long, int]]
            if a2[x86_afs.ad] or x86_afs.imm in a2 or len(k)!=1:
                raise ValueError('bad a2 forge %s'%str(a2))
            out_opc[0].append(k[0]<<3)

        #if not a[x86_afs.ad]:
        del a[x86_afs.size]

        log.debug(a)
        b = ad_to_generic(a)
        log.debug(b)
        raw = self.get_address_afs_hex(b)
        b_out = []
        raw_out = []
        for i in range(len(b)):
            if not raw[i] :
                continue
            b_out.append(b[i])
            raw_out.append(raw[i])

        b = b_out
        raw = raw_out
        out_opc_o = []
        p_val = []

        for i in range(len(raw)):
            for r in raw[i]:
                out_opc_o.append(out_opc[0][:])
                out_opc_o[-1][-1]|=r[0]
                if r[1]!=None:
                    out_opc_o[-1].append(r[1])
                log.debug( b[i])
                if x86_afs.imm in b[i]:
                    if x86_afs.imm in a:
                        v = a[x86_afs.imm]
                    else:
                        v = 0

                    v = check_imm_size(v, b[i][x86_afs.imm])
                    if v == None:
                        log.debug("cannot encode this val in size forge!")
                        return None, None

                    p_val.append({x86_afs.size:b[i][x86_afs.imm], x86_afs.imm:v})
                else:
                    p_val.append({})

        return out_opc_o, p_val

    def check_size_modif(self, size, modifs):
        if modifs[sd] is not None:
            if size != [x86_afs.f32, x86_afs.f64][modifs[sd]==False]: #XXX 32 should be reg not stX???
                log.debug('checksize: not good fXX (%s)'%str(size))
                return False
            else:
                return True
        if modifs[wd] is not None:
            if size != [x86_afs.u32, x86_afs.u16][modifs[wd]]:
                log.debug('checksize: not good w/dw')
                return False
            else:
                return True

        if size != [x86_afs.u32, x86_afs.u08][modifs[w8]==True]:
            log.debug('checksize: not good w8:%s'%str(size))
            return False
        return True


    def __init__(self):

        self.mnemo_lookup = {}
        self.init_pre_modrm()
        self.op_db = {}

        self.db_mnemo = [None for x in range(0x100)]
        addop = self.addop


        #x86

        addop("aaa",   [0x37],             noafs, no_rm         , {}                 ,{}                , {},                         )
        #addop("aad",   [0xD5, 0x0A],       noafs, no_rm         , {}                 ,{}                , {},                         )
        #addop("aam",   [0xD4, 0x0A],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("aad",   [0xD5],             noafs, [u08]         , {}                 ,{}                , {},                         )
        addop("aam",   [0xD4],             noafs, [u08]         , {}                 ,{}                , {},                         )

        addop("aas",   [0x3F],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("adc",   [0x14],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("adc",   [0x80],             d2,    [imm]         , {w8:(0,0),se:(0,1)},{}                , {},                         )
        addop("adc",   [0x10],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("add",   [0x04],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("add",   [0x80],             d0,    [imm]         , {w8:(0,0),se:(0,1)},{}                , {},                         )
        addop("add",   [0x00],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("and",   [0x24],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("and",   [0x80],             d4,    [imm]         , {w8:(0,0),se:(0,1)},{w8:True}         , {},                         )
        addop("and",   [0x20],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("arpl",  [0x63],             noafs, [rmr]         , {}                 ,{sw:True,wd:True} , {},                         )

        addop("bsf",   [0x0F, 0xBC],       noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("bsr",   [0x0F, 0xBD],       noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("bswap", [0x0F, 0xC8],       reg  , no_rm         , {}                 ,{}                , {},                         )

        addop("bt",    [0x0F, 0xA3],       noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )
        addop("bt",    [0x0F, 0xBA],       d4   , [u08]         , {}                 ,{}                , {},                         )
        addop("btc",   [0x0F, 0xBB],       noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )
        addop("btc",   [0x0F, 0xBA],       d7   , [u08]         , {}                 ,{}                , {},                         )
        addop("btr",   [0x0F, 0xB3],       noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )
        addop("btr",   [0x0F, 0xBA],       d6   , [u08]         , {}                 ,{}                , {},                         )
        addop("bts",   [0x0F, 0xAB],       noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )
        addop("bts",   [0x0F, 0xBA],       d5   , [u08]         , {}                 ,{}                , {},                         )

        addop("call",  [0xE8],             noafs, [s32]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("call",  [0xFF],             d2   , no_rm         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("call",  [0x9A],             noafs, [imm,u16]     , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("callf", [0xFF],             d3,    no_rm         , {}                 ,{}                , {bkf:True,spf:True,dtf:True}) #XXX

        addop("cbw",   [0x98],             noafs, [r_eax]       , {}                 ,{}                , {},                         )
        addop("clc",   [0xF8],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("cld",   [0xFC],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("cli",   [0xFA],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("clts",  [0x0F, 0x06],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("cmc",   [0xF5],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("cmov",  [0x0F, 0x40],       cond , [rmr]         , {}                 ,{}                , {},                         )

        addop("cmp",   [0x3C],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("cmp",   [0x80],             d7,    [imm]         , {w8:(0,0),se:(0,1)},{}                , {},                         )
        addop("cmp",   [0x38],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("cmpsb", [0xA6],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        addop("cmpsd", [0xA7],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )


        addop("cmpxchg",[0x0F, 0xB0],      noafs, [r_eax,rmr]   , {w8:(1,0)}         ,{}                , {},                         )
        addop("cmpxchg8b",[0x0F, 0xC7],    d1   , no_rm         , {}                 ,{}                , {},                         )
        addop("cpuid", [0x0F, 0xA2],       noafs, no_rm         , {}                 ,{}                , {},                         )

        #ddop("cwd",   [0x99],             noafs, [r_eax]       , {}                 ,{}                , {},                         )
        addop("cdq",   [0x99],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("daa",   [0x27],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("das",   [0x2F],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("dec",   [0x48],             reg  , no_rm         , {}                 ,{}                , {},                         )
        addop("dec",   [0xFE],             d1   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )
        addop("div",   [0xF6],             d6   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("enter", [0xC8],             noafs, [u16, u08]    , {}                 ,{}                , {},                         )

        addop("hlt",   [0xF4],             noafs, no_rm         , {}                 ,{}                , {bkf:True}                  )

        addop("idiv",  [0xF6],             d7   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("imul",  [0xF6],             d5   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )
        addop("imul",  [0x0F, 0xAF],       noafs, [rmr]         , {}                 ,{sw:False}        , {},                         )
        addop("imul",  [0x69],             noafs, [rmr, imm]    , {se:(0,1)}         ,{sw:False}        , {},                         )

        addop("in",    [0xE4],             noafs, [r_eax, u08]  , {w8:(0,0)}         ,{}                , {},                         )
        addop("in",    [0xEC],             noafs, [r_eax,r_dx]  , {w8:(0,0)}         ,{}                , {},                         )

        addop("inc",   [0x40],             reg  , no_rm         , {}                 ,{}                , {},                         )
        addop("inc",   [0xFE],             d0   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("ins",   [0x6C],             noafs, no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("int",   [0xCC],             noafs, [im3]         , {}                 ,{}                , {},                         )
        addop("int",   [0xCD],             noafs, [u08]         , {}                 ,{}                , {},                         )

        addop("into",  [0xCE],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("invd",  [0x0F, 0x08],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("invlpg",[0x0F, 0x01],       d7   , no_rm         , {}                 ,{}                , {},                         )

        addop("iret",  [0xCF],             noafs, no_rm         , {}                 ,{}                , {bkf:True}                  )

        addop("j",     [0x70],             cond , [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("j",     [0x0F, 0x80],       cond , [s32]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("jecxz", [0xE3],             noafs, [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})

        addop("jmp",   [0xE9],             noafs, [ims]         , {w8:(0,1)}         ,{w8:False}        , {bkf:True,dtf:True}         )
        addop("jmpf",   [0xEa],             noafs, [ims,u16]       ,{}                  ,{}        , {bkf:True,dtf:True}         )
        addop("jmp",   [0xFF],             d4   , no_rm         , {}                 ,{}                , {bkf:True,dtf:True}         )
        addop("jmpf",  [0xFF],             d5   , no_rm         , {}                 ,{}                , {bkf:True,dtf:True}         )

        addop("lahf",  [0x9F],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("lar",   [0x0F, 0x02],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("ldmxcsr",[0x0F, 0xAE],      d2   , no_rm         , {}                 ,{}                , {},                         )
        addop("lds",   [0xC5],             noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("lss",   [0x0F, 0xB2],       noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("les",   [0xC4],             noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("lfs",   [0x0F, 0xB4],       noafs, [rmr]         , {}                 ,{}                , {},                         )
        addop("lgs",   [0x0F, 0xB5],       noafs, [rmr]         , {}                 ,{}                , {},                         )

        addop("lea",   [0x8D],             noafs, [rmr]         , {}                 ,{}                , {},                         )

        addop("leave", [0xC9],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("lfence",[0x0F, 0xAE],       d5   , no_rm         , {}                 ,{}                , {},                         )
        addop("lgdt",  [0x0F, 0x01],       d2   , no_rm         , {}                 ,{}                , {},                         )
        addop("lidt",  [0x0F, 0x01],       d3   , no_rm         , {}                 ,{}                , {},                         )
        addop("lldt",  [0x0F, 0x00],       d2   , no_rm         , {}                 ,{}                , {},                         )
        addop("lmsw",  [0x0F, 0x01],       d6   , no_rm         , {}                 ,{}                , {},                         )

        #ddop("lods",  [0xAC],             noafs, no_rm         , {w8:(0,0)}         ,{}                , {},                         )
        addop("lodsb", [0xAC],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        addop("lodsd", [0xAD],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )

        addop("loop",  [0xE2],             noafs, [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("loope", [0xE1],             noafs, [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})
        addop("loopne",[0xE0],             noafs, [s08]         , {}                 ,{}                , {bkf:True,spf:True,dtf:True})

        addop("lsl",   [0x0F, 0x03],       noafs, [rmr]         , {}                 ,{}                , {},                         )

        addop("ltr",   [0x0F, 0x00],       d3   , no_rm         , {}                 ,{wd:True}         , {},                         )

        addop("mfence",[0x0F, 0xAE],       d6   , no_rm         , {}                 ,{}                , {},                         )

        addop("mov",   [0x88],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )
        addop("mov",   [0xA0],             noafs, [r_eax,mim]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("mov",   [0xA2],             noafs, [mim,r_eax]   , {w8:(0,0)}         ,{}                , {},                         )

        addop("mov",   [0xB0],             reg  , [imm]         , {w8:(0,3)}         ,{}                , {},                         )
        addop("mov",   [0x0F, 0x20],       noafs, [rmr]         , {sw:(1,1)}         ,{cr:True}         , {},                         )
        addop("mov",   [0x0F, 0x21],       noafs, [rmr]         , {sw:(1,1)}         ,{dr:True}         , {},                         )
        addop("mov",   [0x8C],             noafs, [rmr]         , {sw:(0,1)}         ,{sg:True,sw:True} , {},                         )
        addop("mov",   [0xC6],             d0   , [imm]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("movnti",[0x0F, 0xC3],       noafs, [rmr]         , {}                 ,{}                , {},                         )

        addop("movsb", [0xA4],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        addop("movsd", [0xA5],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )
        addop("movsx", [0x0F, 0xBE],       noafs, [rmr]         , {se:(1,0)}         ,{}                , {},                         )
        addop("movzx", [0x0F, 0xB6],       noafs, [rmr]         , {se:(1,0)}         ,{}                , {},                         )

        addop("mul",   [0xF6],             d4   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("neg",   [0xF6],             d3   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )
        addop("nop",   [0x0F, 0x1F],       d0   , no_rm         , {}                 ,{}                , {},                         )
        addop("not",   [0xF6],             d2   , no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("or",    [0x0C],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("or",    [0x80],             d1,    [imm]         , {w8:(0,0),se:(0,1)},{}                , {},                         )
        addop("or",    [0x08],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("out",   [0xE6],             noafs, [u08,r_eax]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("out",   [0xEE],             noafs, [r_dx,r_eax]  , {w8:(0,0)}         ,{}                , {},                         )
        addop("outs",  [0x6E],             noafs, no_rm         , {w8:(0,0)}         ,{}                , {},                         )

        addop("pause", [0xF3, 0x90],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("pop",   [0x58],             reg  , no_rm         , {}                 ,{}                , {},                         )
        addop("pop",   [0x8F],             d0   , no_rm         , {}                 ,{}                , {},                         )
        addop("popad", [0x61],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("popfd", [0x9D],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("pop",   [0x07],             noafs, [r_es]        , {}                 ,{sg:True,}        , {},                         )
        addop("pop",   [0x17],             noafs, [r_ss]        , {}                 ,{sg:True,}        , {},                         )
        addop("pop",   [0x1f],             noafs, [r_ds]        , {}                 ,{sg:True,}        , {},                         )


        addop("pop",[0x0F, 0xa1],         noafs, [r_fs]        , {}                 ,{sg:True,}        , {},                         )
        addop("pop",[0x0F, 0xa9],         noafs, [r_gs]        , {}                 ,{sg:True,}        , {},                         )


        addop("prefetch",[0x0F, 0x18],     d0   , no_rm         , {}                 ,{}                , {},                         )
        addop("prefetch",[0x0F, 0x18],     d1   , no_rm         , {}                 ,{}                , {},                         )
        addop("prefetch",[0x0F, 0x18],     d2   , no_rm         , {}                 ,{}                , {},                         )
        addop("prefetch",[0x0F, 0x18],     d3   , no_rm         , {}                 ,{}                , {},                         )

        addop("push",  [0x68],             noafs, [imm]         , {se:(0,1)}         ,{}                , {},                         )
        addop("push",  [0x50],             reg  , no_rm         , {}                 ,{}                , {},                         )
        addop("push",  [0xFF],             d6   , no_rm         , {}                 ,{}                , {},                         )
        addop("pushad",[0x60],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("pushfd",[0x9C],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("push",  [0x0E],             noafs, [r_cs]        , {}                 ,{sg:True,}        , {},                         )
        addop("push",  [0x06],             noafs, [r_es]        , {}                 ,{sg:True,}        , {},                         )
        addop("push",  [0x16],             noafs, [r_ss]        , {}                 ,{sg:True,}        , {},                         )
        addop("push",  [0x1E],             noafs, [r_ds]        , {}                 ,{sg:True,}        , {},                         )

        addop("push",[0x0F, 0xa0],         noafs, [r_fs]        , {}                 ,{sg:True,}        , {},                         )
        addop("push",[0x0F, 0xa8],         noafs, [r_gs]        , {}                 ,{sg:True,}        , {},                         )

        addop("rcl",   [0xD0],             d2   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("rcl",   [0xD2],             d2   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("rcl",   [0xC0],             d2   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("rcr",   [0xD0],             d3   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("rcr",   [0xD2],             d3   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("rcr",   [0xC0],             d3   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("rol",   [0xD0],             d0   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("rol",   [0xD2],             d0   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("rol",   [0xC0],             d0   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("ror",   [0xD0],             d1   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("ror",   [0xD2],             d1   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("ror",   [0xC0],             d1   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("rdmsr", [0x0F, 0x32],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("rdpmc", [0x0F, 0x33],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("rdtsc", [0x0F, 0x31],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("ret",   [0xC3],             noafs, no_rm         , {}                 ,{}                , {bkf:True}                  )
        addop("retf",  [0xCB],             noafs, no_rm         , {}                 ,{}                , {bkf:True},                 )

        addop("ret",   [0xC2],             noafs, [u16]         , {}                 ,{}                , {bkf:True},                 )
        addop("retf",  [0xCA],             noafs, [u16]         , {}                 ,{}                , {bkf:True},                 )

        addop("rms",   [0x0F, 0xAA],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("sahf",  [0x9E],             noafs, no_rm         , {}                 ,{}                , {},                         )


        addop("sal",   [0xC0],             d4   , [u08]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sal",   [0xC0],             d6   , [u08]        , {w8:(0,0)}         ,{}                , {},                         )

        addop("sal",   [0xC1],             d4   , [u08]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sal",   [0xC1],             d6   , [u08]        , {w8:(0,0)}         ,{}                , {},                         )

        addop("sal",   [0xD1],             d4   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sal",   [0xD1],             d6   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )

        addop("sal",   [0xD3],             d4   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sal",   [0xD3],             d6   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        """
        addop("sal",   [0xD2],             d4   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sal",   [0xC0],             d4   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )
        """                                                                                             , {}

        addop("sal",   [0xD0],             d6   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sar",   [0xD0],             d7   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("sar",   [0xD2],             d6   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sar",   [0xD2],             d7   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("sar",   [0xC0],             d7   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("shl",   [0xD0],             d4   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("shl",   [0xD2],             d4   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("shl",   [0xC0],             d4   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("shr",   [0xD0],             d5   , [im1]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("shr",   [0xD2],             d5   , [r_cl]        , {w8:(0,0)}         ,{}                , {},                         )
        addop("shr",   [0xC0],             d5   , [u08]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("sbb",   [0x1C],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("sbb",   [0x80],             d3,    [imm]         , {w8:(0,0),se:(0,1)},{}                , {},                         )
        addop("sbb",   [0x18],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        #addop("scas",  [0xAE],             noafs, no_rm         , {w8:(0,0)}         ,{}                , {},                         )
        addop("scasb", [0xAE],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        addop("scasd", [0xAF],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )


        addop("set",   [0x0F, 0x90],       cond , [rmr]         , {}                 ,{w8:True}         , {},                         )

        addop("setalc",[0xd6],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("qfence",[0x0F, 0xAE],       d7   , no_rm         , {}                 ,{}                , {},                         )
        addop("sgdt",  [0x0F, 0x01],       d0   , no_rm         , {}                 ,{}                , {},                         )

        addop("shld",  [0x0F, 0xA4],       noafs, [rmr, u08]    , {}                 ,{sw:True}         , {},                         )
        addop("shld_cl",[0x0F, 0xA5],      noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )
        addop("shrd",  [0x0F, 0xAC],       noafs, [rmr, u08]    , {}                 ,{sw:True}         , {},                         )
        addop("shrd_cl",[0x0F, 0xAD],      noafs, [rmr]         , {}                 ,{sw:True}         , {},                         )

        addop("sidt",  [0x0F, 0x01],       d1   , no_rm         , {}                 ,{}                , {},                         )
        addop("sldt",  [0x0F, 0x00],       d0   , no_rm         , {}                 ,{}                , {},                         )
        addop("smsw",  [0x0F, 0x01],       d4   , no_rm         , {}                 ,{}                , {},                         )
        addop("stc",   [0xF9],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("std",   [0xFD],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("sti",   [0xFB],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("stmxcsr",[0x0F, 0xAE],      d3   , no_rm         , {}                 ,{}                , {},                         )

        #addop("stos",  [0xAA],             noafs, [r_eax]       , {w8:(0,0)}         ,{}                , {},                         )
        addop("stosb", [0xAA],             noafs, no_rm         , {}                 ,{w8:True}         , {},                         )
        addop("stosd", [0xAB],             noafs, no_rm         , {}                 ,{w8:False}        , {},                         )

        addop("str",   [0x0F, 0x00],       d1   , no_rm         , {}                 ,{}                , {},                         )

        addop("sub",   [0x2C],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("sub",   [0x80],             d5,    [imm]         , {w8:(0,0),se:(0,1)},{}                , {},                         )
        addop("sub",   [0x28],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        """                                                                                             , {}
        #XXX dup opcode => modrm encoding                                                               , {}
        addop("swapgs",[0x0F, 0x01],       d7   , no_rm         , {}                 ,{}                , {},                         )
        """                                                                                             , {}
        addop("syscall",[0x0F, 0x05],      noafs, no_rm         , {}                 ,{}                , {bkf:True},                         )
        addop("sysenter",[0x0F, 0x34],     noafs, no_rm         , {}                 ,{}                , {bkf:True},                         )
        addop("sysexit",[0x0F, 0x35],      noafs, no_rm         , {}                 ,{}                , {bkf:True},                         )
        addop("sysret",[0x0F, 0x07],       noafs, no_rm         , {}                 ,{}                , {bkf:True},                         )

        addop("test",  [0xA8],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("test",  [0xF6],             d0,    [imm]         , {w8:(0,0)}         ,{}                , {},                         )
        addop("test",  [0x84],             noafs, [rmr]         , {w8:(0,0)}         ,{sw:True}         , {},                         )

        addop("ud2",   [0x0F, 0x0B],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("verr",  [0x0F, 0x00],       d4   , no_rm         , {}                 ,{}                , {},                         )
        addop("verw",  [0x0F, 0x00],       d5   , no_rm         , {}                 ,{}                , {},                         )
        #ddop("wait",  [0x9B],             noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("wbinvd",[0x0F, 0x09],       noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("wrmsr", [0x0F, 0x30],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("xadd",  [0x0F, 0xC0],       noafs, [rmr]         , {w8:(1,0)}         ,{}                , {},                         )

        addop("xchg",  [0x90],             reg  , [r_eax]       , {}                 ,{}                , {},                         )

        addop("nop",   [0x90],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("xchg",  [0x86],             noafs, [rmr]         , {w8:(0,0)}         ,{}                , {},                         )

        addop("xlat",  [0xD7],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("xor",   [0x34],             noafs, [r_eax,imm]   , {w8:(0,0)}         ,{}                , {},                         )
        addop("xor",   [0x80],             d6,    [imm]         , {w8:(0,0),se:(0,1)},{}                , {},                         )
        addop("xor",   [0x30],             noafs, [rmr]         , {w8:(0,0),sw:(0,1)},{}                , {},                         )

        addop("monitor",[0x0F, 0x01, 0xC8],noafs, no_rm         , {}                 ,{}                , {},                         )
        addop("mwait", [0x0F, 0x01, 0xC9], noafs, no_rm         , {}                 ,{}                , {},                         )

        #x87 fpu                                                                                        , {}

        addop("fadd",  [0xD8],             d0,    no_rm         , {sd:(0,2)}         ,{}         , {},                         )
        addop("fadd",  [0xD8, 0xC0],       reg,   [r_eax]       , {sw:(0,2)}         ,{sd:True,sw:False}, {},                         )
        addop("fiadd", [0xDA],             d0,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("faddp", [0xDE, 0xC0],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fbld",  [0xDF],             d4,    no_rm         , {}                 ,{}                , {},                         )
        addop("fbstp", [0xDF],             d6,    no_rm         , {}                 ,{}                , {},                         )

        addop("fchs",  [0xD9, 0xE0],       noafs, no_rm         , {}                 ,{}                , {},                         )
        #ddop("fclex", [0x9B, 0xDB, 0xE2], noafs, no_rm         , {}                 ,{}                , {},                         ) #XXX no mnemo
        addop("fnclex",[0xDB, 0xE2],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fcmovb",[0xDA, 0xC0],       reg,   [r_eax]       , {}                 ,{}                , {},                         )
        addop("fcmove",[0xDA, 0xC8],       reg,   [r_eax]       , {}                 ,{}                , {},                         )
        addop("fcmovbe",[0xDA, 0xD0],      reg,   [r_eax]       , {}                 ,{}                , {},                         )
        addop("fcmovu",[0xDA, 0xD8],       reg,   [r_eax]       , {}                 ,{}                , {},                         )
        addop("fcmovnb",[0xDB, 0xC0],      reg,   [r_eax]       , {}                 ,{}                , {},                         )
        addop("fcmovne",[0xDB, 0xC8],      reg,   [r_eax]       , {}                 ,{}                , {},                         )
        addop("fcmovnbe",[0xDB, 0xD0],     reg,   [r_eax]       , {}                 ,{}                , {},                         )
        addop("fcmovnu",[0xDB, 0xD8],      reg,   [r_eax]       , {}                 ,{}                , {},                         )

        addop("fcom",  [0xD8],             d2,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fcom",  [0xD8, 0xD0],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fcomp", [0xD8],             d3,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fcomp", [0xD8, 0xD8],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fcompp",[0xDE, 0xD9],       noafs, no_rm         , {}                 ,{}                , {},                         )


        addop("ficom", [0xDA],             d2,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("ficomp",[0xDA],             d3,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )


        addop("fdiv",  [0xD8],             d6,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fdivr", [0xD8],             d7,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fdiv",  [0xDC, 0xF8],       reg,   [r_eax]       , {        }         ,{sd:True,sw:True }, {},                         )
        addop("fidiv", [0xDA],             d6,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fidivr",[0xDA],             d7,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fdivp", [0xDE, 0xF8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        addop("fdiv",  [0xD8, 0xF0],       reg,   [r_eax]       , {        }         ,{sd:True,sw:False}, {},                         )
        addop("fdivr", [0xD8, 0xF8],       reg,   [r_eax]       , {        }         ,{sd:True,sw:False}, {},                         )
        addop("fdivr", [0xDC, 0xF0],       reg,   [r_eax]       , {        }         ,{sd:True,sw:True }, {},                         )
        addop("fdivrp",[0xDE, 0xF0],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("ffree", [0xDD, 0xC0],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fwait", [0x9B],             noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fild",  [0xDB],             d0,    no_rm         , {wd:(0,2)}         ,{wd:False}        , {},                         )
        addop("fild",  [0xDF],             d5,    no_rm         , {}                 ,{sd:True,wd:False}, {},                         ) #XXX 64


        addop("fincstp",[0xD9, 0xF7],      noafs, no_rm         , {}                 ,{}                , {},                         )

        #ddop("finit", [0x9B, 0xDB, 0xE3], noafs, no_rm         , {}                 ,{}                , {},                         ) #XXX no mnemo
        addop("fninit",[0xDB, 0xE3],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fist",  [0xDB],             d2,    no_rm         , {wd:(0,2)}         ,{wd:False}        , {},                         )
        addop("fistp", [0xDB],             d3,    no_rm         , {wd:(0,2)}         ,{wd:False}        , {},                         )
        addop("fistp", [0xDF],             d7,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 64
        addop("fisttp",[0xDB],             d1,    no_rm         , {wd:(0,2)}         ,{wd:False}        , {},                         )
        addop("fisttp",[0xDD],             d1,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 64



        addop("fmul",  [0xD8],             d1,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fmul",  [0xD8, 0xC8],       reg,   [r_eax]       , {sw:(0,2)}         ,{sd:True,sw:False}, {},                         )
        addop("fimul", [0xDA],             d1,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fmulp", [0xDE, 0xC8],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )


        addop("frstor",[0xDD],             d4,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX 94/108

        #ddop("fsave", [0x9B, 0xDD],       d6,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnsave",[0xDD],             d6,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX 94/108


        addop("fst",   [0xD9],             d2,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fst",   [0xDD, 0xD0],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fstp",  [0xD9],             d3,    no_rm         , {sd:(0,2)}         ,{sd:False}        , {},                         )
        addop("fstp",  [0xDB],             d7,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 80
        addop("fstp",  [0xDD, 0xD8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        #ddop("fstcw", [0x9B, 0xD9],       d7,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnstcw",[0xD9],             d7,    no_rm         , {}                 ,{wd:True}         , {},                         )
        #ddop("fstenv",[0x9B, 0xD9],       d6,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnstenv",[0xD9],            d6,    no_rm         , {}                 ,{wd:False}        , {},                         )

        addop("f2xm1", [0xD9, 0xF0],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fnop",  [0xD9, 0xD0],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fpatan",[0xD9, 0xF3],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fprem", [0xD9, 0xF8],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fprem1",[0xD9, 0xF5],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fptan", [0xD9, 0xF2],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("frndint",[0xD9, 0xFC],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fscale",[0xD9, 0xFD],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fsin",  [0xD9, 0xFE],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fsincos",[0xD9, 0xFB],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fsqrt", [0xD9, 0xFA],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fcos",  [0xD9, 0xFF],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fdecstp",[0xD9, 0xF6],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fld",   [0xD9],             d0,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fld",   [0xDB],             d5,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 80
        addop("fld",   [0xD9, 0xC0],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fcomi", [0xDB, 0xF0],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fcomip",[0xDF, 0xF0],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fucomi",[0xDB, 0xE8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )
        addop("fucomip",[0xDF, 0xE8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        addop("fldcw", [0xD9],             d5,    no_rm         , {}                 ,{wd:True}         , {},                         )
        addop("fldenv",[0xD9],             d4,    no_rm         , {}                 ,{wd:False}        , {},                         )
        addop("fabs",  [0xD9, 0xE1],       noafs, no_rm         , {}                 ,{}                , {},                         )

        addop("fld1",  [0xD9, 0xE8],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldl2t",[0xD9, 0xE9],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldl2e",[0xD9, 0xEA],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldpi", [0xD9, 0xEB],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldlg2",[0xD9, 0xEC],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldln2",[0xD9, 0xED],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fldz",  [0xD9, 0xEE],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )


        #ddop("fstsw", [0x9B, 0xDD],       d7,    no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnstsw",[0xDD],             d7,    no_rm         , {}                 ,{wd:True}         , {},                         )
        #ddop("fstsw",[0x9B, 0xDF, 0xE0],  noafs, no_rm         , {}                 ,{wd:False}        , {},                         ) #XXX no mnemo
        addop("fnstsw",[0xDF, 0xE0],       noafs, no_rm         , {}                 ,{wd:False}        , {},                         )

        addop("fsub",  [0xD8],             d4,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fsub",  [0xD8, 0xE0],       reg,   [r_eax]       , {sw:(0,2)}         ,{sd:True,sw:False}, {},                         )
        addop("fisub", [0xDA],             d4,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fsubp", [0xDE, 0xE8],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fsubr", [0xD8],             d5,    no_rm         , {sd:(0,2)}         ,{}                , {},                         )
        addop("fsubr", [0xD8, 0xE8],       reg,   [r_eax]       , {sw:(0,2)}         ,{sd:True,sw:False}, {},                         )
        addop("fisubr",[0xDA],             d5,    no_rm         , {wd:(0,2)}         ,{}                , {},                         )
        addop("fsubrp",[0xDE, 0xE0],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("ftst",  [0xD9, 0xE4],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fucom", [0xDD, 0xE0],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fucomp",[0xDD, 0xE8],       reg,   no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fucompp",[0xDA, 0xE9],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )

        addop("fxam",  [0xD9, 0xE5],       noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fxch",  [0xD9, 0xC8],       reg,   no_rm         , {}                 ,{sd:True}         , {},                         )

        addop("fxrstor",[0x0f, 0xAE],      d1,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 512
        addop("fxrsave",[0x0f, 0xAE],      d0,    no_rm         , {}                 ,{sd:False}        , {},                         ) #XXX 512
        addop("fxtract",[0xD9, 0xF4],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fyl2x",  [0xD9, 0xF1],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        addop("fyl2xp1",[0xD9, 0xF9],      noafs, no_rm         , {}                 ,{sd:False}        , {},                         )
        pm = self.db_mnemo[0x9c]
        self.pushfw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.pushfw_m.name = "pushfw"

        self.popfw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.popfw_m.name = "popfw"

        pm = self.find_mnemo("lodsd")[0]
        self.lodsw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.lodsw_m.name = "lodsw"

        pm = self.find_mnemo("stosd")[0]
        self.stosw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.stosw_m.name = "stosw"

        pm = self.find_mnemo("movsd")[0]
        self.movsw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.movsw_m.name = "movsw"

        pm = self.find_mnemo("cmpsd")[0]
        self.cmpsw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.cmpsw_m.name = "cmpsw"

        pm = self.find_mnemo("scasd")[0]
        self.scasw_m = mnemonic(pm.name, pm.opc, pm.afs, pm.rm, pm.modifs, pm.modifs_orig, None)#, pm.sem)
        self.scasw_m.name = "scasw"



x86mndb = x86allmncs()

class x86_mnemo_metaclass(type):
    rebuilt_inst = True


    def dis(cls, op, attrib = {}):
        i = cls.__new__(cls)
        i.__init__(attrib)
        u = i._dis(op)
        if not u:
            return None
        return i
    def asm(cls, l, symbol_off = []):
        i = cls.__new__(cls)
        i.__init__() # admode = u32, opmode = u32, sex = 0)
        return i._asm(l, symbol_off)


    def has_symb(cls, a):
        if type(a) in [int, long]+tab_int_size.keys():
            return False
        if x86_afs.symb in a:
            return True
        return False

    def fix_symbol(cls, a, symbol_pool = None):
        if type(a) in [int, long]+tab_int_size.keys():
            return a

        cp = dict(a)
        if not x86_afs.symb in cp:
            return cp

        if not symbol_pool:
            del cp[x86_afs.symb]
            if not x86_afs.imm in cp:
                cp[x86_afs.imm] = 0
            return cp

        imm_total = 0
        if x86_afs.imm in cp:
            imm_total+=cp[x86_afs.imm]
        for s in cp[x86_afs.symb]:
            base_ad = symbol_pool.s['base_address'].offset_g
            imm_total+=cp[x86_afs.symb][s]*(symbol_pool.s[s.name].offset_g+base_ad)

        cp[x86_afs.imm] = imm_total
        del cp[x86_afs.symb]


        return cp

    def is_mem(cls, a):
        return x86_afs.ad in a and a[x86_afs.ad]

    def get_label(cls, a):
        if not x86_afs.symb in a:
            return None
        n = a[x86_afs.symb]
        if len(n)!=1:
            return None
        k = n.keys()[0]
        if n[k] != 1:
            return None
        return k

    def get_symbols(cls, a):
        if not x86_afs.symb in a:
            return None
        return a[x86_afs.symb].items()
    def set_symbols(cls, a, s):
        print a, s
    def names2symbols(cls, a, s_dict):
        all_s = a[x86_afs.symb]
        for name, s in s_dict.items():
            count = all_s[name]
            del(all_s[name])
            all_s[s] = count


class x86_mn:
    __metaclass__ = x86_mnemo_metaclass
    def __init__(self, attrib = {}):
        self.opmode = attrib.get('opmode', u32)
        self.admode = attrib.get('opmode', u32)
        self.mnemo_mode = self.opmode
        self.cmt = ""


    def get_attrib(self):
        return {"opmode":self.opmode,
                "admode":self.admode}

    @classmethod
    def prefix2hex(self, prefix):
        return reduce(lambda x,y:x+chr(y), prefix, "")


    def breakflow(self):
        return self.m.modifs[bkf]
    def splitflow(self):
        return self.m.modifs[spf]
    def dstflow(self):
        return self.m.modifs[dtf]

    def getnextflow(self):
        return self.offset+self.l

    def getdstflow(self):
        if len(self.arg) !=1:
            print ValueError('should be 1 arg %s'%str(self))
            return []
        a = self.arg[0]
        if is_imm(a) and not x86_afs.symb in a:
            dst = (self.offset+self.l+a[x86_afs.imm])&tab_max_uint[self.opmode]
            out = [dst]
        else:
            out = [a]
        return out

    def setdstflow(self, dst):
        if len(self.arg) !=1:
            print ValueError('should be 1 arg %s'%str(self))
            return
        if len(dst)==0:
            return
        if len(dst)!=1:
            raise ValueError('should be 1 dst')
        l = dst[0]

        #patch only known symbols
        if l.offset !=None:
            self.arg = [{x86_afs.symb:{l:1}}]

    def fixdst(self, lbls, my_offset, is_mem):
        if len(self.arg) !=1:
            raise ValueError('should be 1 arg %s'%str(self))
        a = self.arg[0]
        l = a[x86_afs.symb].keys()[0]
        offset = lbls[l.name]
        if is_mem:
            arg = {x86_afs.ad:is_mem, x86_afs.imm:offset}
        else:
            arg = {x86_afs.imm:offset-(my_offset)}

        self.arg = [arg]

    def is_subcall(self):
        return self.m.name == 'call'

    def __str__(self):
        if type(self.instr_string) is str:
            return self.instr_string

        args_str = ""
        for p in self.prefix:
            if p in prefix_dic_inv:
                args_str += prefix_dic_inv[p]+" "
        args_str+="%-10s"%(self.m.name)

        for a in self.arg:
            if type(a) in [int, long]:
                raise ValueError("should be intsized %s"%str(a))
            if type(a) in tab_int_size:
                raise ValueError("should be dict.. %s"%str(a))
            elif type(a) == dict:
                args_str+="%s, "%dict_to_ad(a, self.m.modifs, self.opmode, self.admode)
            else:
                raise ValueError("arg zarbi %s"%str(a))

        o = args_str[:-2]
        if self.cmt:
            o = "%-50s%s"%(o, self.cmt)
        return o

    def intsize(self, im, ext = False):
        if ext:
            return [uint16, uint32][self.opmode == u32](im)
        if self.m.modifs[w8]:
            return uint8(im)
        if self.opmode == u32:
            return uint32(im)
        elif self.opmode == u16:
            return uint16(im)
        else:
            raise ValueError('unknown mnemo mode %s'%str(im))

    def _dis(self, bin):
        if type(bin) == str:
            from miasm.core.bin_stream import bin_stream
            bin = bin_stream(bin)
        init_offset = bin.offset

        try:
            #find mnemonic
            l = x86mndb.db_mnemo
            index = 0
            m = None
            read_prefix = []
            prefix_done =False
            while True:
                c = ord(bin.readbs())
                if not prefix_done and c in x86_afs.x86_prefix:
                    read_prefix.append(c)
                    continue
                else:
                    prefix_done = True
                if l[c] == None:
                    log.debug( "unknown mnemo")
                    break
                if isinstance(l[c] ,mnemonic):
                    m = l[c]
                    break
                if type(l[c]) == list:
                    l = l[c]

            if m == None:
                return None
            self.m = m

            log.debug(m)
            log.debug("prefix: %s"%str(read_prefix))

            #self.mnemo_mode = self.admode
            if 0x66 in read_prefix:
                self.opmode = [u16,u32][self.opmode==u16]
                #self.opmode = [u16,u32][size_op == u16]
            if 0x67 in read_prefix:
                self.admode = [u16,u32][self.admode == u16]



            #parse mnemonic args
            mnemo_args = []

            afs, dibs = m.afs, m.rm
            modrm = None
            #digit
            if afs in [d0, d1, d2, d3, d4, d5, d6, d7]:
                re, modr = x86mndb.get_afs(bin, c, self.admode)
                mnemo_args.append(modr)
                mnemo_args[-1][x86_afs.size] = self.opmode

                if m.modifs[sd] is not None:
                    if m.modifs[sd]:
                        mnemo_args[-1][x86_afs.size] = x86_afs.f32
                    else:
                        mnemo_args[-1][x86_afs.size] = x86_afs.f64

                if m.modifs[w8]:
                    mnemo_args[-1][x86_afs.size] = x86_afs.u08
                if m.modifs[wd]:
                    #XXX check (for fnst??)=
                    mnemo_args[-1][x86_afs.size] = x86_afs.u16
            #+reg
            elif afs == reg:
                mafs = dict(x86mndb.get_afs_re(c&(0xFF^mask_reg)))
                if m.modifs[w8]:
                    mafs[x86_afs.size] = x86_afs.u08
                else:
                    mafs[x86_afs.size] = self.opmode

                mnemo_args.append(mafs)
            #rm mod
            elif afs in [noafs, cond]:
                if rmr in m.rm:
                    c = ord(bin.readbs())
                    re, modr = x86mndb.get_afs(bin, c, self.admode)
                    reg_cat = 0
                    if m.modifs[dr]:
                        reg_cat+=0x8
                    if m.modifs[cr]:
                        reg_cat+=0x10
                    if m.modifs[sg]:
                        reg_cat+=0x20
                    mafs = dict(x86mndb.get_afs_re(re+reg_cat))
                    if m.modifs[w8]:
                        mafs[x86_afs.size] = x86_afs.u08
                    else:
                        mafs[x86_afs.size] = self.opmode

                    mnemo_args.append(mafs)
                    mnemo_args.append(modr)


                    mnemo_args[-1][x86_afs.size] = self.opmode
                    if m.modifs[w8] :
                        mnemo_args[-1][x86_afs.size] = x86_afs.u08
                    if m.modifs[se] !=None and not (imm in dibs or ims in dibs):
                        mnemo_args[-1][x86_afs.size] = [x86_afs.u08, x86_afs.u16][m.modifs[se]]


                    if m.modifs[wd]:
                        mnemo_args[-1][x86_afs.size] = x86_afs.u16
                        mnemo_args[-2][x86_afs.size] = x86_afs.u16
                    if m.modifs[sg]:
                        mnemo_args[-2][x86_afs.size] = x86_afs.size_seg
                    if afs == cond and m.name.startswith('set'):
                        mnemo_args.pop(0)


            elif afs == cond:
                pass
            else:
                raise ValueError('bug in %s %d'%(name, afs))

            #swap args?
            if m.modifs[sw]:
                mnemo_args.reverse()


            dib_out = []
            for dib in dibs:
                #unsigned
                log.debug(m.modifs)
                if dib in [u08, s08, u16, s16, u32, s32]:
                    if self.admode !=u32:
                        if dib == u32:
                            dib = u16
                        if dib == s32:
                            dib = s16
                    l = struct.calcsize(x86_afs.dict_size[dib])
                    d = struct.unpack(x86_afs.dict_size[dib], bin.readbs(l))[0]
                    d = self.intsize(d)

                    dib_out.append({x86_afs.imm:d})
                elif dib in [imm, ims]:
                    taille, fmt, t = x86mndb.get_im_fmt(m.modifs, self.opmode, dib)
                    dib_out.append({x86_afs.imm:self.intsize(struct.unpack(fmt, bin.readbs(taille))[0], dib==ims)})

                elif dib in [im1, im3]:
                    dib_out.append({im1:{x86_afs.imm:self.intsize(1)},im3:{x86_afs.imm:self.intsize(3)}}[dib])
                elif dib == rmr:
                    continue
                elif dib == r_eax:
                    mafs = dict(x86mndb.get_afs_re(x86_afs.reg_dict[x86_afs.r_eax]))
                    if m.modifs[w8]:
                        mafs[x86_afs.size] = x86_afs.u08
                    else:
                        mafs[x86_afs.size] = self.opmode

                    r = mafs

                    if len(mnemo_args):
                        if m.modifs[sw]:
                            mnemo_args = mnemo_args+[r]
                        else:
                            mnemo_args = [r]+mnemo_args
                    else:
                        dib_out.append(r)
                elif dib == mim:
                    l = struct.calcsize(x86_afs.dict_size[self.admode])
                    d = struct.unpack(x86_afs.dict_size[self.admode], bin.readbs(l))[0]
                    d = uint32(d)

                    size = [self.opmode, x86_afs.u08][m.modifs[w8]]
                    dib_out.append({x86_afs.ad:True, x86_afs.size:size, x86_afs.imm:d})
                elif dib in [r_cl, r_dx]:
                    dib_out.append(dib)
                    pass

                elif dib in segm_regs:
                    size = self.opmode
                    seg_regs = segm_regs
                    if not dib in segm_regs:
                        raise ValueError('segment reg not found', dib)
                    r = dib
                    dib_out.append({x86_afs.ad:False,
                                    x86_afs.size : size,
                                    x86_afs.reg_dict[r]:1})
                else:
                    raise ValueError('bad dib!!%X'%dib)

            mnemo_args+=dib_out

            for a in mnemo_args:
                for p in read_prefix:
                    if is_address(a) and p in prefix_seg.values():
                        a[x86_afs.segm]=prefix_seg_inv[p]
                        continue

            t_len = bin.offset-init_offset
            bin.offset = init_offset
            bytes_ret = bin.readbs(t_len)
            self.offset = init_offset
            self.instr_string = None
            self.l = t_len
            self.b = bytes_ret
            self.m = m
            self.arg = mnemo_args
            self.prefix = read_prefix

            #XXX really need to include this in disasm
            if self.opmode == u16 and self.m.name == "pushfd":
                self.m = x86mndb.pushfw_m
            if self.opmode == u16 and self.m.name == "popfd":
                self.m = x86mndb.popfw_m
            if self.m.name.startswith("lods"):
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m = x86mndb.lodsw_m
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_esi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_ds)}]
            if self.m.name.startswith("stos"):
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m = x86mndb.stosw_m
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_edi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_es)}]
            if self.m.name != "movsx" and self.m.name.startswith("movs"):
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m  = x86mndb.movsw_m
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_edi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_es)},

                            {x86_afs.reg_dict[x86_afs.r_esi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_ds)}]
            if self.m.name.startswith("cmps"):
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m  = x86mndb.cmpsw_m
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_edi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_es)},

                            {x86_afs.reg_dict[x86_afs.r_esi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_ds)}]

            if self.m.name.startswith("scas"):
                if self.m.name[-1] == "b":
                    s = u08
                elif self.opmode == u16:
                    s = u16
                    self.m  = x86mndb.scasw_m
                else:
                    s = u32
                self.arg = [{x86_afs.reg_dict[x86_afs.r_edi]:1,
                             x86_afs.ad:True,
                             x86_afs.size:s,
                             x86_afs.segm:x86_afs.reg_sg.index(x86_afs.r_es)}]
            return True

        except IOError:
            log.warning( "cannot dis: not enougth bytes")
            return None

    @classmethod
    def parse_mnemo(self, l):
        wordsplitted = shlex.shlex(l)
        wordsplitted.wordchars += '.' # Because labels sometimes begin with dot
        tokens = [t for t in wordsplitted]
        prefix = []
        if not tokens:
            raise ValueError('cannot parse mnemo?', l)
        while True:
            name = tokens[0]
            tokens = tokens[1:]
            if name in prefix_dic:
                prefix.append(name)
                continue
            break

        args = []
        arg = []
        s = ','
        while s in tokens:
            i = tokens.index(s)
            args.append(tokens[:i])
            tokens = tokens[i+1:]
        args.append(tokens)
        args = map(lambda x: reduce(lambda x,y: x+' '+y, x, ""), args)

        if args == ['']:
            return prefix, name, []

        for a in args:
            if not isinstance(a, str) and x86_afs.segm in a:
                prefix.append(x86_afs.reg_sg.index(a[x86_afs.segm]))

        # special case ommiting 1 as argument
        if len(args) == 1 and name in ["sal", "sar", "shl", "shr"]:
            args.append("1")
        # special case when the first argument should be omitted
        if len(args) == 2 and name in ["fcomi", "fcomip", "fucomi", "fucomip"]:
            args[0:1] = []
        # special case when the second argument should be omitted
        if len(args) == 2 and name in ["fdivp"]:
            args[1:2] = []
        # special case when the argument should be omitted
        if len(args) == 1 and name in [
                "stosb", "lodsb", "scasb",
                "stosd", "lodsd", "scasd",
                ]:
            args[0:2] = []
        # special case when both arguments should be omitted
        if len(args) == 2 and name in [ "movsb", "movsd", "cmpsb", "cmpsd", ]:
            args[0:2] = []

        return prefix, name, args

    @classmethod
    def parse_address(self, a):
        return parse_ad(a)

    def asm_parse(self, l):
        log.debug("asm: %s"%l)

        prefix, name, args = x86_mn.parse_mnemo(l)
        prefix = [prefix_dic[x] for x in prefix]

        log.debug("name: %s"%name)
        log.debug("args: %s"%str(args))

        args_eval = []
        for a in args:
            args_eval.append(x86_mn.parse_address(a))
            if x86_afs.segm in args_eval[-1]:
                # XXX todo hack: if only one arg, no prefix
                if len(args) == 1:
                    continue
                #print args_eval[-1]
                prefix.append(prefix_seg[args_eval[-1][x86_afs.segm]])
                del args_eval[-1][x86_afs.segm]
            #XXX test if symbol in arg and replace with imm... for pre asm
            if x86_afs.symb in args_eval[-1]:
                log.debug('pre-assembling with symbol! %s'%str(args_eval[-1][x86_afs.symb]))
                if not x86_afs.imm in args_eval[-1]:
                    args_eval[-1][x86_afs.imm] = 0
                del args_eval[-1][x86_afs.symb]
        log.info("prefix:%s"%str(prefix))
        log.info('eval: %s'%str(args_eval))

        #search all candidates
        log.debug('Find mnemo')
        candidate = x86mndb.find_mnemo(name)
        if not candidate:
            log.warning("no mnemonic found")

        can_be_16_32 = True
        log.debug("candi:")
        for c in candidate:
            if c.modifs[sd] or c.modifs[wd]:
                can_be_16_32 = False
            log.debug( c)




        #test for 16/32 bit mode
        if can_be_16_32:
            self.mnemo_mode = None
            for a in args_eval:
                #32 priority
                if (is_reg(a)) and a[x86_afs.size] == u32:
                    self.mnemo_mode = u32
                    break

                #XXX if eax, cx .... 32 bit bug
                if (is_reg(a) or is_address(a)) and a[x86_afs.size] == u16 and self.mnemo_mode == None:
                    self.mnemo_mode = u16
                    break

            if self.mnemo_mode == None:
                self.mnemo_mode = u32
            if self.mnemo_mode == u16:
                log.debug("16 bit mode detected for %s"%str(l))
                prefix.append(0x66)
                if  name in ["movzx", "movsx"]:
                    if args_eval[0][x86_afs.size] == u16:
                        args_eval[0][x86_afs.size] = u32
                        if args_eval[0][x86_afs.ad]:
                            args_eval[0][x86_afs.ad] = u32
                else:
                    for a in args_eval:
                        if a[x86_afs.size] == u16:
                            a[x86_afs.size] = u32
                            if a[x86_afs.ad]:
                                a[x86_afs.ad] = u32
        else:
            self.mnemo_mode = u32

        log.info('eval2: %s'%str(args_eval))

        modifs = dict([[x, None] for x in [w8, se, sw, ww, sg, dr, cr, ft, w64, sd, wd]])
        modifs[sw] = False


        #spot dr/cr regs
        for a in args_eval:
            for x in a:
                if type(x) in [int, long] and x>=0x100:
                    tmp = a[x]
                    for y in mask_drcrsg:
                        if x & mask_drcrsg[y]:
                            modifs[y] = True

        candidate_out = []
        for c in candidate:

            if (modifs[cr] or c.modifs[cr]) and modifs[cr] != c.modifs[cr]:
                continue
            if (modifs[dr] or c.modifs[dr]) and modifs[dr] != c.modifs[dr]:
                continue

            if (modifs[sg] or c.modifs[sg]) and modifs[sg] != c.modifs[sg]:
                continue

            args_sample = [dict(x) for x in args_eval]

            afs, dibs = c.afs, c.rm
            log.debug(c)

            parsed_args = []
            parsed_val = [{}]
            out_opc = [c.opc[:]]
            opc_add = []

            good_c = True
            dib_out = []
            for dib in dibs:
                if dib in [u08, s08, u16, s16, u32, s32]:
                    index_im = [-1, 0][afs == noafs]

                    if len(args_sample)<=0:
                        good_c = False
                        break
                    if not x86_afs.imm in args_sample[index_im] or args_sample[index_im][x86_afs.ad]:
                        log.debug("not imm 1")
                        good_c = False
                        break


                    if self.mnemo_mode !=u32:
                        if dib == u32:
                            dib = u16
                        if dib == s32:
                            dib = s16

                    size = dib

                    v = check_imm_size(args_sample[index_im][x86_afs.imm], size)
                    if v == None:
                        log.debug("cannot encode this val in size %s %x!"%(size, args_sample[index_im][x86_afs.imm]))
                        good_c= False
                        break

                    args_sample[index_im][x86_afs.size] = size
                    args_sample[index_im][x86_afs.imm] = tab_size2int[size](v)


                    opc_add.append({x86_afs.size:size, x86_afs.imm:args_sample[index_im][x86_afs.imm]})
                    r = args_sample[index_im]
                    del args_sample[index_im]
                    dib_out.append(r)

                elif dib in [im1, im3]:
                    if x86_afs.imm in args_sample[-1] and args_sample[-1][x86_afs.imm] =={im1:1,im3:3}[dib]:
                        dib_out.append(args_sample.pop())
                    else:
                        log.debug("not im val fixed")
                        good_c = False
                        break

                elif dib in [imm, ims]:
                    if len(args_sample)<=0:
                        good_c = False
                        break
                    if not x86_afs.imm in args_sample[-1] or args_sample[-1][x86_afs.ad]:
                        log.debug("not imm 2")
                        good_c = False
                        break
                    taille, fmt, t = x86mndb.get_im_fmt(c.modifs, self.admode, dib)
                    r = args_sample.pop()
                    v = check_imm_size(r[x86_afs.imm], t)
                    if v == None:
                        log.debug("cannot encode this val in size %s %x!"%(t, int(r[x86_afs.imm])))
                        good_c= False
                        break
                    r[x86_afs.imm] = tab_size2int[t](v)
                    opc_add.append({x86_afs.size:t, x86_afs.imm:r[x86_afs.imm]})

                    if c.modifs[se]:
                        r[x86_afs.size] = r[x86_afs.size]
                        r[x86_afs.imm] = tab_size2int[r[x86_afs.size]](r[x86_afs.imm])
                    dib_out.append(r)



                elif dib == rmr:
                    continue
                elif dib == r_eax:
                    if not args_sample or args_sample[0][x86_afs.ad]:
                        log.debug("not r_eax1")
                        good_c = False
                        break
                    size = args_sample[0][x86_afs.size]

                    if not x86mndb.check_size_modif(size, c.modifs):
                        log.debug(' bad reg size')
                        good_c = False
                        break
                    if c.modifs[sw]:
                        index = 1
                        if len(args_sample) !=2:
                            raise ValueError("sw in r_eax zarb")
                    else:
                        index = 0
                    if not x86_afs.reg_dict[x86_afs.r_eax] in args_sample[index]:
                        log.debug("not r_eax2")
                        good_c = False
                        break
                    #add front
                    if size == x86_afs.u32:
                        args_sample[index][x86_afs.size] = self.mnemo_mode
                    r = args_sample[index]
                    del(args_sample[index])
                    if len(args_sample) and not c.modifs[sw]:
                        parsed_args.append(r)
                    else:
                        dib_out.append(r)


                elif dib in [r_cl, r_dx]:
                    index_im = [-1, 0][afs == noafs]
                    dib_tmp = dict(dib)
                    del(dib_tmp[x86_afs.size])
                    del(args_sample[index_im][x86_afs.size])
                    #XXX in al, dx => spot 16 bit manip; concat 66 bug
                    if dib_tmp != args_sample[index_im]:
                        log.debug("not r_cl d_dx")
                        good_c = False
                        break

                    r = args_sample[index_im]
                    del args_sample[index_im]
                    dib_out.append(r)

                elif dib == mim:
                    if len(args_sample)<=0:
                        good_c = False
                        break
                    if not x86_afs.imm in args_sample[0] or not x86_afs.ad in args_sample[0] or not args_sample[0][x86_afs.ad]:
                        log.debug("not mim")
                        good_c = False
                        break

                    for k in args_sample[0]:
                        if not k in [x86_afs.imm, x86_afs.ad, x86_afs.size]:
                            log.debug("mim: cannot encode reg ")
                            good_c = False
                            break

                    a_mem = {x86_afs.size:u32, x86_afs.imm:uint32(args_sample[0][x86_afs.imm])}
                    opc_add.append(a_mem)
                    del args_sample[0]
                    a_pmem = dict(a_mem)
                    a_pmem[x86_afs.ad] = u32
                    parsed_args.append(a_pmem)
                elif dib in segm_regs:
                    good_c = False
                    for reg_code in x86_afs.reg_dict:
                        if x86_afs.reg_dict[reg_code] in args_sample[0]:
                            if reg_code == dib:
                                del args_sample[0]
                                good_c = True
                                break

                else:
                    raise ValueError('bad dib!!%X'%dib)

            if not good_c:
                continue

            log.debug("***pass dib***")
            log.debug(modifs)

            if afs in [d0, d1, d2, d3, d4, d5, d6, d7]:
                if len(args_sample)!=1:
                    log.debug(str(c)+' bad arg num1')
                    continue
                if args_sample[0][x86_afs.ad]:
                    size = args_sample[0][x86_afs.ad]
                    if not c.modifs[sd]  == None:
                        size = {x86_afs.u16:x86_afs.u16, x86_afs.u32:x86_afs.u32, x86_afs.f32:x86_afs.f32, x86_afs.f64:x86_afs.f64}[size]
                else:
                    size = args_sample[0][x86_afs.size]
                if not x86mndb.check_size_modif(size, c.modifs):
                    log.debug(' bad size digit')
                    continue


                a = dict(args_sample[-1])
                out_opc, parsed_val = x86mndb.forge_opc(out_opc, a)
                if out_opc == None or parsed_val == None:
                    log.debug('cannot encode opc')
                    continue

                parsed_args.append(args_sample.pop())
            elif afs == reg:
                if len(args_sample)!=1:
                    log.debug(str(c)+' bad arg num')
                    continue
                if  args_sample[0][x86_afs.ad]:
                    log.debug(' address in reg')
                    continue
                size = args_sample[0][x86_afs.size]
                if not x86mndb.check_size_modif(size, c.modifs):
                    log.debug(' bad size reg')
                    continue

                a = args_sample[-1]
                k = [x for x in a.keys() if type(x) in [long, int]]
                if a[x86_afs.ad] or x86_afs.imm in a or len(k)!=1:
                    log.debug('bad a2 %s'%str(a))
                    continue
                out_opc[0][-1]+=k[0]
                parsed_args.append(args_sample.pop())

            elif afs == noafs or (afs == cond and rmr in c.rm and len(args_sample)==2):
                if rmr in c.rm:
                    if len(args_sample)!=2:
                        log.debug(str(c)+' bad arg num')
                        continue
                    if c.modifs[sw] and args_sample[1][x86_afs.ad]:
                        log.debug(' bad sw rmr 1')
                        continue
                    if not c.modifs[sw] and args_sample[0][x86_afs.ad]:
                        log.debug(' bad sw rmr 2')
                        continue

                    for i in range(2):
                        if not args_sample[i][x86_afs.ad] and x86_afs.imm in args_sample[i]:
                            good_c = False
                            log.debug('Imm in rmr')
                            break

                    if not good_c:
                        continue

                    size = []
                    for x in xrange(2):
                        size.append(args_sample[x][x86_afs.size])

                    if not (imm in dibs or ims in dibs):
                        if c.modifs[sw]:
                            size.reverse()

                        if c.modifs[se]!=None:
                            if size[1] != [x86_afs.u08, x86_afs.u16][c.modifs[se]]:
                                log.debug(' bad size se rmr')
                                continue
                        elif not x86mndb.check_size_modif(size[0], c.modifs):
                            log.debug(' bad size rmr')
                            continue


                    #reg, modr
                    a1 = dict(args_sample[-1])
                    a2 = dict(args_sample[-2])
                    args_sample = args_sample[:-2]



                    if c.modifs[sw]:
                        tmp_order = [a2,a1]
                    else:
                        tmp_order = [a1,a2]

                    for y in mask_drcrsg:
                        if not modifs[y]:
                            continue
                        for x in tmp_order[1]:
                            if not type(x) in [int, long]:
                                continue
                            if not x&mask_drcrsg[y]:
                                log.debug('cr dr sg not found in reg')
                                good_c = False
                                break
                            tmp = tmp_order[1][x]
                            del(tmp_order[1][x])
                            tmp_order[1][x&0xFF] = tmp


                    if not good_c:
                        continue



                    out_opc, parsed_val = x86mndb.forge_opc(out_opc, *tmp_order)
                    if out_opc == None or parsed_val == None:
                        log.debug('cannot encode opc')
                        continue
                    tmp_o = [a2,a1]
                    if c.modifs[se] and size[0] !=size[1]:
                        size[1] = size[0]
                    if size[0] !=size[1] and not name in ['movzx', 'movsx']:
                        if tmp_order[0][x86_afs.ad]:
                            size[1] = size[0]
                        else:
                            log.debug('uncompatible size in rmr')
                            continue

                    for i in range(2):
                        tmp_o[-1][x86_afs.size] = size[i]
                    parsed_args+=tmp_o


            elif afs == cond:
                if rmr in c.rm:
                    if len(args_sample)!=1:
                        log.debug(str(c)+' bad arg num cond rmr')
                        continue
                    if args_sample[0][x86_afs.ad]:
                        size = args_sample[0][x86_afs.ad]
                    else:
                        size = args_sample[0][x86_afs.size]

                    a = dict(args_sample[-1])
                    add_out_opc, parsed_val = x86mndb.forge_opc([[0]], a)
                    if add_out_opc == None or parsed_val == None:
                        log.debug('cannot encode opc')
                        continue
                    parsed_args.append(args_sample.pop())
                    out_opc[0]+=add_out_opc[0]



            else:
                raise ValueError('erf ', afs)

            for do in dib_out:
                parsed_args.append(do)

            if len(args_sample):
                log.debug('too many args!')
                continue


            if self.mnemo_mode == u16:

                for a in parsed_args:
                    if not x86_afs.size in a:
                        a[x86_afs.size] = u16
                        continue
                    if a[x86_afs.size] == u32:
                        a[x86_afs.size] = u16
                        if a[x86_afs.ad]:
                            a[x86_afs.ad] = u16


            log.debug( "ok")
            log.debug(out_opc)
            log.debug(parsed_val)
            log.debug(parsed_args)
            for i in range(len(out_opc)):
                candidate_out.append((c, parsed_args, (out_opc[i], parsed_val[i], opc_add), self.mnemo_mode))
        return prefix, candidate_out

    def _asm(self, l, symbol_off_out):
        log.debug("asm: %s"%l)
        prefix, candidate_out = self.asm_parse(l)

        symbol_off = []
        log.info("selected candidate for:")
        log.info(l)
        hex_candidate = []
        for c,eat_arg,opc_o, mnemo_mode in candidate_out:
            log.info(str(c)+' '+str(eat_arg)+' '+str(opc_o))
            out_opc = prefix[:]
            out_opc += opc_o[0]

            # here are the reloc ?
            # note: can the code be more crapy than this?
            reloc_off = None
            if opc_o[1]:
                reloc_off = len(reduce(lambda x,y: x+chr(y), out_opc, ""))

            val_add = [opc_o[1]]+opc_o[2]
            out_byte = reduce(lambda x,y: x+chr(y), out_opc, "")
            for c in val_add:
                if c == {}:
                    continue
                if c[x86_afs.size] in [u08, s08, u16, s16, u32, s32]:
                    out_byte+=struct.pack(x86_afs.dict_size[c[x86_afs.size]], int(c[x86_afs.imm]))
                else:
                    raise ValueError('bad size in asm! %s'%str(c))

            # XXX only one reloc per instruction max?
            has_symb = None
            if reloc_off != None:
                has_symb = reloc_off
            symbol_off.append(has_symb)

            hex_candidate.append(out_byte)
            log.info( hexdump(out_byte))
        if not len(hex_candidate):
            log.warning('cannot asm %s'%str(l))
        all_candidate = zip(hex_candidate, symbol_off)
        all_candidate.sort(cmp = lambda x,y:len(x[0])-len(y[0]))
        hex_candidate = [x[0] for x in all_candidate]
        for x in all_candidate:
            symbol_off_out.append(x[1])
        return hex_candidate


x86mnemo = x86_mn

if __name__ == '__main__':
    test_out = []
    log.setLevel(logging.DEBUG)

    instr = x86mnemo.dis('67e1fa'.replace(' ', '').decode('hex'))
    print instr
    print instr.arg
    print instr.l
    print instr.opmode, instr.admode
    fds


    instr = x86mnemo.dis('0fa9'.replace(' ', '').decode('hex'),
                         {"admode":x86_afs.u16,"opmode":x86_afs.u16})
    print instr
    print instr.arg
    print instr.l
    print instr.opmode, instr.admode
    fds


    instr = x86mnemo.dis('ea21060000'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print instr
    print instr.arg
    print instr.l
    print instr.opmode, instr.admode
    fds


    instr = x86mnemo.dis('0fbe13'.replace(' ', '').decode('hex'),)
                         #admode=x86_afs.u16,
                         #opmode=x86_afs.u16)
    print instr
    print instr.arg
    print instr.l
    print instr.arg[1]["imm"].__class__
    print instr.opmode, instr.admode
    fds



    instr = x86mnemo.dis('038678ff'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print instr
    print instr.arg
    print instr.l
    print instr.arg[1]["imm"].__class__
    print instr.opmode, instr.admode
    fds


    instr = x86mnemo.dis('8946da'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print instr
    print instr.arg
    print instr.l
    print instr.opmode, instr.admode
    fds

    instr = x86mnemo.dis('66c74440ffffffff'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print instr
    print instr.arg
    print instr.l
    print instr.opmode, instr.admode
    fds

    instr = x86mnemo.dis('c57608'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('66af'.replace(' ', '').decode('hex'))
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('64a100000000'.replace(' ', '').decode('hex'))
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('8d03'.replace(' ', '').decode('hex'),
                         admode=x86_afs.u16,
                         opmode=x86_afs.u16)
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('669d'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    print instr.l
    fds



    instr = x86mnemo.dis('07'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('66A5'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('DB 28'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('DB 6D 08'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('C7 44 24 08 00 00 00 00'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('F0 65 0F B1 0D 84 00 00 00'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('F0 65 83 0D 84 00 00 00 10'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    print instr.l
    fds

    instr = x86mnemo.dis('65 C7 05 28 02 00 00 FF FF FF FF'.replace(' ', '').decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    fds

    instr = x86mnemo.dis('66ab'.decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
    fds

    instr = x86mnemo.dis('6681384D5A0000'.decode('hex'), admode=x86_afs.u32)
    print instr
    print instr.arg
