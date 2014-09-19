#!/usr/bin/env python
#-*- coding:utf-8 -*-

import logging
from pyparsing import *
from miasm2.expression.expression import *
from miasm2.core.cpu import *
from collections import defaultdict
from miasm2.core.bin_stream import bin_stream
import regs as regs_module
from regs import *
from pdb import pm

log = logging.getLogger("mips32dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)


gpregs = reg_info(regs32_str, regs32_expr)



LPARENTHESIS = Literal("(")
RPARENTHESIS = Literal(")")

def deref2expr(s, l, t):
    t = t[0]
    if len(t) != 4:
        raise NotImplementedError("TODO")

    return ExprMem(t[2] + t[0])

def deref2expr_nooff(s, l, t):
    t = t[0]
    if len(t) != 3:
        raise NotImplementedError("TODO")
    return ExprMem(t[1])

my_var_parser = parse_ast(ast_id2expr, ast_int2expr)
base_expr.setParseAction(my_var_parser)


deref_off = Group(Optional(base_expr) + LPARENTHESIS + gpregs.parser + RPARENTHESIS).setParseAction(deref2expr)
deref_nooff = Group(LPARENTHESIS + gpregs.parser + RPARENTHESIS).setParseAction(deref2expr_nooff)
deref = deref_off | deref_nooff


class additional_info:
    def __init__(self):
        self.except_on_instr = False
br_flt = ['BC1F']

br_0 = ['B', 'JR', 'BAL', 'JAL', 'JALR']
br_1 = ['BGEZ', 'BLTZ', 'BGTZ', 'BLEZ', 'BC1T', 'BC1F'] + br_flt
br_2 = ['BEQ', 'BEQL', 'BNE']


class instruction_mips32(instruction):
    delayslot = 1

    def __init__(self, *args, **kargs):
        super(instruction_mips32, self).__init__(*args, **kargs)


    @staticmethod
    def arg2str(e, pos = None):
        if isinstance(e, ExprId) or isinstance(e, ExprInt):
            return str(e)
        assert(isinstance(e, ExprMem))
        arg = e.arg
        if isinstance(arg, ExprId):
            return "(%s)"%arg
        assert(len(arg.args) == 2 and arg.op == '+')
        return "%s(%s)"%(arg.args[1], arg.args[0])

    def dstflow(self):
        if self.name == 'BREAK':
            return False
        if self.name.startswith('B'):
            return True
        if self.name in ['JAL', 'JALR', 'JR', 'J']:
            return True
        return False

    def get_dst_num(self):
        if self.name in br_0:
            i = 0
        elif self.name in br_1:
            i = 1
        elif self.name in br_2:
            i = 2
        else:
            raise NotImplementedError("TODO %s"%self)
        return i

    def dstflow2label(self, symbol_pool):
        if self.name in ["J", 'JAL']:
            e = self.args[0].arg
            ad = (self.offset & (0xFFFFFFFF ^ ((1<< 28)-1))) + e
            l = symbol_pool.getby_offset_create(ad)
            self.args[0] = ExprId(l, e.size)
            return

        ndx = self.get_dst_num()
        e = self.args[ndx]

        if not isinstance(e, ExprInt):
            return
        ad = e.arg + self.offset + 4
        l = symbol_pool.getby_offset_create(ad)
        s = ExprId(l, e.size)
        self.args[ndx] = s

    def breakflow(self):
        if self.name == 'BREAK':
            return False
        if self.name.startswith('B') or self.name in ['JR', 'J', 'JAL', 'JALR']:
            return True
        return False

    def is_subcall(self):
        if self.name in ['JAL', 'JALR']:
            return True
        return False

        if self.name == 'BLX':
            return True
        return self.additional_info.lnk

    def getdstflow(self, symbol_pool):
        if self.name in br_0:
            return [self.args[0]]
        elif self.name in br_1:
            return [self.args[1]]
        elif self.name in br_2:
            return [self.args[2]]
        elif self.name in ['JAL', 'JALR', 'JR', 'J']:
            return [self.args[0]]
        else:
            raise NotImplementedError("fix mnemo %s"%self.name)

    def splitflow(self):
        if self.name in ["B", 'JR', 'J']:
            return False
        if self.name in br_0:
            return True
        if self.name in br_1:
            return True
        if self.name in br_2:
            return True
        if self.name in ['JAL', 'JALR']:
            return True
        return False

    def get_symbol_size(self, symbol, symbol_pool):
        return 32

    def fixDstOffset(self):
        ndx = self.get_dst_num()
        e = self.args[ndx]
        print 'FIX', ndx, e, self.offset, self.l
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, ExprInt):
            return
        off = e.arg - (self.offset + self.l)
        print "diff", e, hex(self.offset)
        print hex(off)
        if int(off % 4):
            raise ValueError('strange offset! %r' % off)
        self.args[ndx] = ExprInt32(off)
        print 'final', self

    def get_args_expr(self):
        args = [a for a in self.args]
        return args


class mn_mips32(cls_mn):
    delayslot = 0
    name = "mips32"
    regs = regs_module
    bintree = {}
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    pc = {'l':PC, 'b':PC}
    sp = {'l':SP, 'b':SP}
    instruction = instruction_mips32
    max_instruction_len = 4

    @classmethod
    def getpc(cls, attrib = None):
        return PC

    @classmethod
    def getsp(cls, attrib = None):
        return SP

    def additional_info(self):
        info = additional_info()
        return info

    @classmethod
    def getbits(cls, bs, attrib, start, n):
        if not n:
            return 0
        o = 0
        while n:
            offset = start / 8
            n_offset = cls.endian_offset(attrib, offset)
            c = cls.getbytes(bs, n_offset, 1)
            if not c:
                raise IOError
            c = ord(c)
            r = 8 - start % 8
            c &= (1 << r) - 1
            l = min(r, n)
            c >>= (r - l)
            o <<= l
            o |= c
            n -= l
            start += l
        return o

    @classmethod
    def endian_offset(cls, attrib, offset):
        if attrib == "l":
            return (offset & ~3) + 3 - offset % 4
        elif attrib == "b":
            return offset
        else:
            raise NotImplementedError('bad attrib')

    @classmethod
    def check_mnemo(cls, fields):
        l = sum([x.l for x in fields])
        assert l == 32, "len %r" % l

    @classmethod
    def getmn(cls, name):
        return name.upper()

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def value(self, mode):
        v = super(mn_mips32, self).value(mode)
        if mode == 'l':
            return [x[::-1] for x in v]
        elif mode == 'b':
            return [x for x in v]
        else:
            raise NotImplementedError('bad attrib')



def mips32op(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_mips32,), dct)
    #type(name, (mn_mips32b,), dct)


class mips32_reg(reg_noarg, m_arg):
    pass

class mips32_gpreg(mips32_reg):
    reg_info = gpregs
    parser = reg_info.parser

class mips32_fltpreg(mips32_reg):
    reg_info = fltregs
    parser = reg_info.parser


class mips32_fccreg(mips32_reg):
    reg_info = fccregs
    parser = reg_info.parser

class mips32_imm(imm_noarg):
    parser = base_expr


class mips32_s16imm_noarg(mips32_imm):
    def decode(self, v):
        v = v & self.lmask
        v = sign_ext(v, 16, 32)
        self.expr = ExprInt32(v)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = self.expr.arg.arg
        if v & 0x80000000:
            nv = v & ((1 << 16) - 1)
            assert( v == sign_ext(nv, 16, 32))
            v = nv
        self.value = v
        return True

class mips32_soff_noarg(mips32_imm):
    def decode(self, v):
        v = v & self.lmask
        v <<= 2
        v = sign_ext(v, 16+2, 32)
        self.expr = ExprInt32(v)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = self.expr.arg.arg
        if v & 0x80000000:
            nv = v & ((1 << 16+2) - 1)
            assert( v == sign_ext(nv, 16+2, 32))
            v = nv
        self.value = v>>2
        return True


class mips32_s16imm(mips32_s16imm_noarg, m_arg):
    pass

class mips32_soff(mips32_soff_noarg, m_arg):
    pass


class mips32_instr_index(mips32_imm, m_arg):
    def decode(self, v):
        v = v & self.lmask
        self.expr = ExprInt32(v<<2)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = self.expr.arg.arg
        if v & 3:
            return False
        v>>=2
        if v > (1<<self.l):
            return False
        self.value = v
        return True


class mips32_u16imm(mips32_imm, m_arg):
    def decode(self, v):
        v = v & self.lmask
        self.expr = ExprInt32(v)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = self.expr.arg.arg
        assert(v < (1<<16))
        self.value = v
        return True

class mips32_dreg_imm(m_arg):
    parser = deref
    def decode(self, v):
        imm = self.parent.imm.expr
        r = gpregs.expr[v]
        self.expr = ExprMem(r+imm)
        return True

    def encode(self):
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        arg = e.arg
        if isinstance(arg, ExprId):
            self.parent.imm.expr = ExprInt32(0)
            r = arg
        elif len(arg.args) == 2 and arg.op == "+":
            self.parent.imm.expr = arg.args[1]
            r = arg.args[0]
        else:
            return False
        self.value = gpregs.expr.index(r)
        return True

    @staticmethod
    def arg2str(e):
        assert(isinstance(e, ExprMem))
        arg = e.arg
        if isinstance(arg, ExprId):
            return "(%s)"%arg
        assert(len(arg.args) == 2 and arg.op == '+')
        return "%s(%s)"%(arg.args[1], arg.args[0])

class mips32_esize(mips32_imm, m_arg):
    def decode(self, v):
        v = v & self.lmask
        self.expr = ExprInt32(v+1)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = self.expr.arg.arg -1
        assert(v < (1<<16))
        self.value = v
        return True

class mips32_eposh(mips32_imm, m_arg):
    def decode(self, v):
        self.expr = ExprInt32(v-int(self.parent.epos.expr.arg)+1)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr.arg) + int(self.parent.epos.expr.arg) -1
        self.value = v
        return True


class mips32_imm(mips32_imm):
    pass


class mips32_cpr(m_arg):
    parser = regs_cpr0_info.parser
    def decode(self, v):
        index = int(self.parent.cpr0.expr.arg) << 3
        index += v
        self.expr = regs_cpr0_expr[index]
        return True
    def encode(self):
        e = self.expr
        if not e in regs_cpr0_expr:
            return False
        index = regs_cpr0_expr.index(e)
        self.value = index & 7
        index >>=2
        self.parent.cpr0.value = index
        return True

rs = bs(l=5, cls=(mips32_gpreg,))
rt = bs(l=5, cls=(mips32_gpreg,))
rd = bs(l=5, cls=(mips32_gpreg,))
ft = bs(l=5, cls=(mips32_fltpreg,))
fs = bs(l=5, cls=(mips32_fltpreg,))
fd = bs(l=5, cls=(mips32_fltpreg,))

s16imm = bs(l=16, cls=(mips32_s16imm,))
u16imm = bs(l=16, cls=(mips32_u16imm,))
sa = bs(l=5, cls=(mips32_u16imm,))
base = bs(l=5, cls=(mips32_dreg_imm,))
soff = bs(l=16, cls=(mips32_soff,))

cpr0 = bs(l=5, cls=(mips32_imm,), fname="cpr0")
cpr =  bs(l=3, cls=(mips32_cpr,))


s16imm_noarg = bs(l=16, cls=(mips32_s16imm_noarg,), fname="imm",
                  order=-1)

hint = bs(l=5, default_val="00000")
fcc = bs(l=3, cls=(mips32_fccreg,))

sel = bs(l=3, cls=(mips32_u16imm,))

code = bs(l=20, cls=(mips32_u16imm,))

esize = bs(l=5, cls=(mips32_esize,))
epos = bs(l=5, cls=(mips32_u16imm,), fname="epos",
          order=-1)

eposh = bs(l=5, cls=(mips32_eposh,))

instr_index = bs(l=26, cls=(mips32_instr_index,))
bs_fmt = bs_mod_name(l=5, fname='fmt', mn_mod={0x10: '.S', 0x11: '.D', 0x14: '.W',
                                               0x15: '.L', 0x16: '.PS'})
class bs_cond(bs_mod_name):
    mn_mod = ['.F', '.UN', '.EQ', '.UEQ',
              '.OLT', '.ULT', '.OLE', '.ULE',
              '.SF', '.NGLE', '.SEQ', '.NGL',
              '.LT', '.NGE', '.LE', '.NGT'
              ]

    def modname(self, name, f_i):
        fds
        return name + self.args['mn_mod'][f_i]


class bs_cond_name(bs_divert):
    prio = 2
    mn_mod = [['.F', '.UN', '.EQ', '.UEQ',
               '.OLT', '.ULT', '.OLE', '.ULE'],
              ['.SF', '.NGLE', '.SEQ', '.NGL',
               '.LT', '.NGE', '.LE', '.NGT']
              ]

    def divert(self, i, candidates):
        out = []
        for candidate in candidates:
            cls, name, bases, dct, fields = candidate
            cond1 = [f for f in fields if f.fname == "cond1"]
            assert(len(cond1) == 1)
            cond1 = cond1.pop()
            mm = self.mn_mod[cond1.value]
            for value, new_name in enumerate(mm):
                nfields = fields[:]
                s = int2bin(value, self.args['l'])
                args = dict(self.args)
                args.update({'strbits': s})
                f = bs(**args)
                nfields[i] = f
                ndct = dict(dct)
                ndct['name'] = name + new_name
                out.append((cls, new_name, bases, ndct, nfields))
        return out



class bs_cond_mod(bs_mod_name):
    prio = 1

bs_cond = bs_cond_mod(l=4,
                      mn_mod = ['.F', '.UN', '.EQ', '.UEQ',
                                '.OLT', '.ULT', '.OLE', '.ULE',
                                '.SF', '.NGLE', '.SEQ', '.NGL',
                                '.LT', '.NGE', '.LE', '.NGT'])



bs_arith = bs_name(l=6, name={'ADDU':0b100001,
                              'SUBU':0b100011,
                              'OR':0b100101,
                              'AND':0b100100,
                              'SLTU':0b101011,
                              'XOR':0b100110,
                              'SLT':0b101010,
                              'SUBU':0b100011,
                              'NOR':0b100111,
                              'MOVN':0b001011,
                              'MOVZ':0b001010,
                              })

bs_shift = bs_name(l=6, name={'SLL':0b000000,
                              'SRL':0b000010,
                              'SRA':0b000011,
                              })

bs_shift1 = bs_name(l=6, name={'SLLV':0b000100,
                               'SRLV':0b000110,
                               'SRAV':0b000111,
                               })


bs_arithfmt = bs_name(l=6, name={'ADD':0b000000,
                                 'SUB':0b000001,
                                 'MUL':0b000010,
                                 'DIV':0b000011,
                                 })

bs_s_l = bs_name(l=6, name = {"SW":    0b101011,
                              "SH":    0b101001,
                              "SB":    0b101000,
                              "LW":    0b100011,
                              "LH":    0b100001,
                              "LB":    0b100000,
                              "LHU":   0b100101,
                              "LBU":   0b100100,
                              "LWL":   0b100010,
                              "LWR":   0b100110,

                              "SWL":   0b101010,
                              "SWR":   0b101110,
                              })


bs_oax = bs_name(l=6, name = {"ORI":    0b001101,
                              "ANDI":   0b001100,
                              "XORI":   0b001110,
                              })

bs_bcc = bs_name(l=5, name = {"BGEZ":    0b00001,
                              "BGEZL":   0b00011,
                              "BGEZAL":  0b10001,
                              "BGEZALL": 0b10011,
                              "BLTZ":    0b00000,
                              "BLTZL":   0b00010,
                              "BLTZAL":  0b10000,
                              "BLTZALL": 0b10010,
                              })



mips32op("addi",    [bs('001000'), rs, rt, s16imm], [rt, rs, s16imm])
mips32op("addiu",   [bs('001001'), rs, rt, s16imm], [rt, rs, s16imm])
mips32op("nop",     [bs('0'*32)], alias = True)
mips32op("lui",     [bs('001111'), bs('00000'), rt, u16imm])
mips32op("oax",     [bs_oax, rs, rt, u16imm], [rt, rs, u16imm])

mips32op("arith",   [bs('000000'), rs, rt, rd, bs('00000'), bs_arith], [rd, rs, rt])
mips32op("shift1",  [bs('000000'), rs, rt, rd, bs('00000'), bs_shift1], [rd, rt, rs])

mips32op("shift",   [bs('000000'), bs('00000'), rt, rd, sa, bs_shift], [rd, rt, sa])

mips32op("rotr",    [bs('000000'), bs('00001'), rt, rd, sa, bs('000010')], [rd, rt, sa])

mips32op("mul",     [bs('011100'), rs, rt, rd, bs('00000'), bs('000010')], [rd, rs, rt])
mips32op("div",     [bs('000000'), rs, rt, bs('0000000000'), bs('011010')])

mips32op("s_l",     [bs_s_l, base, rt, s16imm_noarg], [rt, base])

#mips32op("mfc0",    [bs('010000'), bs('00000'), rt, rd, bs('00000000'), sel])
mips32op("mfc0",    [bs('010000'), bs('00000'), rt, cpr0, bs('00000000'), cpr])
mips32op("mfc1",    [bs('010001'), bs('00000'), rt, fs, bs('00000000000')])

mips32op("ldc1",    [bs('110101'), base, ft, s16imm_noarg], [ft, base])

mips32op("mov",     [bs('010001'), bs_fmt, bs('00000'), fs, fd, bs('000110')], [fd, fs])

mips32op("add",     [bs('010001'), bs_fmt, ft, fs, fd, bs_arithfmt], [fd, fs, ft])

mips32op("divu",    [bs('000000'), rs, rt, bs('0000000000'), bs('011011')])
mips32op("mult",    [bs('000000'), rs, rt, bs('0000000000'), bs('011000')])
mips32op("multu",   [bs('000000'), rs, rt, bs('0000000000'), bs('011001')])
mips32op("mflo",    [bs('000000'), bs('0000000000'), rd, bs('00000'), bs('010010')])
mips32op("mfhi",    [bs('000000'), bs('0000000000'), rd, bs('00000'), bs('010000')])


mips32op("b",       [bs('000100'), bs('00000'), bs('00000'), soff], alias = True)
mips32op("bne",     [bs('000101'), rs, rt, soff])
mips32op("beq",     [bs('000100'), rs, rt, soff])

mips32op("blez",    [bs('000110'), rs, bs('00000'), soff])

mips32op("bcc",     [bs('000001'), rs, bs_bcc, soff])

mips32op("bgtz",    [bs('000111'), rs, bs('00000'), soff])
mips32op("bal",     [bs('000001'), bs('00000'), bs('10001'), soff], alias = True)


mips32op("slti",    [bs('001010'), rs, rt, s16imm], [rt, rs, s16imm])
mips32op("sltiu",   [bs('001011'), rs, rt, s16imm], [rt, rs, s16imm])


mips32op("j",       [bs('000010'), instr_index])
mips32op("jal",     [bs('000011'), instr_index])
mips32op("jalr",    [bs('000000'), rs, bs('00000'), rd, hint, bs('001001')])
mips32op("jr",      [bs('000000'), rs, bs('0000000000'), hint, bs('001000')])

mips32op("lwc1",    [bs('110001'), base, ft, s16imm_noarg], [ft, base])

#mips32op("mtc0",    [bs('010000'), bs('00100'), rt, rd, bs('00000000'), sel])
mips32op("mtc0",    [bs('010000'), bs('00100'), rt, cpr0, bs('00000000'), cpr])
mips32op("mtc1",    [bs('010001'), bs('00100'), rt, fs, bs('00000000000')])

# XXXX TODO CFC1
mips32op("cfc1",    [bs('010001'), bs('00010'), rt, fs, bs('00000000000')])
# XXXX TODO CTC1
mips32op("ctc1",    [bs('010001'), bs('00110'), rt, fs, bs('00000000000')])

mips32op("break",   [bs('000000'), code, bs('001101')])
mips32op("syscall", [bs('000000'), code, bs('001100')])


mips32op("c",       [bs('010001'), bs_fmt, ft, fs, fcc, bs('0'), bs('0'), bs('11'), bs_cond], [fcc, fs, ft])


mips32op("bc1t",    [bs('010001'), bs('01000'), fcc, bs('0'), bs('1'), soff])
mips32op("bc1f",    [bs('010001'), bs('01000'), fcc, bs('0'), bs('0'), soff])

mips32op("swc1",    [bs('111001'), base, ft, s16imm_noarg], [ft, base])

mips32op("cvt.d",   [bs('010001'), bs_fmt, bs('00000'), fs, fd, bs('100001')], [fd, fs])
mips32op("cvt.w",   [bs('010001'), bs_fmt, bs('00000'), fs, fd, bs('100100')], [fd, fs])
mips32op("cvt.s",   [bs('010001'), bs_fmt, bs('00000'), fs, fd, bs('100000')], [fd, fs])

mips32op("ext",     [bs('011111'), rs, rt, esize, epos, bs('000000')], [rt, rs, epos, esize])
mips32op("ins",     [bs('011111'), rs, rt, eposh, epos, bs('000100')], [rt, rs, epos, eposh])

mips32op("seb",     [bs('011111'), bs('00000'), rt, rd, bs('10000'), bs('100000')], [rd, rt])
mips32op("seh",     [bs('011111'), bs('00000'), rt, rd, bs('11000'), bs('100000')], [rd, rt])
mips32op("wsbh",    [bs('011111'), bs('00000'), rt, rd, bs('00010'), bs('100000')], [rd, rt])

mips32op("di",      [bs('010000'), bs('01011'), rt, bs('01100'), bs('00000'), bs('0'), bs('00'), bs('000')])
mips32op("ei",      [bs('010000'), bs('01011'), rt, bs('01100'), bs('00000'), bs('1'), bs('00'), bs('000')])


mips32op("tlbp",    [bs('010000'), bs('1'), bs('0'*19), bs('001000')])
mips32op("tlbwi",   [bs('010000'), bs('1'), bs('0'*19), bs('000010')])
