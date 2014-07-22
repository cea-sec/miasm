#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os
from pyparsing import *
from miasm2.core.cpu import *
from miasm2.expression.expression import *
from collections import defaultdict
from regs import *


jra = ExprId('jra')
jrb = ExprId('jrb')
jrc = ExprId('jrc')


# parser helper ###########
PLUS = Suppress("+")
MULT = Suppress("*")
MINUS = Suppress("-")
AND = Suppress("&")
LBRACK = Suppress("[")
RBRACK = Suppress("]")
DEREF = Suppress("@")
COMMA = Suppress(",")
LPARENT = Suppress("(")
RPARENT = Suppress(")")


def parse_deref_pcimm(t):
    t = t[0]
    return t[0] + t[1]


def parse_pcandimmimm(t):
    t = t[0]
    return (t[0] & t[1]) + t[2]

def ast_id2expr(a):
    return ExprId(a, 32)

def ast_int2expr(a):
    return ExprInt32(a)


my_var_parser = parse_ast(ast_id2expr, ast_int2expr)
base_expr.setParseAction(my_var_parser)

int_or_expr = base_expr

ref_pc = Group(LPARENT + regi_pc.parser + COMMA +
               int_or_expr + RPARENT).setParseAction(parse_deref_pcimm)
ref_pcandimm = Group(
    LPARENT + regi_pc.parser + AND + int_or_expr +
    COMMA + int_or_expr + RPARENT).setParseAction(parse_pcandimmimm)


pcdisp = Group(regi_pc.parser + AND + int_or_expr +
               PLUS + int_or_expr).setParseAction(parse_pcandimmimm)

PTR = Suppress('PTR')


def parse_deref_mem(s, l, t):
    t = t[0]
    e = ExprMem(t[0], 32)
    return e


def parse_predec(s, l, t):
    t = t[0]
    e = ExprOp('predec', t[0])
    return e


def parse_postinc(s, l, t):
    t = t[0]
    e = ExprOp('postinc', t[0])
    return e


def parse_regdisp(t):
    t = t[0]
    e = ExprMem(t[0] + t[1])
    return e


def parse_regreg(t):
    t = t[0]
    e = ExprMem(t[0] + t[1])
    return e


deref_pc = Group(DEREF + ref_pc).setParseAction(parse_deref_mem)
deref_pcimm = Group(DEREF + ref_pcandimm).setParseAction(parse_deref_mem)

dgpregs_base = Group(DEREF + gpregs.parser).setParseAction(parse_deref_mem)
dgpregs_predec = Group(
    DEREF + MINUS + gpregs.parser).setParseAction(parse_predec)
dgpregs_postinc = Group(
    DEREF + gpregs.parser + PLUS).setParseAction(parse_postinc)

dgpregs = dgpregs_base | dgpregs_predec | dgpregs_postinc

d_gpreg_gpreg = Group(DEREF +
    LPARENT + gpregs.parser + COMMA + gpregs.parser + RPARENT
    ).setParseAction(parse_regdisp)
dgpregs_p = dgpregs_predec | dgpregs_postinc


dgpregs_ir = Group(DEREF + LPARENT + gpregs.parser +
                   COMMA + int_or_expr + RPARENT).setParseAction(parse_regdisp)
dgpregs_ir |= d_gpreg_gpreg

dgbr_imm = Group(DEREF + LPARENT + regi_gbr.parser +
                 COMMA + int_or_expr + RPARENT).setParseAction(parse_regdisp)

dgbr_reg = Group(DEREF + LPARENT + regi_gbr.parser +
                 COMMA + gpregs.parser + RPARENT).setParseAction(parse_regreg)


class sh4_reg(reg_noarg, m_arg):
    pass


class sh4_gpreg(sh4_reg):
    reg_info = gpregs
    parser = reg_info.parser


class sh4_dr(sh4_reg):
    reg_info = dregs
    parser = reg_info.parser


class sh4_bgpreg(sh4_reg):
    reg_info = bgpregs
    parser = reg_info.parser


class sh4_gpreg_noarg(reg_noarg, ):
    reg_info = gpregs
    parser = reg_info.parser


class sh4_freg(sh4_reg):
    reg_info = fregs
    parser = reg_info.parser


class sh4_dgpreg(m_arg):
    parser = dgpregs_base

    def fromstring(self, s, parser_result=None):
        start, stop = super(sh4_dgpreg, self).fromstring(s, parser_result)
        if start is None:
            return start, stop
        self.expr = ExprMem(self.expr.arg, self.sz)
        return start, stop

    def decode(self, v):
        r = gpregs.expr[v]
        self.expr = ExprMem(r, self.sz)
        return True

    def encode(self):
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        if not isinstance(e.arg, ExprId):
            return False
        v = gpregs.expr.index(e.arg)
        self.value = v
        return True

    @staticmethod
    def arg2str(e):
        ad = e.arg
        if isinstance(ad, ExprOp):
            s = ','.join([str(x).replace('(', '').replace(')', '')
                         for x in ad.args])
            s = "@(%s)" % s
        else:
            s = "@%s" % ad
        return s


class sh4_dgpregpinc(m_arg):
    parser = dgpregs_p

    def fromstring(self, s, parser_result=None):
        start, stop = super(sh4_dgpregpinc, self).fromstring(s, parser_result)
        if not isinstance(self.expr, ExprOp):
            return None, None
        if self.expr.op != self.op:
            return None, None
        return start, stop

    def decode(self, v):
        r = gpregs.expr[v]
        e = ExprOp(self.op, r, ExprInt32(self.sz))
        self.expr = e
        return True

    def encode(self):
        e = self.expr
        res = MatchExpr(e, ExprOp(self.op, jra), [jra])
        if not res:
            return False
        r = res[jra]
        if not r in gpregs.expr:
            return False
        v = gpregs.expr.index(r)
        self.value = v
        return True

    @staticmethod
    def arg2str(e):
        if e.op == "predec":
            o = '-%s' % e.args[0]
        elif e.op == "postinc":
            o = '%s+' % e.args[0]
        else:
            raise ValueError('unknown e.op: %s' % e.op)
        return "@%s" % o


class sh4_dgpregpdec(m_arg):
    parser = dgpregs_postinc
    op = "preinc"


class sh4_dgpreg_imm(sh4_dgpreg):
    parser = dgpregs_ir

    def decode(self, v):
        p = self.parent
        r = gpregs.expr[v]
        s = self.sz
        d = ExprInt32(p.disp.value * s / 8)
        e = ExprMem(r + d, s)
        self.expr = e
        return True

    def encode(self):
        e = self.expr
        p = self.parent
        s = self.sz
        if not isinstance(e, ExprMem):
            return False
        if isinstance(e.arg, ExprId):
            v = gpregs.expr.index(e.arg)
            p.disp.value = 0
        elif isinstance(e.arg, ExprOp):
            res = MatchExpr(e, ExprMem(jra + jrb, self.sz), [jra, jrb])
            if not res:
                return False
            if not isinstance(res[jra], ExprId):
                return False
            if not isinstance(res[jrb], ExprInt):
                return False
            d = int(res[jrb].arg)
            p.disp.value = d / (s / 8)
            if not res[jra] in gpregs.expr:
                return False
            v = gpregs.expr.index(res[jra])
        else:
            return False
        self.value = v
        return True


class sh4_imm(imm_noarg, m_arg):
    parser = base_expr
    pass


class sh4_simm(sh4_imm):
    parser = base_expr

    def decode(self, v):
        v = sign_ext(v, self.l, 32)
        v = self.decodeval(v)
        self.expr = ExprInt32(v)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr.arg)
        if (1 << (self.l - 1)) & v:
            v = -((0xffffffff ^ v) + 1)
        v = self.encodeval(v)
        self.value = (v & 0xffffffff) & self.lmask
        return True


class sh4_dpc16imm(sh4_dgpreg):
    parser = deref_pc

    def decode(self, v):
        self.expr = ExprMem(PC + ExprInt32(v * 2 + 4), 16)
        return True

    def calcdisp(self, v):
        v = (int(v.arg) - 4) / 2
        if not 0 < v <= 0xff:
            return None
        return v

    def encode(self):
        res = MatchExpr(self.expr, ExprMem(PC + jra, 16), [jra])
        if not res:
            return False
        if not isinstance(res[jra], ExprInt):
            return False
        v = self.calcdisp(res[jra])
        if v is None:
            return False
        self.value = v
        return True


class sh4_dgbrimm8(sh4_dgpreg):
    parser = dgbr_imm

    def decode(self, v):
        s = self.sz
        self.expr = ExprMem(GBR + ExprInt32(v * s / 8), s)
        return True

    def encode(self):
        e = self.expr
        s = self.sz
        if e == ExprMem(GBR):
            self.value = 0
            return True
        res = MatchExpr(self.expr, ExprMem(GBR + jra, s), [jra])
        if not res:
            return False
        if not isinstance(res[jra], ExprInt):
            return False
        self.value = int(res[jra].arg) / (s / 8)
        return True


class sh4_dpc32imm(sh4_dpc16imm):
    parser = deref_pcimm

    def decode(self, v):
        self.expr = ExprMem(
            (PC & ExprInt32(0xfffffffc)) + ExprInt32(v * 4 + 4))
        return True

    def calcdisp(self, v):
        v = (int(v.arg) - 4) / 4
        if not 0 < v <= 0xff:
            return None
        return v

    def encode(self):
        res = MatchExpr(
            self.expr, ExprMem((PC & ExprInt32(0xFFFFFFFC)) + jra, 32), [jra])
        if not res:
            return False
        if not isinstance(res[jra], ExprInt):
            return False
        v = self.calcdisp(res[jra])
        if v is None:
            return False
        self.value = v
        return True


class sh4_pc32imm(m_arg):
    parser = pcdisp

    def decode(self, v):
        self.expr = (PC & ExprInt32(0xfffffffc)) + ExprInt32(v * 4 + 4)
        return True

    def encode(self):
        res = MatchExpr(self.expr, (PC & ExprInt32(0xfffffffc)) + jra, [jra])
        if not res:
            return False
        if not isinstance(res[jra], ExprInt):
            return False
        v = (int(res[jra].arg) - 4) / 4
        if v is None:
            return False
        self.value = v
        return True

    @staticmethod
    def arg2str(e):
        s = str(e).replace('(', '').replace(')', '')
        return "%s" % s


class additional_info:

    def __init__(self):
        self.except_on_instr = False


class instruction_sh4(instruction):
    delayslot = 0

    def __init__(self, *args, **kargs):
        super(instruction_sh4, self).__init__(*args, **kargs)

    def dstflow(self):
        return self.name.startswith('J')
    """
    def dstflow2label(self, symbol_pool):
        e = self.args[0]
        if not isinstance(e, ExprInt):
            return
        if self.name == 'BLX':
            ad = e.arg+8+self.offset
        else:
            ad = e.arg+8+self.offset
        l = symbol_pool.getby_offset_create(ad)
        s = ExprId(l, e.size)
        self.args[0] = s
    """

    def breakflow(self):
        if self.name.startswith('J'):
            return True
        return False

    def is_subcall(self):
        return self.name == 'JSR'

    def getdstflow(self, symbol_pool):
        return [self.args[0]]

    def splitflow(self):
        return self.name == 'JSR'

    def get_symbol_size(self, symbol, symbol_pool):
        return 32

    def fixDstOffset(self):
        e = self.args[0]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, ExprInt):
            log.debug('dyn dst %r' % e)
            return
        off = e.arg - (self.offset + 4 + self.l)
        print hex(off)
        if int(off % 4):
            raise ValueError('strange offset! %r' % off)
        self.args[0] = ExprInt32(off)
        print 'final', self.args[0]

    def get_args_expr(self):
        args = [a for a in self.args]
        return args


class mn_sh4(cls_mn):
    bintree = {}
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    pc = PC
    # delayslot:
    # http://resource.renesas.com/lib/eng/e_learnig/sh4/13/index.html
    delayslot = 0  # unit is instruction instruction

    def additional_info(self):
        info = additional_info()
        return info

    @classmethod
    def getbits(cls, bs, start, n):
        if not n:
            return 0
        o = 0
        if n > bs.getlen() * 8:
            raise ValueError('not enought bits %r %r' % (n, len(bs.bin) * 8))
        while n:
            i = start / 8
            c = cls.getbytes(bs, i)
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
    def getbytes(cls, bs, offset, l=1):
        out = ""
        for _ in xrange(l):
            n_offset = (offset & ~1) + 1 - offset % 2
            out += bs.getbytes(n_offset, 1)
            offset += 1
        return out

    @classmethod
    def check_mnemo(cls, fields):
        l = sum([x.l for x in fields])
        assert l == 16, "len %r" % l

    @classmethod
    def getmn(cls, name):
        return name.upper().replace('_', '.')

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def value(self, mode):
        v = super(mn_sh4, self).value(mode)
        return [x[::-1] for x in v]


class bs_dr0gbr(sh4_dgpreg):
    parser = dgbr_reg

    def decode(self, v):
        self.expr = ExprMem(GBR + R0, 8)
        return True

    def encode(self):
        return self.expr == ExprMem(GBR + R0, 8)


class bs_dr0gp(sh4_dgpreg):
    parser = d_gpreg_gpreg

    def decode(self, v):
        self.expr = ExprMem(gpregs.expr[v] + R0, self.sz)
        return True

    def encode(self):
        res = MatchExpr(self.expr, ExprMem(R0 + jra, self.sz), [jra])
        if not res:
            return False
        r = res[jra]
        if not r in gpregs.expr:
            return False
        self.value = gpregs.expr.index(r)
        return True


class bs_dgpreg(sh4_dgpreg):
    parser = dgpregs_base


rn = bs(l=4, cls=(sh4_gpreg,), fname="rn")
rm = bs(l=4, cls=(sh4_gpreg,), fname="rm")


d08_rn = bs(l=4, cls=(sh4_dgpreg,), fname="rn", sz = 8)
d16_rn = bs(l=4, cls=(sh4_dgpreg,), fname="rn", sz = 16)
d32_rn = bs(l=4, cls=(sh4_dgpreg,), fname="rn", sz = 32)
d08_rm = bs(l=4, cls=(sh4_dgpreg,), fname="rm", sz = 8)
d16_rm = bs(l=4, cls=(sh4_dgpreg,), fname="rm", sz = 16)
d32_rm = bs(l=4, cls=(sh4_dgpreg,), fname="rm", sz = 32)


brm = bs(l=3, cls=(sh4_bgpreg,), fname="brm")
brn = bs(l=3, cls=(sh4_bgpreg,), fname="brn")

d08rnimm = bs(l=4, fname="rn", cls=(sh4_dgpreg_imm,), sz = 8)
d16rnimm = bs(l=4, fname="rn", cls=(sh4_dgpreg_imm,), sz = 16)
d32rnimm = bs(l=4, fname="rn", cls=(sh4_dgpreg_imm,), sz = 32)

d08rmimm = bs(l=4, fname="rm", cls=(sh4_dgpreg_imm,), sz = 8)
d16rmimm = bs(l=4, fname="rm", cls=(sh4_dgpreg_imm,), sz = 16)
d32rmimm = bs(l=4, fname="rm", cls=(sh4_dgpreg_imm,), sz = 32)

btype = bs(l=4, fname="btype", order=-1)

s08imm = bs(l=8, cls=(sh4_simm,), fname="imm")
s12imm = bs(l=12, cls=(sh4_simm,), fname="imm")
dpc16imm = bs(l=8, cls=(sh4_dpc16imm,), fname="pcimm", sz=16)
dpc32imm = bs(l=8, cls=(sh4_dpc32imm,), fname="pcimm", sz=32)
dimm4 = bs(l=4, fname='disp', order=-1)
d08gbrimm8 = bs(l=8, cls=(sh4_dgbrimm8,), fname='disp', sz=8)
d16gbrimm8 = bs(l=8, cls=(sh4_dgbrimm8,), fname='disp', sz=16)
d32gbrimm8 = bs(l=8, cls=(sh4_dgbrimm8,), fname='disp', sz=32)

pc32imm = bs(l=8, cls=(sh4_pc32imm,), fname="pcimm")

d08rnpinc = bs(l=4, cls=(sh4_dgpregpinc,), op='postinc', sz=8, fname="rn")
d08rmpinc = bs(l=4, cls=(sh4_dgpregpinc,), op='postinc', sz=8, fname="rm")

d16rnpinc = bs(l=4, cls=(sh4_dgpregpinc,), op='postinc', sz=16, fname="rn")
d16rmpinc = bs(l=4, cls=(sh4_dgpregpinc,), op='postinc', sz=16, fname="rm")

d32rnpinc = bs(l=4, cls=(sh4_dgpregpinc,), op='postinc', sz=32, fname="rn")
d32rmpinc = bs(l=4, cls=(sh4_dgpregpinc,), op='postinc', sz=32, fname="rm")

d08rnpdec = bs(l=4, cls=(sh4_dgpregpinc,), op='predec', sz=8, fname="rn")
d08rmpdec = bs(l=4, cls=(sh4_dgpregpinc,), op='predec', sz=8, fname="rm")

d16rnpdec = bs(l=4, cls=(sh4_dgpregpinc,), op='predec', sz=16, fname="rn")
d16rmpdec = bs(l=4, cls=(sh4_dgpregpinc,), op='predec', sz=16, fname="rm")

d32rnpdec = bs(l=4, cls=(sh4_dgpregpinc,), op='predec', sz=32, fname="rn")
d32rmpdec = bs(l=4, cls=(sh4_dgpregpinc,), op='predec', sz=32, fname="rm")


u08imm = bs(l=8, cls=(sh4_imm,), fname="imm")
dr0gbr = bs(l=0, cls=(bs_dr0gbr,), sz=8)

d08gpreg = bs(l=4, cls=(bs_dgpreg,), sz=8)
d32gpreg = bs(l=4, cls=(bs_dgpreg,), sz=32)

frn = bs(l=4, cls=(sh4_freg,), fname="frn")
frm = bs(l=4, cls=(sh4_freg,), fname="frm")

bd08r0gp = bs(l=4, cls=(bs_dr0gp,), sz=8)
bd16r0gp = bs(l=4, cls=(bs_dr0gp,), sz=16)
bd32r0gp = bs(l=4, cls=(bs_dr0gp,), sz=32)

drn = bs(l=3, cls=(sh4_dr,), fname="drn")
drm = bs(l=3, cls=(sh4_dr,), fname="drm")


def addop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_sh4,), dct)

addop("mov", [bs('1110'), rn, s08imm], [s08imm, rn])
addop("mov_w", [bs('1001'), rn, dpc16imm], [dpc16imm, rn])
addop("mov_l", [bs('1101'), rn, dpc32imm], [dpc32imm, rn])
addop("mov", [bs('0110', fname="opc"), rn, rm, bs('0011')], [rm, rn])
addop("mov_b", [bs('0010', fname="opc"), d08_rn, rm, bs('0000')], [rm, d08_rn])
addop("mov_w", [bs('0010', fname="opc"), d16_rn, rm, bs('0001')], [rm, d16_rn])
addop("mov_l", [bs('0010', fname="opc"), d32_rn, rm, bs('0010')], [rm, d32_rn])
addop("mov_b", [bs('0110', fname="opc"), rn, d08_rm, bs('0000')], [d08_rm, rn])
addop("mov_w", [bs('0110', fname="opc"), rn, d16_rm, bs('0001')], [d16_rm, rn])
addop("mov_l", [bs('0110', fname="opc"), rn, d32_rm, bs('0010')], [d32_rm, rn])
addop("mov_b",
      [bs('0010', fname="opc"), d08rnpdec, rm, bs('0100')], [rm, d08rnpdec])
addop("mov_w",
      [bs('0010', fname="opc"), d16rnpdec, rm, bs('0101')], [rm, d16rnpdec])
addop("mov_l",
      [bs('0010', fname="opc"), d32rnpdec, rm, bs('0110')], [rm, d32rnpdec])
addop("mov_b",
      [bs('0110', fname="opc"), rn, d08rmpinc, bs('0100')], [rm, d08rnpinc])
addop("mov_w",
      [bs('0110', fname="opc"), rn, d16rmpinc, bs('0101')], [d16rmpinc, rn])
addop("mov_l",
      [bs('0110', fname="opc"), rn, d32rmpinc, bs('0110')], [d32rmpinc, rn])
addop("mov_b", [bs('10000000', fname='opc'), bsr0, d08rnimm, dimm4])
addop("mov_w", [bs('10000001', fname='opc'), bsr0, d16rnimm, dimm4])
addop("mov_l", [bs('0001', fname='opc'), d32rnimm, rm, dimm4], [rm, d32rnimm])
addop("mov_b", [bs('10000100', fname='opc'), d08rmimm, dimm4, bsr0])
addop("mov_w", [bs('10000101', fname='opc'), d16rmimm, dimm4, bsr0])
addop("mov_l", [bs('0101', fname='opc'), rn, d32rmimm, dimm4], [d32rmimm, rn])
addop("mov_b",
      [bs('0000', fname='opc'), bd08r0gp, rm, bs('0100')], [rm, bd08r0gp])
addop("mov_w",
      [bs('0000', fname='opc'), bd16r0gp, rm, bs('0101')], [rm, bd16r0gp])
addop("mov_l",
      [bs('0000', fname='opc'), bd32r0gp, rm, bs('0110')], [rm, bd32r0gp])
addop("mov_b",
      [bs('0000', fname='opc'), rn, bd08r0gp, bs('1100')], [bd08r0gp, rn])
addop("mov_w",
      [bs('0000', fname='opc'), rn, bd16r0gp, bs('1101')], [bd16r0gp, rn])
addop("mov_l",
      [bs('0000', fname='opc'), rn, bd32r0gp, bs('1110')], [bd32r0gp, rn])

addop("mov_b", [bs('11000000'), bsr0, d08gbrimm8])
addop("mov_w", [bs('11000001'), bsr0, d16gbrimm8])
addop("mov_l", [bs('11000010'), bsr0, d32gbrimm8])

addop("mov_b", [bs('11000100'), d08gbrimm8, bsr0])
addop("mov_w", [bs('11000101'), d16gbrimm8, bsr0])
addop("mov_l", [bs('11000110'), d32gbrimm8, bsr0])

addop("mov", [bs('11000111'), pc32imm, bsr0])

addop("swapb", [bs('0110'), rn, rm, bs('1000')], [rm, rn])
addop("swapw", [bs('0110'), rn, rm, bs('1001')], [rm, rn])
addop("xtrct", [bs('0010'), rn, rm, bs('1101')], [rm, rn])


addop("add", [bs('0011'), rn, rm, bs('1100')], [rm, rn])
addop("add", [bs('0111'), rn, s08imm], [s08imm, rn])
addop("addc", [bs('0011'), rn, rm, bs('1110')], [rm, rn])
addop("addv", [bs('0011'), rn, rm, bs('1111')], [rm, rn])


addop("cmpeq", [bs('10001000'), s08imm, bsr0])


addop("cmpeq", [bs('0011'), rn, rm, bs('0000')], [rm, rn])
addop("cmphs", [bs('0011'), rn, rm, bs('0010')], [rm, rn])
addop("cmpge", [bs('0011'), rn, rm, bs('0011')], [rm, rn])
addop("cmphi", [bs('0011'), rn, rm, bs('0110')], [rm, rn])
addop("cmpgt", [bs('0011'), rn, rm, bs('0111')], [rm, rn])


addop("cmppz", [bs('0100'), rn, bs('00010001')])
addop("cmppl", [bs('0100'), rn, bs('00010101')])
addop("cmpstr", [bs('0010'), rn, rm, bs('1100')], [rm, rn])


addop("div1", [bs('0011'), rn, rm, bs('0100')], [rm, rn])

addop("div0s", [bs('0010'), rn, rm, bs('0111')], [rm, rn])
addop("div0u", [bs('0000000000011001')])

addop("dmuls", [bs('0011'), rn, rm, bs('1101')], [rm, rn])
addop("dmulu", [bs('0011'), rn, rm, bs('0101')], [rm, rn])

addop("dt", [bs('0100'), rn, bs('00010000')])


addop("extsb", [bs('0110'), rn, rm, bs('1110')], [rm, rn])
addop("extsw", [bs('0110'), rn, rm, bs('1111')], [rm, rn])
addop("extub", [bs('0110'), rn, rm, bs('1100')], [rm, rn])
addop("extuw", [bs('0110'), rn, rm, bs('1101')], [rm, rn])

addop("mac_l", [bs('0000', fname='opc'), d32rnpinc,
      d32rmpinc, bs('1111')], [d32rmpinc, d32rnpinc])
addop("mac_w", [bs('0100', fname='opc'), d16rnpinc,
      d16rmpinc, bs('1111')], [d16rmpinc, d16rnpinc])

addop("mull", [bs('0000'), rn, rm, bs('0111')], [rm, rn])
addop("mulsw", [bs('0010'), rn, rm, bs('1111')], [rm, rn])
addop("muluw", [bs('0010'), rn, rm, bs('1110')], [rm, rn])

addop("neg", [bs('0110'), rn, rm, bs('1011')], [rm, rn])
addop("negc", [bs('0110'), rn, rm, bs('1010')], [rm, rn])

addop("sub", [bs('0011'), rn, rm, bs('1000')], [rm, rn])
addop("subc", [bs('0011'), rn, rm, bs('1010')], [rm, rn])
addop("subv", [bs('0011'), rn, rm, bs('1011')], [rm, rn])

addop("and", [bs('0010'), rn, rm, bs('1001')], [rm, rn])
addop("and", [bs('11001001'), u08imm, bsr0])
addop("and_b", [bs('11001101'), u08imm, dr0gbr])

addop("not", [bs('0110'), rn, rm, bs('0111')], [rm, rn])

addop("or", [bs('0010'), rn, rm, bs('1011')], [rm, rn])

addop("or", [bs('11001011'), u08imm, bsr0])
addop("or_b", [bs('11001111'), u08imm, dr0gbr])

addop("tas_b", [bs('0100'), d08gpreg, bs('00011011')])
addop("tst", [bs('0010'), rn, rm, bs('1000')], [rm, rn])
addop("tst", [bs('11001000'), u08imm, bsr0])
addop("tst_b", [bs('11001100'), u08imm, dr0gbr])


addop("xor", [bs('0010'), rn, rm, bs('1010')], [rm, rn])
addop("xor", [bs('11001010'), u08imm, bsr0])
addop("xor_b", [bs('11001110'), u08imm, dr0gbr])

addop("rotl", [bs('0100'), rn, bs('00000100')])
addop("rotr", [bs('0100'), rn, bs('00000101')])
addop("rotcl", [bs('0100'), rn, bs('00100100')])
addop("rotcr", [bs('0100'), rn, bs('00100101')])

addop("shad", [bs('0100'), rn, rm, bs('1100')], [rm, rn])
addop("shal", [bs('0100'), rn, bs('00100000')])
addop("shar", [bs('0100'), rn, bs('00100001')])
addop("shld", [bs('0100'), rn, rm, bs('1101')], [rm, rn])

addop("shll", [bs('0100'), rn, bs('00000000')])
addop("shlr", [bs('0100'), rn, bs('00000001')])
addop("shll2", [bs('0100'), rn, bs('00001000')])
addop("shlr2", [bs('0100'), rn, bs('00001001')])
addop("shll8", [bs('0100'), rn, bs('00011000')])
addop("shlr8", [bs('0100'), rn, bs('00011001')])
addop("shll16", [bs('0100'), rn, bs('00101000')])
addop("shlr16", [bs('0100'), rn, bs('00101001')])


addop("bf", [bs('10001011'), s08imm])
"""
    def splitflow(self):
        return True
    def breakflow(self):
        return True
    def dstflow(self):
        return True
    def dstflow2label(self, symbol_pool):
        e = self.args[0].expr
        ad = e.arg*2+4+self.offset
        l = symbol_pool.getby_offset_create(ad)
        s = ExprId(l, e.size)
        self.args[0].expr = s
"""

addop("bfs", [bs('10001111'), s08imm])
"""
    delayslot = 1
"""
addop("bt", [bs('10001001'), s08imm])

addop("bts", [bs('10001101'), s08imm])

addop("bra", [bs('1010'), s12imm])
"""
    delayslot = 1
    def breakflow(self):
        return True
    def dstflow(self):
        return True
    def dstflow2label(self, symbol_pool):
        e = self.args[0].expr
        ad = e.arg*2+4+self.offset
        l = symbol_pool.getby_offset_create(ad)
        s = ExprId(l, e.size)
        self.args[0].expr = s
"""

addop("braf", [bs('0000'), rn, bs('00100011')])
"""
    delayslot = 1
    def breakflow(self):
        return True
    def dstflow(self):
        return True
"""
addop("bsr", [bs('1011'), s12imm])

addop("bsrf", [bs('0000'), rn, bs('00000011')])
"""
    delayslot = 1
    def breakflow(self):
        return True
    def is_subcall(self):
        return True
    def splitflow(self):
        return True
"""

addop("jmp_l", [bs('0100'), d32gpreg, bs('00101011')])
"""
    delayslot = 1
    def breakflow(self):
        return True
"""

addop("jsr_l", [bs('0100'), d32gpreg, bs('00001011')])
"""
    delayslot = 1
    def breakflow(self):
        return True
    def is_subcall(self):
        return True
    def splitflow(self):
        return True
"""

addop("rts", [bs('0000000000001011')])
"""
    delayslot = 1
    def breakflow(self):
        return True
"""
addop("clrmac", [bs('0000000000101000')])
addop("clrs", [bs('0000000001001000')])
addop("clrt", [bs('0000000000001000')])


addop("ldc", [bs('0100'), rm, bssr, bs('00001110')])
addop("ldc", [bs('0100'), rm, bsgbr, bs('00011110')])
addop("ldc", [bs('0100'), rm, bsvbr, bs('00101110')])
addop("ldc", [bs('0100'), rm, bsssr, bs('00111110')])
addop("ldc", [bs('0100'), rm, bsspc, bs('01001110')])
addop("ldc", [bs('0100'), rm, bsdbr, bs('11111010')])
addop("ldc", [bs('0100'), rm, bs('1'), brn, bs('1110')], [rm, brn])
addop("ldc_l", [bs('0100'), d32rmpinc, bssr,  bs('00000111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bsgbr, bs('00010111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bsvbr, bs('00100111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bsssr, bs('00110111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bsspc, bs('01000111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bsdbr, bs('11110110')])
addop("ldc_l", [bs('0100'), d32rmpinc, bs('1'), brn, bs('0111')])
addop("lds", [bs('0100'), rm, bsmach, bs('00001010')])
addop("lds", [bs('0100'), rm, bsmacl, bs('00011010')])
addop("lds", [bs('0100'), rm, bspr, bs('00101010')])
addop("lds_l", [bs('0100'), d32rmpinc, bsmach, bs('00000110')])
addop("lds_l", [bs('0100'), d32rmpinc, bsmacl, bs('00010110')])
addop("lds_l", [bs('0100'), d32rmpinc, bspr, bs('00100110')])
addop("ldtlb", [bs('0000000000111000')])

addop("movca_l", [bs('0000'), bsr0, d32gpreg, bs('11000011')])
addop("nop", [bs('0000000000001001')])
addop("ocbi_l", [bs('0000'), d32gpreg, bs('10010011')])
addop("ocbp_l", [bs('0000'), d32gpreg, bs('10100011')])
addop("ocbwb_l", [bs('0000'), d32gpreg, bs('10110011')])
addop("pref_l", [bs('0000'), d32gpreg, bs('10000011')])


addop("rte", [bs('0000000000101011')])
addop("sets", [bs('0000000001011000')])
addop("sett", [bs('0000000000011000')])
addop("sleep", [bs('0000000000011011')])
addop("stc", [bs('0000'), bssr,  rn, bs('00000010')])
addop("stc", [bs('0000'), bsgbr, rn, bs('00010010')])
addop("stc", [bs('0000'), bsvbr, rn, bs('00100010')])
addop("stc", [bs('0000'), bsssr, rn, bs('00110010')])
addop("stc", [bs('0000'), bsspc, rn, bs('01000010')])
addop("stc", [bs('0000'), bssgr, rn, bs('00111010')])
addop("stc", [bs('0000'), bsdbr, rn, bs('11111010')])
addop("stc", [bs('0000'), rn, bs('1'), brm, bs('0010')], [brm, rn])

addop("stc_l", [bs('0100'), bssr, d32rmpdec,  bs('00000011')])
addop("stc_l", [bs('0100'), bsgbr, d32rmpdec, bs('00010011')])
addop("stc_l", [bs('0100'), bsvbr, d32rmpdec, bs('00100011')])
addop("stc_l", [bs('0100'), bsssr, d32rmpdec, bs('00110011')])
addop("stc_l", [bs('0100'), bsspc, d32rmpdec, bs('01000011')])
addop("stc_l", [bs('0100'), bssgr, d32rmpdec, bs('00110010')])
addop("stc_l", [bs('0100'), bsdbr, d32rmpdec, bs('11110010')])
addop("stc_l",
      [bs('0100'), d32rnpdec, bs('1'), brm, bs('0011')], [brm, d32rnpdec])

# float
addop("sts", [bs('0000'), bsmach, rm, bs('00001010')])
addop("sts", [bs('0000'), bsmacl, rm, bs('00011010')])
addop("sts", [bs('0000'), bspr, rm, bs('00101010')])
addop("sts_l", [bs('0100'), bsmach, d32rmpdec, bs('00000010')])
addop("sts_l", [bs('0100'), bsmacl, d32rmpdec, bs('00010010')])
addop("sts_l",
      [bs('0100'), d32rnpdec, bspr, bs('00100010')], [bspr, d32rnpdec])
addop("trapa", [bs('11000011'), u08imm])

addop("fldi0", [bs('1111'), frn, bs('10001101')])
addop("fldi1", [bs('1111'), frn, bs('10011101')])
addop("fmov", [bs('1111'), frn, frm, bs('1100')], [frm, frn])
addop("fmov_s", [bs('1111'), frn, d32gpreg, bs('1000')], [d32gpreg, frn])
addop("fmov_s", [bs('1111'), frn, bd32r0gp, bs('0110')], [bd32r0gp, frn])
addop("fmov_s", [bs('1111'), frn, d32rmpinc, bs('1001')], [d32rmpinc, frn])
addop("fmov_s", [bs('1111'), d32gpreg, frm, bs('1010')], [frm, d32gpreg])
addop("fmov_s", [bs('1111'), d32rnpdec, frm, bs('1011')], [frm, d32rnpdec])
addop("fmov_s", [bs('1111'), bd32r0gp, frm, bs('0111')], [frm, bd32r0gp])

addop("flds", [bs('1111'), frm, bsfpul, bs('00011101')])
addop("fsts", [bs('1111'), bsfpul, frm, bs('00001101')])
addop("fabs", [bs('1111'), frn, bs('01011101')])
addop("fadd", [bs('1111'), frn, frm, bs('0000')], [frm, frn])
addop("fcmpeq", [bs('1111'), frn, frm, bs('0100')], [frm, frn])
addop("fcmpgt", [bs('1111'), frn, frm, bs('0101')], [frm, frn])
addop("fdiv", [bs('1111'), frn, frm, bs('0011')], [frm, frn])

addop("float", [bs('1111'), bsfpul, frn, bs('00101101')])
addop("fmac", [bs('1111'), bsfr0, frn, frm, bs('1110')], [bsfr0, frm, frn])
addop("fmul", [bs('1111'), frn, frm, bs('0010')], [frm, frn])
addop("fneg", [bs('1111'), frn, bs('01001101')])
addop("fsqrt", [bs('1111'), frn, bs('01101101')])
addop("fsub", [bs('1111'), frn, frm, bs('0001')], [frm, frn])
addop("ftrc", [bs('1111'), frm, bsfpul, bs('00111101')])


if __name__ == '__main__':
    import os
    import time
    filename = os.environ.get('PYTHONSTARTUP')
    if filename and os.path.isfile(filename):
        execfile(filename)

    def h2i(s):
        return s.replace(' ', '').decode('hex')

    reg_tests_sh4 = [
        # vxworks
        ("c80022f2    MOV        0x10, R6",
         "10e6"),
        ("c8002250    MOV        0xFFFFFFFF, R0",
         "ffe0"),
        ("c800226a    MOV.W      @(PC,0xC0), R9",
         "5e99"),
        ("c8002006    MOV.L      @(PC&0xFFFFFFFC,0x10), R15",
         "03df"),
        ("c800cfc4    MOV        R4, R9",
         "4369"),
        ("C8005004    MOV.B      R1, @R2",
         "1022"),
        ("C8002E04    MOV.W      R0, @R8",
         '0128'),
        ("c800223e    MOV.L      R1, @R14",
         "122E"),

        ("c8002002    MOV.L      @R1, R0",
         "1260"),
        ("c8002E08    MOV.W      @R8, R1",
         "8161"),
        ("c800357c    MOV.B      @R4, R1",
         "4061"),

        ("c8002220    MOV.L      R8, @-R15",
         "862f"),
        ("c8022a66    MOV.B      R4, @-R0",
         "4420"),
        ("c8002310    MOV.L      @R15+, R14",
         "f66e"),
        ("c80038a4    MOV.W      @R8+, R5",
         "8565"),
        ("xxxxxxxx    MOV.B      R0, @(R8,0x2)",
         "8280"),
        ("xxxxxxxx    MOV.W      R0, @(R8,0x4)",
         "8281"),
        ("c8002274    MOV.L      R0, @(R9,0x8)",
         "0219"),
        ("xxxxxxxx    MOV.B      @(R8,0x8), R0",
         "8884"),
        ("xxxxxxxx    MOV.W      @(R8,0x10), R0",
         "8885"),
        ("c8002500    MOV.L      @(R14,0x4), R5",
         "e155"),
        ("xxxxxxxx    MOV.B      R4, @(R0,R8)",
         "4408"),
        ("xxxxxxxx    MOV.W      R4, @(R0,R8)",
         "4508"),
        ("xxxxxxxx    MOV.L      R4, @(R0,R8)",
         "4608"),
        ("xxxxxxxx    MOV.B      @(R0,R4), R8",
         "4c08"),
        ("xxxxxxxx    MOV.W      @(R0,R4), R8",
         "4d08"),
        ("xxxxxxxx    MOV.L      @(R0,R4), R8",
         "4e08"),
        ("xxxxxxxx    MOV.B      R0, @(GBR,0x4)",
         "04c0"),
        ("xxxxxxxx    MOV.W      R0, @(GBR,0x8)",
         "04c1"),
        ("xxxxxxxx    MOV.L      R0, @(GBR,0x10)",
         "04c2"),
        ("xxxxxxxx    MOV.B      @(GBR,0x4), R0",
         "04c4"),
        ("xxxxxxxx    MOV.W      @(GBR,0x8), R0",
         "04c5"),
        ("xxxxxxxx    MOV.L      @(GBR,0x10), R0",
         "04c6"),
        #("xxxxxxxx    MOV        PC&0xFFFFFFFC+0x14, R0",
        # "04c7"),
        ("xxxxxxxx    SWAPB      R2, R1",
         "2861"),
        ("c803f492    SWAPW      R4, R9",
         "4969"),
        ("xxxxxxxx    XTRCT      R4, R9",
         "4d29"),
        ("c8002270    ADD        R12, R9",
         "cc39"),
        ("c8002238    ADD        0xFFFFFFFC, R15",
         "FC7F"),
        ("c80164cc    ADDC       R0, R1",
         "0e31"),
        ("xxxxxxxx    ADDV       R0, R1",
         "0f31"),
        ("c8002994    CMPEQ      0x20, R0",
         "2088"),
        ("c80029d2    CMPEQ      R2, R1",
         "2031"),
        ("c8003964    CMPHS      R5, R3",
         "5233"),
        ("c8002df2    CMPGE      R0, R1",
         "0331"),
        ("c80029a4    CMPHI      R1, R0",
         "1630"),
        ("c8002bfe    CMPGT      R10, R8",
         "a738"),
        ("c8002bf8    CMPPZ      R0",
         "1140"),
        ("c8006294    CMPPL      R2",
         "1542"),
        ("c8033800    CMPSTR     R14, R4",
         "ec24"),
        ("xxxxxxxx    DIV1       R14, R4",
         "e434"),
        ("c8d960de    DIV0S      R0, R3",
         "0723"),
        ("xxxxxxxx    DIV0U      ",
         "1900"),
        ("c800dcd8    DMULS      R1, R0",
         "1d30"),
        ("c80164da    DMULU      R3, R8",
         "3538"),
        ("c80024e2    DT         R10",
         "104a"),
        ("c800343a    EXTSB      R1, R1",
         "1e61"),
        ("c8002bf6    EXTSW      R0, R0",
         "0f60"),
        ("c8002fba    EXTUB      R0, R0",
         "0c60"),
        ("c8002398    EXTUW      R0, R0",
         "0d60"),
        ("xxxxxxxx    MAC.L      @R5+, @R4+",
         "5f04"),
        ("xxxxxxxx    MAC.W      @R5+, @R4+",
         "5f44"),
        ("c8005112    MULL       R1, R3",
         "1703"),
        ("xxxxxxxx    MULSW      R1, R3",
         "1F23"),
        ("xxxxxxxx    MULUW      R1, R3",
         "1e23"),
        ("c8004856    NEG        R1, R8",
         "1b68"),
        ("c80054fc    NEGC       R9, R7",
         "9a67"),
        ("c8004b36    SUB        R1, R5",
         "1835"),
        ("c800a536    SUBC       R1, R0",
         "1a30"),
        ("xxxxxxxx    SUBV       R1, R0",
         "1b30"),
        ("c80023ca    AND        R0, R5",
         "0925"),
        ("c800257c    AND        0x2, R0",
         "02c9"),
        ("xxxxxxxx    AND.B      0x2, @(GBR,R0)",
         "02cd"),
        ("c80065fe    NOT        R5, R1",
         "5761"),
        ("c8002586    OR         R10, R1",
         "ab21"),
        ("c80023aa    OR         0x4, R0",
         "04cb"),
        ("xxxxxxxx    OR.B       0x4, @(GBR,R0)",
         "04cf"),
        ("xxxxxxxx    TAS.B      @R8",
         "1b48"),
        ("c8002368    TST        R10, R13",
         "a82d"),
        ("c8003430    TST        0x11, R0",
         "11c8"),
        ("xxxxxxxx    TST.B      0x4, @(GBR,R0)",
         "04cc"),
        ("c8003978    XOR        R1, R6",
         "1a26"),
        ("c8028270    XOR        0x1, R0",
         "01ca"),
        ("xxxxxxxx    XOR.B      0x4, @(GBR,R0)",
         "04cE"),
        ("xxxxxxxx    ROTL       R9",
         "0449"),
        ("xxxxxxxx    ROTR       R9",
         "0549"),
        ("xxxxxxxx    ROTCL      R9",
         "2449"),
        ("xxxxxxxx    ROTCR      R9",
         "2549"),
        ("xxxxxxxx    SHAL       R11",
         "204b"),
        ("xxxxxxxx    SHAR       R11",
         "214b"),
        ("c800236c    SHLD       R6, R10",
         "6d4a"),
        ("xxxxxxxx    SHLL       R11",
         "004b"),
        ("xxxxxxxx    SHLR       R11",
         "014b"),
        ("xxxxxxxx    SHLL2      R11",
         "084b"),
        ("xxxxxxxx    SHLR2      R11",
         "094b"),
        ("xxxxxxxx    SHLL8      R11",
         "184b"),
        ("xxxxxxxx    SHLR8      R11",
         "194b"),
        ("xxxxxxxx    SHLL16     R11",
         "284b"),
        ("xxxxxxxx    SHLR16     R11",
         "294b"),
        ("c8002c00    BF         0xFFFFFFF4",
         "f48b"),
        ("c80023c2    BFS        0xFFFFFFD8",
         "d88f"),
        ("c8002266    BT         0x5B",
         "5b89"),
        ("c8002266    BTS        0x5C",
         "5c8d"),
        ("c8002326    BRA        0xFFFFFFF0",
         "f0af"),
        ("c8004b4a    BRAF       R1",
         "2301"),
        ("c8055da4    BSR        0xFFFFFE48",
         "48be"),
        ("xxxxxxxx    BSRF       R1",
         "0301"),
        ("c80027b4    JMP.L      @R1",
         "2b41"),
        ("c800200c    JSR.L      @R0",
         "0b40"),
        ("c800231a    RTS        ",
         "0b00"),
        ("xxxxxxxx    CLRMAC     ",
         "2800"),
        ("xxxxxxxx    CLRS       ",
         "4800"),
        ("xxxxxxxx    CLRT       ",
         "0800"),
        ("c8002004    LDC        R0, SR",
         "0e40"),
        ("c800200e    LDC        R1, GBR",
         "1e41"),
        ("c8064bd4    LDC        R8, VBR",
         "2e48"),
        ("xxxxxxxx    LDC        R8, SSR",
         "3e48"),
        ("xxxxxxxx    LDC        R8, SPC",
         "4e48"),
        ("xxxxxxxx    LDC        R8, DBR",
         "fa48"),
        ("xxxxxxxx    LDC        R8, R0_BANK",
         "8e48"),
        ("xxxxxxxx    LDC.L      @R8+, SR",
         "0748"),
        ("xxxxxxxx    LDC.L      @R8+, GBR",
         "1748"),
        ("xxxxxxxx    LDC.L      @R8+, VBR",
         "2748"),
        ("xxxxxxxx    LDC.L      @R8+, SSR",
         "3748"),
        ("xxxxxxxx    LDC.L      @R8+, SPC",
         "4748"),
        ("xxxxxxxx    LDC.L      @R8+, DBR",
         "f648"),
        ("xxxxxxxx    LDC.L      @R8+, R2_BANK",
         "a748"),
        ("xxxxxxxx    LDS        R8, MACH",
         "0a48"),
        ("xxxxxxxx    LDS        R8, MACL",
         "1a48"),
        ("xxxxxxxx    LDS        R8, PR",
         "2a48"),
        ("xxxxxxxx    LDS.L      @R8+, MACH",
         "0648"),
        ("xxxxxxxx    LDS.L      @R8+, MACL",
         "1648"),
        ("xxxxxxxx    LDTLB      ",
         "3800"),
        ("xxxxxxxx    MOVCA.L    R0, @R8",
         "c308"),
        ("xxxxxxxx    NOP        ",
         "0900"),
        ("xxxxxxxx    OCBI.L     @R8",
         "9308"),
        ("xxxxxxxx    OCBP.L     @R8",
         "a308"),
        ("xxxxxxxx    OCBWB.L    @R8",
         "b308"),
        ("xxxxxxxx    PREF.L     @R8",
         "8308"),
        ("xxxxxxxx    STS        MACH, R8",
         "0a08"),
        ("xxxxxxxx    STS        MACL, R8",
         "1a08"),
        ("xxxxxxxx    STS        PR, R8",
         "2a08"),
        ("xxxxxxxx    STS.L      MACH, @-R8",
         "0248"),
        ("xxxxxxxx    STS.L      MACL, @-R8",
         "1248"),
        ("xxxxxxxx    STS.L      PR, @-R8",
         "2248"),





        ("c8004b50    STC        GBR, R0",
         "1200"),
        ("c8064516    STC        VBR, R1",
         "2201"),
        ("c8004b54    STC        SSR, R1",
         "3201"),
        ("c801ed6c    STC        SPC, R0",
         "4200"),
        ("xxxxxxxx    STC        SGR, R0",
         "3a00"),
        ("xxxxxxxx    STC        DBR, R0",
         "fa00"),
        ("c8004b56    STC        R3_BANK, R1",
         "B201"),
        ("xxxxxxxx    STC.L      SR, @-R8",
         "0348"),
        ("xxxxxxxx    STC.L      GBR, @-R8",
         "1348"),
        ("xxxxxxxx    STC.L      VBR, @-R8",
         "2348"),
        ("xxxxxxxx    STC.L      SSR, @-R8",
         "3348"),
        ("xxxxxxxx    STC.L      SPC, @-R8",
         "4348"),
        ("xxxxxxxx    STC.L      DBR, @-R8",
         "f248"),
        ("xxxxxxxx    STC.L      R7_BANK, @-R8",
         "f348"),
        ("c803b130    TRAPA      0xE0",
         "e0c3"),

        ("xxxxxxxx    FLDI0      FR8",
         "8df8"),
        ("xxxxxxxx    FLDI1      FR8",
         "9df8"),
        ("c8019ca8    FMOV       FR15, FR5",
         "fcf5"),
        ("c800affe    FMOV.S     @R1, FR4",
         "18f4"),
        ("c80283f6    FMOV.S     @(R0,R14), FR5",
         "e6f5"),
        ("c800aff8    FMOV.S     @R1+, FR5",
         "19f5"),
        ("c80cb692    FMOV.S     FR0, @R2",
         "0af2"),
        ("c80cb694    FMOV.S     FR1, @-R2",
         "1bf2"),
        ("c80283aa    FMOV.S     FR1, @(R0,R14)",
         "17fe"),
        ("c800ce16    FLDS       FR13, FPUL",
         "1dfd"),
        ("c800ce08    FSTS       FPUL, FR13",
         "0dfd"),
        ("xxxxxxxx    FABS       FR8",
         "5df8"),
        ("c800cf28    FADD       FR2, FR6",
         "20f6"),
        ("c805dacc    FCMPEQ     FR2, FR6",
         "24f6"),
        ("c8028406    FCMPGT     FR4, FR2",
         "45f2"),
        ("c8019ca4    FDIV       FR2, FR12",
         "23fc"),
        ("c800ce5e    FLOAT      FPUL, FR2",
         "2df2"),
        ("xxxxxxxx    FMAC       FR0, FR1, FR2",
         "1ef2"),
        ("c800b006    FMUL       FR2, FR4",
         "22f4"),
        ("c805e412    FNEG       FR14",
         "4dfe"),
        ("xxxxxxxx    FSQRT      FR14",
         "6dfe"),
        ("c8030400    FSUB       FR4, FR2",
         "41f2"),
        ("c80303ba    FTRC       FR2, FPUL",
         "3df2"),

    ]

    for s, l in reg_tests_sh4:
        print "-" * 80
        s = s[12:]
        b = h2i((l))
        print b.encode('hex')
        mn = mn_sh4.dis(b, None)
        print [str(x) for x in mn.args]
        print s
        print mn
        assert(str(mn) == s)
        # print hex(b)
        # print [str(x.get()) for x in mn.args]
        l = mn_sh4.fromstring(s, None)
        # print l
        assert(str(l) == s)
        a = mn_sh4.asm(l, None)
        print [x for x in a]
        print repr(b)
        # print mn.args
        assert(b in a)

    # speed test
    o = ""
    for s, l, in reg_tests_sh4:
        s = s[12:]
        b = h2i((l))
        o += b

    while len(o) < 1000:
        o += o
    bs = bin_stream_str(o)
    off = 0
    instr_num = 0
    ts = time.time()
    while off < bs.getlen():
        mn = mn_sh4.dis(bs, None, off)
        # print instr_num, off, mn.l, str(mn)
        instr_num += 1
        off += mn.l
    print 'instr per sec:', instr_num / (time.time() - ts)

    import cProfile
    cProfile.run(r'mn_sh4.dis("\x17\xfe", None)')
