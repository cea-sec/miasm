#!/usr/bin/env python
#-*- coding:utf-8 -*-

from pyparsing import *
from miasm2.core.cpu import *
from miasm2.expression.expression import *
from collections import defaultdict
from miasm2.arch.sh4.regs import *


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
    e = ExprMem(ExprOp('predec', t[0]))
    return e


def parse_postinc(s, l, t):
    t = t[0]
    e = ExprMem(ExprOp('postinc', t[0]))
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


class sh4_dgpregpinc(m_arg):
    parser = dgpregs_p

    def fromstring(self, s, parser_result=None):
        start, stop = super(sh4_dgpregpinc, self).fromstring(s, parser_result)
        if self.expr is None:
            return None, None
        if not isinstance(self.expr.arg, ExprOp):
            return None, None
        if self.expr.arg.op != self.op:
            return None, None
        return start, stop

    def decode(self, v):
        r = gpregs.expr[v]
        e = ExprOp(self.op, r)
        self.expr = ExprMem(e, self.sz)
        return True

    def encode(self):
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        e = e.arg
        res = MatchExpr(e, ExprOp(self.op, jra), [jra])
        if not res:
            return False
        r = res[jra]
        if not r in gpregs.expr:
            return False
        v = gpregs.expr.index(r)
        self.value = v
        return True


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

class additional_info:

    def __init__(self):
        self.except_on_instr = False


class instruction_sh4(instruction):
    delayslot = 0

    def __init__(self, *args, **kargs):
        super(instruction_sh4, self).__init__(*args, **kargs)

    def dstflow(self):
        return self.name.startswith('J')

    @staticmethod
    def arg2str(e, pos = None):
        if isinstance(e, ExprId) or isinstance(e, ExprInt):
            return str(e)
        assert(isinstance(e, ExprMem))
        e = e.arg

        if isinstance(e, ExprOp):
            if e.op == "predec":
                s = '-%s' % e.args[0]
            elif e.op == "postinc":
                s = '%s+' % e.args[0]
            else:
                s = ','.join([str(x).replace('(', '').replace(')', '')
                              for x in e.args])
                s = "(%s)"%s
            s = "@%s" % s
        elif isinstance(e, ExprId):
            s = "@%s" % e
        else:
            raise NotImplementedError('zarb arg2str')
        return s


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
    instruction = instruction_sh4

    def additional_info(self):
        info = additional_info()
        return info

    @classmethod
    def getbits(cls, bs, attrib, start, n):
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
