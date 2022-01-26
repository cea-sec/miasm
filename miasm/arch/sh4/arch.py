#-*- coding:utf-8 -*-

from __future__ import print_function
from builtins import range

from pyparsing import *
from miasm.core.cpu import *
from miasm.expression.expression import *
from collections import defaultdict
import miasm.arch.sh4.regs as regs_module
from miasm.arch.sh4.regs import *


from miasm.core.asm_ast import AstInt, AstId, AstMem, AstOp

jra = ExprId('jra', 32)
jrb = ExprId('jrb', 32)
jrc = ExprId('jrc', 32)


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


def cb_deref_pcimm(tokens):
    return tokens[0] + tokens[1]


def cb_pcandimmimm(tokens):
    return (tokens[0] & tokens[1]) + tokens[2]



ref_pc = (LPARENT + reg_info_pc.parser + COMMA + base_expr + RPARENT).setParseAction(cb_deref_pcimm)
ref_pcandimm = (LPARENT + reg_info_pc.parser + AND + base_expr + COMMA + base_expr + RPARENT).setParseAction(cb_pcandimmimm)
pcdisp = (reg_info_pc.parser + AND + base_expr + PLUS + base_expr).setParseAction(cb_pcandimmimm)

PTR = Suppress('PTR')


def cb_deref_mem(tokens):
    assert len(tokens) == 1
    result = AstMem(tokens[0], 32)
    return result


def cb_predec(tokens):
    assert len(tokens) == 1
    result = AstMem(AstOp('predec', tokens[0]), 32)
    return result


def cb_postinc(tokens):
    assert len(tokens) == 1
    result = AstMem(AstOp('postinc', tokens[0]), 32)
    return result


def cb_regdisp(tokens):
    assert len(tokens) == 2
    result = AstMem(tokens[0] + tokens[1], 32)
    return result


def cb_regreg(tokens):
    assert len(tokens) == 2
    result = AstMem(tokens[0] + tokens[1], 32)
    return result


deref_pc = (DEREF + ref_pc).setParseAction(cb_deref_mem)
deref_pcimm = (DEREF + ref_pcandimm).setParseAction(cb_deref_mem)

dgpregs_base = (DEREF + gpregs.parser).setParseAction(cb_deref_mem)
dgpregs_predec = (DEREF + MINUS + gpregs.parser).setParseAction(cb_predec)
dgpregs_postinc = (DEREF + gpregs.parser + PLUS).setParseAction(cb_postinc)

dgpregs = dgpregs_base | dgpregs_predec | dgpregs_postinc

d_gpreg_gpreg = (DEREF + LPARENT + gpregs.parser + COMMA + gpregs.parser + RPARENT).setParseAction(cb_regdisp)
dgpregs_p = dgpregs_predec | dgpregs_postinc


dgpregs_ir = (DEREF + LPARENT + gpregs.parser + COMMA + base_expr + RPARENT).setParseAction(cb_regdisp)
dgpregs_ir |= d_gpreg_gpreg

dgbr_imm = (DEREF + LPARENT + reg_info_gbr.parser + COMMA + base_expr + RPARENT).setParseAction(cb_regdisp)

dgbr_reg = (DEREF + LPARENT + reg_info_gbr.parser + COMMA + gpregs.parser + RPARENT).setParseAction(cb_regreg)


class sh4_arg(m_arg):
    def asm_ast_to_expr(self, arg, loc_db):
        if isinstance(arg, AstId):
            if isinstance(arg.name, ExprId):
                return arg.name
            if arg.name in gpregs.str:
                return None
            loc_key = loc_db.get_or_create_name_location(arg.name)
            return ExprLoc(loc_key, 32)
        if isinstance(arg, AstOp):
            args = [self.asm_ast_to_expr(tmp, loc_db) for tmp in arg.args]
            if None in args:
                return None
            return ExprOp(arg.op, *args)
        if isinstance(arg, AstInt):
            return ExprInt(arg.value, 32)
        if isinstance(arg, AstMem):
            ptr = self.asm_ast_to_expr(arg.ptr, loc_db)
            if ptr is None:
                return None
            return ExprMem(ptr, arg.size)
        return None


_, bs_pr = gen_reg_bs('PR', reg_info_pr, (m_reg, sh4_arg,))
_, bs_r0 = gen_reg_bs('R0', reg_info_r0, (m_reg, sh4_arg,))
_, bs_sr = gen_reg_bs('SR', reg_info_sr, (m_reg, sh4_arg,))
_, bs_gbr = gen_reg_bs('GBR', reg_info_gbr, (m_reg, sh4_arg,))
_, bs_vbr = gen_reg_bs('VBR', reg_info_vbr, (m_reg, sh4_arg,))
_, bs_ssr = gen_reg_bs('SSR', reg_info_ssr, (m_reg, sh4_arg,))
_, bs_spc = gen_reg_bs('SPC', reg_info_spc, (m_reg, sh4_arg,))
_, bs_sgr = gen_reg_bs('SGR', reg_info_sgr, (m_reg, sh4_arg,))
_, bs_dbr = gen_reg_bs('dbr', reg_info_dbr, (m_reg, sh4_arg,))
_, bs_mach = gen_reg_bs('mach', reg_info_mach, (m_reg, sh4_arg,))
_, bs_macl = gen_reg_bs('macl', reg_info_macl, (m_reg, sh4_arg,))
_, bs_fpul = gen_reg_bs('fpul', reg_info_fpul, (m_reg, sh4_arg,))
_, bs_fr0 = gen_reg_bs('fr0', reg_info_fr0, (m_reg, sh4_arg,))

class sh4_reg(reg_noarg, sh4_arg):
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


class sh4_dgpreg(sh4_arg):
    parser = dgpregs_base

    def fromstring(self, text, loc_db, parser_result=None):
        start, stop = super(sh4_dgpreg, self).fromstring(text, loc_db, parser_result)
        if start is None or self.expr == [None]:
            return start, stop
        self.expr = ExprMem(self.expr.ptr, self.sz)
        return start, stop

    def decode(self, v):
        r = gpregs.expr[v]
        self.expr = ExprMem(r, self.sz)
        return True

    def encode(self):
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        if not isinstance(e.ptr, ExprId):
            return False
        v = gpregs.expr.index(e.ptr)
        self.value = v
        return True


class sh4_dgpregpinc(sh4_arg):
    parser = dgpregs_p

    def fromstring(self, text, loc_db, parser_result=None):
        start, stop = super(sh4_dgpregpinc, self).fromstring(text, loc_db, parser_result)
        if self.expr == [None]:
            return None, None
        if not isinstance(self.expr.ptr, ExprOp):
            return None, None
        if self.expr.ptr.op != self.op:
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
        e = e.ptr
        res = match_expr(e, ExprOp(self.op, jra), [jra])
        if not res:
            return False
        r = res[jra]
        if not r in gpregs.expr:
            return False
        v = gpregs.expr.index(r)
        self.value = v
        return True


class sh4_dgpregpdec(sh4_arg):
    parser = dgpregs_postinc
    op = "preinc"


class sh4_dgpreg_imm(sh4_dgpreg):
    parser = dgpregs_ir

    def decode(self, v):
        p = self.parent
        r = gpregs.expr[v]
        s = self.sz
        d = ExprInt((p.disp.value * s) // 8, 32)
        e = ExprMem(r + d, s)
        self.expr = e
        return True

    def encode(self):
        e = self.expr
        p = self.parent
        s = self.sz
        if not isinstance(e, ExprMem):
            return False
        if isinstance(e.ptr, ExprId):
            v = gpregs.expr.index(e.ptr)
            p.disp.value = 0
        elif isinstance(e.ptr, ExprOp):
            res = match_expr(e, ExprMem(jra + jrb, self.sz), [jra, jrb])
            if not res:
                return False
            if not isinstance(res[jra], ExprId):
                return False
            if not isinstance(res[jrb], ExprInt):
                return False
            d = int(res[jrb])
            p.disp.value = d // (s // 8)
            if not res[jra] in gpregs.expr:
                return False
            v = gpregs.expr.index(res[jra])
        else:
            return False
        self.value = v
        return True


class sh4_imm(imm_noarg, sh4_arg):
    parser = base_expr
    pass


class sh4_simm(sh4_imm):
    parser = base_expr

    def decode(self, v):
        v = sign_ext(v, self.l, 32)
        v = self.decodeval(v)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if (1 << (self.l - 1)) & v:
            v = -((0xffffffff ^ v) + 1)
        v = self.encodeval(v)
        self.value = (v & 0xffffffff) & self.lmask
        return True


class sh4_dpc16imm(sh4_dgpreg):
    parser = deref_pc

    def decode(self, v):
        self.expr = ExprMem(PC + ExprInt(v * 2 + 4, 32), 16)
        return True

    def calcdisp(self, v):
        v = (int(v) - 4) // 2
        if not 0 < v <= 0xff:
            return None
        return v

    def encode(self):
        res = match_expr(self.expr, ExprMem(PC + jra, 16), [jra])
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
        self.expr = ExprMem(GBR + ExprInt((v * s) // 8, 32), s)
        return True

    def encode(self):
        e = self.expr
        s = self.sz
        if e == ExprMem(GBR, 32):
            self.value = 0
            return True
        res = match_expr(self.expr, ExprMem(GBR + jra, s), [jra])
        if not res:
            return False
        if not isinstance(res[jra], ExprInt):
            return False
        self.value = int(res[jra]) // (s // 8)
        return True


class sh4_dpc32imm(sh4_dpc16imm):
    parser = deref_pcimm

    def decode(self, v):
        self.expr = ExprMem(
            (PC & ExprInt(0xfffffffc, 32)) + ExprInt(v * 4 + 4, 32), 32)
        return True

    def calcdisp(self, v):
        v = (int(v) - 4) // 4
        if not 0 < v <= 0xff:
            return None
        return v

    def encode(self):
        res = match_expr(
            self.expr, ExprMem((PC & ExprInt(0xFFFFFFFC, 32)) + jra, 32), [jra])
        if not res:
            return False
        if not isinstance(res[jra], ExprInt):
            return False
        v = self.calcdisp(res[jra])
        if v is None:
            return False
        self.value = v
        return True


class sh4_pc32imm(sh4_arg):
    parser = pcdisp

    def decode(self, v):
        self.expr = (PC & ExprInt(0xfffffffc, 32)) + ExprInt(v * 4 + 4, 32)
        return True

    def encode(self):
        res = match_expr(self.expr, (PC & ExprInt(0xfffffffc, 32)) + jra, [jra])
        if not res:
            return False
        if not isinstance(res[jra], ExprInt):
            return False
        v = (int(res[jra]) - 4) // 4
        if v is None:
            return False
        self.value = v
        return True

class additional_info(object):

    def __init__(self):
        self.except_on_instr = False


class instruction_sh4(instruction):
    __slots__ = []

    def __init__(self, *args, **kargs):
        super(instruction_sh4, self).__init__(*args, **kargs)

    def dstflow(self):
        return self.name.startswith('J')

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        if isinstance(expr, ExprId) or isinstance(expr, ExprInt):
            return str(expr)
        elif expr.is_loc():
            if loc_db is not None:
                return loc_db.pretty_str(expr.loc_key)
            else:
                return str(expr)
        assert(isinstance(expr, ExprMem))
        ptr = expr.ptr

        if isinstance(ptr, ExprOp):
            if ptr.op == "predec":
                s = '-%s' % ptr.args[0]
            elif ptr.op == "postinc":
                s = '%s+' % ptr.args[0]
            else:
                s = ','.join(
                    str(x).replace('(', '').replace(')', '')
                    for x in ptr.args
                )
                s = "(%s)"%s
            s = "@%s" % s
        elif isinstance(ptr, ExprId):
            s = "@%s" % ptr
        else:
            raise NotImplementedError('zarb arg2str')
        return s


    """
    def dstflow2label(self, loc_db):
        e = self.args[0]
        if not isinstance(e, ExprInt):
            return
        if self.name == 'BLX':
            ad = e.arg+8+self.offset
        else:
            ad = e.arg+8+self.offset
        l = loc_db.get_or_create_offset_location(ad)
        s = ExprId(l, e.size)
        self.args[0] = s
    """

    def breakflow(self):
        if self.name.startswith('J'):
            return True
        return False

    def is_subcall(self):
        return self.name == 'JSR'

    def getdstflow(self, loc_db):
        return [self.args[0]]

    def splitflow(self):
        return self.name == 'JSR'

    def get_symbol_size(self, symbol, loc_db):
        return 32

    def fixDstOffset(self):
        e = self.args[0]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, ExprInt):
            log.debug('dyn dst %r', e)
            return
        off = e.arg - (self.offset + 4 + self.l)
        print(hex(off))
        if int(off % 4):
            raise ValueError('strange offset! %r' % off)
        self.args[0] = ExprInt(off, 32)
        print('final', self.args[0])

    def get_args_expr(self):
        args = [a for a in self.args]
        return args


class mn_sh4(cls_mn):
    bintree = {}
    regs = regs_module
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
            raise ValueError('not enough bits %r %r' % (n, len(bs.bin) * 8))
        while n:
            i = start // 8
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
        out = b""
        for _ in range(l):
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
        res = match_expr(self.expr, ExprMem(R0 + jra, self.sz), [jra])
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
addop("mov_b", [bs('10000000', fname='opc'), bs_r0, d08rnimm, dimm4])
addop("mov_w", [bs('10000001', fname='opc'), bs_r0, d16rnimm, dimm4])
addop("mov_l", [bs('0001', fname='opc'), d32rnimm, rm, dimm4], [rm, d32rnimm])
addop("mov_b", [bs('10000100', fname='opc'), d08rmimm, dimm4, bs_r0])
addop("mov_w", [bs('10000101', fname='opc'), d16rmimm, dimm4, bs_r0])
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

addop("mov_b", [bs('11000000'), bs_r0, d08gbrimm8])
addop("mov_w", [bs('11000001'), bs_r0, d16gbrimm8])
addop("mov_l", [bs('11000010'), bs_r0, d32gbrimm8])

addop("mov_b", [bs('11000100'), d08gbrimm8, bs_r0])
addop("mov_w", [bs('11000101'), d16gbrimm8, bs_r0])
addop("mov_l", [bs('11000110'), d32gbrimm8, bs_r0])

addop("mov", [bs('11000111'), pc32imm, bs_r0])

addop("swapb", [bs('0110'), rn, rm, bs('1000')], [rm, rn])
addop("swapw", [bs('0110'), rn, rm, bs('1001')], [rm, rn])
addop("xtrct", [bs('0010'), rn, rm, bs('1101')], [rm, rn])


addop("add", [bs('0011'), rn, rm, bs('1100')], [rm, rn])
addop("add", [bs('0111'), rn, s08imm], [s08imm, rn])
addop("addc", [bs('0011'), rn, rm, bs('1110')], [rm, rn])
addop("addv", [bs('0011'), rn, rm, bs('1111')], [rm, rn])


addop("cmpeq", [bs('10001000'), s08imm, bs_r0])


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
addop("and", [bs('11001001'), u08imm, bs_r0])
addop("and_b", [bs('11001101'), u08imm, dr0gbr])

addop("not", [bs('0110'), rn, rm, bs('0111')], [rm, rn])

addop("or", [bs('0010'), rn, rm, bs('1011')], [rm, rn])

addop("or", [bs('11001011'), u08imm, bs_r0])
addop("or_b", [bs('11001111'), u08imm, dr0gbr])

addop("tas_b", [bs('0100'), d08gpreg, bs('00011011')])
addop("tst", [bs('0010'), rn, rm, bs('1000')], [rm, rn])
addop("tst", [bs('11001000'), u08imm, bs_r0])
addop("tst_b", [bs('11001100'), u08imm, dr0gbr])


addop("xor", [bs('0010'), rn, rm, bs('1010')], [rm, rn])
addop("xor", [bs('11001010'), u08imm, bs_r0])
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
    def dstflow2label(self, loc_db):
        e = self.args[0].expr
        ad = e.arg*2+4+self.offset
        l = loc_db.get_or_create_offset_location(ad)
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
    def dstflow2label(self, loc_db):
        e = self.args[0].expr
        ad = e.arg*2+4+self.offset
        l = loc_db.get_or_create_offset_location(ad)
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


addop("ldc", [bs('0100'), rm, bs_sr, bs('00001110')])
addop("ldc", [bs('0100'), rm, bs_gbr, bs('00011110')])
addop("ldc", [bs('0100'), rm, bs_vbr, bs('00101110')])
addop("ldc", [bs('0100'), rm, bs_ssr, bs('00111110')])
addop("ldc", [bs('0100'), rm, bs_spc, bs('01001110')])
addop("ldc", [bs('0100'), rm, bs_dbr, bs('11111010')])
addop("ldc", [bs('0100'), rm, bs('1'), brn, bs('1110')], [rm, brn])
addop("ldc_l", [bs('0100'), d32rmpinc, bs_sr,  bs('00000111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bs_gbr, bs('00010111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bs_vbr, bs('00100111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bs_ssr, bs('00110111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bs_spc, bs('01000111')])
addop("ldc_l", [bs('0100'), d32rmpinc, bs_dbr, bs('11110110')])
addop("ldc_l", [bs('0100'), d32rmpinc, bs('1'), brn, bs('0111')])
addop("lds", [bs('0100'), rm, bs_mach, bs('00001010')])
addop("lds", [bs('0100'), rm, bs_macl, bs('00011010')])
addop("lds", [bs('0100'), rm, bs_pr, bs('00101010')])
addop("lds_l", [bs('0100'), d32rmpinc, bs_mach, bs('00000110')])
addop("lds_l", [bs('0100'), d32rmpinc, bs_macl, bs('00010110')])
addop("lds_l", [bs('0100'), d32rmpinc, bs_pr, bs('00100110')])
addop("ldtlb", [bs('0000000000111000')])

addop("movca_l", [bs('0000'), bs_r0, d32gpreg, bs('11000011')])
addop("nop", [bs('0000000000001001')])
addop("ocbi_l", [bs('0000'), d32gpreg, bs('10010011')])
addop("ocbp_l", [bs('0000'), d32gpreg, bs('10100011')])
addop("ocbwb_l", [bs('0000'), d32gpreg, bs('10110011')])
addop("pref_l", [bs('0000'), d32gpreg, bs('10000011')])


addop("rte", [bs('0000000000101011')])
addop("sets", [bs('0000000001011000')])
addop("sett", [bs('0000000000011000')])
addop("sleep", [bs('0000000000011011')])
addop("stc", [bs('0000'), bs_sr,  rn, bs('00000010')])
addop("stc", [bs('0000'), bs_gbr, rn, bs('00010010')])
addop("stc", [bs('0000'), bs_vbr, rn, bs('00100010')])
addop("stc", [bs('0000'), bs_ssr, rn, bs('00110010')])
addop("stc", [bs('0000'), bs_spc, rn, bs('01000010')])
addop("stc", [bs('0000'), bs_sgr, rn, bs('00111010')])
addop("stc", [bs('0000'), bs_dbr, rn, bs('11111010')])
addop("stc", [bs('0000'), rn, bs('1'), brm, bs('0010')], [brm, rn])

addop("stc_l", [bs('0100'), bs_sr, d32rmpdec,  bs('00000011')])
addop("stc_l", [bs('0100'), bs_gbr, d32rmpdec, bs('00010011')])
addop("stc_l", [bs('0100'), bs_vbr, d32rmpdec, bs('00100011')])
addop("stc_l", [bs('0100'), bs_ssr, d32rmpdec, bs('00110011')])
addop("stc_l", [bs('0100'), bs_spc, d32rmpdec, bs('01000011')])
addop("stc_l", [bs('0100'), bs_sgr, d32rmpdec, bs('00110010')])
addop("stc_l", [bs('0100'), bs_dbr, d32rmpdec, bs('11110010')])
addop("stc_l",
      [bs('0100'), d32rnpdec, bs('1'), brm, bs('0011')], [brm, d32rnpdec])

# float
addop("sts", [bs('0000'), bs_mach, rm, bs('00001010')])
addop("sts", [bs('0000'), bs_macl, rm, bs('00011010')])
addop("sts", [bs('0000'), bs_pr, rm, bs('00101010')])
addop("sts_l", [bs('0100'), bs_mach, d32rmpdec, bs('00000010')])
addop("sts_l", [bs('0100'), bs_macl, d32rmpdec, bs('00010010')])
addop("sts_l",
      [bs('0100'), d32rnpdec, bs_pr, bs('00100010')], [bs_pr, d32rnpdec])
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

addop("flds", [bs('1111'), frm, bs_fpul, bs('00011101')])
addop("fsts", [bs('1111'), bs_fpul, frm, bs('00001101')])
addop("fabs", [bs('1111'), frn, bs('01011101')])
addop("fadd", [bs('1111'), frn, frm, bs('0000')], [frm, frn])
addop("fcmpeq", [bs('1111'), frn, frm, bs('0100')], [frm, frn])
addop("fcmpgt", [bs('1111'), frn, frm, bs('0101')], [frm, frn])
addop("fdiv", [bs('1111'), frn, frm, bs('0011')], [frm, frn])

addop("float", [bs('1111'), bs_fpul, frn, bs('00101101')])
addop("fmac", [bs('1111'), bs_fr0, frn, frm, bs('1110')], [bs_fr0, frm, frn])
addop("fmul", [bs('1111'), frn, frm, bs('0010')], [frm, frn])
addop("fneg", [bs('1111'), frn, bs('01001101')])
addop("fsqrt", [bs('1111'), frn, bs('01101101')])
addop("fsub", [bs('1111'), frn, frm, bs('0001')], [frm, frn])
addop("ftrc", [bs('1111'), frm, bs_fpul, bs('00111101')])
