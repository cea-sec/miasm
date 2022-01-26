from builtins import range

import logging
from pyparsing import *
from miasm.expression.expression import *
from miasm.core.cpu import *
from collections import defaultdict
from miasm.core.bin_stream import bin_stream
import miasm.arch.ppc.regs as regs_module
from miasm.arch.ppc.regs import *
from miasm.core.asm_ast import AstInt, AstId, AstMem, AstOp
from miasm.ir.ir import color_expr_html

log = logging.getLogger("ppcdis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

LPARENTHESIS = Suppress(Literal("("))
RPARENTHESIS = Suppress(Literal(")"))

def cb_deref_imm_reg(tokens):
    if len(tokens) == 1:
        return AstMem(tokens[0], 32)
    elif len(tokens) == 2:
        return AstMem(tokens[1] + tokens[0], 32)
    else:
        raise NotImplementedError('len(tokens) > 2')


deref_reg_disp = (Optional(base_expr) + LPARENTHESIS + gpregs.parser +  RPARENTHESIS).setParseAction(cb_deref_imm_reg)
deref_reg = (LPARENTHESIS + gpregs.parser +  RPARENTHESIS).setParseAction(cb_deref_imm_reg)

deref = deref_reg | deref_reg_disp


class ppc_arg(m_arg):
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


class additional_info(object):

    def __init__(self):
        self.except_on_instr = False
        self.bo_bi_are_defined = False
        self.bi = 0
        self.bo = 0


class instruction_ppc(instruction):

    def __init__(self, *args, **kargs):
        super(instruction_ppc, self).__init__(*args, **kargs)

    @staticmethod
    def arg2str(e, pos = None, loc_db=None):
        if isinstance(e, ExprId) or isinstance(e, ExprInt):
            return str(e)
        elif isinstance(e, ExprMem):
            addr = e.ptr
            if isinstance(addr, ExprInt) or isinstance(addr, ExprId):
                out = '(%s)'%addr
            elif isinstance(addr, ExprOp):
                if len(addr.args) == 1:
                    out = '(%s)'%addr
                elif len(addr.args) == 2:
                    out = '%s(%s)'%(addr.args[1], addr.args[0])
                else:
                    raise NotImplementedError('More than two args to ExprOp of address')
            else:
                raise NotImplementedError('Invalid memory expression')
            return out

        return str(e)


    @staticmethod
    def arg2html(e, pos = None, loc_db=None):
        if isinstance(e, ExprId) or isinstance(e, ExprInt) or isinstance(e, ExprLoc):
            return color_expr_html(e, loc_db)
        elif isinstance(e, ExprMem):
            addr = e.ptr
            if isinstance(addr, ExprInt) or isinstance(addr, ExprId):
                out = '(%s)'%color_expr_html(addr, loc_db)
            elif isinstance(addr, ExprOp):
                if len(addr.args) == 1:
                    out = '(%s)'%color_expr_html(addr, loc_db)
                elif len(addr.args) == 2:
                    out = '%s(%s)'%(color_expr_html(addr.args[1], loc_db), color_expr_html(addr.args[0], loc_db))
                else:
                    raise NotImplementedError('More than two args to ExprOp of address')
            else:
                raise NotImplementedError('Invalid memory expression')
            return out

        return color_expr_html(e, loc_db)

    @staticmethod
    def is_conditional_jump(s):
        return (s[0] == 'B' and
                s[1:3] in { 'DN', 'DZ', 'LT', 'GT', 'EQ', 'SO',
                            'GE', 'LE', 'NE', 'NS' })

    def dstflow(self):
        name = self.name
        if name[-1] == '+' or name[-1] == '-':
            name = name[:-1]
        return (name[0] == 'B' and
                name[-2:] != 'LR' and
                name[-3:] != 'LRL' and
                name[-3:] != 'CTR' and
                name[-4:] != 'CTRL')

    def dstflow2label(self, loc_db):
        name = self.name
        if name[-1] == '+' or name[-1] == '-':
            name = name[:-1]

        if name[-1] == 'L':
            name = name[:-1]
        elif name[-2:] == 'LA':
            name = name[:-2] + 'A'

        if name[-2:] != 'LR' and name[-3:] != 'CTR':
            if len(self.args) == 2:
                address_index = 1
            else:
                address_index = 0
            e = self.args[address_index]
            if not isinstance(e, ExprInt):
                return
            if name[-1] != 'A':
                ad = (int(e) + self.offset) & 0xFFFFFFFF
            else:
                ad = int(e)
            loc_key = loc_db.get_or_create_offset_location(ad)
            s = ExprLoc(loc_key, e.size)
            self.args[address_index] = s

    def breakflow(self):
        return self.name[0] == 'B'

    def is_subcall(self):
        name = self.name
        if name[-1] == '+' or name[-1] == '-':
            name = name[0:-1]
        return name[0] == 'B' and (name[-1] == 'L' or name[-2:-1] == 'LA')

    def getdstflow(self, loc_db):
        if 'LR' in self.name:
            return [ LR ]
        elif 'CTR' in self.name:
            return [ CTR ]
        elif len(self.args) == 2:
            address_index = 1
        else:
            address_index = 0
        return [ self.args[address_index] ]

    def splitflow(self):
        ret = False
        if self.is_conditional_jump(self.name):
            if self.additional_info.bo & 0b10100 != 0b10100:
                ret = True
        ret = ret or self.is_subcall()
        return ret

    def get_symbol_size(self, symbol, loc_db):
        return 32

    def fixDstOffset(self):
        e = self.args[0]
        if not isinstance(e, ExprInt):
            log.debug('Dynamic destination offset %r' % e)
            return
        if self.name[-1] != 'A':
            if self.offset is None:
                raise ValueError('symbol not resolved %s' % self.l)
            off = (int(e) + 0x100000000 - (self.offset + self.l)) & 0xFFFFFFFF
            if int(off % 4):
                raise ValueError('Offset %r must be a multiple of four' % off)
        else:
            off = int(e)
        self.args[0] = ExprInt(off, 32)

    def get_args_expr(self):
        args = [a for a in self.args]
        return args

    def get_asm_offset(self, x):
        return ExprInt_from(x, self.offset)


class mn_ppc(cls_mn):
    delayslot = 0
    name = "ppc32"
    regs = regs_module
    bintree = {}
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    instruction = instruction_ppc
    max_instruction_len = 4

    @classmethod
    def getpc(cls, attrib = None):
        return PC

    @classmethod
    def getsp(cls, attrib = None):
        return R1

    def additional_info(self):
        info = additional_info()
        info.bo_bi_are_defined = False
        if hasattr(self, "bo"):
            info.bo_bi_are_defined = True
            info.bi = int(self.bi.strbits, 2)
            info.bo = int(self.bo.strbits, 2)
        return info

    @classmethod
    def getbits(cls, bs, attrib, start, n):
        if not n:
            return 0
        o = 0
        if n > bs.getlen() * 8:
            raise ValueError('not enough bits %r %r' % (n, len(bs.bin) * 8))
        while n:
            offset = start // 8
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
        if attrib == "b":
            return offset
        else:
            raise NotImplementedError("bad attrib")

    @classmethod
    def check_mnemo(cls, fields):
        l = sum([x.l for x in fields])
        assert l == 32, "len %r" % l

    @classmethod
    def getmn(cls, name):
        return name.upper()

    @classmethod
    def mod_fields(cls, fields):
        l = sum([x.l for x in fields])
        return fields

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def post_dis(self):
        return self

    def value(self, mode):
        v = super(mn_ppc, self).value(mode)
        if mode == 'b':
            return [x for x in v]
        else:
            raise NotImplementedError("bad attrib")

    def get_symbol_size(self, symbol, loc_db, mode):
        return 32


class ppc_reg(reg_noarg, ppc_arg):
    pass


class ppc_gpreg_noarg(reg_noarg):
    reg_info = gpregs
    parser = reg_info.parser

class ppc_gpreg_or_0_noarg(reg_noarg):
    reg_info = gpregs
    parser = reg_info.parser

    def decode(self, v):
        ret = super(ppc_gpreg_or_0_noarg, self).decode(v)
        if ret == False:
            return False
        reg = self.expr
        if reg == R0:
            self.expr = ExprInt(0, 32)
        return ret

class ppc_gpreg(ppc_reg):
    reg_info = gpregs
    parser = reg_info.parser

class ppc_gpreg_or_0(ppc_reg):
    reg_info = gpregs
    parser = reg_info.parser

    def decode(self, v):
        ret = super(ppc_gpreg_or_0, self).decode(v)
        if ret == False:
            return False
        reg = self.expr
        if reg == R0:
            self.expr = ExprInt(0, 32)
        return ret

class ppc_crfreg_noarg(reg_noarg):
    reg_info = crfregs
    parser = reg_info.parser

class ppc_crfreg(ppc_reg):
    reg_info = crfregs
    parser = reg_info.parser

class ppc_imm(imm_noarg, ppc_arg):
    parser = base_expr

class ppc_s14imm_branch(ppc_imm):

    def decode(self, v):
        v = sign_ext(v << 2, 16, 32)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v & 0x3:
            return False
        v = v >> 2
        if sign_ext(v & self.lmask, 14, 32) != v:
            return False
        self.value = v & self.lmask
        return True

class ppc_s24imm_branch(ppc_imm):

    def decode(self, v):
        v = sign_ext(v << 2, 26, 32)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v & 0x3:
            return False
        v = v >> 2
        if sign_ext(v & self.lmask, 24, 32) != v:
            return False
        self.value = v & self.lmask
        return True

class ppc_s16imm(ppc_imm):

    def decode(self, v):
        v = sign_ext(v, 16, 32)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if sign_ext(v & self.lmask, 16, 32) != v:
            return False
        self.value = v & self.lmask
        return True

class ppc_u16imm(ppc_imm):

    def decode(self, v):
        if v & self.lmask != v:
            return False
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v & self.lmask != v:
            return False
        self.value = v & self.lmask
        return True

def ppc_swap_10(v):
    return ((v & 0b11111) << 5) | ((v & 0b1111100000) >> 5)

class ppc_spr(ppc_imm):

    def decode(self, v):
        self.expr = ExprInt(ppc_swap_10(v), 32)
        return True

    def encode(self, e):
        if not isinstance(e, ExprInt):
            return False
        self.value = ppc_swap_10(int(e))
        return True

class ppc_tbr(ppc_imm):

    def decode(self, v):
        self.expr = ExprInt(ppc_swap_10(v), 32)
        return True

    def encode(self, e):
        if not isinstance(e, ExprInt):
            return False
        self.value = ppc_swap_10(int(e))
        return True

class ppc_u08imm(ppc_u16imm):
    pass

class ppc_u05imm(ppc_u16imm):
    pass

class ppc_u04imm(ppc_u16imm):
    pass

class ppc_u02imm_noarg(imm_noarg):
    pass

class ppc_float(ppc_reg):
    reg_info = floatregs
    parser = reg_info.parser

class ppc_vex(ppc_reg):
    reg_info = vexregs
    parser = reg_info.parser

def ppc_bo_bi_to_mnemo(bo, bi, prefer_taken=True, default_taken=True):
    bo2mnemo = { 0: 'DNZF', 2: 'DZF', 4: 'F', 8: 'DNZT',
                 10: 'DZT', 12: 'T', 16: 'DNZ', 18: 'DZ',
                 20: '' }
    bi2cond = { 0b00: 'LT', 0b01: 'GT', 0b10: 'EQ', 0b11: 'SO' }
    bi2ncond = { 0b00: 'GE', 0b01: 'LE', 0b10: 'NE', 0b11: 'NS' }
    n = bo & 0b11110
    if not n in bo2mnemo:
        raise NotImplementedError("Unknown BO field")
    mnem = 'B' + bo2mnemo[n]
    if mnem[-1] == 'T':
        mnem = mnem[:-1] + bi2cond[bi & 0b11]
    if mnem[-1] == 'F':
        mnem = mnem[:-1] + bi2ncond[bi & 0b11]

    if prefer_taken != default_taken:
        if prefer_taken:
            mnem += '+'
        else:
            mnem += '-'

    return mnem

def ppc_all_bo_bi():
    for bo in [0, 2, 4, 8, 10, 12, 16, 18, 20]:
        for bi in range(4):
            yield bo, bi

class ppc_divert_conditional_branch(bs_divert):
    prio=3
    def divert(self, i, candidates):
        out = []
        for cls, _, bases, dct, fields in candidates:
            bi_i = getfieldindexby_name(fields, 'bi')[1]
            bo_i = getfieldindexby_name(fields, 'bo')[1]

            for bo, bi in ppc_all_bo_bi():
                nfields = fields[:]
                nfields[bi_i] = bs(int2bin(bi, 2), fname="bi")
                nfields[bo_i] = bs(int2bin(bo, 5), fname="bo")
                ndct = dict(dct)
                ndct['name'] = ppc_bo_bi_to_mnemo(bo, bi)
                out.append((cls, ndct['name'], bases, ndct, nfields))

                nfields = fields[:]
                nfields[bi_i] = bs(int2bin(bi, 2), fname="bi")
                nfields[bo_i] = bs(int2bin(bo+1, 5), fname="bo")
                ndct = dict(dct)
                ndct['name'] = ppc_bo_bi_to_mnemo(bo, bi)
                out.append((cls, ndct['name'], bases, ndct, nfields))

        return out

class ppc_deref32(ppc_arg):
    parser = deref

    def decode(self, v):
        v = sign_ext(v, 16, 32)
        e = self.parent.ra.expr + ExprInt(v, 32)
        self.expr = ExprMem(e, size=32)
        return True

    def encode(self):
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        addr = e.ptr
        if isinstance(addr, ExprId) or isinstance(addr, ExprInt):
            addr = addr + ExprInt(0, 32)
        elif not isinstance(addr, ExprOp):
            return False
        if addr.op != '+':
            return False
        if len(addr.args) != 2:
            return False
        reg, disp = addr.args[0], addr.args[1]
        v = int(disp)
        if sign_ext(v & 0xFFFF, 16, 32) != v:
            return False
        v &= 0xFFFF
        self.value = v
        self.parent.ra.expr = reg
        return True


def ppcop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_ppc,), dct)

rd = bs(l=5, cls=(ppc_gpreg,))
ra = bs(l=5, cls=(ppc_gpreg,))
ra_or_0 = bs(l=5, cls=(ppc_gpreg_or_0,))
rb = bs(l=5, cls=(ppc_gpreg,))
rs = bs(l=5, cls=(ppc_gpreg,))
crfd = bs(l=3, cls=(ppc_crfreg,))
crfs = bs(l=3, cls=(ppc_crfreg,))
sh = bs(l=5, cls=(ppc_u05imm,))
mb = bs(l=5, cls=(ppc_u05imm,))
me = bs(l=5, cls=(ppc_u05imm,))
nb = bs(l=5, cls=(ppc_u05imm,))
crm = bs(l=8, cls=(ppc_u08imm,))
sr = bs(l=4, cls=(ppc_u04imm,))
spr = bs(l=10, cls=(ppc_spr,))
tbr = bs(l=10, cls=(ppc_tbr,))
u05imm = bs(l=5, cls=(ppc_u05imm,))

s24imm_branch = bs(l=24, cls=(ppc_s24imm_branch,), fname="imm")
s14imm_branch = bs(l=14, cls=(ppc_s14imm_branch,), fname="imm")
s16imm = bs(l=16, cls=(ppc_s16imm,), fname="imm")
u16imm = bs(l=16, cls=(ppc_u16imm,), fname="imm")
u08imm = bs(l=5, cls=(ppc_u08imm,), fname="imm")
u02imm_noarg = bs(l=2, cls=(ppc_u02imm_noarg,), fname="imm")

ra_noarg = bs(l=5, cls=(ppc_gpreg_noarg,), fname="ra")
ra_or_0_noarg = bs(l=5, cls=(ppc_gpreg_or_0_noarg,), fname="ra")
dregimm = bs(l=16, cls=(ppc_deref32,))

rc_mod = bs_mod_name(l=1, mn_mod=['', '.'], fname='rc')

frd = bs(l=5, cls=(ppc_float,))
frb = bs(l=5, cls=(ppc_float,))
frs = bs(l=5, cls=(ppc_float,))
fm = bs(l=8, cls=(ppc_u08imm,))

va = bs(l=5, cls=(ppc_vex,))
vb = bs(l=5, cls=(ppc_vex,))
vd = bs(l=5, cls=(ppc_vex,))
rb_noarg = bs(l=5, cls=(ppc_gpreg_noarg,), fname="rb")

arith1_name = {"MULLI": 0b000111, "SUBFIC": 0b001000, "ADDIC": 0b001100,
               "ADDIC.": 0b001101 }

logic2_name = {"ORI": 0b011000, "XORI": 0b011010, "ANDI.": 0b011100 }
slogic2_name = {"ORIS": 0b011001, "XORIS": 0b011011, "ANDIS.": 0b011101 }

arith3_name = {"SUBFC": 0b0000001000, "ADDC": 0b0000001010,
               "MULHWU": 0b0000001011, "SUBF": 0b0000101000,
               "MULHW": 0b0001001011, "SUBFE": 0b0010001000,
               "ADDE": 0b0010001010, "MULLW": 0b0011101011,
               "ADD": 0b0100001010, "DIVWU": 0b0111001011,
               "DIVW": 0b0111101011, "SUBFCO": 0b1000001000,
               "ADDCO": 0b1000001010, "SUBFO": 0b1000101000,
               "SUBFEO": 0b1010001000, "ADDEO": 0b1010001010,
               "MULLWO": 0b1011101011, "ADDO": 0b1100001010,
               "DIVWUO": 0b1111001011, "DIVWO": 0b1111101011 }

xor_name = { "EQV": 0b0100011100, "XOR": 0b0100111100 }

arith4_name = {"NEG": 0b0001101000, "SUBFZE": 0b0011001000,
               "ADDZE": 0b0011001010, "SUBFME": 0b0011101000,
               "ADDME": 0b0011101010, "NEGO": 0b1001101000,
               "SUBFZEO": 0b1011001000, "ADDZEO": 0b1011001010,
               "SUBFMEO": 0b1011101000, "ADDMEO": 0b1011101010 }

arith5_name = {"CNTLZW": 0b00000, "EXTSH": 0b11100, "EXTSB": 0b11101 }

crlogic_name = {"CRAND": 0b1000, "CRANDC": 0b0100, "CREQV": 0b1001,
                "CRNAND": 0b0111, "CRNOR": 0b0001, "CROR": 0b1110,
                "CRORC": 0b1101, "CRXOR": 0b0110 }

rotins_name = {"RLWIMI": 0b010100, "RLWINM": 0b010101 }

bs_arith1_name = bs_name(l=6, name=arith1_name)

load1_name = {"LWARX": 0b0000010100, "LWZX": 0b0000010111,
              "LBZX": 0b0001010111, "LHZX": 0b0100010111,
              "ECIWX": 0b0100110110, "LHAX": 0b0101010111,
              "LSWX": 0b1000010101, "LWBRX": 0b1000010110,
              "LHBRX": 0b1100010110 }

load1_name_u = {"LWZUX": 0b0000110111, "LBZUX": 0b0001110111,
                "LHZUX": 0b0100110111, "LHAUX": 0b0101110111 }

load2_name = {"LWZ": 0b0000, "LBZ": 0b0010, "LHZ": 0b1000, "LHA": 0b1010,
              "LMW": 0b1110 }

load2_name_u = {"LWZU": 0b0001, "LBZU": 0b0011, "LHZU": 0b1001, "LHAU": 0b1011}

store1_name = { "STWCX.": 0b00100101101, "STWX": 0b00100101110,
                "STBX": 0b00110101110, "STHX": 0b01100101110,
                "ECOWX": 0b01101101100, "STSWX": 0b10100101010,
                "STWBRX": 0b10100101100, "STHBRX": 0b11100101100 }
store1_name_u = { "STWUX": 0b00101101110, "STBUX": 0b00111101110,
                  "STHUX": 0b01101101110 }

store2_name = { "STW": 0b0100, "STB": 0b0110, "STH": 0b1100, "STMW": 0b1111 }
store2_name_u = { "STWU": 0b0101, "STBU": 0b0111, "STHU": 0b1101 }

logic1_name = {"SLW": 0b0000011000, "AND": 0b0000011100,
               "ANDC": 0b0000111100, "NOR": 0b0001111100,
               "ORC": 0b0110011100, "OR": 0b0110111100,
               "NAND": 0b0111011100, "SRW": 0b1000011000,
               "SRAW": 0b1100011000 }

dcb_name = {"DCBST": 0b00001, "DCBF": 0b00010,
            "DCBTST": 0b00111, "DCBT": 0b01000,
            "DCBI": 0b01110, "DCBA": 0b10111,
            "ICBI": 0b11110, "DCBZ": 0b11111 }


load1_name_float = {"LFS": 0b110000, "LFD": 0b110010 }
load1_name_float_u = {"LFSU": 0b110001, "LFDU": 0b110011 }
store1_name_float = {"STFS": 0b110100, "STFD": 0b110110 }
store1_name_float_u = {"STFSU": 0b110101, "STFDU": 0b110111 }

load1_name_vex = {"LVEBX": 0b0000000111, "LVEHX": 0b0000100111,
                  "LVEWX": 0b0001000111, "LVSL": 0b0000000110,
                  "LVSR": 0b0000100110, "LVX": 0b0001100111,
                  "LVXL": 0b0101100111 }

class bs_mod_name_prio4(bs_mod_name):
    prio = 4

class bs_mod_name_prio5(bs_mod_name):
    prio = 5

class bs_mod_name_prio6(bs_mod_name):
    prio = 6

branch_to_reg = bs_mod_name_prio4(l=1, mn_mod=['LR', 'CTR'], fname='btoreg')
branch_lk = bs_mod_name_prio5(l=1, mn_mod=['', 'L'], fname='lk')
branch_aa = bs_mod_name_prio6(l=1, mn_mod=['', 'A'], fname='aa')

ppcop("arith1", [bs_arith1_name, rd, ra, s16imm])
ppcop("ADDIS", [bs('001111'), rd, ra_or_0, u16imm])
ppcop("ADDI", [bs('001110'), rd, ra_or_0, s16imm])

ppcop("logic2", [bs_name(l=6, name=logic2_name), rs, ra, u16imm],
      [ra, rs, u16imm])
ppcop("slogic2", [bs_name(l=6, name=slogic2_name), rs, ra, u16imm],
      [ra, rs, u16imm])

ppcop("store1", [bs('011111'), rs, ra_or_0, rb,
                 bs_name(l=11, name=store1_name)])
ppcop("store1u", [bs('011111'), rs, ra, rb,
                  bs_name(l=11, name=store1_name_u)])

ppcop("store2", [bs('10'), bs_name(l=4, name=store2_name), rs,
                    ra_noarg, dregimm])
ppcop("store2u", [bs('10'), bs_name(l=4, name=store2_name_u), rs,
                    ra_or_0_noarg, dregimm])

ppcop("arith3", [bs('011111'), rd, ra, rb, bs_name(l=10, name=arith3_name),
                 rc_mod])

ppcop("xor", [bs('011111'), rs, ra, rb, bs_name(l=10, name=xor_name),
                 rc_mod], [ra, rs, rb])

ppcop("arith4", [bs('011111'), rd, ra, bs('00000'),
                 bs_name(l=10, name=arith4_name), rc_mod])

ppcop("arith5", [bs('011111'), rs, ra, bs('00000'),
                 bs_name(l=5, name=arith5_name),
                 bs('11010'), rc_mod], [ra, rs])

ppcop("load1", [bs('011111'), rd, ra_or_0, rb,
                bs_name(l=10, name=load1_name), bs('0')])
ppcop("load1u", [bs('011111'), rd, ra, rb,
                 bs_name(l=10, name=load1_name_u), bs('0')])
ppcop("load2", [bs('10'), bs_name(l=4, name=load2_name),
                rd, ra_or_0_noarg, dregimm])
ppcop("load2u", [bs('10'), bs_name(l=4, name=load2_name_u),
                 rd, ra_noarg, dregimm])

ppcop("logic1", [bs('011111'), rs, ra, rb, bs_name(l=10, name=logic1_name),
                 rc_mod],
      [ra, rs, rb])

ppcop("TWI", [bs('000011'), u05imm, ra, s16imm])
ppcop("TW", [bs('011111'), u05imm, ra, rb, bs('00000001000')])

ppcop("CMPW", [bs('011111'), crfd, bs('00'), ra, rb, bs('00000000000')])
ppcop("CMPLW", [bs('011111'), crfd, bs('00'), ra, rb, bs('00001000000')])
ppcop("CMPLWI", [bs('001010'), crfd, bs('00'), ra, u16imm])
ppcop("CMPWI", [bs('001011'), crfd, bs('00'), ra, s16imm])

ppcop("BC", [bs('010000'), bs(l=5, cls=(ppc_u05imm,), fname='bo'),
             crfs,
             ppc_divert_conditional_branch(l=2, fname='bi'),
             s14imm_branch, branch_aa, branch_lk])
ppcop("SC", [bs('01000100000000000000000000000010')])
ppcop("B", [bs('010010'), s24imm_branch, branch_aa, branch_lk])
ppcop("MCRF", [bs('010011'), crfd, bs('00'), crfs, bs('000000000000000000')])

ppcop("BCXXX", [bs('010011'), bs(l=5, cls=(ppc_u05imm,), fname='bo'),
                crfs,
                ppc_divert_conditional_branch(l=2, fname='bi'),
                bs('00000'), branch_to_reg,
                bs('000010000'), branch_lk])

ppcop("crlogic", [bs('010011'),
                  bs(l=5, cls=(ppc_u05imm,), fname='crbd'),
                  bs(l=5, cls=(ppc_u05imm,), fname='crba'),
                  bs(l=5, cls=(ppc_u05imm,), fname='crbb'),
                  bs('0'),
                  bs_name(l=4, name=crlogic_name),
                  bs('000010')])

ppcop("rotins", [bs_name(l=6, name=rotins_name),
                 rs, ra, sh, mb, me, rc_mod],
      [ ra, rs, sh, mb, me ])
ppcop("RLWNM", [bs('010111'), rs, ra, rb, mb, me, rc_mod],
      [ ra, rs, rb, mb, me ])
ppcop("MFXXX", [bs('011111'), rd, bs('0000000000'),
                bs('000'),
                bs_name(l=1, name={'MFCR':0, 'MFMSR':1}),
                bs('0100110')])

ppcop("dcb", [bs('01111100000'), ra, rb, bs_name(l=5, name=dcb_name),
              bs('101100')])

ppcop("MTCRF", [bs('011111'), rs, bs('0'), crm, bs('000100100000')], [crm, rs])
ppcop("MTMSR", [bs('011111'), rs, bs('0000000000'), bs('00100100100')])
ppcop("MTSR", [bs('011111'), rs, bs('0'), sr, bs('0000000110100100')], [sr, rs])
ppcop("MTSRIN", [bs('011111'), rs, bs('00000'), rb, bs('00111100100')])

ppcop("TLBIE", [bs('011111'), bs('0000000000'), rb, bs('01001100100')])
ppcop("MFSPR", [bs('011111'), rd, spr, bs('01010100110')])
ppcop("TLBIA", [bs('01111100000000000000001011100100')])
ppcop("MFTB", [bs('011111'), rd, tbr, bs('01011100110')])
ppcop("RFI", [bs('01001100000000000000000001100100')])
ppcop("ISYNC", [bs('01001100000000000000000100101100')])
ppcop("MTSPR", [bs('011111'), rs, spr, bs('01110100110')], [spr, rs])
ppcop("MCRXR", [bs('011111'), crfd, bs('000000000000'),
                bs('10000000000')])
ppcop("TLBSYNC", [bs('01111100000000000000010001101100')])
ppcop("MFSR", [bs('011111'), rd, bs('0'), sr, bs('00000'), bs('10010100110')])
ppcop("LSWI", [bs('011111'), rd, ra, nb, bs('10010101010')])
ppcop("STSWI", [bs('011111'), rs, ra, nb, bs('10110101010')])
ppcop("SYNC", [bs('011111'), bs('000000000000000'), bs('10010101100')])
ppcop("MFSRIN", [bs('011111'), rd, bs('00000'), rb, bs('10100100110')])

ppcop("SRAWI", [bs('011111'), rs, ra, sh, bs('1100111000'), rc_mod],
      [ra, rs, sh])

ppcop("EIEIO", [bs('011111'), bs('000000000000000'), bs('11010101100')])

ppcop("load1f", [bs_name(l=6, name=load1_name_float), frd, ra_noarg, dregimm])
ppcop("load1fu", [bs_name(l=6, name=load1_name_float_u), frd, ra_noarg, dregimm])
ppcop("store1f", [bs_name(l=6, name=store1_name_float), frd, ra_noarg, dregimm])
ppcop("store1fu", [bs_name(l=6, name=store1_name_float_u), frd, ra_noarg, dregimm])
ppcop("MTFSF", [bs('111111'), bs('0'), fm, bs('0'), frb, bs('10110001110')])
ppcop("MTFSF.", [bs('111111'), bs('0'), fm, bs('0'), frb, bs('10110001111')])
ppcop("MFFS", [bs('111111'), frd, bs('00000000001001000111'), bs('0')])
ppcop("MFFS.", [bs('111111'), frd, bs('00000000001001000111'), bs('1')])

ppcop("load1vex", [bs('011111'), vd, ra, rb, bs_name(l=10, name=load1_name_vex), bs('0')])
ppcop("mtvscr", [bs('0001000000000000'), vb, bs('11001000100')])
