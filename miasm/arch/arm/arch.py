#-*- coding:utf-8 -*-

from builtins import range
from future.utils import viewitems

import logging
from pyparsing import *
from miasm.expression.expression import *
from miasm.core.cpu import *
from collections import defaultdict
from miasm.core.bin_stream import bin_stream
import miasm.arch.arm.regs as regs_module
from miasm.arch.arm.regs import *
from miasm.core.asm_ast import AstInt, AstId, AstMem, AstOp
from miasm.ir.ir import color_expr_html
from miasm.core import utils

# A1 encoding

log = logging.getLogger("armdis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

# arm regs ##############
reg_dum = ExprId('DumReg', 32)

PC, _ = gen_reg('PC')

# GP
regs_str = ['R%d' % r for r in range(0x10)]
regs_str[13] = 'SP'
regs_str[14] = 'LR'
regs_str[15] = 'PC'
regs_expr = [ExprId(x, 32) for x in regs_str]

gpregs = reg_info(regs_str, regs_expr)

gpregs_pc = reg_info(regs_str[-1:], regs_expr[-1:])
gpregs_sp = reg_info(regs_str[13:14], regs_expr[13:14])

gpregs_nosppc = reg_info(regs_str[:13] + [str(reg_dum), regs_str[14]],
                         regs_expr[:13] + [reg_dum, regs_expr[14]])

gpregs_nopc = reg_info(regs_str[:14],
                       regs_expr[:14])

gpregs_nosp = reg_info(regs_str[:13] + [str(reg_dum), regs_str[14], regs_str[15]],
                       regs_expr[:13] + [reg_dum, regs_expr[14], regs_expr[15]])


# psr
sr_flags = "cxsf"
cpsr_regs_str = []
spsr_regs_str = []
for i in range(0x10):
    o = ""
    for j in range(4):
        if i & (1 << j):
            o += sr_flags[j]
    cpsr_regs_str.append("CPSR_%s" % o)
    spsr_regs_str.append("SPSR_%s" % o)

# psr_regs_str = ['CPSR', 'SPSR']
# psr_regs_expr = [ExprId(x, 32) for x in psr_regs_str]

# psr_regs = reg_info(psr_regs_str, psr_regs_expr)

cpsr_regs_expr = [ExprId(x, 32) for x in cpsr_regs_str]
spsr_regs_expr = [ExprId(x, 32) for x in spsr_regs_str]

cpsr_regs = reg_info(cpsr_regs_str, cpsr_regs_expr)
spsr_regs = reg_info(spsr_regs_str, spsr_regs_expr)

# CP
cpregs_str = ['c%d' % r for r in range(0x10)]
cpregs_expr = [ExprId(x, 32) for x in cpregs_str]

cp_regs = reg_info(cpregs_str, cpregs_expr)

# P
pregs_str = ['p%d' % r for r in range(0x10)]
pregs_expr = [ExprId(x, 32) for x in pregs_str]

p_regs = reg_info(pregs_str, pregs_expr)

conditional_branch = ["BEQ", "BNE", "BCS", "BCC", "BMI", "BPL", "BVS",
                      "BVC", "BHI", "BLS", "BGE", "BLT", "BGT", "BLE"]

unconditional_branch = ["B", "BX", "BL", "BLX"]

barrier_expr = {
    0b1111: ExprId("SY", 32),
    0b1110: ExprId("ST", 32),
    0b1101: ExprId("LD", 32),
    0b1011: ExprId("ISH", 32),
    0b1010: ExprId("ISHST", 32),
    0b1001: ExprId("ISHLD", 32),
    0b0111: ExprId("NSH", 32),
    0b0110: ExprId("NSHST", 32),
    0b0011: ExprId("OSH", 32),
    0b0010: ExprId("OSHST", 32),
    0b0001: ExprId("OSHLD", 32),
}

barrier_info = reg_info_dct(barrier_expr)



# parser helper ###########

def cb_tok_reg_duo(tokens):
    tokens = tokens[0]
    i1 = gpregs.expr.index(tokens[0].name)
    i2 = gpregs.expr.index(tokens[1].name)
    o = []
    for i in range(i1, i2 + 1):
        o.append(AstId(gpregs.expr[i]))
    return o

LPARENTHESIS = Literal("(")
RPARENTHESIS = Literal(")")

LACC = Suppress(Literal("{"))
RACC = Suppress(Literal("}"))
MINUS = Suppress(Literal("-"))
CIRCUNFLEX = Literal("^")


def check_bounds(left_bound, right_bound, value):
    if left_bound <= value and value <= right_bound:
        return AstInt(value)
    else:
        raise ValueError('shift operator immediate value out of bound')


def check_values(values, value):
    if value in values:
        return AstInt(value)
    else:
        raise ValueError('shift operator immediate value out of bound')

int_1_31 = str_int.copy().setParseAction(lambda v: check_bounds(1, 31, v[0]))
int_1_32 = str_int.copy().setParseAction(lambda v: check_bounds(1, 32, v[0]))

int_8_16_24 = str_int.copy().setParseAction(lambda v: check_values([8, 16, 24], v[0]))


def cb_reglistparse(tokens):
    tokens = tokens[0]
    if tokens[-1] == "^":
        return AstOp('sbit', AstOp('reglist', *tokens[:-1]))
    return AstOp('reglist', *tokens)


allshifts = ['<<', '>>', 'a>>', '>>>', 'rrx']
allshifts_armt = ['<<', '>>', 'a>>', '>>>', 'rrx']

shift2expr_dct = {'LSL': '<<', 'LSR': '>>', 'ASR': 'a>>',
                  'ROR': ">>>", 'RRX': "rrx"}

expr2shift_dct = dict((value, key) for key, value in viewitems(shift2expr_dct))


def op_shift2expr(tokens):
    return shift2expr_dct[tokens[0]]

reg_duo = Group(gpregs.parser + MINUS +
                gpregs.parser).setParseAction(cb_tok_reg_duo)
reg_or_duo = reg_duo | gpregs.parser
gpreg_list = Group(LACC + delimitedList(
    reg_or_duo, delim=',') + RACC + Optional(CIRCUNFLEX))
gpreg_list.setParseAction(cb_reglistparse)

LBRACK = Suppress("[")
RBRACK = Suppress("]")
COMMA = Suppress(",")
all_binaryop_1_31_shifts_t = literal_list(
    ['LSL', 'ROR']).setParseAction(op_shift2expr)
all_binaryop_1_32_shifts_t = literal_list(
    ['LSR', 'ASR']).setParseAction(op_shift2expr)
all_unaryop_shifts_t = literal_list(['RRX']).setParseAction(op_shift2expr)

ror_shifts_t = literal_list(['ROR']).setParseAction(op_shift2expr)
shl_shifts_t = literal_list(['SHL']).setParseAction(op_shift2expr)


allshifts_t_armt = literal_list(
    ['LSL', 'LSR', 'ASR', 'ROR', 'RRX']).setParseAction(op_shift2expr)

gpreg_p = gpregs.parser

psr_p = cpsr_regs.parser | spsr_regs.parser


def cb_shift(tokens):
    if len(tokens) == 1:
        ret = tokens[0]
    elif len(tokens) == 2:
        ret = AstOp(tokens[1], tokens[0])
    elif len(tokens) == 3:
        ret = AstOp(tokens[1], tokens[0], tokens[2])
    else:
        raise ValueError("Bad arg")
    return ret

shift_off = (gpregs.parser + Optional(
    (all_unaryop_shifts_t) |
    (all_binaryop_1_31_shifts_t + (gpregs.parser | int_1_31)) |
    (all_binaryop_1_32_shifts_t + (gpregs.parser | int_1_32))
)).setParseAction(cb_shift)
shift_off |= base_expr


rot2_expr = (gpregs.parser + Optional(
    (ror_shifts_t + (int_8_16_24))
)).setParseAction(cb_shift)


rot5_expr = shift_off

OP_LSL = Suppress("LSL")

def cb_deref_reg_reg(tokens):
    if len(tokens) != 2:
        raise ValueError("Bad mem format")
    return AstMem(AstOp('+', tokens[0], tokens[1]), 8)

def cb_deref_reg_reg_lsl_1(tokens):
    if len(tokens) != 3:
        raise ValueError("Bad mem format")
    reg1, reg2, index = tokens
    if not isinstance(index, AstInt) or index.value != 1:
        raise ValueError("Bad index")
    ret = AstMem(AstOp('+', reg1, AstOp('<<', reg2, index)), 16)
    return ret


deref_reg_reg = (LBRACK + gpregs.parser + COMMA + gpregs.parser + RBRACK).setParseAction(cb_deref_reg_reg)
deref_reg_reg_lsl_1 = (LBRACK + gpregs.parser + COMMA + gpregs.parser + OP_LSL + base_expr + RBRACK).setParseAction(cb_deref_reg_reg_lsl_1)



(gpregs.parser + Optional(
    (ror_shifts_t + (int_8_16_24))
)).setParseAction(cb_shift)



reg_or_base = gpregs.parser | base_expr

def deref2expr_nooff(tokens):
    tokens = tokens[0]
    # XXX default
    return ExprOp("preinc", tokens[0], ExprInt(0, 32))


def cb_deref_preinc(tokens):
    tokens = tokens[0]
    if len(tokens) == 1:
        return AstOp("preinc", tokens[0], AstInt(0))
    elif len(tokens) == 2:
        return AstOp("preinc", tokens[0], tokens[1])
    else:
        raise NotImplementedError('len(tokens) > 2')


def cb_deref_pre_mem(tokens):
    tokens = tokens[0]
    if len(tokens) == 1:
        return AstMem(AstOp("preinc", tokens[0], AstInt(0)), 32)
    elif len(tokens) == 2:
        return AstMem(AstOp("preinc", tokens[0], tokens[1]), 32)
    else:
        raise NotImplementedError('len(tokens) > 2')


def cb_deref_post(tokens):
    tokens = tokens[0]
    return AstOp("postinc", tokens[0], tokens[1])


def cb_deref_wb(tokens):
    tokens = tokens[0]
    if tokens[-1] == '!':
        return AstMem(AstOp('wback', *tokens[:-1]), 32)
    return AstMem(tokens[0], 32)

# shift_off.setParseAction(deref_off)
deref_nooff = Group(
    LBRACK + gpregs.parser + RBRACK).setParseAction(deref2expr_nooff)
deref_pre = Group(LBRACK + gpregs.parser + Optional(
    COMMA + shift_off) + RBRACK).setParseAction(cb_deref_preinc)
deref_post = Group(LBRACK + gpregs.parser + RBRACK +
                   COMMA + shift_off).setParseAction(cb_deref_post)
deref = Group((deref_post | deref_pre | deref_nooff)
              + Optional('!')).setParseAction(cb_deref_wb)


def cb_gpreb_wb(tokens):
    assert len(tokens) == 1
    tokens = tokens[0]
    if tokens[-1] == '!':
        return AstOp('wback', *tokens[:-1])
    return tokens[0]

gpregs_wb = Group(gpregs.parser + Optional('!')).setParseAction(cb_gpreb_wb)


cond_list_full = ['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC',
                  'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'NV']


cond_list = ['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC',
             'HI', 'LS', 'GE', 'LT', 'GT', 'LE', '']  # , 'NV']
cond_dct = dict([(x[1], x[0]) for x in enumerate(cond_list)])
bm_cond = bs_mod_name(l=4, fname='cond', mn_mod=cond_list)



cond_dct_barmt = dict([(x[0], x[1]) for x in enumerate(cond_list) if x[0] & 0b1110 != 0b1110])
bm_cond_barmt = bs_mod_name(l=4, fname='cond', mn_mod=cond_dct_barmt)



def permut_args(order, args):
    l = []
    for i, x in enumerate(order):
        l.append((x.__class__, i))
    l = dict(l)
    out = [None for x in range(len(args))]
    for a in args:
        out[l[a.__class__]] = a
    return out


class additional_info(object):

    def __init__(self):
        self.except_on_instr = False
        self.lnk = None
        self.cond = None


class instruction_arm(instruction):
    __slots__ = []

    def __init__(self, *args, **kargs):
        super(instruction_arm, self).__init__(*args, **kargs)

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        wb = False
        if expr.is_id() or expr.is_int():
            return str(expr)
        elif expr.is_loc():
            if loc_db is not None:
                return loc_db.pretty_str(expr.loc_key)
            else:
                return str(expr)
        if isinstance(expr, ExprOp) and expr.op in expr2shift_dct:
            if len(expr.args) == 1:
                return '%s %s' % (expr.args[0], expr2shift_dct[expr.op])
            elif len(expr.args) == 2:
                return '%s %s %s' % (expr.args[0], expr2shift_dct[expr.op], expr.args[1])
            else:
                raise NotImplementedError('zarb arg2str')


        sb = False
        if isinstance(expr, ExprOp) and expr.op == "sbit":
            sb = True
            expr = expr.args[0]
        if isinstance(expr, ExprOp) and expr.op == "reglist":
            o = [gpregs.expr.index(x) for x in expr.args]
            out = reglist2str(o)
            if sb:
                out += "^"
            return out


        if isinstance(expr, ExprOp) and expr.op == 'wback':
            wb = True
            expr = expr.args[0]
        if isinstance(expr, ExprId):
            out = str(expr)
            if wb:
                out += "!"
            return out

        if not isinstance(expr, ExprMem):
            return str(expr)

        expr = expr.ptr
        if isinstance(expr, ExprOp) and expr.op == 'wback':
            wb = True
            expr = expr.args[0]


        if isinstance(expr, ExprId):
            r, s = expr, None
        elif len(expr.args) == 1 and isinstance(expr.args[0], ExprId):
            r, s = expr.args[0], None
        elif isinstance(expr.args[0], ExprId):
            r, s = expr.args[0], expr.args[1]
        else:
            r, s = expr.args[0].args
        if isinstance(s, ExprOp) and s.op in expr2shift_dct:
            s = ' '.join(
                str(x)
                for x in (s.args[0], expr2shift_dct[s.op], s.args[1])
            )

        if isinstance(expr, ExprOp) and expr.op == 'postinc':
            o = '[%s]' % r
            if s and not (isinstance(s, ExprInt) and int(s) == 0):
                o += ', %s' % s
        else:
            if s and not (isinstance(s, ExprInt) and int(s) == 0):
                o = '[%s, %s]' % (r, s)
            else:
                o = '[%s]' % (r)


        if wb:
            o += "!"
        return o

    @staticmethod
    def arg2html(expr, index=None, loc_db=None):
        wb = False
        if expr.is_id() or expr.is_int() or expr.is_loc():
            return color_expr_html(expr, loc_db)
        if isinstance(expr, ExprOp) and expr.op in expr2shift_dct:
            if len(expr.args) == 1:
                return '%s %s' % (color_expr_html(expr.args[0], loc_db), expr2shift_dct[expr.op])
            elif len(expr.args) == 2:
                return '%s %s %s' % (color_expr_html(expr.args[0], loc_db), expr2shift_dct[expr.op], expr.args[1])
            else:
                raise NotImplementedError('zarb arg2str')


        sb = False
        if isinstance(expr, ExprOp) and expr.op == "sbit":
            sb = True
            expr = expr.args[0]
        if isinstance(expr, ExprOp) and expr.op == "reglist":
            o = [gpregs.expr.index(x) for x in expr.args]
            out = reglist2html(o)
            if sb:
                out += "^"
            return out


        if isinstance(expr, ExprOp) and expr.op == 'wback':
            wb = True
            expr = expr.args[0]
        if isinstance(expr, ExprId):
            out = color_expr_html(expr, loc_db)
            if wb:
                out += "!"
            return out

        if not isinstance(expr, ExprMem):
            return color_expr_html(expr, loc_db)

        expr = expr.ptr
        if isinstance(expr, ExprOp) and expr.op == 'wback':
            wb = True
            expr = expr.args[0]


        if isinstance(expr, ExprId):
            r, s = expr, None
        elif len(expr.args) == 1 and isinstance(expr.args[0], ExprId):
            r, s = expr.args[0], None
        elif isinstance(expr.args[0], ExprId):
            r, s = expr.args[0], expr.args[1]
        else:
            r, s = expr.args[0].args
        if isinstance(s, ExprOp) and s.op in expr2shift_dct:
            s_html = ' '.join(
                str(x)
                for x in (
                        color_expr_html(s.args[0], loc_db),
                        utils.set_html_text_color(expr2shift_dct[s.op], utils.COLOR_OP),
                        color_expr_html(s.args[1], loc_db)
                )
            )
        else:
            s_html = color_expr_html(s, loc_db)

        if isinstance(expr, ExprOp) and expr.op == 'postinc':
            o = '[%s]' % color_expr_html(r, loc_db)
            if s and not (isinstance(s, ExprInt) and int(s) == 0):
                o += ', %s' % s_html
        else:
            if s and not (isinstance(s, ExprInt) and int(s) == 0):
                o = '[%s, %s]' % (color_expr_html(r, loc_db), s_html)
            else:
                o = '[%s]' % color_expr_html(r, loc_db)


        if wb:
            o += "!"
        return o


    def dstflow(self):
        if self.is_subcall():
            return True
        return self.name in conditional_branch + unconditional_branch

    def dstflow2label(self, loc_db):
        expr = self.args[0]
        if not isinstance(expr, ExprInt):
            return
        if self.name == 'BLX':
            addr = (int(expr) + self.offset) & int(expr.mask)
        else:
            addr = (int(expr) + self.offset) & int(expr.mask)
        loc_key = loc_db.get_or_create_offset_location(addr)
        self.args[0] = ExprLoc(loc_key, expr.size)

    def breakflow(self):
        if self.is_subcall():
            return True
        if self.name in conditional_branch + unconditional_branch:
            return True
        if self.name.startswith("LDM") and PC in self.args[1].args:
            return True
        if self.args and PC in self.args[0].get_r():
            return True
        return False

    def is_subcall(self):
        if self.name == 'BLX':
            return True
        return self.additional_info.lnk

    def getdstflow(self, loc_db):
        return [self.args[0]]

    def splitflow(self):
        if self.additional_info.lnk:
            return True
        if self.name == 'BLX':
            return True
        if self.name == 'BX':
            return False
        return self.breakflow() and self.additional_info.cond != 14

    def get_symbol_size(self, symbol, loc_db):
        return 32

    def fixDstOffset(self):
        e = self.args[0]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, ExprInt):
            log.debug('dyn dst %r', e)
            return
        off = (int(e) - self.offset) & int(e.mask)
        if int(off % 4):
            raise ValueError('strange offset! %r' % off)
        self.args[0] = ExprInt(off, 32)

    def get_args_expr(self):
        args = [a for a in self.args]
        return args

    def get_asm_offset(self, expr):
        # LDR XXX, [PC, offset] => PC is self.offset+8
        return ExprInt(self.offset+8, expr.size)

class instruction_armt(instruction_arm):
    __slots__ = []

    def __init__(self, *args, **kargs):
        super(instruction_armt, self).__init__(*args, **kargs)

    def dstflow(self):
        if self.name in ["CBZ", "CBNZ"]:
            return True
        return self.name in conditional_branch + unconditional_branch

    def dstflow2label(self, loc_db):
        if self.name in ["CBZ", "CBNZ"]:
            expr = self.args[1]
        else:
            expr = self.args[0]
        if not isinstance(expr, ExprInt):
            return
        if self.name == 'BLX':
            addr = (int(expr) + (self.offset & 0xfffffffc)) & int(expr.mask)
        elif self.name == 'BL':
            addr = (int(expr) + self.offset) & int(expr.mask)
        elif self.name.startswith('BP'):
            addr = (int(expr) + self.offset) & int(expr.mask)
        elif self.name.startswith('CB'):
            addr = (int(expr) + self.offset + self.l + 2) & int(expr.mask)
        else:
            addr = (int(expr) + self.offset) & int(expr.mask)

        loc_key = loc_db.get_or_create_offset_location(addr)
        dst = ExprLoc(loc_key, expr.size)

        if self.name in ["CBZ", "CBNZ"]:
            self.args[1] = dst
        else:
            self.args[0] = dst

    def breakflow(self):
        if self.name in conditional_branch + unconditional_branch +["CBZ", "CBNZ", 'TBB', 'TBH']:
            return True
        if self.name.startswith("LDM") and PC in self.args[1].args:
            return True
        if self.args and PC in self.args[0].get_r():
            return True
        return False

    def getdstflow(self, loc_db):
        if self.name in ['CBZ', 'CBNZ']:
            return [self.args[1]]
        return [self.args[0]]

    def splitflow(self):
        if self.name in conditional_branch + ['BL', 'BLX', 'CBZ', 'CBNZ']:
            return True
        return False

    def is_subcall(self):
        return self.name in ['BL', 'BLX']

    def fixDstOffset(self):
        e = self.args[0]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, ExprInt):
            log.debug('dyn dst %r', e)
            return
        # The first +2 is to compensate instruction len, but strangely, 32 bits
        # thumb2 instructions len is 2... For the second +2, didn't find it in
        # the doc.
        off = (int(e) - self.offset) & int(e.mask)
        if int(off % 2):
            raise ValueError('strange offset! %r' % off)
        self.args[0] = ExprInt(off, 32)

    def get_asm_offset(self, expr):
        # ADR XXX, PC, imm => PC is 4 aligned + imm
        new_offset = ((self.offset + self.l) // 4) * 4
        return ExprInt(new_offset, expr.size)


class mn_arm(cls_mn):
    delayslot = 0
    name = "arm"
    regs = regs_module
    bintree = {}
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    pc = {'l':PC, 'b':PC}
    sp = {'l':SP, 'b':SP}
    instruction = instruction_arm
    max_instruction_len = 4
    alignment = 4

    @classmethod
    def getpc(cls, attrib = None):
        return PC

    @classmethod
    def getsp(cls, attrib = None):
        return SP

    def additional_info(self):
        info = additional_info()
        info.lnk = False
        if hasattr(self, "lnk"):
            info.lnk = self.lnk.value != 0
        if hasattr(self, "cond"):
            info.cond = self.cond.value
        else:
            info.cond = None
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
    def mod_fields(cls, fields):
        l = sum([x.l for x in fields])
        if l == 32:
            return fields
        return [bm_cond] + fields

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def value(self, mode):
        v = super(mn_arm, self).value(mode)
        if mode == 'l':
            return [x[::-1] for x in v]
        elif mode == 'b':
            return [x for x in v]
        else:
            raise NotImplementedError('bad attrib')


    def get_symbol_size(self, symbol, loc_db, mode):
        return 32


class mn_armt(cls_mn):
    name = "armt"
    regs = regs_module
    delayslot = 0
    bintree = {}
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    pc = PC
    sp = SP
    instruction = instruction_armt
    max_instruction_len = 4
    alignment = 4

    @classmethod
    def getpc(cls, attrib = None):
        return PC

    @classmethod
    def getsp(cls, attrib = None):
        return SP

    def additional_info(self):
        info = additional_info()
        info.lnk = False
        if hasattr(self, "lnk"):
            info.lnk = self.lnk.value != 0
        info.cond = 14  # COND_ALWAYS
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
        if attrib == "l":
            return (offset & ~1) + 1 - offset % 2
        elif attrib == "b":
            return offset
        else:
            raise NotImplementedError('bad attrib')

    @classmethod
    def check_mnemo(cls, fields):
        l = sum([x.l for x in fields])
        assert l in [16, 32], "len %r" % l

    @classmethod
    def getmn(cls, name):
        return name.upper()

    @classmethod
    def mod_fields(cls, fields):
        return list(fields)

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def value(self, mode):
        v = super(mn_armt, self).value(mode)
        if mode == 'l':
            out = []
            for x in v:
                if len(x) == 2:
                    out.append(x[::-1])
                elif len(x) == 4:
                    out.append(x[:2][::-1] + x[2:4][::-1])
            return out
        elif mode == 'b':
            return [x for x in v]
        else:
            raise NotImplementedError('bad attrib')

    def get_args_expr(self):
        args = [a.expr for a in self.args]
        return args

    def get_symbol_size(self, symbol, loc_db, mode):
        return 32


class arm_arg(m_arg):
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
            if arg.op == "-":
                assert len(args) == 2
                return args[0] - args[1]
            return ExprOp(arg.op, *args)
        if isinstance(arg, AstInt):
            return ExprInt(arg.value, 32)
        if isinstance(arg, AstMem):
            ptr = self.asm_ast_to_expr(arg.ptr, loc_db)
            if ptr is None:
                return None
            return ExprMem(ptr, arg.size)
        return None


class arm_reg(reg_noarg, arm_arg):
    pass


class arm_gpreg_noarg(reg_noarg):
    reg_info = gpregs
    parser = reg_info.parser


class arm_gpreg(arm_reg):
    reg_info = gpregs
    parser = reg_info.parser


class arm_reg_wb(arm_reg):
    reg_info = gpregs
    parser = gpregs_wb

    def decode(self, v):
        v = v & self.lmask
        e = self.reg_info.expr[v]
        if self.parent.wback.value:
            e = ExprOp('wback', e)
        self.expr = e
        return True

    def encode(self):
        e = self.expr
        self.parent.wback.value = 0
        if isinstance(e, ExprOp) and e.op == 'wback':
            self.parent.wback.value = 1
            e = e.args[0]
        if isinstance(e, ExprId):
            self.value = self.reg_info.expr.index(e)
        else:
            self.parent.wback.value = 1
            self.value = self.reg_info.expr.index(e.args[0])
        return True


class arm_psr(arm_arg):
    parser = psr_p

    def decode(self, v):
        v = v & self.lmask
        if self.parent.psr.value == 0:
            e = cpsr_regs.expr[v]
        else:
            e = spsr_regs.expr[v]
        self.expr = e
        return True

    def encode(self):
        e = self.expr
        if e in spsr_regs.expr:
            self.parent.psr.value = 1
            v = spsr_regs.expr.index(e)
        elif e in cpsr_regs.expr:
            self.parent.psr.value = 0
            v = cpsr_regs.expr.index(e)
        else:
            return False
        self.value = v
        return True


class arm_cpreg(arm_reg):
    reg_info = cp_regs
    parser = reg_info.parser


class arm_preg(arm_reg):
    reg_info = p_regs
    parser = reg_info.parser


class arm_imm(imm_noarg, arm_arg):
    parser = base_expr


class arm_offs(arm_imm):
    parser = base_expr

    def int2expr(self, v):
        if v & ~self.intmask != 0:
            return None
        return ExprInt(v, self.intsize)

    def decodeval(self, v):
        v <<= 2
        # Add pipeline offset
        v += 8
        return v

    def encodeval(self, v):
        if v%4 != 0:
            return False
        # Remove pipeline offset
        v -= 8
        return v >> 2

    def decode(self, v):
        v = v & self.lmask
        if (1 << (self.l - 1)) & v:
            v |= ~0 ^ self.lmask
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
        if v is False:
            return False
        self.value = (v & 0xffffffff) & self.lmask
        return True


class arm_imm8_12(arm_arg):
    parser = deref

    def decode(self, v):
        v = v & self.lmask
        if self.parent.updown.value:
            e = ExprInt(v << 2, 32)
        else:
            e = ExprInt(-v << 2, 32)
        if self.parent.ppi.value:
            e = ExprOp('preinc', self.parent.rn.expr, e)
        else:
            e = ExprOp('postinc', self.parent.rn.expr, e)
        if self.parent.wback.value == 1:
            e = ExprOp('wback', e)
        self.expr = ExprMem(e, 32)
        return True

    def encode(self):
        self.parent.updown.value = 1
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        e = e.ptr
        if isinstance(e, ExprOp) and e.op == 'wback':
            self.parent.wback.value = 1
            e = e.args[0]
        else:
            self.parent.wback.value = 0
        if e.op == "postinc":
            self.parent.ppi.value = 0
        elif e.op == "preinc":
            self.parent.ppi.value = 1
        else:
            # XXX default
            self.parent.ppi.value = 1
        self.parent.rn.expr = e.args[0]
        if len(e.args) == 1:
            self.value = 0
            return True
        e = e.args[1]
        if not isinstance(e, ExprInt):
            log.debug('should be int %r', e)
            return False
        v = int(e)
        if v < 0 or v & (1 << 31):
            self.parent.updown.value = 0
            v = -v & 0xFFFFFFFF
        if v & 0x3:
            log.debug('arg should be 4 aligned')
            return False
        v >>= 2
        self.value = v
        return True


class arm_imm_4_12(arm_arg):
    parser = reg_or_base

    def decode(self, v):
        v = v & self.lmask
        imm = (self.parent.imm4.value << 12) | v
        self.expr = ExprInt(imm, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v > 0xffff:
            return False
        self.parent.imm4.value = v >> 12
        self.value = v & 0xfff
        return True


class arm_imm_12_4(arm_arg):
    parser = base_expr

    def decode(self, v):
        v = v & self.lmask
        imm =  (self.parent.imm.value << 4) | v
        self.expr = ExprInt(imm, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v > 0xffff:
            return False
        self.parent.imm.value = (v >> 4) & 0xfff
        self.value = v & 0xf
        return True


class arm_op2(arm_arg):
    parser = shift_off

    def str_to_imm_rot_form(self, s, neg=False):
        if neg:
            s = -s & 0xffffffff
        for i in range(0, 32, 2):
            v = myrol32(s, i)
            if 0 <= v < 0x100:
                return ((i // 2) << 8) | v
        return None

    def decode(self, v):
        val = v & self.lmask
        if self.parent.immop.value:
            rot = val >> 8
            imm = val & 0xff
            imm = myror32(imm, rot * 2)
            self.expr = ExprInt(imm, 32)
            return True
        rm = val & 0xf
        shift = val >> 4
        shift_kind = shift & 1
        shift_type = (shift >> 1) & 3
        shift >>= 3
        if shift_kind:
            # shift kind is reg
            if shift & 1:
                return False
            rs = shift >> 1
            if rs == 0xf:
                return False
            shift_op = regs_expr[rs]
        else:
            # shift kind is imm
            amount = shift
            shift_op = ExprInt(amount, 32)
        a = regs_expr[rm]
        if shift_op == ExprInt(0, 32):
            if shift_type == 3:
                self.expr = ExprOp(allshifts[4], a)
            else:
                self.expr = a
        else:
            self.expr = ExprOp(allshifts[shift_type], a, shift_op)
        return True

    def encode(self):
        e = self.expr
        # pure imm
        if isinstance(e, ExprInt):
            val = self.str_to_imm_rot_form(int(e))
            if val is None:
                return False
            self.parent.immop.value = 1
            self.value = val
            return True

        self.parent.immop.value = 0
        # pure reg
        if isinstance(e, ExprId):
            rm = gpregs.expr.index(e)
            shift_kind = 0
            shift_type = 0
            amount = 0
            self.value = (
                ((((amount << 2) | shift_type) << 1) | shift_kind) << 4) | rm
            return True
        # rot reg
        if not isinstance(e, ExprOp):
            log.debug('bad reg rot1 %r', e)
            return False
        rm = gpregs.expr.index(e.args[0])
        shift_type = allshifts.index(e.op)
        if e.op == 'rrx':
            shift_kind = 0
            amount = 0
            shift_type = 3
        elif isinstance(e.args[1], ExprInt):
            shift_kind = 0
            amount = int(e.args[1])
            # LSR/ASR of 32 => 0
            if amount == 32 and e.op in ['>>', 'a>>']:
                amount = 0
        else:
            shift_kind = 1
            amount = gpregs.expr.index(e.args[1]) << 1
        self.value = (
            ((((amount << 2) | shift_type) << 1) | shift_kind) << 4) | rm
        return True

# op2imm + rn


class arm_op2imm(arm_imm8_12):
    parser = deref

    def str_to_imm_rot_form(self, s, neg=False):
        if neg:
            s = -s & 0xffffffff
        if 0 <= s < (1 << 12):
            return s
        return None

    def decode(self, v):
        val = v & self.lmask
        if self.parent.immop.value == 0:
            imm = val
            if self.parent.updown.value == 0:
                imm = -imm
            if self.parent.ppi.value:
                e = ExprOp('preinc', self.parent.rn.expr, ExprInt(imm, 32))
            else:
                e = ExprOp('postinc', self.parent.rn.expr, ExprInt(imm, 32))
            if self.parent.wback.value == 1:
                e = ExprOp('wback', e)
            self.expr = ExprMem(e, 32)
            return True
        rm = val & 0xf
        shift = val >> 4
        shift_kind = shift & 1
        shift_type = (shift >> 1) & 3
        shift >>= 3
        # print self.parent.immop.value, hex(shift), hex(shift_kind),
        # hex(shift_type)
        if shift_kind:
            # log.debug('error in disasm xx')
            return False
        else:
            # shift kind is imm
            amount = shift
            shift_op = ExprInt(amount, 32)
        a = regs_expr[rm]
        if shift_op == ExprInt(0, 32):
            pass
        else:
            a = ExprOp(allshifts[shift_type], a, shift_op)
        if self.parent.ppi.value:
            e = ExprOp('preinc', self.parent.rn.expr, a)
        else:
            e = ExprOp('postinc', self.parent.rn.expr, a)
        if self.parent.wback.value == 1:
            e = ExprOp('wback', e)
        self.expr = ExprMem(e, 32)
        return True

    def encode(self):
        self.parent.immop.value = 1
        self.parent.updown.value = 1

        e = self.expr
        assert(isinstance(e, ExprMem))
        e = e.ptr
        if e.op == 'wback':
            self.parent.wback.value = 1
            e = e.args[0]
        else:
            self.parent.wback.value = 0
        if e.op == "postinc":
            self.parent.ppi.value = 0
        elif e.op == "preinc":
            self.parent.ppi.value = 1
        else:
            # XXX default
            self.parent.ppi.value = 1

        # if len(v) <1:
        #    raise ValueError('cannot parse', s)
        self.parent.rn.expr = e.args[0]
        if len(e.args) == 1:
            self.parent.immop.value = 0
            self.value = 0
            return True
        # pure imm
        if isinstance(e.args[1], ExprInt):
            self.parent.immop.value = 0
            val = self.str_to_imm_rot_form(int(e.args[1]))
            if val is None:
                val = self.str_to_imm_rot_form(int(e.args[1]), True)
                if val is None:
                    log.debug('cannot encode inm')
                    return False
                self.parent.updown.value = 0
            self.value = val
            return True
        # pure reg
        if isinstance(e.args[1], ExprId):
            rm = gpregs.expr.index(e.args[1])
            shift_kind = 0
            shift_type = 0
            amount = 0
            self.value = (
                ((((amount << 2) | shift_type) << 1) | shift_kind) << 4) | rm
            return True
        # rot reg
        if not isinstance(e.args[1], ExprOp):
            log.debug('bad reg rot2 %r', e)
            return False
        e = e.args[1]
        rm = gpregs.expr.index(e.args[0])
        shift_type = allshifts.index(e.op)
        if isinstance(e.args[1], ExprInt):
            shift_kind = 0
            amount = int(e.args[1])
        else:
            shift_kind = 1
            amount = gpregs.expr.index(e.args[1]) << 1
        self.value = (
            ((((amount << 2) | shift_type) << 1) | shift_kind) << 4) | rm
        return True


def reglist2str(rlist):
    out = []
    i = 0
    while i < len(rlist):
        j = i + 1
        while j < len(rlist) and rlist[j] < 13 and rlist[j] == rlist[j - 1] + 1:
            j += 1
        j -= 1
        if j < i + 2:
            out.append(regs_str[rlist[i]])
            i += 1
        else:
            out.append(regs_str[rlist[i]] + '-' + regs_str[rlist[j]])
            i = j + 1
    return "{" + ", ".join(out) + '}'

def reglist2html(rlist):
    out = []
    i = 0
    while i < len(rlist):
        j = i + 1
        while j < len(rlist) and rlist[j] < 13 and rlist[j] == rlist[j - 1] + 1:
            j += 1
        j -= 1
        if j < i + 2:
            out.append(color_expr_html(regs_expr[rlist[i]], None))
            i += 1
        else:
            out.append(color_expr_html(regs_expr[rlist[i]], None) + '-' + color_expr_html(regs_expr[rlist[j]], None))
            i = j + 1
    out = utils.fix_html_chars("{") + ", ".join(out) + utils.fix_html_chars("}")
    return out


class arm_rlist(arm_arg):
    parser = gpreg_list

    def encode(self):
        self.parent.sbit.value = 0
        e = self.expr
        if isinstance(e, ExprOp) and e.op == "sbit":
            e = e.args[0]
            self.parent.sbit.value = 1
        rlist = [gpregs.expr.index(x) for x in e.args]
        v = 0
        for r in rlist:
            v |= 1 << r
        self.value = v
        return True

    def decode(self, v):
        v = v & self.lmask
        out = []
        for i in range(0x10):
            if 1 << i & v:
                out.append(gpregs.expr[i])
        if not out:
            return False
        e = ExprOp('reglist', *out)
        if self.parent.sbit.value == 1:
            e = ExprOp('sbit', e)
        self.expr = e
        return True


class updown_b_nosp_mn(bs_mod_name):
    mn_mod = ['D', 'I']

    def modname(self, name, f_i):
        return name + self.args['mn_mod'][f_i]


class ppi_b_nosp_mn(bs_mod_name):
    prio = 5
    mn_mod = ['A', 'B']


class updown_b_sp_mn(bs_mod_name):
    mn_mod = ['A', 'D']

    def modname(self, name, f_i):
        if name.startswith("STM"):
            f_i = [1, 0][f_i]
        return name + self.args['mn_mod'][f_i]


class ppi_b_sp_mn(bs_mod_name):
    mn_mod = ['F', 'E']

    def modname(self, name, f_i):
        if name.startswith("STM"):
            f_i = [1, 0][f_i]
        return name + self.args['mn_mod'][f_i]


class arm_reg_wb_nosp(arm_reg_wb):

    def decode(self, v):
        v = v & self.lmask
        if v == 13:
            return False
        e = self.reg_info.expr[v]
        if self.parent.wback.value:
            e = ExprOp('wback', e)
        self.expr = e
        return True


class arm_offs_blx(arm_imm):

    def decode(self, v):
        v = v & self.lmask
        v = (v << 2) + (self.parent.lowb.value << 1)
        v = sign_ext(v, 26, 32)
        # Add pipeline offset
        v += 8
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        # Remove pipeline offset
        v = (int(self.expr) - 8) & int(self.expr.mask)
        if v & 0x80000000:
            v &= (1 << 26) - 1
        self.parent.lowb.value = (v >> 1) & 1
        self.value = v >> 2
        return True


class bs_lnk(bs_mod_name):

    def modname(self, name, i):
        return name[:1] + self.args['mn_mod'][i] + name[1:]


class armt_rm_cp(bsi):

    def decode(self, v):
        if v != gpregs.expr.index(self.parent.rm.expr):
            return False
        return True

    def encode(self):
        self.value = gpregs.expr.index(self.parent.rm.expr)
        return True


accum = bs(l=1)
scc = bs_mod_name(l=1, fname='scc', mn_mod=['', 'S'])
dumscc = bs("1")
rd = bs(l=4, cls=(arm_gpreg,))
rdl = bs(l=4, cls=(arm_gpreg,))

rn = bs(l=4, cls=(arm_gpreg,), fname="rn")
rs = bs(l=4, cls=(arm_gpreg,))
rm = bs(l=4, cls=(arm_gpreg,), fname='rm')
ra = bs(l=4, cls=(arm_gpreg,))
rt = bs(l=4, cls=(arm_gpreg,), fname='rt')
rt2 = bs(l=4, cls=(arm_gpreg,))

rm_cp = bs(l=4, cls=(armt_rm_cp,))

op2 = bs(l=12, cls=(arm_op2,))
lnk = bs_lnk(l=1, fname='lnk', mn_mod=['', 'L'])
offs = bs(l=24, cls=(arm_offs,), fname="offs")

rn_noarg = bs(l=4, cls=(arm_gpreg_noarg,), fname="rn")
rm_noarg = bs(l=4, cls=(arm_gpreg_noarg,), fname="rm", order = -1)

immop = bs(l=1, fname='immop')
dumr = bs(l=4, default_val="0000", fname="dumr")
# psr = bs(l=1, cls=(arm_psr,), fname="psr")

psr = bs(l=1, fname="psr")
psr_field = bs(l=4, cls=(arm_psr,))

ppi = bs(l=1, fname='ppi')
updown = bs(l=1, fname='updown')
trb = bs_mod_name(l=1, fname='trb', mn_mod=['', 'B'])
wback = bs_mod_name(l=1, fname="wback", mn_mod=['', 'T'])
wback_no_t = bs(l=1, fname="wback")

op2imm = bs(l=12, cls=(arm_op2imm,))

updown_b_nosp = updown_b_nosp_mn(l=1, mn_mod=['D', 'I'], fname='updown')
ppi_b_nosp = ppi_b_nosp_mn(l=1, mn_mod=['A', 'B'], fname='ppi')
updown_b_sp = updown_b_sp_mn(l=1, mn_mod=['A', 'D'], fname='updown')
ppi_b_sp = ppi_b_sp_mn(l=1, mn_mod=['F', 'E'], fname='ppi')

sbit = bs(l=1, fname="sbit")
rn_sp = bs("1101", cls=(arm_reg_wb,), fname='rnsp')
rn_wb = bs(l=4, cls=(arm_reg_wb_nosp,), fname='rn')
rlist = bs(l=16, cls=(arm_rlist,), fname='rlist')

swi_i = bs(l=24, cls=(arm_imm,), fname="swi_i")

opc = bs(l=4, cls=(arm_imm, m_arg), fname='opc')
crn = bs(l=4, cls=(arm_cpreg,), fname='crn')
crd = bs(l=4, cls=(arm_cpreg,), fname='crd')
crm = bs(l=4, cls=(arm_cpreg,), fname='crm')
cpnum = bs(l=4, cls=(arm_preg,), fname='cpnum')
cp = bs(l=3, cls=(arm_imm, m_arg), fname='cp')

imm8_12 = bs(l=8, cls=(arm_imm8_12, m_arg), fname='imm')
tl = bs_mod_name(l=1, fname="tl", mn_mod=['', 'L'])

cpopc = bs(l=3, cls=(arm_imm, m_arg), fname='cpopc')
imm20 = bs(l=20, cls=(arm_imm, m_arg))
imm4 = bs(l=4, cls=(arm_imm, m_arg))
imm12 = bs(l=12, cls=(arm_imm, m_arg))
imm16 = bs(l=16, cls=(arm_imm, m_arg))

imm12_off = bs(l=12, fname="imm")

imm2_noarg = bs(l=2, fname="imm")
imm4_noarg = bs(l=4, fname="imm4")


imm_4_12 = bs(l=12, cls=(arm_imm_4_12,))

imm12_noarg = bs(l=12, fname="imm")
imm_12_4 = bs(l=4, cls=(arm_imm_12_4,))

lowb = bs(l=1, fname='lowb')
offs_blx = bs(l=24, cls=(arm_offs_blx,), fname="offs")

fix_cond = bs("1111", fname="cond")

class mul_part_x(bs_mod_name):
    prio = 5
    mn_mod = ['B', 'T']

class mul_part_y(bs_mod_name):
    prio = 6
    mn_mod = ['B', 'T']

mul_x = mul_part_x(l=1, fname='x', mn_mod=['B', 'T'])
mul_y = mul_part_y(l=1, fname='y', mn_mod=['B', 'T'])

class arm_immed(arm_arg):
    parser = deref

    def decode(self, v):
        if self.parent.immop.value == 1:
            imm = ExprInt((self.parent.immedH.value << 4) | v, 32)
        else:
            imm = gpregs.expr[v]
        if self.parent.updown.value == 0:
            imm = -imm
        if self.parent.ppi.value:
            e = ExprOp('preinc', self.parent.rn.expr, imm)
        else:
            e = ExprOp('postinc', self.parent.rn.expr, imm)
        if self.parent.wback.value == 1:
            e = ExprOp('wback', e)
        self.expr = ExprMem(e, 32)

        return True

    def encode(self):
        self.parent.immop.value = 1
        self.parent.updown.value = 1
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        e = e.ptr
        if isinstance(e, ExprOp) and e.op == 'wback':
            self.parent.wback.value = 1
            e = e.args[0]
        else:
            self.parent.wback.value = 0
        if e.op == "postinc":
            self.parent.ppi.value = 0
        elif e.op == "preinc":
            self.parent.ppi.value = 1
        else:
            # XXX default
            self.parent.ppi.value = 1
        self.parent.rn.expr = e.args[0]
        if len(e.args) == 1:
            self.value = 0
            self.parent.immedH.value = 0
            return True
        e = e.args[1]
        if isinstance(e, ExprInt):
            v = int(e)
            if v < 0 or v & (1 << 31):
                self.parent.updown.value = 0
                v = (-v) & 0xFFFFFFFF
            if v > 0xff:
                log.debug('cannot encode imm XXX')
                return False
            self.value = v & 0xF
            self.parent.immedH.value = v >> 4
            return True

        self.parent.immop.value = 0
        if isinstance(e, ExprOp) and len(e.args) == 1 and e.op == "-":
            self.parent.updown.value = 0
            e = e.args[0]
        if e in gpregs.expr:
            self.value = gpregs.expr.index(e)
            self.parent.immedH.value = 0x0
            return True
        else:
            raise ValueError('e should be int: %r' % e)

immedH = bs(l=4, fname='immedH')
immedL = bs(l=4, cls=(arm_immed, m_arg), fname='immedL')
hb = bs(l=1)


class armt2_rot_rm(arm_arg):
    parser = shift_off
    def decode(self, v):
        r = self.parent.rm.expr
        if v == 00:
            e = r
        else:
            raise NotImplementedError('rotation')
        self.expr = e
        return True
    def encode(self):
        e = self.expr
        if isinstance(e, ExprId):
            self.value = 0
        else:
            raise NotImplementedError('rotation')
        return True

rot_rm = bs(l=2, cls=(armt2_rot_rm,), fname="rot_rm")


class arm_mem_rn_imm(arm_arg):
    parser = deref
    def decode(self, v):
        value = self.parent.imm.value
        if self.parent.rw.value == 0:
            value = -value
        imm = ExprInt(value, 32)
        reg = gpregs.expr[v]
        if value:
            expr = ExprMem(reg + imm, 32)
        else:
            expr = ExprMem(reg, 32)
        self.expr = expr
        return True

    def encode(self):
        self.parent.add_imm.value = 1
        self.parent.imm.value = 0
        expr = self.expr
        if not isinstance(expr, ExprMem):
            return False
        ptr = expr.ptr
        if ptr in gpregs.expr:
            self.value = gpregs.expr.index(ptr)
        elif (isinstance(ptr, ExprOp) and
              len(ptr.args) == 2 and
              ptr.op == 'preinc'):
            reg, imm = ptr.args
            if not reg in gpregs.expr:
                return False
            self.value = gpregs.expr.index(reg)
            if not isinstance(imm, ExprInt):
                return False
            value = int(imm)
            if value & 0x80000000:
                value = -value
                self.parent.add_imm.value = 0
            self.parent.imm.value = value
        else:
            return False
        return True

mem_rn_imm = bs(l=4, cls=(arm_mem_rn_imm,), order=1)

def armop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_arm,), dct)


def armtop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_armt,), dct)


op_list = ['AND', 'EOR', 'SUB', 'RSB', 'ADD', 'ADC', 'SBC', 'RSC',
           'TST', 'TEQ', 'CMP', 'CMN', 'ORR', 'MOV', 'BIC', 'MVN']
data_mov_name = {'MOV': 13, 'MVN': 15}
data_test_name = {'TST': 8, 'TEQ': 9, 'CMP': 10, 'CMN': 11}

data_name = {}
for i, n in enumerate(op_list):
    if n in list(data_mov_name) + list(data_test_name):
        continue
    data_name[n] = i
bs_data_name = bs_name(l=4, name=data_name)

bs_data_mov_name = bs_name(l=4, name=data_mov_name)

bs_data_test_name = bs_name(l=4, name=data_test_name)


transfer_name = {'STR': 0, 'LDR': 1}
bs_transfer_name = bs_name(l=1, name=transfer_name)

transferh_name = {'STRH': 0, 'LDRH': 1}
bs_transferh_name = bs_name(l=1, name=transferh_name)


transfer_ldr_name = {'LDRD': 0, 'LDRSB': 1}
bs_transfer_ldr_name = bs_name(l=1, name=transfer_ldr_name)

btransfer_name = {'STM': 0, 'LDM': 1}
bs_btransfer_name = bs_name(l=1, name=btransfer_name)

ctransfer_name = {'STC': 0, 'LDC': 1}
bs_ctransfer_name = bs_name(l=1, name=ctransfer_name)

mr_name = {'MCR': 0, 'MRC': 1}
bs_mr_name = bs_name(l=1, name=mr_name)


bs_addi = bs(l=1, fname="add_imm")
bs_rw = bs_mod_name(l=1, fname='rw', mn_mod=['W', ''])

class armt_barrier_option(reg_noarg, arm_arg):
    reg_info = barrier_info
    parser = reg_info.parser

    def decode(self, v):
        v = v & self.lmask
        if v not in self.reg_info.dct_expr:
            return False
        self.expr = self.reg_info.dct_expr[v]
        return True

    def encode(self):
        if not self.expr in self.reg_info.dct_expr_inv:
            log.debug("cannot encode reg %r", self.expr)
            return False
        self.value = self.reg_info.dct_expr_inv[self.expr]
        return True

    def check_fbits(self, v):
        return v & self.fmask == self.fbits

barrier_option = bs(l=4, cls=(armt_barrier_option,))

armop("mul", [bs('000000'), bs('0'), scc, rd, bs('0000'), rs, bs('1001'), rm], [rd, rm, rs])
armop("umull", [bs('000010'), bs('0'), scc, rd, rdl, rs, bs('1001'), rm], [rdl, rd, rm, rs])
armop("umlal", [bs('000010'), bs('1'), scc, rd, rdl, rs, bs('1001'), rm], [rdl, rd, rm, rs])
armop("smull", [bs('000011'), bs('0'), scc, rd, rdl, rs, bs('1001'), rm], [rdl, rd, rm, rs])
armop("smlal", [bs('000011'), bs('1'), scc, rd, rdl, rs, bs('1001'), rm], [rdl, rd, rm, rs])
armop("mla", [bs('000000'), bs('1'), scc, rd, rn, rs, bs('1001'), rm], [rd, rm, rs, rn])
armop("mrs", [bs('00010'), psr, bs('00'), psr_field, rd, bs('000000000000')], [rd, psr])
armop("msr", [bs('00010'), psr, bs('10'), psr_field, bs('1111'), bs('0000'), bs('0000'), rm], [psr_field, rm])
armop("data", [bs('00'), immop, bs_data_name, scc, rn, rd, op2], [rd, rn, op2])
armop("data_mov", [bs('00'), immop, bs_data_mov_name, scc, bs('0000'), rd, op2], [rd, op2])
armop("data_test", [bs('00'), immop, bs_data_test_name, dumscc, rn, dumr, op2])
armop("b", [bs('101'), lnk, offs])

armop("smul", [bs('00010110'), rd, bs('0000'), rs, bs('1'), mul_y, mul_x, bs('0'), rm], [rd, rm, rs])

# TODO TEST
#armop("und", [bs('011'), imm20, bs('1'), imm4])
armop("transfer", [bs('01'), immop, ppi, updown, trb, wback_no_t, bs_transfer_name, rn_noarg, rd, op2imm], [rd, op2imm])
armop("transferh", [bs('000'), ppi, updown, immop, wback_no_t, bs_transferh_name, rn_noarg, rd, immedH, bs('1011'), immedL], [rd, immedL])
armop("ldrd", [bs('000'), ppi, updown, immop, wback_no_t, bs_transfer_ldr_name, rn_noarg, rd, immedH, bs('1101'), immedL], [rd, immedL])
armop("ldrsh", [bs('000'),  ppi, updown, immop, wback_no_t, bs('1'), rn_noarg, rd, immedH, bs('1'), bs('1'), bs('1'), bs('1'), immedL], [rd, immedL])
armop("strd", [bs('000'),  ppi, updown, immop, wback_no_t, bs('0'), rn_noarg, rd, immedH, bs('1'), bs('1'), bs('1'), bs('1'), immedL], [rd, immedL])
armop("btransfersp", [bs('100'),  ppi_b_sp, updown_b_sp, sbit, wback_no_t, bs_btransfer_name, rn_sp, rlist])
armop("btransfer", [bs('100'),  ppi_b_nosp, updown_b_nosp, sbit, wback_no_t, bs_btransfer_name, rn_wb, rlist])
# TODO: TEST
armop("swp", [bs('00010'), trb, bs('00'), rn, rd, bs('0000'), bs('1001'), rm])
armop("svc", [bs('1111'), swi_i])
armop("cdp", [bs('1110'), opc, crn, crd, cpnum, cp, bs('0'), crm], [cpnum, opc, crd, crn, crm, cp])
armop("cdata", [bs('110'), ppi, updown, tl, wback_no_t, bs_ctransfer_name, rn_noarg, crd, cpnum, imm8_12], [cpnum, crd, imm8_12])
armop("mr", [bs('1110'), cpopc, bs_mr_name, crn, rd, cpnum, cp, bs('1'), crm], [cpnum, cpopc, rd, crn, crm, cp])
armop("bkpt", [bs('00010010'), imm12_noarg, bs('0111'), imm_12_4])
armop("bx", [bs('000100101111111111110001'), rn])
armop("mov", [bs('00110000'), imm4_noarg, rd, imm_4_12], [rd, imm_4_12])
armop("movt", [bs('00110100'), imm4_noarg, rd, imm_4_12], [rd, imm_4_12])
armop("blx", [bs('00010010'), bs('1111'), bs('1111'), bs('1111'), bs('0011'), rm], [rm])
armop("blx", [fix_cond, bs('101'), lowb, offs_blx], [offs_blx])
armop("clz", [bs('00010110'), bs('1111'), rd, bs('1111'), bs('0001'), rm], [rd, rm])
armop("qadd", [bs('00010000'), rn, rd, bs('0000'), bs('0101'), rm], [rd, rm, rn])

armop("uxtb", [bs('01101110'), bs('1111'), rd, rot_rm, bs('00'), bs('0111'), rm_noarg])
armop("uxth", [bs('01101111'), bs('1111'), rd, rot_rm, bs('00'), bs('0111'), rm_noarg])
armop("sxtb", [bs('01101010'), bs('1111'), rd, rot_rm, bs('00'), bs('0111'), rm_noarg])
armop("sxth", [bs('01101011'), bs('1111'), rd, rot_rm, bs('00'), bs('0111'), rm_noarg])

armop("rev", [bs('01101011'), bs('1111'), rd, bs('1111'), bs('0011'), rm])
armop("rev16", [bs('01101011'), bs('1111'), rd, bs('1111'), bs('1011'), rm])

armop("pld", [bs8(0xF5), bs_addi, bs_rw, bs('01'), mem_rn_imm, bs('1111'), imm12_off])

armop("dsb", [bs('111101010111'), bs('1111'), bs('1111'), bs('0000'), bs('0100'), barrier_option])
armop("isb", [bs('111101010111'), bs('1111'), bs('1111'), bs('0000'), bs('0110'), barrier_option])
armop("nop", [bs8(0xE3), bs8(0x20), bs8(0xF0), bs8(0)])

class arm_widthm1(arm_imm, m_arg):
    def decode(self, v):
        self.expr = ExprInt(v+1, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr) +  -1
        self.value = v
        return True


class arm_rm_rot2(arm_arg):
    parser = rot2_expr
    def decode(self, v):
        expr = gpregs.expr[v]
        shift_value = self.parent.rot2.value
        if shift_value:
            expr = ExprOp(allshifts[3], expr, ExprInt(shift_value * 8, 32))
        self.expr = expr
        return True
    def encode(self):
        if self.expr in gpregs.expr:
            self.value = gpregs.expr.index(self.expr)
            self.parent.rot2.value = 0
        elif (isinstance(self.expr, ExprOp) and
              self.expr.op == allshifts[3]):
            reg, value = self.expr.args
            if reg not in gpregs.expr:
                return False
            self.value = gpregs.expr.index(reg)
            if not isinstance(value, ExprInt):
                return False
            value = int(value)
            if not value in [8, 16, 24]:
                return False
            self.parent.rot2.value = value // 8
        return True



class arm_rm_rot5_lsl(arm_arg):
    parser = rot5_expr
    index_op = 0
    def decode(self, v):
        expr = gpregs.expr[v]
        shift_value = self.parent.rot5.value
        if shift_value:
            expr = ExprOp(allshifts[self.index_op], expr, ExprInt(shift_value, 32))
        self.expr = expr
        return True
    def encode(self):
        if self.expr in gpregs.expr:
            self.value = gpregs.expr.index(self.expr)
            self.parent.rot5.value = 0
        elif (isinstance(self.expr, ExprOp) and
              self.expr.op == allshifts[self.index_op]):
            reg, value = self.expr.args
            if reg not in gpregs.expr:
                return False
            self.value = gpregs.expr.index(reg)
            if not isinstance(value, ExprInt):
                return False
            value = int(value)
            if not 0 <= value < 32:
                return False
            self.parent.rot5.value = value
        return True

class arm_rm_rot5_asr(arm_rm_rot5_lsl):
    parser = rot5_expr
    index_op = 2
    def decode(self, v):
        expr = gpregs.expr[v]
        shift_value = self.parent.rot5.value
        if shift_value == 0:
            expr = ExprOp(allshifts[self.index_op], expr, ExprInt(32, 32))
        else:
            expr = ExprOp(allshifts[self.index_op], expr, ExprInt(shift_value, 32))
        self.expr = expr
        return True
    def encode(self):
        if (isinstance(self.expr, ExprOp) and
              self.expr.op == allshifts[self.index_op]):
            reg, value = self.expr.args
            if reg not in gpregs.expr:
                return False
            self.value = gpregs.expr.index(reg)
            if not isinstance(value, ExprInt):
                return False
            value = int(value)
            if not 0 < value <= 32:
                return False
            if value == 32:
                value = 0
            self.parent.rot5.value = value
        else:
            return False
        return True


class arm_gpreg_nopc(reg_noarg):
    reg_info = gpregs_nopc
    parser = reg_info.parser


    def decode(self, v):
        ret = super(arm_gpreg_nopc, self).decode(v)
        if ret is False:
            return False
        if self.expr == reg_dum:
            return False
        return True


class arm_gpreg_nosp(reg_noarg):
    reg_info = gpregs_nosp
    parser = reg_info.parser

    def decode(self, v):
        ret = super(arm_gpreg_nosp, self).decode(v)
        if ret is False:
            return False
        if self.expr == reg_dum:
            return False
        return True


rm_rot2 = bs(l=4, cls=(arm_rm_rot2,), fname="rm")
rot2 = bs(l=2, fname="rot2")

rm_rot5_lsl = bs(l=4, cls=(arm_rm_rot5_lsl,), fname="rm")
rm_rot5_asr = bs(l=4, cls=(arm_rm_rot5_asr,), fname="rm")
rot5 = bs(l=5, fname="rot5")

widthm1 = bs(l=5, cls=(arm_widthm1, m_arg))
lsb = bs(l=5, cls=(arm_imm, m_arg))

rd_nopc = bs(l=4, cls=(arm_gpreg_nopc, arm_arg), fname="rd")
rn_nopc = bs(l=4, cls=(arm_gpreg_nopc, arm_arg), fname="rn")
ra_nopc = bs(l=4, cls=(arm_gpreg_nopc, arm_arg), fname="ra")
rt_nopc = bs(l=4, cls=(arm_gpreg_nopc, arm_arg), fname="rt")

rn_nosp = bs(l=4, cls=(arm_gpreg_nosp, arm_arg), fname="rn")

rn_nopc_noarg = bs(l=4, cls=(arm_gpreg_nopc,), fname="rn")

armop("ubfx", [bs('0111111'), widthm1, rd, lsb, bs('101'), rn], [rd, rn, lsb, widthm1])

armop("bfc", [bs('0111110'), widthm1, rd, lsb, bs('001'), bs('1111')], [rd, lsb, widthm1])

armop("uxtab", [bs('01101110'), rn_nopc, rd, rot2, bs('000111'), rm_rot2], [rd, rn_nopc, rm_rot2])

armop("pkhbt", [bs('01101000'), rn, rd, rot5, bs('001'), rm_rot5_lsl], [rd, rn, rm_rot5_lsl])
armop("pkhtb", [bs('01101000'), rn, rd, rot5, bs('101'), rm_rot5_asr], [rd, rn, rm_rot5_asr])



#
# thumnb #######################
#
# ARM7-TDMI-manual-pt3
gpregs_l = reg_info(regs_str[:8], regs_expr[:8])
gpregs_h = reg_info(regs_str[8:], regs_expr[8:])

gpregs_sppc = reg_info(regs_str[-1:] + regs_str[13:14],
                       regs_expr[-1:] + regs_expr[13:14])

deref_reg_imm = Group(LBRACK + gpregs.parser + Optional(
    COMMA + shift_off) + RBRACK).setParseAction(cb_deref_pre_mem)
deref_low = Group(LBRACK + gpregs_l.parser + Optional(
    COMMA + shift_off) + RBRACK).setParseAction(cb_deref_pre_mem)
deref_pc = Group(LBRACK + gpregs_pc.parser + Optional(
    COMMA + shift_off) + RBRACK).setParseAction(cb_deref_pre_mem)
deref_sp = Group(LBRACK + gpregs_sp.parser + COMMA +
                 shift_off + RBRACK).setParseAction(cb_deref_pre_mem)

gpregs_l_wb = Group(
    gpregs_l.parser + Optional('!')).setParseAction(cb_gpreb_wb)


gpregs_l_13 = reg_info(regs_str[:13], regs_expr[:13])


class arm_offreg(arm_arg):
    parser = deref_pc

    def decodeval(self, v):
        return v

    def encodeval(self, v):
        return v

    def decode(self, v):
        v = v & self.lmask
        v = self.decodeval(v)
        if v:
            self.expr = self.off_reg + ExprInt(v, 32)
        else:
            self.expr = self.off_reg

        e = self.expr
        if isinstance(e, ExprOp) and e.op == 'wback':
            self.parent.wback.value = 1
            e = e.args[0]
        return True

    def encode(self):
        e = self.expr
        if not (isinstance(e, ExprOp) and e.op == "preinc"):
            log.debug('cannot encode %r', e)
            return False
        if e.args[0] != self.off_reg:
            log.debug('cannot encode reg %r', e.args[0])
            return False
        v = int(e.args[1])
        v = self.encodeval(v)
        self.value = v
        return True


class arm_offpc(arm_offreg):
    off_reg = regs_expr[15]

    def decode(self, v):
        v = v & self.lmask
        v <<= 2
        if v:
            self.expr = ExprMem(self.off_reg + ExprInt(v, 32), 32)
        else:
            self.expr = ExprMem(self.off_reg, 32)

        e = self.expr.ptr
        if isinstance(e, ExprOp) and e.op == 'wback':
            self.parent.wback.value = 1
            e = e.args[0]
        return True

    def encode(self):
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        e = e.ptr
        if not (isinstance(e, ExprOp) and e.op == "preinc"):
            log.debug('cannot encode %r', e)
            return False
        if e.args[0] != self.off_reg:
            log.debug('cannot encode reg %r', e.args[0])
            return False
        v = int(e.args[1])
        if v & 3:
            return False
        v >>= 2
        self.value = v
        return True




class arm_offsp(arm_offpc):
    parser = deref_sp
    off_reg = regs_expr[13]


class arm_offspc(arm_offs):

    def decodeval(self, v):
        v = v << 1
        # Add pipeline offset
        v += 2 + 2
        return v

    def encodeval(self, v):
        # Remove pipeline offset
        v -= 2 + 2
        if v % 2 != 0:
            return False
        if v > (1 << (self.l - 1)) - 1:
            return False
        return v >> 1


class arm_off8sppc(arm_imm):

    def decodeval(self, v):
        return v << 2

    def encodeval(self, v):
        return v >> 2


class arm_off7(arm_imm):

    def decodeval(self, v):
        return v << 2

    def encodeval(self, v):
        return v >> 2

class arm_deref_reg_imm(arm_arg):
    parser = deref_reg_imm

    def decode(self, v):
        v = v & self.lmask
        rbase = regs_expr[v]
        e = ExprOp('preinc', rbase, self.parent.off.expr)
        self.expr = ExprMem(e, 32)
        return True

    def encode(self):
        self.parent.off.expr = None
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        e = e.ptr
        if not (isinstance(e, ExprOp) and e.op == 'preinc'):
            log.debug('cannot encode %r', e)
            return False
        off = e.args[1]
        if isinstance(off, ExprId):
            self.parent.off.expr = off
        elif isinstance(off, ExprInt):
            self.parent.off.expr = off
        else:
            log.debug('cannot encode off %r', off)
            return False
        self.value = gpregs.expr.index(e.args[0])
        if self.value >= 1 << self.l:
            log.debug('cannot encode reg %r', off)
            return False
        return True

class arm_derefl(arm_deref_reg_imm):
    parser = deref_low


class arm_offbw(imm_noarg):

    def decode(self, v):
        v = v & self.lmask
        if self.parent.trb.value == 0:
            v <<= 2
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if self.parent.trb.value == 0:
            if v & 3:
                log.debug('off must be aligned %r', v)
                return False
            v >>= 2
        self.value = v
        return True



class arm_off(imm_noarg):

    def decode(self, v):
        v = v & self.lmask
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        self.value = v
        return True


class arm_offh(imm_noarg):

    def decode(self, v):
        v = v & self.lmask
        v <<= 1
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v & 1:
            log.debug('off must be aligned %r', v)
            return False
        v >>= 1
        self.value = v
        return True


class armt_rlist(arm_arg):
    parser = gpreg_list

    def encode(self):
        e = self.expr
        rlist = [gpregs_l.expr.index(x) for x in e.args]
        v = 0
        for r in rlist:
            v |= 1 << r
        self.value = v
        return True

    def decode(self, v):
        v = v & self.lmask
        out = []
        for i in range(0x10):
            if 1 << i & v:
                out.append(gpregs.expr[i])
        if not out:
            return False
        e = ExprOp('reglist', *out)
        self.expr = e
        return True


class armt_rlist13(armt_rlist):
    parser = gpreg_list

    def encode(self):
        e = self.expr
        rlist = []
        reg_l = list(e.args)

        self.parent.pclr.value = 0
        if self.parent.name.startswith('PUSH'):
            if regs_expr[14] in reg_l:
                reg_l.remove(regs_expr[14])
                self.parent.pclr.value = 1
        else:
            if regs_expr[15] in reg_l:
                reg_l.remove(regs_expr[15])
                self.parent.pclr.value = 1

        for reg in reg_l:
            if reg not in gpregs_l_13.expr:
                return False
            rlist.append(gpregs_l_13.expr.index(reg))
        v = 0
        for r in rlist:
            v |= 1 << r
        self.value = v
        return True

    def decode(self, v):
        v = v & self.lmask
        out = []
        for i in range(13):
            if 1 << i & v:
                out.append(gpregs_l_13.expr[i])

        if self.parent.pclr.value == 1:
            if self.parent.name.startswith("PUSH"):
                out += [regs_expr[14]]
            else:
                out += [regs_expr[15]]

        if not out:
            return False
        e = ExprOp('reglist', *out)
        self.expr = e
        return True



class armt_rlist13_pc_lr(armt_rlist):
    parser = gpreg_list

    def encode(self):
        e = self.expr
        rlist = []
        reg_l = list(e.args)

        self.parent.pc_in.value = 0
        self.parent.lr_in.value = 0
        if regs_expr[14] in reg_l:
            reg_l.remove(regs_expr[14])
            self.parent.lr_in.value = 1
        if regs_expr[15] in reg_l:
            reg_l.remove(regs_expr[15])
            self.parent.pc_in.value = 1

        for reg in reg_l:
            if reg not in gpregs_l_13.expr:
                return False
            rlist.append(gpregs_l_13.expr.index(reg))
        v = 0
        for r in rlist:
            v |= 1 << r
        self.value = v
        return True

    def decode(self, v):
        v = v & self.lmask
        out = []
        for i in range(13):
            if 1 << i & v:
                out.append(gpregs_l_13.expr[i])

        if self.parent.lr_in.value == 1:
            out += [regs_expr[14]]
        if self.parent.pc_in.value == 1:
            out += [regs_expr[15]]

        if not out:
            return False
        e = ExprOp('reglist', *out)
        self.expr = e
        return True



class armt_rlist_pclr(armt_rlist):

    def encode(self):
        e = self.expr
        reg_l = list(e.args)
        self.parent.pclr.value = 0
        if self.parent.pp.value == 0:
            if regs_expr[14] in reg_l:
                reg_l.remove(regs_expr[14])
                self.parent.pclr.value = 1
        else:
            if regs_expr[15] in reg_l:
                reg_l.remove(regs_expr[15])
                self.parent.pclr.value = 1
        rlist = [gpregs.expr.index(x) for x in reg_l]
        v = 0
        for r in rlist:
            v |= 1 << r
        self.value = v
        return True

    def decode(self, v):
        v = v & self.lmask
        out = []
        for i in range(0x10):
            if 1 << i & v:
                out.append(gpregs.expr[i])

        if self.parent.pclr.value == 1:
            if self.parent.pp.value == 0:
                out += [regs_expr[14]]
            else:
                out += [regs_expr[15]]
        if not out:
            return False
        e = ExprOp('reglist', *out)
        self.expr = e
        return True


class armt_reg_wb(arm_reg_wb):
    reg_info = gpregs_l
    parser = gpregs_l_wb

    def decode(self, v):
        v = v & self.lmask
        e = self.reg_info.expr[v]
        if not e in self.parent.trlist.expr.args:
            e = ExprOp('wback', e)
        self.expr = e
        return True

    def encode(self):
        e = self.expr
        if isinstance(e, ExprOp):
            if e.op != 'wback':
                return False
            e = e.args[0]
        self.value = self.reg_info.expr.index(e)
        return True


class arm_gpreg_l(arm_reg):
    reg_info = gpregs_l
    parser = reg_info.parser


class arm_gpreg_h(arm_reg):
    reg_info = gpregs_h
    parser = reg_info.parser


class arm_gpreg_l_noarg(arm_gpreg_noarg):
    reg_info = gpregs_l
    parser = reg_info.parser


class arm_sppc(arm_reg):
    reg_info = gpregs_sppc
    parser = reg_info.parser


class arm_sp(arm_reg):
    reg_info = gpregs_sp
    parser = reg_info.parser

off5 = bs(l=5, cls=(arm_imm,), fname="off")
off3 = bs(l=3, cls=(arm_imm,), fname="off")
off8 = bs(l=8, cls=(arm_imm,), fname="off")
off7 = bs(l=7, cls=(arm_off7,), fname="off")

rdl = bs(l=3, cls=(arm_gpreg_l,), fname="rd")
rnl = bs(l=3, cls=(arm_gpreg_l,), fname="rn")
rsl = bs(l=3, cls=(arm_gpreg_l,), fname="rs")
rml = bs(l=3, cls=(arm_gpreg_l,), fname="rm")
rol = bs(l=3, cls=(arm_gpreg_l,), fname="ro")
rbl = bs(l=3, cls=(arm_gpreg_l,), fname="rb")
rbl_deref = bs(l=3, cls=(arm_derefl,), fname="rb")
dumrh = bs(l=3, default_val="000")

rdh = bs(l=3, cls=(arm_gpreg_h,), fname="rd")
rsh = bs(l=3, cls=(arm_gpreg_h,), fname="rs")

offpc8 = bs(l=8, cls=(arm_offpc,), fname="offs")
offsp8 = bs(l=8, cls=(arm_offsp,), fname="offs")
rol_noarg = bs(l=3, cls=(arm_gpreg_l_noarg,), fname="off")

off5bw = bs(l=5, cls=(arm_offbw,), fname="off")
off5h = bs(l=5, cls=(arm_offh,), fname="off")
sppc = bs(l=1, cls=(arm_sppc,))

off12 = bs(l=12, cls=(arm_off,), fname="off", order=-1)
rn_deref = bs(l=4, cls=(arm_deref_reg_imm,), fname="rt")



pclr = bs(l=1, fname='pclr', order=-2)


pc_in = bs(l=1, fname='pc_in', order=-2)
lr_in = bs(l=1, fname='lr_in', order=-2)


sp = bs(l=0, cls=(arm_sp,))


off8s = bs(l=8, cls=(arm_offs,), fname="offs")
trlistpclr = bs(l=8, cls=(armt_rlist_pclr,))
trlist = bs(l=8, cls=(armt_rlist,), fname="trlist", order = -1)
trlist13 = bs(l=13, cls=(armt_rlist13,), fname="trlist", order = -1)
trlist13pclr = bs(l=13, cls=(armt_rlist13_pc_lr,), fname="trlist", order = -1)


rbl_wb = bs(l=3, cls=(armt_reg_wb,), fname='rb')

offs8 = bs(l=8, cls=(arm_offspc,), fname="offs")
offs11 = bs(l=11, cls=(arm_offspc,), fname="offs")

hl = bs(l=1, prio=default_prio + 1, fname='hl')
off8sppc = bs(l=8, cls=(arm_off8sppc,), fname="off")

imm8_d1 = bs(l=8, default_val="00000001")
imm8 = bs(l=8, cls=(arm_imm,), default_val = "00000001")


mshift_name = {'LSLS': 0, 'LSRS': 1, 'ASRS': 2}
bs_mshift_name = bs_name(l=2, name=mshift_name)


addsub_name = {'ADDS': 0, 'SUBS': 1}
bs_addsub_name = bs_name(l=1, name=addsub_name)

mov_cmp_add_sub_name = {'MOVS': 0, 'CMP': 1, 'ADDS': 2, 'SUBS': 3}
bs_mov_cmp_add_sub_name = bs_name(l=2, name=mov_cmp_add_sub_name)

alu_name = {'ANDS': 0, 'EORS': 1, 'LSLS': 2, 'LSRS': 3,
            'ASRS': 4, 'ADCS': 5, 'SBCS': 6, 'RORS': 7,
            'TST': 8, 'NEGS': 9, 'CMP': 10, 'CMN': 11,
            'ORRS': 12, 'MULS': 13, 'BICS': 14, 'MVNS': 15}
bs_alu_name = bs_name(l=4, name=alu_name)

hiregop_name = {'ADDS': 0, 'CMP': 1, 'MOV': 2}
bs_hiregop_name = bs_name(l=2, name=hiregop_name)

ldr_str_name = {'STR': 0, 'LDR': 1}
bs_ldr_str_name = bs_name(l=1, name=ldr_str_name)

ldrh_strh_name = {'STRH': 0, 'LDRH': 1}
bs_ldrh_strh_name = bs_name(l=1, name=ldrh_strh_name)

ldstsp_name = {'STR': 0, 'LDR': 1}
bs_ldstsp_name = bs_name(l=1, name=ldstsp_name)

addsubsp_name = {'ADD': 0, 'SUB': 1}
bs_addsubsp_name = bs_name(l=1, name=addsubsp_name)

pushpop_name = {'PUSH': 0, 'POP': 1}
bs_pushpop_name = bs_name(l=1, name=pushpop_name, fname='pp')

tbtransfer_name = {'STMIA': 0, 'LDMIA': 1}
bs_tbtransfer_name = bs_name(l=1, name=tbtransfer_name)

br_name = {'BEQ': 0, 'BNE': 1, 'BCS': 2, 'BCC': 3, 'BMI': 4,
           'BPL': 5, 'BVS': 6, 'BVC': 7, 'BHI': 8, 'BLS': 9,
           'BGE': 10, 'BLT': 11, 'BGT': 12, 'BLE': 13}
bs_br_name = bs_name(l=4, name=br_name)


armtop("mshift", [bs('000'), bs_mshift_name, off5, rsl, rdl], [rdl, rsl, off5])
armtop("addsubr", [bs('000110'),  bs_addsub_name, rnl, rsl, rdl], [rdl, rsl, rnl])
armtop("addsubi", [bs('000111'),  bs_addsub_name, off3, rsl, rdl], [rdl, rsl, off3])
armtop("mcas", [bs('001'), bs_mov_cmp_add_sub_name, rnl, off8])
armtop("alu", [bs('010000'), bs_alu_name, rsl, rdl], [rdl, rsl])
  # should not be used ??
armtop("hiregop00", [bs('010001'), bs_hiregop_name, bs('00'), rsl, rdl], [rdl, rsl])
armtop("hiregop01", [bs('010001'), bs_hiregop_name, bs('01'), rsh, rdl], [rdl, rsh])
armtop("hiregop10", [bs('010001'), bs_hiregop_name, bs('10'), rsl, rdh], [rdh, rsl])
armtop("hiregop11", [bs('010001'), bs_hiregop_name, bs('11'), rsh, rdh], [rdh, rsh])
armtop("bx", [bs('010001'), bs('11'), bs('00'), rsl, dumrh])
armtop("bx", [bs('010001'), bs('11'), bs('01'), rsh, dumrh])
armtop("ldr", [bs('01001'),  rdl, offpc8])
armtop("ldrstr", [bs('0101'), bs_ldr_str_name, trb, bs('0'), rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("strh", [bs('0101'), bs('00'), bs('1'), rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldrh", [bs('0101'), bs('10'), bs('1'), rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldsb", [bs('0101'), bs('01'), bs('1'), rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldsh", [bs('0101'), bs('11'), bs('1'), rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldst", [bs('011'), trb, bs_ldr_str_name, off5bw, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldhsth", [bs('1000'), bs_ldrh_strh_name, off5h, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldstsp", [bs('1001'), bs_ldstsp_name, rdl, offsp8], [rdl, offsp8])
armtop("add", [bs('1010'), sppc, rdl, off8sppc], [rdl, sppc, off8sppc])
armtop("addsp", [bs('10110000'), bs_addsubsp_name, sp, off7], [sp, off7])
armtop("pushpop", [bs('1011'), bs_pushpop_name, bs('10'), pclr, trlistpclr], [trlistpclr])
armtop("btransfersp", [bs('1100'),  bs_tbtransfer_name, rbl_wb, trlist])
armtop("br", [bs('1101'),  bs_br_name, offs8])
armtop("blx", [bs("01000111"),  bs('1'), rm, bs('000')])
armtop("svc", [bs('11011111'),  imm8])
armtop("b", [bs('11100'),  offs11])
armtop("und", [bs('1101'), bs('1110'), imm8_d1])

armtop("rev",    [bs('10111010'), bs('00'), rsl, rdl], [rdl, rsl])
armtop("rev16",  [bs('10111010'), bs('01'), rsl, rdl], [rdl, rsl])

armtop("uxtb", [bs('10110010'), bs('11'), rml, rdl], [rdl, rml])
armtop("uxth", [bs('10110010'), bs('10'), rml, rdl], [rdl, rml])
armtop("sxtb", [bs('10110010'), bs('01'), rml, rdl], [rdl, rml])
armtop("sxth", [bs('10110010'), bs('00'), rml, rdl], [rdl, rml])

armtop("uxtab", [bs('111110100'), bs('101'), rn_nopc, bs('1111'), rd, bs('10'), rot2, rm_rot2], [rd, rn_nopc, rm_rot2])
armtop("uxtah", [bs('111110100'), bs('001'), rn_nopc, bs('1111'), rd, bs('10'), rot2, rm_rot2], [rd, rn_nopc, rm_rot2])

# thumb2 ######################
#
# ARM Architecture Reference Manual Thumb-2 Supplement

armt_gpreg_shift_off = (gpregs_nosppc.parser + allshifts_t_armt + (gpregs.parser | int_1_31)).setParseAction(cb_shift)


armt_gpreg_shift_off |= gpregs_nosppc.parser


class arm_gpreg_nosppc(arm_reg):
    reg_info = gpregs_nosppc
    parser = reg_info.parser

    def decode(self, v):
        ret = super(arm_gpreg_nosppc, self).decode(v)
        if ret is False:
            return False
        if self.expr == reg_dum:
            return False
        return True


class armt_gpreg_rm_shift_off(arm_reg):
    parser = armt_gpreg_shift_off

    def decode(self, v):
        v = v & self.lmask
        if v >= len(gpregs_nosppc.expr):
            return False
        r = gpregs_nosppc.expr[v]
        if r == reg_dum:
            return False

        i = int(self.parent.imm5_3.value) << 2
        i |= int(self.parent.imm5_2.value)

        if self.parent.stype.value < 3 or i != 0:
            shift = allshifts_armt[self.parent.stype.value]
        else:
            shift = allshifts_armt[4]
        self.expr = ExprOp(shift, r, ExprInt(i, 32))
        return True

    def encode(self):
        e = self.expr
        if isinstance(e, ExprId):
            if e not in gpregs_nosppc.expr:
                return False
            self.value = gpregs_nosppc.expr.index(e)
            self.parent.stype.value = 0
            self.parent.imm5_3.value = 0
            self.parent.imm5_2.value = 0
            return True
        if not e.is_op():
            return False
        shift = e.op
        r = gpregs_nosppc.expr.index(e.args[0])
        self.value = r
        i = int(e.args[1])
        if shift == 'rrx':
            if i != 1:
                log.debug('rrx shift must be 1')
                return False
            self.parent.imm5_3.value = 0
            self.parent.imm5_2.value = 0
            self.parent.stype.value = 3
            return True
        self.parent.stype.value = allshifts_armt.index(shift)
        self.parent.imm5_2.value = i & 3
        self.parent.imm5_3.value = i >> 2
        return True

rn_nosppc = bs(l=4, cls=(arm_gpreg_nosppc,), fname="rn")
rd_nosppc = bs(l=4, cls=(arm_gpreg_nosppc,), fname="rd")
rm_sh = bs(l=4, cls=(armt_gpreg_rm_shift_off,), fname="rm")


class armt2_imm12(arm_imm):

    def decode(self, v):
        v = v & self.lmask
        v |= int(self.parent.imm12_3.value) << 8
        v |= int(self.parent.imm12_1.value) << 11

        # simple encoding
        if 0 <= v < 0x100:
            self.expr = ExprInt(v, 32)
            return True
        # 00XY00XY form
        if v >> 8 == 1:
            v &= 0xFF
            self.expr = ExprInt((v << 16) | v, 32)
            return True
        # XY00XY00 form
        if v >> 8 == 2:
            v &= 0xFF
            self.expr = ExprInt((v << 24) | (v << 8), 32)
            return True
        # XYXYXYXY
        if v >> 8 == 3:
            v &= 0xFF
            self.expr = ExprInt((v << 24) | (v << 16) | (v << 8) | v, 32)
            return True
        r = v >> 7
        v = 0x80 | (v & 0x7F)
        self.expr = ExprInt(myror32(v, r), 32)
        return True

    def encode(self):
        if not self.expr.is_int():
            return False
        v = int(self.expr)
        value = None
        # simple encoding
        if 0 <= v < 0x100:
            value = v
        elif v & 0xFF00FF00 == 0 and v & 0xFF == (v >> 16) & 0xff:
            # 00XY00XY form
            value = (1 << 8) | (v & 0xFF)
        elif v & 0x00FF00FF == 0 and (v >> 8) & 0xff == (v >> 24) & 0xff:
            # XY00XY00 form
            value = (2 << 8) | ((v >> 8) & 0xff)
        elif (v & 0xFF ==
             (v >> 8)  & 0xFF ==
             (v >> 16) & 0xFF ==
             (v >> 24) & 0xFF):
            # XYXYXYXY form
            value = (3 << 8) | ((v >> 16) & 0xff)
        else:
            # rol encoding
            for i in range(32):
                o = myrol32(v, i)
                if 0x80 <= o <= 0xFF:
                    value = (i << 7) | (o & 0x7F)
                    break
        if value is None:
            log.debug('cannot encode imm12')
            return False
        self.value = value & self.lmask
        self.parent.imm12_3.value = (value >> 8) & self.parent.imm12_3.lmask
        self.parent.imm12_1.value = (value >> 11) & self.parent.imm12_1.lmask
        return True




class armt4_imm12(arm_imm):

    def decode(self, v):
        v = v & self.lmask
        v |= int(self.parent.imm12_3.value) << 8
        v |= int(self.parent.imm12_1.value) << 11
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not self.expr.is_int():
            return False
        value = int(self.expr)
        if value >= (1 << 16):
            return False
        self.value = value & self.lmask
        self.parent.imm12_3.value = (value >> 8) & self.parent.imm12_3.lmask
        self.parent.imm12_1.value = (value >> 11) & self.parent.imm12_1.lmask
        return True



class armt2_imm16(arm_imm):

    def decode(self, v):
        v = v & self.lmask
        v |= int(self.parent.imm16_3.value) << 8
        v |= int(self.parent.imm16_1.value) << 11
        v |= int(self.parent.imm16_4.value) << 12
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not self.expr.is_int():
            return False
        value = int(self.expr)
        if value >= (1 << 16):
            return False
        self.value = value & self.lmask
        self.parent.imm16_3.value = (value >> 8) & self.parent.imm16_3.lmask
        self.parent.imm16_1.value = (value >> 11) & self.parent.imm16_1.lmask
        self.parent.imm16_4.value = (value >> 12) & self.parent.imm16_4.lmask
        return True


class armt2_lsb5(arm_imm):

    def decode(self, v):
        v = v & self.lmask
        v |= int(self.parent.lsb5_3.value) << 2
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not self.expr.is_int():
            return False
        value = int(self.expr)
        self.value = value & self.lmask
        self.parent.lsb5_3.value = (value >> 2) & self.parent.lsb5_3.lmask
        return True


class armt_widthm1(arm_imm):
    parser = base_expr

    def decodeval(self, v):
        return v + 1

    def encodeval(self, v):
        if v <= 0:
            return False
        return v - 1




class armt2_off20(arm_imm):

    def decode(self, v):
        v = v & self.lmask
        v <<= 1
        v |= int(self.parent.off20_6.value) << 12
        v |= int(self.parent.off20_j1.value) << 18
        v |= int(self.parent.off20_j2.value) << 19
        v |= int(self.parent.off20_s.value) << 20
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not self.expr.is_int():
            return False
        value = int(self.expr)
        if value & 1:
            return False
        self.value = (value >> 1) & self.lmask
        self.parent.off20_6.value = (value >> 12) & self.parent.off20_6.lmask
        self.parent.off20_j1.value = (value >> 18) & self.parent.off20_j1.lmask
        self.parent.off20_j2.value = (value >> 19) & self.parent.off20_j2.lmask
        self.parent.off20_s.value = (value >> 20) & self.parent.off20_s.lmask
        return True



class armt2_imm10l(arm_imm):

    def decode(self, v):
        v = v & self.lmask
        s = self.parent.sign.value
        j1 = self.parent.j1.value
        j2 = self.parent.j2.value
        imm10h = self.parent.imm10h.value
        imm10l = v

        i1, i2 = j1 ^ s ^ 1, j2 ^ s ^ 1

        v = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10h << 12) | (imm10l << 2)
        v = sign_ext(v, 25, 32)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        s = 0
        if v & 0x80000000:
            s = 1
            v &= (1<<26) - 1
        if v >= (1 << 26):
            return False
        i1, i2, imm10h, imm10l = (v >> 23) & 1, (v >> 22) & 1, (v >> 12) & 0x3ff, (v >> 2) & 0x3ff
        j1, j2 = i1 ^ s ^ 1, i2 ^ s ^ 1
        self.parent.sign.value = s
        self.parent.j1.value = j1
        self.parent.j2.value = j2
        self.parent.imm10h.value = imm10h
        self.value = imm10l
        return True


class armt2_imm11l(arm_imm):

    def decode(self, v):
        v = v & self.lmask
        s = self.parent.sign.value
        j1 = self.parent.j1.value
        j2 = self.parent.j2.value
        imm10h = self.parent.imm10h.value
        imm11l = v

        i1, i2 = j1 ^ s ^ 1, j2 ^ s ^ 1

        v = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10h << 12) | (imm11l << 1)
        v = sign_ext(v, 25, 32)
        self.expr = ExprInt(v + 4, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = (int(self.expr) - 4) & int(self.expr.mask)
        s = 0
        if v & 0x80000000:
            s = 1
            v &= (1<<26) - 1
        if v >= (1 << 26):
            return False
        if v & 1:
            return False
        i1, i2, imm10h, imm11l = (v >> 23) & 1, (v >> 22) & 1, (v >> 12) & 0x3ff, (v >> 1) & 0x7ff
        j1, j2 = i1 ^ s ^ 1, i2 ^ s ^ 1
        self.parent.sign.value = s
        self.parent.j1.value = j1
        self.parent.j2.value = j2
        self.parent.imm10h.value = imm10h
        self.value = imm11l
        return True



class armt2_imm6_11l(arm_imm):

    def decode(self, v):
        v = v & self.lmask
        s = self.parent.sign.value
        j1 = self.parent.j1.value
        j2 = self.parent.j2.value
        imm6h = self.parent.imm6h.value
        imm11l = v

        v = (s << 20) | (j2 << 19) | (j1 << 18) | (imm6h << 12) | (imm11l << 1)
        v = sign_ext(v, 21, 32)
        self.expr = ExprInt(v + 4, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = (int(self.expr) - 4) & int(self.expr.mask)
        s = 0
        if v != sign_ext(v & ((1 << 22) - 1), 21, 32):
            return False
        if v & 0x80000000:
            s = 1
        v &= (1<<22) - 1
        if v & 1:
            return False
        i2, i1, imm6h, imm11l = (v >> 19) & 1, (v >> 18) & 1, (v >> 12) & 0x3f, (v >> 1) & 0x7ff
        self.parent.sign.value = s
        self.parent.j1.value = i1
        self.parent.j2.value = i2
        self.parent.imm6h.value = imm6h
        self.value = imm11l
        return True



imm12_1 = bs(l=1, fname="imm12_1", order=1)
imm12_3 = bs(l=3, fname="imm12_3", order=1)
imm12_8 = bs(l=8, cls=(armt2_imm12,), fname="imm", order=2)


imm12_8_t4 = bs(l=8, cls=(armt4_imm12,), fname="imm", order=2)


imm16_1 = bs(l=1, fname="imm16_1", order=1)
imm16_3 = bs(l=3, fname="imm16_3", order=1)
imm16_4 = bs(l=4, fname="imm16_4", order=1)
imm16_8 = bs(l=8, cls=(armt2_imm16,), fname="imm", order=2)


imm5_3 = bs(l=3, fname="imm5_3")
imm5_2 = bs(l=2, fname="imm5_2")
imm_stype = bs(l=2, fname="stype")

imm_stype_00 = bs('00', fname="stype")
imm_stype_01 = bs('01', fname="stype")
imm_stype_11 = bs('11', fname="stype")


imm1 = bs(l=1, fname="imm1")



off20_6 = bs(l=6, fname="off20_6", order=1)
off20_11 = bs(l=11, cls=(armt2_off20,), fname="imm", order=2)



lsb5_3 = bs(l=3, fname="lsb5_3", order=1)
lsb5_2 = bs(l=2, cls=(armt2_lsb5,), fname="imm", order=2)

widthm1 = bs(l=5, cls=(armt_widthm1,), fname="imm", order=2)



class armt_imm5_1(arm_imm):

    def decode(self, v):
        v = ((self.parent.imm1.value << 5) | v) << 1
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v & 0x1:
            return False
        self.parent.imm1.value = (v >> 6) & 1
        self.value = (v >> 1) & 0x1f
        return True

aif_str = ["X", "F", "I", "IF", "A", "AF", "AI", "AIF"]
aif_expr = [ExprId(x, 32) if x != None else None for x in aif_str]

aif_reg = reg_info(aif_str, aif_expr)

class armt_aif(reg_noarg, arm_arg):
    reg_info = aif_reg
    parser = reg_info.parser

    def decode(self, v):
        if v == 0:
            return False
        return super(armt_aif, self).decode(v)

    def encode(self):
        ret = super(armt_aif, self).encode()
        if not ret:
            return ret
        return self.value != 0

    def fromstring(self, text, loc_db, parser_result=None):
        start, stop = super(armt_aif, self).fromstring(text, loc_db, parser_result)
        if self.expr.name == "X":
            return None, None
        return start, stop


class armt_it_arg(arm_arg):
    arg_E = ExprId('E', 1)
    arg_NE = ExprId('NE', 1)

    def decode(self, v):
        if v:
            return self.arg_E
        else:
            return self.arg_NE

    def encode(self):
        if self.expr == self.arg_E:
            return 1
        elif self.expr == self.arg_NE:
            return 0

class armt_itmask(bs_divert):
    prio = 2

    def divert(self, i, candidates):
        out = []
        for cls, _, bases, dct, fields in candidates:
            for value in range(1, 0x10):
                nfields = fields[:]
                s = int2bin(value, self.args['l'])
                args = dict(self.args)
                args.update({'strbits': s})
                f = bs(**args)
                nfields[i] = f
                inv = nfields[-2].value
                ndct = dict(dct)
                ndct['name'] = self.modname(ndct['name'], value, inv)
                out.append((cls, ndct['name'], bases, ndct, nfields))
        return out

    def modname(self, name, value, inv):
        count = 0
        while value & (1 << count) == 0:
            count += 1
        out = []
        values = ['E', 'T']
        if inv== 1:
            values.reverse()
        for index in range(3 - count):
            if value & (1 << (3 - index)):
                out.append(values[0])
            else:
                out.append(values[1])
        return name + "".join(out)



class armt_cond_lsb(bs_divert):
    prio = 2

    def divert(self, i, candidates):
        out = []
        for cls, _, bases, dct, fields in candidates:
            for value in range(2):
                nfields = fields[:]
                s = int2bin(value, self.args['l'])
                args = dict(self.args)
                args.update({'strbits': s})
                f = bs(**args)
                nfields[i] = f
                ndct = dict(dct)
                out.append((cls, ndct['name'], bases, ndct, nfields))
        return out


cond_expr = [ExprId(x, 32) for x in cond_list_full]
cond_info = reg_info(cond_list_full, cond_expr)

class armt_cond_arg(arm_arg):
    parser = cond_info.parser

    def decode(self, v):
        v = (v << 1) | self.parent.condlsb.value
        self.expr = ExprId(cond_list_full[v], 32)
        return True

    def encode(self):
        index = cond_list_full.index(self.expr.name)
        self.value = index >> 1
        if index & 1 != self.parent.condlsb.value:
            return False
        return True


class armt_op2imm(arm_imm8_12):
    parser = deref

    def str_to_imm_rot_form(self, s, neg=False):
        if neg:
            s = -s & 0xffffffff
        if 0 <= s < (1 << 12):
            return s
        return None

    def decodeval(self, v):
        return v

    def encodeval(self, v):
        return v

    def decode(self, v):
        val = v & self.lmask
        val = self.decodeval(val)
        if val is False:
            return False
        imm = val
        if self.parent.updown.value == 0:
            imm = -imm
        if self.parent.ppi.value == 0 and self.parent.wback.value == 0:
            return False
        if self.parent.ppi.value:
            e = ExprOp('preinc', self.parent.rn.expr, ExprInt(imm, 32))
            if self.parent.wback.value == 1:
                e = ExprOp('wback', e)
        else:
            e = ExprOp('postinc', self.parent.rn.expr, ExprInt(imm, 32))
        self.expr = ExprMem(e, 32)
        return True

    def encode(self):
        self.parent.updown.value = 1
        self.parent.wback.value = 0

        e = self.expr
        assert(isinstance(e, ExprMem))
        e = e.ptr
        if e.op == 'wback':
            self.parent.wback.value = 1
            e = e.args[0]
        if e.op == "postinc":
            self.parent.ppi.value = 0
            self.parent.wback.value = 1
        elif e.op == "preinc":
            self.parent.ppi.value = 1
        else:
            # XXX default
            self.parent.ppi.value = 1

        self.parent.rn.expr = e.args[0]

        if len(e.args) == 1:
            self.value = 0
            return True
        # pure imm
        if isinstance(e.args[1], ExprInt):
            val = self.str_to_imm_rot_form(int(e.args[1]))
            if val is None:
                val = self.str_to_imm_rot_form(int(e.args[1]), True)
                if val is None:
                    log.debug('cannot encode inm')
                    return False
                self.parent.updown.value = 0
            val = self.encodeval(val)
            if val is False:
                return False
            self.value = val
            return True
        # pure reg
        if isinstance(e.args[1], ExprId):
            rm = gpregs.expr.index(e.args[1])
            shift_kind = 0
            shift_type = 0
            amount = 0
            val = (((((amount << 2) | shift_type) << 1) | shift_kind) << 4) | rm
            val = self.encodeval(val)
            if val is False:
                return False
            self.value = val
            return True
        return False


class armt_op2imm00(armt_op2imm):

    def decodeval(self, v):
        return v << 2

    def encodeval(self, v):
        if v & 3:
            return False
        return v >> 2


class armt_deref_reg(arm_imm8_12):
    parser = deref

    def decode(self, v):
        base = self.parent.rn.expr
        off = gpregs.expr[v]
        if self.parent.imm.value != 0:
            off = off << ExprInt(self.parent.imm.value, 32)
        e = ExprMem(ExprOp('preinc', base, off), 8)
        self.expr = e
        return True

    def encode(self):
        if not isinstance(self.expr, ExprMem):
            return False
        ptr = self.expr.ptr
        if not ptr.is_op('preinc'):
            return False
        if len(ptr.args) != 2:
            return False
        base, off = ptr.args
        if base.is_id() and off.is_id():
            self.parent.rn.expr = base
            self.parent.imm.value = 0
            self.value = gpregs.expr.index(off)
        elif off.is_int():
            return False
        elif off.is_op('<<'):
            if len(off.args) != 2:
                return False
            reg, off = off.args
            self.parent.rn.expr = base
            self.parent.imm.value = 0
            self.value = gpregs.expr.index(reg)
            off = int(off)
            if off > self.parent.imm.lmask:
                return False
            self.parent.imm.value = off
        return True


class armt_deref_reg_reg(arm_arg):
    parser = deref_reg_reg
    reg_info = gpregs

    def decode(self, v):
        expr = self.reg_info.expr[v]
        expr = ExprMem(self.parent.rn.expr + expr, 8)
        self.expr = expr
        return True

    def encode(self):
        expr = self.expr
        if not expr.is_mem():
            return False
        ptr = expr.ptr
        if not ptr.is_op('+') or len(ptr.args) != 2:
            return False
        reg1, reg2 = ptr.args
        self.parent.rn.expr = reg1
        self.value = self.reg_info.expr.index(reg2)
        return True


class armt_deref_reg_reg_lsl_1(arm_reg):
    parser = deref_reg_reg_lsl_1
    reg_info = gpregs

    def decode(self, v):
        expr = self.reg_info.expr[v]
        expr = ExprMem(self.parent.rn.expr + (expr << ExprInt(1, 32)), 16)
        self.expr = expr
        return True

    def encode(self):
        expr = self.expr
        if not expr.is_mem():
            return False
        ptr = expr.ptr
        if not ptr.is_op('+') or len(ptr.args) != 2:
            return False
        reg1, reg_shift = ptr.args
        self.parent.rn.expr = reg1
        if not reg_shift.is_op('<<') or len(reg_shift.args) != 2:
            return False
        if reg_shift.args[1] != ExprInt(1, 32):
            return False
        self.value = self.reg_info.expr.index(reg_shift.args[0])
        return True


aif = bs(l=3, cls=(armt_aif,))


imm5_off = bs(l=5, cls=(armt_imm5_1,), fname="imm5_off")

tsign = bs(l=1, fname="sign")
tj1 = bs(l=1, fname="j1")
tj2 = bs(l=1, fname="j2")

timm6h = bs(l=6, fname="imm6h")
timm10H = bs(l=10, fname="imm10h")
timm10L = bs(l=10, cls=(armt2_imm10l,), fname="imm10l")
timm11L = bs(l=11, cls=(armt2_imm11l,), fname="imm11l")

timm6h11l = bs(l=11, cls=(armt2_imm6_11l,), fname="imm6h11l")

itcond = bs(l=4, fname="itcond")
itmask = armt_itmask(l=4, fname="itmask")
bs_cond_arg_msb = bs(l=3, cls=(armt_cond_arg,))


condlsb = armt_cond_lsb(l=1, fname="condlsb")

deref_immpuw = bs(l=8, cls=(armt_op2imm,))
deref_immpuw00 = bs(l=8, cls=(armt_op2imm00,))


rm_deref_reg = bs(l=4, cls=(armt_deref_reg,))

bs_deref_reg_reg = bs(l=4, cls=(armt_deref_reg_reg,))
bs_deref_reg_reg_lsl_1 = bs(l=4, cls=(armt_deref_reg_reg_lsl_1,))


armtop("adc", [bs('11110'),  imm12_1, bs('0'), bs('1010'), scc, rn_nosppc, bs('0'), imm12_3, rd_nosppc, imm12_8])
armtop("adc", [bs('11101'),  bs('01'), bs('1010'), scc, rn_nosppc, bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype, rm_sh])
armtop("bl", [bs('11110'), tsign, timm10H, bs('11'), tj1, bs('1'), tj2, timm11L])
armtop("blx", [bs('11110'), tsign, timm10H, bs('11'), tj1, bs('0'), tj2, timm10L, bs('0')])
armtop("cbz", [bs('101100'), imm1, bs('1'), imm5_off, rnl], [rnl, imm5_off])
armtop("cbnz", [bs('101110'), imm1, bs('1'), imm5_off, rnl], [rnl, imm5_off])

armtop("bkpt", [bs('1011'), bs('1110'), imm8])


armtop("it", [bs('10111111'), bs_cond_arg_msb, condlsb, itmask])


armtop("nop", [bs8(0xBF),bs8(0x0)])
armtop("wfi", [bs8(0xBF),bs8(0x30)])
armtop("cpsid", [bs8(0xB6),bs('0111'), bs('0'), aif], [aif])
armtop("cpsie", [bs8(0xB6),bs('0110'), bs('0'), aif], [aif])

armtop("push", [bs('1110100'), bs('10'), bs('0'), bs('1'), bs('0'), bs('1101'), bs('0'), pclr, bs('0'), trlist13], [trlist13])
armtop("pop",  [bs('1110100'), bs('01'), bs('0'), bs('1'), bs('1'), bs('1101'), pc_in, lr_in, bs('0'), trlist13pclr], [trlist13pclr])
armtop("mov", [bs('11110'), imm12_1, bs('00010'), scc, bs('1111'), bs('0'), imm12_3, rd_nosppc, imm12_8])
armtop("asr", [bs('11111010'), bs('0100'), rm, bs('1111'), rd, bs('0000'), rs], [rd, rm, rs])
armtop("lsl", [bs('11111010'), bs('0000'), rm, bs('1111'), rd, bs('0000'), rs], [rd, rm, rs])
armtop("sel", [bs('11111010'), bs('1010'), rm, bs('1111'), rd, bs('1000'), rs], [rd, rm, rs])
armtop("rev", [bs('11111010'), bs('1001'), rm, bs('1111'), rd, bs('1000'), rm_cp], [rd, rm])
armtop("uadd8", [bs('111110101000'), rn, bs('1111'), rd, bs('0100'), rm], [rd, rn, rm])
armtop("mvn", [bs('11101010011'), scc, bs('11110'), imm5_3, rd_nosppc, imm5_2, imm_stype, rm_sh] )
armtop("and", [bs('11101010000'), scc, rn_nosppc, bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype, rm_sh], [rd_nosppc, rn_nosppc, rm_sh] )
armtop("orr", [bs('11101010010'), scc, rn_nosppc, bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype, rm_sh], [rd_nosppc, rn_nosppc, rm_sh] )
armtop("bic", [bs('11101010001'), scc, rn_nosppc, bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype, rm_sh], [rd_nosppc, rn_nosppc, rm_sh] )
armtop("add", [bs('11101011000'), scc, rn_nosppc, bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype, rm_sh], [rd_nosppc, rn_nosppc, rm_sh] )
armtop("sub", [bs('11101011101'), scc, rn_nosppc, bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype, rm_sh], [rd_nosppc, rn_nosppc, rm_sh] )
armtop("eor", [bs('11101010100'), scc, rn_nosppc, bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype, rm_sh], [rd_nosppc, rn_nosppc, rm_sh] )
armtop("rsb", [bs('11101011110'), scc, rn, bs('0'), imm5_3, rd, imm5_2, imm_stype, rm_sh], [rd, rn, rm_sh] )
armtop("orn", [bs('11101010011'), scc, rn_nopc, bs('0'), imm5_3, rd, imm5_2, imm_stype, rm_sh], [rd, rn_nopc, rm_sh] )
# lsl
armtop("mov", [bs('11101010010'), scc, bs('1111'), bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype_00, rm_sh], [rd_nosppc, rm_sh] )
armtop("mov", [bs('11101010010'), scc, bs('1111'), bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype_01, rm_sh], [rd_nosppc, rm_sh] )
armtop("mov", [bs('11101010010'), scc, bs('1111'), bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype_11, rm_sh], [rd_nosppc, rm_sh] )


armtop("orr", [bs('11110'), imm12_1, bs('00010'), scc, rn_nosppc, bs('0'), imm12_3, rd, imm12_8] )
armtop("add", [bs('11110'), imm12_1, bs('01000'), bs('0'), rn, bs('0'), imm12_3, rd_nopc, imm12_8], [rd_nopc, rn, imm12_8])
armtop("adds",[bs('11110'), imm12_1, bs('01000'), bs('1'), rn, bs('0'), imm12_3, rd_nopc, imm12_8], [rd_nopc, rn, imm12_8])
armtop("bic", [bs('11110'), imm12_1, bs('00001'), scc, rn_nosppc, bs('0'), imm12_3, rd, imm12_8], [rd, rn_nosppc, imm12_8])
armtop("and", [bs('11110'), imm12_1, bs('00000'), scc, rn, bs('0'), imm12_3, rd_nopc, imm12_8], [rd_nopc, rn, imm12_8])
armtop("sub", [bs('11110'), imm12_1, bs('01101'), scc, rn, bs('0'), imm12_3, rd_nopc, imm12_8], [rd_nopc, rn, imm12_8])
armtop("eor", [bs('11110'), imm12_1, bs('00100'), scc, rn, bs('0'), imm12_3, rd_nopc, imm12_8], [rd_nopc, rn, imm12_8])
armtop("add", [bs('11110'), imm12_1, bs('10000'), scc, rn_nosppc, bs('0'), imm12_3, rd, imm12_8_t4], [rd, rn_nosppc, imm12_8_t4])
armtop("cmp", [bs('11110'), imm12_1, bs('01101'), bs('1'), rn, bs('0'), imm12_3, bs('1111'), imm12_8] )

armtop("cmp", [bs('11101011101'), bs('1'), rn, bs('0'), imm5_3, bs('1111'), imm5_2, imm_stype, rm_sh], [rn, rm_sh] )

armtop("cmn", [bs('11110'), imm12_1, bs('01000'), bs('1'), rn, bs('0'), imm12_3, bs('1111'), imm12_8], [rn, imm12_8])


armtop("mvn", [bs('11110'), imm12_1, bs('00011'), scc, bs('1111'), bs('0'), imm12_3, rd, imm12_8])
armtop("rsb", [bs('11110'), imm12_1, bs('01110'), scc, rn_nosppc, bs('0'), imm12_3, rd, imm12_8], [rd, rn_nosppc, imm12_8])
armtop("sub", [bs('11110'), imm12_1, bs('101010'), rn_nosppc, bs('0'), imm12_3, rd, imm12_8_t4], [rd, rn_nosppc, imm12_8_t4])
armtop("tst", [bs('11110'), imm12_1, bs('000001'), rn, bs('0'), imm12_3, bs('1111'), imm12_8], [rn, imm12_8])

armtop("mov",  [bs('11110'), imm16_1, bs('100100'), imm16_4, bs('0'), imm16_3, rd, imm16_8] )
armtop("movt", [bs('11110'), imm16_1, bs('101100'), imm16_4, bs('0'), imm16_3, rd, imm16_8] )

armtop("sdiv", [bs('111110111001'), rn, bs('1111'), rd, bs('1111'), rm], [rd, rn, rm] )
armtop("udiv", [bs('111110111011'), rn, bs('1111'), rd, bs('1111'), rm], [rd, rn, rm] )
armtop("mls",  [bs('111110110000'), rn, ra, rd, bs('0001'), rm], [rd, rn, rm, ra] )
armtop("mla",  [bs('111110110000'), rn, ra_nopc, rd, bs('0000'), rm], [rd, rn, rm, ra_nopc] )
armtop("mul",  [bs('111110110000'), rn, bs('1111'), rd, bs('0000'), rm], [rd, rn, rm] )

armtop("smlabb", [bs('111110110001'), rn, ra_nopc, rd, bs('00'), bs('00'), rm], [rd, rn, rm, ra_nopc])
armtop("smlabt", [bs('111110110001'), rn, ra_nopc, rd, bs('00'), bs('01'), rm], [rd, rn, rm, ra_nopc])
armtop("smlatb", [bs('111110110001'), rn, ra_nopc, rd, bs('00'), bs('10'), rm], [rd, rn, rm, ra_nopc])
armtop("smlatt", [bs('111110110001'), rn, ra_nopc, rd, bs('00'), bs('11'), rm], [rd, rn, rm, ra_nopc])

armtop("b", [bs('11110'), tsign, bm_cond_barmt, timm6h, bs('10'), tj1, bs('0'), tj2, timm6h11l], [timm6h11l])
armtop("b", [bs('11110'), tsign, timm10H, bs('10'), tj1, bs('1'), tj2, timm11L], [timm11L])

armtop("ubfx", [bs('111100111100'), rn, bs('0'), lsb5_3, rd, lsb5_2, bs('0'), widthm1], [rd, rn, lsb5_2, widthm1])
armtop("uxth", [bs('111110100001'), bs('1111'), bs('1111'), rd, bs('10'), rot2, rm_rot2], [rd, rm_rot2])



armtop("str",  [bs('111110001100'), rn_deref, rt, off12], [rt, rn_deref])
armtop("str",  [bs('111110000100'), rn_noarg, rt, bs('000000'), imm2_noarg, rm_deref_reg], [rt, rm_deref_reg])
armtop("str",  [bs('111110000100'), rn_noarg, rt, bs('1'), ppi, updown, wback_no_t, deref_immpuw], [rt, deref_immpuw])
armtop("strb", [bs('111110001000'), rn_deref, rt, off12], [rt, rn_deref])
armtop("strb", [bs('111110000000'), rn_noarg, rt, bs('1'), ppi, updown, wback_no_t, deref_immpuw], [rt, deref_immpuw])
armtop("strh", [bs('111110001010'), rn_deref, rt, off12], [rt, rn_deref])
armtop("strh", [bs('111110000010'), rn_noarg, rt, bs('1'), ppi, updown, wback_no_t, deref_immpuw], [rt, deref_immpuw])

armtop("strd", [bs('1110100'), ppi, updown, bs('1'), wback_no_t, bs('0'), rn_nopc_noarg, rt, rt2, deref_immpuw00], [rt, rt2, deref_immpuw00])
armtop("ldrd", [bs('1110100'), ppi, updown, bs('1'), wback_no_t, bs('1'), rn_nopc_noarg, rt, rt2, deref_immpuw00], [rt, rt2, deref_immpuw00])


armtop("ldr",  [bs('111110001101'), rn_deref, rt, off12], [rt, rn_deref])
armtop("ldr",  [bs('111110000101'), rn_noarg, rt, bs('1'), ppi, updown, wback_no_t, deref_immpuw], [rt, deref_immpuw])
armtop("ldr",  [bs('111110000101'), rn_noarg, rt, bs('000000'), imm2_noarg, rm_deref_reg], [rt, rm_deref_reg])
armtop("ldrb", [bs('111110000001'), rn_noarg, rt, bs('000000'), imm2_noarg, rm_deref_reg], [rt, rm_deref_reg])
armtop("ldrb", [bs('111110000001'), rn_noarg, rt, bs('1'), ppi, updown, wback_no_t, deref_immpuw], [rt, deref_immpuw])
armtop("ldrb", [bs('111110001001'), rn_deref, rt_nopc, off12], [rt_nopc, rn_deref])
armtop("ldrsb",[bs('111110011001'), rn_deref, rt, off12], [rt, rn_deref])
armtop("ldrsh",[bs('111110011011'), rn_deref, rt, off12], [rt, rn_deref])
armtop("ldrh", [bs('111110001011'), rn_deref, rt, off12], [rt, rn_deref])
armtop("ldrh", [bs('111110000011'), rn_noarg, rt, bs('1'), ppi, updown, wback_no_t, deref_immpuw], [rt, deref_immpuw])

armtop("pld",  [bs('111110001001'), rn_deref, bs('1111'), off12], [rn_deref])
armtop("pldw", [bs('111110001011'), rn_deref, bs('1111'), off12], [rn_deref])

armtop("clz",  [bs('111110101011'), rm, bs('1111'), rd, bs('1000'), rm_cp], [rd, rm])
armtop("tbb",  [bs('111010001101'), rn_noarg, bs('11110000000'), bs('0'), bs_deref_reg_reg], [bs_deref_reg_reg])
armtop("tbh",  [bs('111010001101'), rn_noarg, bs('11110000000'), bs('1'), bs_deref_reg_reg_lsl_1], [bs_deref_reg_reg_lsl_1])
armtop("dsb",  [bs('111100111011'), bs('1111'), bs('1000'), bs('1111'), bs('0100'), barrier_option])

armtop("adr", [bs('11110'), imm12_1, bs('100000'), bs('1111'), bs('0'), imm12_3, rd, imm12_8_t4], [rd, imm12_8_t4])
