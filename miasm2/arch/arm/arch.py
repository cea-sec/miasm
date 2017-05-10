#-*- coding:utf-8 -*-

import logging
from pyparsing import *
from miasm2.expression.expression import *
from miasm2.core.cpu import *
from collections import defaultdict
from miasm2.core.bin_stream import bin_stream
import miasm2.arch.arm.regs as regs_module
from miasm2.arch.arm.regs import *

# A1 encoding

log = logging.getLogger("armdis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

# arm regs ##############
reg_dum = ExprId('DumReg')

gen_reg('PC', globals())

# GP
regs_str = ['R%d' % r for r in xrange(0x10)]
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


# psr
sr_flags = "cxsf"
cpsr_regs_str = []
spsr_regs_str = []
for i in xrange(0x10):
    o = ""
    for j in xrange(4):
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
cpregs_str = ['c%d' % r for r in xrange(0x10)]
cpregs_expr = [ExprId(x) for x in cpregs_str]

cp_regs = reg_info(cpregs_str, cpregs_expr)

# P
pregs_str = ['p%d' % r for r in xrange(0x10)]
pregs_expr = [ExprId(x) for x in pregs_str]

p_regs = reg_info(pregs_str, pregs_expr)

conditional_branch = ["BEQ", "BNE", "BCS", "BCC", "BMI", "BPL", "BVS",
                      "BVC", "BHI", "BLS", "BGE", "BLT", "BGT", "BLE"]

unconditional_branch = ["B", "BX", "BL", "BLX"]

# parser helper ###########

def tok_reg_duo(s, l, t):
    t = t[0]
    i1 = gpregs.expr.index(t[0])
    i2 = gpregs.expr.index(t[1])
    o = []
    for i in xrange(i1, i2 + 1):
        o.append(gpregs.expr[i])
    return o

LPARENTHESIS = Literal("(")
RPARENTHESIS = Literal(")")

LACC = Suppress(Literal("{"))
RACC = Suppress(Literal("}"))
MINUS = Suppress(Literal("-"))
CIRCUNFLEX = Literal("^")


def check_bounds(left_bound, right_bound, value):
    if left_bound <= value and value <= right_bound:
        return ExprInt(value, 32)
    else:
        raise ValueError('shift operator immediate value out of bound')


def check_values(values, value):
    if value in values:
        return ExprInt(value, 32)
    else:
        raise ValueError('shift operator immediate value out of bound')

int_1_31 = str_int.copy().setParseAction(lambda v: check_bounds(1, 31, v[0]))
int_1_32 = str_int.copy().setParseAction(lambda v: check_bounds(1, 32, v[0]))

int_8_16_24 = str_int.copy().setParseAction(lambda v: check_values([8, 16, 24], v[0]))


def reglistparse(s, l, t):
    t = t[0]
    if t[-1] == "^":
        return ExprOp('sbit', ExprOp('reglist', *t[:-1]))
    return ExprOp('reglist', *t)


allshifts = ['<<', '>>', 'a>>', '>>>', 'rrx']
allshifts_armt = ['<<', '>>', 'a>>', '>>>', 'rrx']

shift2expr_dct = {'LSL': '<<', 'LSR': '>>', 'ASR': 'a>>',
                  'ROR': ">>>", 'RRX': "rrx"}

expr2shift_dct = dict([(x[1], x[0]) for x in shift2expr_dct.items()])


def op_shift2expr(s, l, t):
    return shift2expr_dct[t[0]]

reg_duo = Group(gpregs.parser + MINUS +
                gpregs.parser).setParseAction(tok_reg_duo)
reg_or_duo = reg_duo | gpregs.parser
gpreg_list = Group(LACC + delimitedList(
    reg_or_duo, delim=',') + RACC + Optional(CIRCUNFLEX))
gpreg_list.setParseAction(reglistparse)

LBRACK = Suppress("[")
RBRACK = Suppress("]")
COMMA = Suppress(",")
all_binaryop_1_31_shifts_t = literal_list(
    ['LSL', 'ROR']).setParseAction(op_shift2expr)
all_binaryop_1_32_shifts_t = literal_list(
    ['LSR', 'ASR']).setParseAction(op_shift2expr)
all_unaryop_shifts_t = literal_list(['RRX']).setParseAction(op_shift2expr)

ror_shifts_t = literal_list(['ROR']).setParseAction(op_shift2expr)


allshifts_t_armt = literal_list(
    ['LSL', 'LSR', 'ASR', 'ROR', 'RRX']).setParseAction(op_shift2expr)

gpreg_p = gpregs.parser

psr_p = cpsr_regs.parser | spsr_regs.parser


def shift2expr(t):
    if len(t) == 1:
        return t[0]
    elif len(t) == 2:
        return ExprOp(t[1], t[0])
    elif len(t) == 3:
        return ExprOp(t[1], t[0], t[2])

variable, operand, base_expr = gen_base_expr()

int_or_expr = base_expr


def ast_id2expr(t):
    return mn_arm.regs.all_regs_ids_byname.get(t, t)


def ast_int2expr(a):
    return ExprInt(a, 32)


my_var_parser = ParseAst(ast_id2expr, ast_int2expr)
base_expr.setParseAction(my_var_parser)


shift_off = (gpregs.parser + Optional(
    (all_unaryop_shifts_t) |
    (all_binaryop_1_31_shifts_t + (gpregs.parser | int_1_31)) |
    (all_binaryop_1_32_shifts_t + (gpregs.parser | int_1_32))
)).setParseAction(shift2expr)
shift_off |= base_expr


rot2_expr = (gpregs.parser + Optional(
    (ror_shifts_t + (int_8_16_24))
)).setParseAction(shift2expr)



def deref2expr_nooff(s, l, t):
    t = t[0]
    # XXX default
    return ExprOp("preinc", t[0], ExprInt(0, 32))


def deref2expr_pre(s, l, t):
    t = t[0]
    if len(t) == 1:
        return ExprOp("preinc", t[0], ExprInt(0, 32))
    elif len(t) == 2:
        return ExprOp("preinc", t[0], t[1])
    else:
        raise NotImplementedError('len(t) > 2')


def deref2expr_pre_mem(s, l, t):
    t = t[0]
    if len(t) == 1:
        return ExprMem(ExprOp("preinc", t[0], ExprInt(0, 32)))
    elif len(t) == 2:
        return ExprMem(ExprOp("preinc", t[0], t[1]))
    else:
        raise NotImplementedError('len(t) > 2')


def deref2expr_post(s, l, t):
    t = t[0]
    return ExprOp("postinc", t[0], t[1])


def deref_wb(s, l, t):
    t = t[0]
    if t[-1] == '!':
        return ExprMem(ExprOp('wback', *t[:-1]))
    return ExprMem(t[0])

# shift_off.setParseAction(deref_off)
deref_nooff = Group(
    LBRACK + gpregs.parser + RBRACK).setParseAction(deref2expr_nooff)
deref_pre = Group(LBRACK + gpregs.parser + Optional(
    COMMA + shift_off) + RBRACK).setParseAction(deref2expr_pre)
deref_post = Group(LBRACK + gpregs.parser + RBRACK +
                   COMMA + shift_off).setParseAction(deref2expr_post)
deref = Group((deref_post | deref_pre | deref_nooff)
              + Optional('!')).setParseAction(deref_wb)


def parsegpreg_wb(s, l, t):
    t = t[0]
    if t[-1] == '!':
        return ExprOp('wback', *t[:-1])
    return t[0]

gpregs_wb = Group(gpregs.parser + Optional('!')).setParseAction(parsegpreg_wb)


#


cond_list = ['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC',
             'HI', 'LS', 'GE', 'LT', 'GT', 'LE', '']  # , 'NV']
cond_dct = dict([(x[1], x[0]) for x in enumerate(cond_list)])
# default_prio = 0x1337

bm_cond = bs_mod_name(l=4, fname='cond', mn_mod=cond_list)  # cond_dct)


def permut_args(order, args):
    l = []
    for i, x in enumerate(order):
        l.append((x.__class__, i))
    l = dict(l)
    out = [None for x in xrange(len(args))]
    for a in args:
        out[l[a.__class__]] = a
    return out


class additional_info:

    def __init__(self):
        self.except_on_instr = False
        self.lnk = None
        self.cond = None


class instruction_arm(instruction):
    __slots__ = []
    delayslot = 0

    def __init__(self, *args, **kargs):
        super(instruction_arm, self).__init__(*args, **kargs)

    @staticmethod
    def arg2str(e, pos = None):
        wb = False
        if isinstance(e, ExprId) or isinstance(e, ExprInt):
            return str(e)
        if isinstance(e, ExprOp) and e.op in expr2shift_dct:
            if len(e.args) == 1:
                return '%s %s' % (e.args[0], expr2shift_dct[e.op])
            elif len(e.args) == 2:
                return '%s %s %s' % (e.args[0], expr2shift_dct[e.op], e.args[1])
            else:
                raise NotImplementedError('zarb arg2str')


        sb = False
        if isinstance(e, ExprOp) and e.op == "sbit":
            sb = True
            e = e.args[0]
        if isinstance(e, ExprOp) and e.op == "reglist":
            o = [gpregs.expr.index(x) for x in e.args]
            out = reglist2str(o)
            if sb:
                out += "^"
            return out


        if isinstance(e, ExprOp) and e.op == 'wback':
            wb = True
            e = e.args[0]
        if isinstance(e, ExprId):
            out = str(e)
            if wb:
                out += "!"
            return out

        if not isinstance(e, ExprMem):
            return str(e)

        e = e.arg
        if isinstance(e, ExprOp) and e.op == 'wback':
            wb = True
            e = e.args[0]


        if isinstance(e, ExprId):
            r, s = e, None
        elif len(e.args) == 1 and isinstance(e.args[0], ExprId):
            r, s = e.args[0], None
        elif isinstance(e.args[0], ExprId):
            r, s = e.args[0], e.args[1]
        else:
            r, s = e.args[0].args
        if isinstance(s, ExprOp) and s.op in expr2shift_dct:
            s = ' '.join([str(x)
                for x in s.args[0], expr2shift_dct[s.op], s.args[1]])

        if isinstance(e, ExprOp) and e.op == 'postinc':
            o = '[%s]' % r
            if s and not (isinstance(s, ExprInt) and s.arg == 0):
                o += ', %s' % s
        else:
            if s and not (isinstance(s, ExprInt) and s.arg == 0):
                o = '[%s, %s]' % (r, s)
            else:
                o = '[%s]' % (r)


        if wb:
            o += "!"
        return o


    def dstflow(self):
        return self.name in conditional_branch + unconditional_branch

    def dstflow2label(self, symbol_pool):
        e = self.args[0]
        if not isinstance(e, ExprInt):
            return
        if self.name == 'BLX':
            ad = e.arg + self.offset
        else:
            ad = e.arg + self.offset
        l = symbol_pool.getby_offset_create(ad)
        s = ExprId(l, e.size)
        self.args[0] = s

    def breakflow(self):
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

    def getdstflow(self, symbol_pool):
        return [self.args[0]]

    def splitflow(self):
        if self.additional_info.lnk:
            return True
        if self.name == 'BLX':
            return True
        if self.name == 'BX':
            return False
        return self.breakflow() and self.additional_info.cond != 14

    def get_symbol_size(self, symbol, symbol_pool):
        return 32

    def fixDstOffset(self):
        e = self.args[0]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, ExprInt):
            log.debug('dyn dst %r', e)
            return
        off = e.arg - self.offset
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
    delayslot = 0

    def __init__(self, *args, **kargs):
        super(instruction_armt, self).__init__(*args, **kargs)

    def dstflow(self):
        if self.name in ["CBZ", "CBNZ"]:
            return True
        return self.name in conditional_branch + unconditional_branch

    def dstflow2label(self, symbol_pool):
        if self.name in ["CBZ", "CBNZ"]:
            e = self.args[1]
        else:
            e = self.args[0]
        if not isinstance(e, ExprInt):
            return
        if self.name == 'BLX':
            ad = e.arg + (self.offset & 0xfffffffc)
        else:
            ad = e.arg + self.offset
        l = symbol_pool.getby_offset_create(ad)
        s = ExprId(l, e.size)
        if self.name in ["CBZ", "CBNZ"]:
            self.args[1] = s
        else:
            self.args[0] = s

    def breakflow(self):
        if self.name in conditional_branch + unconditional_branch +["CBZ", "CBNZ"]:
            return True
        if self.name.startswith("LDM") and PC in self.args[1].args:
            return True
        if self.args and PC in self.args[0].get_r():
            return True
        return False

    def getdstflow(self, symbol_pool):
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
        off = e.arg - self.offset
        if int(off % 2):
            raise ValueError('strange offset! %r' % off)
        self.args[0] = ExprInt(off, 32)

    def get_asm_offset(self, expr):
        # ADR XXX, PC, imm => PC is 4 aligned + imm
        new_offset = ((self.offset+self.l)/4)*4
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
            raise ValueError('not enought bits %r %r' % (n, len(bs.bin) * 8))
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


    def get_symbol_size(self, symbol, symbol_pool, mode):
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
            raise ValueError('not enought bits %r %r' % (n, len(bs.bin) * 8))
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

    def get_symbol_size(self, symbol, symbol_pool, mode):
        return 32


class arm_reg(reg_noarg, m_arg):
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


class arm_psr(m_arg):
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


class arm_imm(imm_noarg, m_arg):
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
        self.value = (v & 0xffffffff) & self.lmask
        return True


class arm_imm8_12(m_arg):
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
        self.expr = ExprMem(e)
        return True

    def encode(self):
        self.parent.updown.value = 1
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        e = e.arg
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


class arm_imm_4_12(m_arg):
    parser = base_expr

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


class arm_imm_12_4(m_arg):
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


class arm_op2(m_arg):
    parser = shift_off

    def str_to_imm_rot_form(self, s, neg=False):
        if neg:
            s = -s & 0xffffffff
        for i in xrange(0, 32, 2):
            v = myrol32(s, i)
            if 0 <= v < 0x100:
                return ((i / 2) << 8) | v
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
        # print self.parent.immop.value, hex(shift), hex(shift_kind),
        # hex(shift_type)
        if shift_kind:
            # shift kind is reg
            if shift & 1:
                # log.debug('error in shift1')
                return False
            rs = shift >> 1
            if rs == 0xf:
                # log.debug('error in shift2')
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
            self.expr = ExprMem(e)
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
        self.expr = ExprMem(e)
        return True

    def encode(self):
        self.parent.immop.value = 1
        self.parent.updown.value = 1

        e = self.expr
        assert(isinstance(e, ExprMem))
        e = e.arg
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
        self.parent.rn.fromstring(e.args[0])
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


class arm_rlist(m_arg):
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
        for i in xrange(0x10):
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
        v = int(self.expr.arg - 8)
        if v & 0x80000000:
            v &= (1 << 26) - 1
        self.parent.lowb.value = (v >> 1) & 1
        self.value = v >> 2
        return True


class bs_lnk(bs_mod_name):

    def modname(self, name, i):
        return name[:1] + self.args['mn_mod'][i] + name[1:]


accum = bs(l=1)
scc = bs_mod_name(l=1, fname='scc', mn_mod=['', 'S'])
dumscc = bs("1")
rd = bs(l=4, cls=(arm_gpreg,))
rdl = bs(l=4, cls=(arm_gpreg,))

rn = bs(l=4, cls=(arm_gpreg,), fname="rn")
rs = bs(l=4, cls=(arm_gpreg,))
rm = bs(l=4, cls=(arm_gpreg,))
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

class arm_immed(m_arg):
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
        self.expr = ExprMem(e)

        return True

    def encode(self):
        self.parent.immop.value = 1
        self.parent.updown.value = 1
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        e = e.arg
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


class armt2_rot_rm(m_arg):
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


class arm_mem_rn_imm(m_arg):
    parser = deref
    def decode(self, v):
        value = self.parent.imm.value
        if self.parent.rw.value == 0:
            value = -value
        imm = ExprInt(value, 32)
        reg = gpregs.expr[v]
        if value:
            expr = ExprMem(reg + imm)
        else:
            expr = ExprMem(reg)
        self.expr = expr
        return True

    def encode(self):
        self.parent.add_imm.value = 1
        self.parent.imm.value = 0
        expr = self.expr
        if not isinstance(expr, ExprMem):
            return False
        ptr = expr.arg
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
    if n in data_mov_name.keys() + data_test_name.keys():
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

armop("mul", [bs('000000'), bs('0'), scc, rd,
      bs('0000'), rs, bs('1001'), rm], [rd, rm, rs])
armop("umull", [bs('000010'),
      bs('0'), scc, rd, rdl, rs, bs('1001'), rm], [rdl, rd, rm, rs])
armop("umlal", [bs('000010'),
      bs('1'), scc, rd, rdl, rs, bs('1001'), rm], [rdl, rd, rm, rs])
armop("smull", [bs('000011'), bs('0'), scc, rd,
      rdl, rs, bs('1001'), rm], [rdl, rd, rm, rs])
armop("smlal", [bs('000011'), bs('1'), scc, rd,
      rdl, rs, bs('1001'), rm], [rdl, rd, rm, rs])
armop("mla", [bs('000000'), bs('1'), scc, rd,
      rn, rs, bs('1001'), rm], [rd, rm, rs, rn])
armop("mrs", [bs('00010'), psr, bs('00'),
      psr_field, rd, bs('000000000000')], [rd, psr])
armop("msr", [bs('00010'), psr, bs('10'), psr_field,
              bs('1111'), bs('0000'), bs('0000'), rm], [psr_field, rm])
armop("data", [bs('00'), immop, bs_data_name, scc, rn, rd, op2], [rd, rn, op2])
armop("data_mov",
      [bs('00'), immop, bs_data_mov_name, scc, bs('0000'), rd, op2], [rd, op2])
armop("data_test", [bs('00'), immop, bs_data_test_name, dumscc, rn, dumr, op2])
armop("b", [bs('101'), lnk, offs])

armop("smul", [bs('00010110'), rd, bs('0000'), rs, bs('1'), mul_y, mul_x, bs('0'), rm], [rd, rm, rs])

# TODO TEST
#armop("und", [bs('011'), imm20, bs('1'), imm4])
armop("transfer", [bs('01'), immop, ppi, updown, trb, wback_no_t,
    bs_transfer_name, rn_noarg, rd, op2imm], [rd, op2imm])
armop("transferh", [bs('000'), ppi, updown, immop, wback_no_t,
    bs_transferh_name, rn_noarg, rd, immedH, bs('1011'), immedL], [rd, immedL])
armop("ldrd", [bs('000'), ppi, updown, immop, wback_no_t, bs_transfer_ldr_name,
    rn_noarg, rd, immedH, bs('1101'), immedL], [rd, immedL])
armop("ldrsh", [bs('000'),  ppi, updown, immop, wback_no_t, bs('1'), rn_noarg,
    rd, immedH, bs('1'), bs('1'), bs('1'), bs('1'), immedL], [rd, immedL])
armop("strd", [bs('000'),  ppi, updown, immop, wback_no_t, bs('0'), rn_noarg,
    rd, immedH, bs('1'), bs('1'), bs('1'), bs('1'), immedL], [rd, immedL])
armop("btransfersp", [bs('100'),  ppi_b_sp, updown_b_sp, sbit, wback_no_t,
                      bs_btransfer_name, rn_sp, rlist])
armop("btransfer", [bs('100'),  ppi_b_nosp, updown_b_nosp, sbit, wback_no_t,
                    bs_btransfer_name, rn_wb, rlist])
# TODO: TEST
armop("swp", [bs('00010'), trb, bs('00'), rn, rd, bs('0000'), bs('1001'), rm])
armop("svc", [bs('1111'), swi_i])
armop("cdp", [bs('1110'), opc, crn, crd, cpnum, cp, bs('0'), crm],
      [cpnum, opc, crd, crn, crm, cp])
armop("cdata", [bs('110'), ppi, updown, tl, wback_no_t, bs_ctransfer_name,
                rn_noarg, crd, cpnum, imm8_12], [cpnum, crd, imm8_12])
armop("mr", [bs('1110'), cpopc, bs_mr_name, crn, rd, cpnum, cp, bs('1'), crm],
      [cpnum, cpopc, rd, crn, crm, cp])
armop("bkpt", [bs('00010010'), imm12_noarg, bs('0111'), imm_12_4])
armop("bx", [bs('000100101111111111110001'), rn])
armop("mov", [bs('00110000'), imm4_noarg, rd, imm_4_12], [rd, imm_4_12])
armop("movt", [bs('00110100'), imm4_noarg, rd, imm_4_12], [rd, imm_4_12])
armop("blx", [bs('00010010'), bs('1111'),
              bs('1111'), bs('1111'), bs('0011'), rm], [rm])
armop("blx", [fix_cond, bs('101'), lowb, offs_blx], [offs_blx])
armop("clz", [bs('00010110'), bs('1111'),
      rd, bs('1111'), bs('0001'), rm], [rd, rm])
armop("qadd",
      [bs('00010000'), rn, rd, bs('0000'), bs('0101'), rm], [rd, rm, rn])

armop("uxtb", [bs('01101110'), bs('1111'), rd, rot_rm, bs('00'), bs('0111'), rm_noarg])
armop("uxth", [bs('01101111'), bs('1111'), rd, rot_rm, bs('00'), bs('0111'), rm_noarg])
armop("sxtb", [bs('01101010'), bs('1111'), rd, rot_rm, bs('00'), bs('0111'), rm_noarg])
armop("sxth", [bs('01101011'), bs('1111'), rd, rot_rm, bs('00'), bs('0111'), rm_noarg])

armop("rev", [bs('01101011'), bs('1111'), rd, bs('1111'), bs('0011'), rm])

armop("pld", [bs8(0xF5), bs_addi, bs_rw, bs('01'), mem_rn_imm, bs('1111'), imm12_off])

armop("isb", [bs8(0xF5), bs8(0x7F), bs8(0xF0), bs8(0x6F)])

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


class arm_rm_rot2(m_arg):
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
            self.parent.rot2.value = value / 8
        return True

class arm_gpreg_nopc(arm_reg):
    reg_info = gpregs_nopc
    parser = reg_info.parser


rm_rot2 = bs(l=4, cls=(arm_rm_rot2,), fname="rm")
rot2 = bs(l=2, fname="rot2")

widthm1 = bs(l=5, cls=(arm_widthm1, m_arg))
lsb = bs(l=5, cls=(arm_imm, m_arg))

rn_nopc = bs(l=4, cls=(arm_gpreg_nopc,), fname="rn")

armop("ubfx", [bs('0111111'), widthm1, rd, lsb, bs('101'), rn], [rd, rn, lsb, widthm1])

armop("bfc", [bs('0111110'), widthm1, rd, lsb, bs('001'), bs('1111')], [rd, lsb, widthm1])

armop("uxtab", [bs('01101110'), rn_nopc, rd, rot2, bs('000111'), rm_rot2], [rd, rn_nopc, rm_rot2])



#
# thumnb #######################
#
# ARM7-TDMI-manual-pt3
gpregs_l = reg_info(regs_str[:8], regs_expr[:8])
gpregs_h = reg_info(regs_str[8:], regs_expr[8:])

gpregs_sppc = reg_info(regs_str[-1:] + regs_str[13:14],
                       regs_expr[-1:] + regs_expr[13:14])

deref_low = Group(LBRACK + gpregs_l.parser + Optional(
    COMMA + shift_off) + RBRACK).setParseAction(deref2expr_pre_mem)
deref_pc = Group(LBRACK + gpregs_pc.parser + Optional(
    COMMA + shift_off) + RBRACK).setParseAction(deref2expr_pre_mem)
deref_sp = Group(LBRACK + gpregs_sp.parser + COMMA +
                 shift_off + RBRACK).setParseAction(deref2expr_pre_mem)

gpregs_l_wb = Group(
    gpregs_l.parser + Optional('!')).setParseAction(parsegpreg_wb)


class arm_offreg(m_arg):
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
            self.expr = ExprMem(self.off_reg + ExprInt(v, 32))
        else:
            self.expr = ExprMem(self.off_reg)

        e = self.expr.arg
        if isinstance(e, ExprOp) and e.op == 'wback':
            self.parent.wback.value = 1
            e = e.args[0]
        return True

    def encode(self):
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        e = e.arg
        if not (isinstance(e, ExprOp) and e.op == "preinc"):
            log.debug('cannot encode %r', e)
            return False
        if e.args[0] != self.off_reg:
            log.debug('cannot encode reg %r', e.args[0])
            return False
        v = int(e.args[1])
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
        if v % 2 == 0:
            return v >> 1
        return False


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


class arm_deref(m_arg):
    parser = deref_low

    def decode(self, v):
        v = v & self.lmask
        rbase = regs_expr[v]
        e = ExprOp('preinc', rbase, self.parent.off.expr)
        self.expr = ExprMem(e)
        return True

    def encode(self):
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        e = e.arg
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


class armt_rlist(m_arg):
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
        for i in xrange(0x10):
            if 1 << i & v:
                out.append(gpregs.expr[i])
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
            # print 'push'
            if regs_expr[14] in reg_l:
                reg_l.remove(regs_expr[14])
                self.parent.pclr.value = 1
        else:
            # print 'pop',
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
        for i in xrange(0x10):
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
rbl_deref = bs(l=3, cls=(arm_deref,), fname="rb")
dumrh = bs(l=3, default_val="000")

rdh = bs(l=3, cls=(arm_gpreg_h,), fname="rd")
rsh = bs(l=3, cls=(arm_gpreg_h,), fname="rs")

offpc8 = bs(l=8, cls=(arm_offpc,), fname="offs")
offsp8 = bs(l=8, cls=(arm_offsp,), fname="offs")
rol_noarg = bs(l=3, cls=(arm_gpreg_l_noarg,), fname="off")

off5bw = bs(l=5, cls=(arm_offbw,), fname="off")
off5h = bs(l=5, cls=(arm_offh,), fname="off")
sppc = bs(l=1, cls=(arm_sppc,))


pclr = bs(l=1, fname='pclr')


sp = bs(l=0, cls=(arm_sp,))


off8s = bs(l=8, cls=(arm_offs,), fname="offs")
trlistpclr = bs(l=8, cls=(armt_rlist_pclr,))
trlist = bs(l=8, cls=(armt_rlist,), fname="trlist", order = -1)

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
armtop("addsubr",
       [bs('000110'),  bs_addsub_name, rnl, rsl, rdl], [rdl, rsl, rnl])
armtop("addsubi",
       [bs('000111'),  bs_addsub_name, off3, rsl, rdl], [rdl, rsl, off3])
armtop("mcas", [bs('001'), bs_mov_cmp_add_sub_name, rnl, off8])
armtop("alu", [bs('010000'), bs_alu_name, rsl, rdl], [rdl, rsl])
  # should not be used ??
armtop("hiregop00",
       [bs('010001'), bs_hiregop_name, bs('00'), rsl, rdl], [rdl, rsl])
armtop("hiregop01",
       [bs('010001'), bs_hiregop_name, bs('01'), rsh, rdl], [rdl, rsh])
armtop("hiregop10",
       [bs('010001'), bs_hiregop_name, bs('10'), rsl, rdh], [rdh, rsl])
armtop("hiregop11",
       [bs('010001'), bs_hiregop_name, bs('11'), rsh, rdh], [rdh, rsh])
armtop("bx", [bs('010001'), bs('11'), bs('00'), rsl, dumrh])
armtop("bx", [bs('010001'), bs('11'), bs('01'), rsh, dumrh])
armtop("ldr", [bs('01001'),  rdl, offpc8])
armtop("ldrstr", [bs('0101'), bs_ldr_str_name,
                  trb, bs('0'), rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("strh", [bs('0101'), bs('00'), bs('1'),
       rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldrh", [bs('0101'), bs('10'), bs('1'),
       rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldsb", [bs('0101'), bs('01'), bs('1'),
       rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldsh", [bs('0101'), bs('11'), bs('1'),
       rol_noarg, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldst", [bs('011'), trb,
       bs_ldr_str_name, off5bw, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldhsth",
       [bs('1000'), bs_ldrh_strh_name, off5h, rbl_deref, rdl], [rdl, rbl_deref])
armtop("ldstsp", [bs('1001'), bs_ldstsp_name, rdl, offsp8], [rdl, offsp8])
armtop("add", [bs('1010'), sppc, rdl, off8sppc], [rdl, sppc, off8sppc])
armtop("addsp", [bs('10110000'), bs_addsubsp_name, sp, off7], [sp, off7])
armtop("pushpop",
       [bs('1011'), bs_pushpop_name, bs('10'), pclr, trlistpclr], [trlistpclr])
armtop("btransfersp", [bs('1100'),  bs_tbtransfer_name, rbl_wb, trlist])
armtop("br", [bs('1101'),  bs_br_name, offs8])
armtop("blx", [bs("01000111"),  bs('10'), rnl, bs('000')])
armtop("svc", [bs('11011111'),  imm8])
armtop("b", [bs('11100'),  offs11])
armtop("und", [bs('1101'), bs('1110'), imm8_d1])


armtop("uxtb", [bs('10110010'), bs('11'), rml, rdl], [rdl, rml])
armtop("uxth", [bs('10110010'), bs('10'), rml, rdl], [rdl, rml])
armtop("sxtb", [bs('10110010'), bs('01'), rml, rdl], [rdl, rml])
armtop("sxth", [bs('10110010'), bs('00'), rml, rdl], [rdl, rml])

# thumb2 ######################
#

# ARM Architecture Reference Manual Thumb-2 Supplement

armt_gpreg_shift_off = Group(
    gpregs_nosppc.parser + allshifts_t_armt + base_expr
).setParseAction(shift2expr)
armt_gpreg_shift_off |= gpregs_nosppc.parser


class arm_gpreg_nosppc(arm_reg):
    reg_info = gpregs_nosppc



class armt_gpreg_rm_shift_off(arm_reg):
    parser = armt_gpreg_shift_off

    def decode(self, v):
        v = v & self.lmask
        if v >= len(gpregs_nosppc.expr):
            return False
        r = gpregs_nosppc.expr[v]

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
            self.value = gpregs_nosppc.index(e)
            self.parent.stype.value = 0
            self.parent.imm5_3.value = 0
            self.parent.imm5_2.value = 0
            return True
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
        v = v & 0xFF
        self.expr = ExprInt(myror32(v, r), 32)
        return True

    def encode(self):
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
            for i in xrange(32):
                o = myrol32(v, i)
                if 0 <= o < 0x100 and o & 0x80:
                    value = (i << 7) | o
                    break
        if value is None:
            log.debug('cannot encode imm12')
            return False
        self.value = value & self.lmask
        self.parent.imm12_3.value = (value >> 8) & self.parent.imm12_3.lmask
        self.parent.imm12_1.value = (value >> 11) & self.parent.imm12_1.lmask
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

        v = (s << 24) | (i1 << 23) | (
            i2 << 22) | (imm10h << 12) | (imm10l << 2)
        v = sign_ext(v, 25, 32)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = self.expr.arg.arg
        s = 0
        if v & 0x80000000:
            s = 1
            v = (-v) & 0xffffffff
        if v > (1 << 26):
            return False
        i1, i2, imm10h, imm10l = (v >> 23) & 1, (
            v >> 22) & 1, (v >> 12) & 0x3ff, (v >> 2) & 0x3ff
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

        v = (s << 24) | (i1 << 23) | (
            i2 << 22) | (imm10h << 12) | (imm11l << 1)
        v = sign_ext(v, 25, 32)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = self.expr.arg.arg
        s = 0
        if v & 0x80000000:
            s = 1
            v = (-v) & 0xffffffff
        if v > (1 << 26):
            return False
        i1, i2, imm10h, imm11l = (v >> 23) & 1, (
            v >> 22) & 1, (v >> 12) & 0x3ff, (v >> 1) & 0x7ff
        j1, j2 = i1 ^ s ^ 1, i2 ^ s ^ 1
        self.parent.sign.value = s
        self.parent.j1.value = j1
        self.parent.j2.value = j2
        self.parent.imm10h.value = imm10h
        self.value = imm11l
        return True


imm12_1 = bs(l=1, fname="imm12_1", order=1)
imm12_3 = bs(l=3, fname="imm12_3", order=1)
imm12_8 = bs(l=8, cls=(armt2_imm12,), fname="imm", order=2)


imm5_3 = bs(l=3, fname="imm5_3")
imm5_2 = bs(l=2, fname="imm5_2")
imm_stype = bs(l=2, fname="stype")

imm1 = bs(l=1, fname="imm1")


class armt_imm5_1(arm_imm):

    def decode(self, v):
        v = sign_ext(((self.parent.imm1.value << 5) | v) << 1, 7, 32)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = self.expr.arg.arg
        if v & 0x80000000:
            v &= (1 << 7) - 1
        self.parent.imm1.value = (v >> 6) & 1
        self.value = (v >> 1) & 0x1f
        return True

imm5_off = bs(l=5, cls=(armt_imm5_1,), fname="imm5_off")

tsign = bs(l=1, fname="sign")
tj1 = bs(l=1, fname="j1")
tj2 = bs(l=1, fname="j2")

timm10H = bs(l=10, fname="imm10h")
timm10L = bs(l=10, cls=(armt2_imm10l,), fname="imm10l")
timm11L = bs(l=11, cls=(armt2_imm11l,), fname="imm11l")


armtop("adc", [bs('11110'),  imm12_1, bs('0'), bs('1010'), scc, rn_nosppc,
               bs('0'), imm12_3, rd_nosppc, imm12_8])
armtop("adc", [bs('11101'),  bs('01'), bs('1010'), scc, rn_nosppc,
               bs('0'), imm5_3, rd_nosppc, imm5_2, imm_stype, rm_sh])
armtop("bl", [bs('11110'), tsign, timm10H,
              bs('11'), tj1, bs('1'), tj2, timm11L])
armtop("blx", [bs('11110'), tsign, timm10H,
               bs('11'), tj1, bs('0'), tj2, timm10L, bs('0')])
armtop("cbz", [bs('101100'), imm1, bs('1'), imm5_off, rnl], [rnl, imm5_off])
armtop("cbnz", [bs('101110'), imm1, bs('1'), imm5_off, rnl], [rnl, imm5_off])

armtop("bkpt", [bs('1011'), bs('1110'), imm8])
