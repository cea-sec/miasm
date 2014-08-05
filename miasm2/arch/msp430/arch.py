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

log = logging.getLogger("armdis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)


def deref2expr_nooff(s, l, t):
    t = t[0]
    if len(t) == 1 and isinstance(t[0], ExprId):
        return ExprMem(t[0], 16)
    elif len(t) == 1 and isinstance(t[0], ExprInt):
        return ExprMem(t[0], 16)
    raise NotImplementedError('not fully functional')


def deref2expr_pinc(s, l, t):
    t = t[0]
    if len(t) == 1 and isinstance(t[0], ExprId):
        return ExprOp('autoinc', t[0])
    raise NotImplementedError('not fully functional')


def deref2expr_off(s, l, t):
    t = t[0]
    if len(t) == 2 and isinstance(t[1], ExprId):
        return ExprMem(t[1] + t[0], 16)
    raise NotImplementedError('not fully functional')


def deref_expr(s, l, t):
    t = t[0]
    assert(len(t) == 1)
    t = t[0]
    if isinstance(t, ExprId):
        return t
    elif isinstance(t, ExprInt):
        return t
    elif isinstance(t, ExprMem):
        return t
    elif isinstance(t, ExprOp) and t.op == "autoinc":
        return t
    raise NotImplementedError('not fully functional')
    if t[-1] == '!':
        return ExprOp('wback', *t[:-1])
    return t[0]


def f_reg2expr(t):
    t = t[0]
    i = regs16_str.index(t)
    r = regs16_expr[i]
    return r

# gpregs.parser.setParseAction(f_reg2expr)

ARO = Suppress("@")
LPARENT = Suppress("(")
RPARENT = Suppress(")")

PINC = Suppress("+")


def ast_id2expr(t):
    if not t in mn_msp430.regs.all_regs_ids_byname:
        r = ExprId(t, 16)
    else:
        r = mn_msp430.regs.all_regs_ids_byname[t]
    return r


def ast_int2expr(a):
    return ExprInt16(a)


variable, operand, base_expr = gen_base_expr()

my_var_parser = parse_ast(ast_id2expr, ast_int2expr)
base_expr.setParseAction(my_var_parser)


deref_nooff = Group(ARO + base_expr).setParseAction(deref2expr_nooff)
deref_pinc = Group(ARO + base_expr + PINC).setParseAction(deref2expr_pinc)
deref_off = Group(base_expr + LPARENT +
                  gpregs.parser + RPARENT).setParseAction(deref2expr_off)


sreg_p = Group(deref_pinc | deref_nooff |
               deref_off | base_expr).setParseAction(deref_expr)


class additional_info:

    def __init__(self):
        self.except_on_instr = False


class instruction_msp430(instruction):
    delayslot = 0

    def dstflow(self):
        if self.name.startswith('j'):
            return True
        return self.name in ['call']

    @staticmethod
    def arg2str(e, pos = None):
        if isinstance(e, ExprId):
            o = str(e)
        elif isinstance(e, ExprInt):
            o = str(e)
        elif isinstance(e, ExprOp) and e.op == "autoinc":
            o = "@%s+" % str(e.args[0])
        elif isinstance(e, ExprMem):
            if isinstance(e.arg, ExprId):
                if pos == 0:
                    o = "@%s" % e.arg
                else:
                    o = "0x0(%s)" % e.arg
            elif isinstance(e.arg, ExprInt):
                o = "@%s" % e.arg
            elif isinstance(e.arg, ExprOp):
                o = "%s(%s)" % (e.arg.args[1], e.arg.args[0])
        else:
            raise NotImplementedError('unknown instance e = %s' % type(e))
        return o


    def dstflow2label(self, symbol_pool):
        e = self.args[0]
        if not isinstance(e, ExprInt):
            return
        if self.name == "call":
            ad = e.arg
        else:
            ad = e.arg + int(self.offset) + self.l

        l = symbol_pool.getby_offset_create(ad)
        s = ExprId(l, e.size)
        self.args[0] = s

    def breakflow(self):
        if self.name.startswith('j'):
            return True
        if self.name.startswith('ret'):
            return True
        if self.name.startswith('int'):
            return True
        if self.name.startswith('mov') and self.args[1] == PC:
            return True
        return self.name in ['call']

    def splitflow(self):
        if self.name.startswith('jmp'):
            return False
        if self.name.startswith('j'):
            return True
        return self.name in ['call']

    def setdstflow(self, a):
        return

    def is_subcall(self):
        return self.name in ['call']

    def getdstflow(self, symbol_pool):
        return [self.args[0]]

    def get_symbol_size(self, symbol, symbol_pool):
        return self.mode

    def fixDstOffset(self):
        e = self.args[0]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, ExprInt):
            # raise ValueError('dst must be int or label')
            log.warning('dynamic dst %r' % e)
            return
        # return ExprInt32(e.arg - (self.offset + self.l))
        self.args[0] = ExprInt_fromsize(self.mode, e.arg)

    def get_info(self, c):
        pass

    def __str__(self):
        o = super(instruction_msp430, self).__str__()
        return o

    def get_args_expr(self):
        args = []
        for a in self.args:
            # a = a.replace_expr(replace_regs[self.mode])
            args.append(a)
        return args


mode_msp430 = None


class mn_msp430(cls_mn):
    name = "msp430"
    regs = regs_module
    all_mn = []
    bintree = {}
    num = 0
    delayslot = 0
    pc = {None: PC}
    sp = {None: SP}
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    instruction = instruction_msp430
    max_instruction_len = 8

    @classmethod
    def getpc(cls, attrib):
        return PC

    @classmethod
    def getsp(cls, attrib):
        return SP

    @classmethod
    def check_mnemo(cls, fields):
        l = sum([x.l for x in fields])
        assert l % 16 == 00, "len %r" % l

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

    def decoded2bytes(self, result):
        tmp = super(mn_msp430, self).decoded2bytes(result)
        out = []
        for x in tmp:
            o = ""
            while x:
                o += x[:2][::-1]
                x = x[2:]
            out.append(o)
        return out

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def additional_info(self):
        info = additional_info()
        return info

    @classmethod
    def getmn(cls, name):
        return name.upper()

    def reset_class(self):
        super(mn_msp430, self).reset_class()

    def getnextflow(self, symbol_pool):
        raise NotImplementedError('not fully functional')
        return self.offset + 4


def addop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_msp430,), dct)


class bw_mn(bs_mod_name):
    prio = 5
    mn_mod = ['.w', '.b']


class msp430_sreg_arg(reg_noarg, m_arg):
    prio = default_prio + 1
    reg_info = gpregs
    parser = sreg_p

    def decode(self, v):
        size = 16
        if hasattr(self.parent, 'size'):
            size = [16, 8][self.parent.size.value]
        v = v & self.lmask
        e = self.reg_info.expr[v]
        if self.parent.a_s.value == 0b00:
            if e == R3:
                self.expr = ExprInt_fromsize(size, 0)
            else:
                self.expr = e
        elif self.parent.a_s.value == 0b01:
            if e == SR:
                self.expr = ExprMem(ExprInt16(self.parent.off_s.value), size)
            elif e == R3:
                self.expr = ExprInt_fromsize(size, 1)
            else:
                self.expr = ExprMem(
                    e + ExprInt16(self.parent.off_s.value), size)
        elif self.parent.a_s.value == 0b10:
            if e == SR:
                self.expr = ExprInt_fromsize(size, 4)
            elif e == R3:
                self.expr = ExprInt_fromsize(size, 2)
            else:
                self.expr = ExprMem(e, size)
        elif self.parent.a_s.value == 0b11:
            if e == SR:
                self.expr = ExprInt_fromsize(size, 8)
            elif e == R3:
                if self.parent.size.value == 0:
                    self.expr = ExprInt_fromsize(size, 0xffff)
                else:
                    self.expr = ExprInt_fromsize(size, 0xff)
            elif e == PC:
                self.expr = ExprInt_fromsize(size, self.parent.off_s.value)
            else:
                self.expr = ExprOp('autoinc', e)
        else:
            raise NotImplementedError(
                "unknown value self.parent.a_s.value = " +
                "%d" % self.parent.a_s.value)
        return True

    def encode(self):
        e = self.expr
        if e in self.reg_info.expr:
            self.parent.a_s.value = 0
            self.value = self.reg_info.expr.index(e)
        elif isinstance(e, ExprInt):
            v = int(e.arg)
            if v == 0xffff and self.parent.size.value == 0:
                self.parent.a_s.value = 0b11
                self.value = 3
            elif v == 0xff and self.parent.size.value == 1:
                self.parent.a_s.value = 0b11
                self.value = 3
            elif v == 2:
                self.parent.a_s.value = 0b10
                self.value = 3
            elif v == 1:
                self.parent.a_s.value = 0b01
                self.value = 3
            elif v == 8:
                self.parent.a_s.value = 0b11
                self.value = 2
            elif v == 4:
                self.parent.a_s.value = 0b10
                self.value = 2
            elif v == 0:
                self.parent.a_s.value = 0b00
                self.value = 3
            else:
                self.parent.a_s.value = 0b11
                self.value = 0
                self.parent.off_s.value = v
        elif isinstance(e, ExprMem):
            if isinstance(e.arg, ExprId):
                self.parent.a_s.value = 0b10
                self.value = self.reg_info.expr.index(e.arg)
            elif isinstance(e.arg, ExprInt):
                self.parent.a_s.value = 0b01
                self.value = self.reg_info.expr.index(SR)
                self.parent.off_s.value = int(e.arg.arg)
            elif isinstance(e.arg, ExprOp):
                self.parent.a_s.value = 0b01
                self.value = self.reg_info.expr.index(e.arg.args[0])
                self.parent.off_s.value = int(e.arg.args[1].arg)
            else:
                raise NotImplementedError(
                    'unknown instance e.arg = %s' % type(e.arg))
        elif isinstance(e, ExprOp) and e.op == "autoinc":
            self.parent.a_s.value = 0b11
            self.value = self.reg_info.expr.index(e.args[0])
        else:
            raise NotImplementedError('unknown instance e = %s' % type(e))
        return True


class msp430_dreg_arg(msp430_sreg_arg):
    prio = default_prio + 1
    reg_info = gpregs
    parser = sreg_p

    def decode(self, v):
        if hasattr(self.parent, 'size'):
            size = [16, 8][self.parent.size.value]
        else:
            size = 16

        v = v & self.lmask
        e = self.reg_info.expr[v]
        if self.parent.a_d.value == 0:
            self.expr = e
        elif self.parent.a_d.value == 1:
            if e == SR:
                x = ExprInt16(self.parent.off_d.value)
            else:
                x = e + ExprInt16(self.parent.off_d.value)
            self.expr = ExprMem(x, size)
        else:
            raise NotImplementedError(
                "unknown value self.parent.a_d.value = " +
                "%d" % self.parent.a_d.value)
        return True

    def encode(self):
        e = self.expr
        if e in self.reg_info.expr:
            self.parent.a_d.value = 0
            self.value = self.reg_info.expr.index(e)
        elif isinstance(e, ExprMem):
            if isinstance(e.arg, ExprId):
                r, i = e.arg, ExprInt16(0)
            elif isinstance(e.arg, ExprOp):
                r, i = e.arg.args[0], e.arg.args[1]
            elif isinstance(e.arg, ExprInt):
                r, i = SR, e.arg
            else:
                raise NotImplementedError(
                    'unknown instance e.arg = %s' % type(e.arg))
            self.parent.a_d.value = 1
            self.value = self.reg_info.expr.index(r)
            self.parent.off_d.value = int(i.arg)
        else:
            raise NotImplementedError('unknown instance e = %s' % type(e))
        return True

class bs_cond_off_s(bs_cond):

    @classmethod
    def flen(cls, mode, v):
        if v['a_s'] == 0b00:
            return None
        elif v['a_s'] == 0b01:
            if v['sreg'] in [3]:
                return None
            else:
                return 16
        elif v['a_s'] == 0b10:
            return None
        elif v['a_s'] == 0b11:
            """
            if v['sreg'] in [2, 3]:
                return None
            else:
                return 16
            """
            if v['sreg'] in [0]:
                return 16
            else:
                return None
        else:
            raise NotImplementedError("unknown value v[a_s] = %d" % v['a_s'])

    def encode(self):
        return super(bs_cond, self).encode()

    def decode(self, v):
        if self.l == 0:
            self.value = None
        self.value = v
        return True


class bs_cond_off_d(bs_cond_off_s):

    @classmethod
    def flen(cls, mode, v):
        if v['a_d'] == 0:
            return None
        elif v['a_d'] == 1:
            return 16
        else:
            raise NotImplementedError("unknown value v[a_d] = %d" % v['a_d'])


class msp430_offs(imm_noarg, m_arg):
    parser = base_expr

    def int2expr(self, v):
        if v & ~self.intmask != 0:
            return None
        return ExprInt_fromsize(16, v)

    def decodeval(self, v):
        return v << 1

    def encodeval(self, v):
        return v >> 1

    def decode(self, v):
        v = v & self.lmask
        if (1 << (self.l - 1)) & v:
            v |= ~0 ^ self.lmask
        v = self.decodeval(v)
        self.expr = ExprInt16(v)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr.arg)
        if (1 << (self.l - 1)) & v:
            v = -((0xffff ^ v) + 1)
        v = self.encodeval(v)
        self.value = (v & 0xffff) & self.lmask
        return True


off_s = bs(l=16, order=-10, cls=(bs_cond_off_s,), fname = "off_s")
off_d = bs(l=16, order=-10, cls=(bs_cond_off_d,), fname = "off_d")

a_s = bs(l=2, order=-4, fname='a_s')
a_d = bs(l=1, order=-6, fname='a_d')

a_d2 = bs(l=2, order=-2, fname='a_d')

sreg = bs(l=4, order=-3, cls=(msp430_sreg_arg,), fname='sreg')
dreg = bs(l=4, order=-5, cls=(msp430_dreg_arg,), fname='dreg')

bw = bw_mn(l=1, order=-10, mn_mod=['.w', '.b'], fname='size')

bs_f1 = bs_name(
    l=4, name={
        'mov': 4, 'add': 5, 'addc': 6, 'subc': 7, 'sub': 8, 'cmp': 9,
        'dadd': 10, 'bit': 11, 'bic': 12, 'bis': 13, 'xor': 14, 'and': 15})
addop("f1", [bs_f1, sreg, a_d, bw, a_s, dreg, off_s, off_d])

bs_f2 = bs_name(l=3, name={'rrc': 0, 'rra': 2,
                           'push': 4})
addop("f2_1", [bs('000100'), bs_f2, bw, a_s, sreg, off_s])


bs_f2_nobw = bs_name(l=3, name={'swpb': 1, 'sxt': 3,
                                'call': 5})
addop("f2_2", [bs('000100'), bs_f2_nobw, bs('0'), a_s, sreg, off_s])


offimm = bs(l=10, cls=(msp430_offs,), fname="offs")

bs_f2_jcc = bs_name(l=3, name={'jnz': 0, 'jz': 1, 'jnc': 2, 'jc': 3, 'jn': 4,
                               'jge': 5, 'jl': 6, 'jmp': 7})
addop("f2_3", [bs('001'), bs_f2_jcc, offimm])
