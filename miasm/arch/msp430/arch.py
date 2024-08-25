#-*- coding:utf-8 -*-

from builtins import range

import logging
from pyparsing import *
from miasm.expression.expression import *
from miasm.core.cpu import *
from collections import defaultdict
from miasm.core.bin_stream import bin_stream
import miasm.arch.msp430.regs as regs_module
from miasm.arch.msp430.regs import *
from miasm.core.asm_ast import AstInt, AstId, AstMem, AstOp
from miasm.ir.ir import color_expr_html

log = logging.getLogger("msp430dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

conditional_branch = ['jnz', 'jz', 'jnc', 'jc',
                      'jn', 'jge', 'jl']
unconditional_branch = ['jmp']

def cb_deref_nooff(tokens):
    assert len(tokens) == 1
    result = AstMem(tokens[0], 16)
    return result


def cb_deref_pinc(tokens):
    assert len(tokens) == 1

    result = AstOp('autoinc', *tokens)
    return result


def cb_deref_off(tokens):
    assert len(tokens) == 2
    result = AstMem(tokens[1] + tokens[0], 16)
    return result


def cb_expr(tokens):
    assert(len(tokens) == 1)
    result = tokens[0]
    return result


ARO = Suppress("@")
LPARENT = Suppress("(")
RPARENT = Suppress(")")

PINC = Suppress("+")

deref_nooff = (ARO + base_expr).setParseAction(cb_deref_nooff)
deref_pinc = (ARO + base_expr + PINC).setParseAction(cb_deref_pinc)
deref_off = (base_expr + LPARENT + gpregs.parser + RPARENT).setParseAction(cb_deref_off)
sreg_p = (deref_pinc | deref_nooff | deref_off | base_expr).setParseAction(cb_expr)



class msp430_arg(m_arg):
    def asm_ast_to_expr(self, value, loc_db):
        if isinstance(value, AstId):
            name = value.name
            if is_expr(name):
                return name
            assert isinstance(name, str)
            if name in gpregs.str:
                index = gpregs.str.index(name)
                reg = gpregs.expr[index]
                return reg
            loc_key = loc_db.get_or_create_name_location(value.name)
            return ExprLoc(loc_key, 16)
        if isinstance(value, AstOp):
            args = [self.asm_ast_to_expr(tmp, loc_db) for tmp in value.args]
            if None in args:
                return None
            return ExprOp(value.op, *args)
        if isinstance(value, AstInt):
            return ExprInt(value.value, 16)
        if isinstance(value, AstMem):
            ptr = self.asm_ast_to_expr(value.ptr, loc_db)
            if ptr is None:
                return None
            return ExprMem(ptr, value.size)
        return None


class additional_info(object):

    def __init__(self):
        self.except_on_instr = False


class instruction_msp430(instruction):
    __slots__ = []

    def dstflow(self):
        if self.name.startswith('j'):
            return True
        return self.name in ['call']

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        if isinstance(expr, ExprId):
            o = str(expr)
        elif isinstance(expr, ExprInt):
            o = str(expr)
        elif expr.is_loc():
            if loc_db is not None:
                return loc_db.pretty_str(expr.loc_key)
            else:
                return str(expr)
        elif isinstance(expr, ExprOp) and expr.op == "autoinc":
            o = "@%s+" % str(expr.args[0])
        elif isinstance(expr, ExprMem):
            if isinstance(expr.ptr, ExprId):
                if index == 0:
                    o = "@%s" % expr.ptr
                else:
                    o = "0x0(%s)" % expr.ptr
            elif isinstance(expr.ptr, ExprInt):
                o = "@%s" % expr.ptr
            elif isinstance(expr.ptr, ExprOp):
                o = "%s(%s)" % (expr.ptr.args[1], expr.ptr.args[0])
        else:
            raise NotImplementedError('unknown instance expr = %s' % type(expr))
        return o

    @staticmethod
    def arg2html(expr, index=None, loc_db=None):
        if isinstance(expr, ExprId) or isinstance(expr, ExprInt) or expr.is_loc():
            return color_expr_html(expr, loc_db)
        elif isinstance(expr, ExprOp) and expr.op == "autoinc":
            o = "@%s+" % color_expr_html(expr.args[0], loc_db)
        elif isinstance(expr, ExprMem):
            if isinstance(expr.ptr, ExprId):
                if index == 0:
                    o = "@%s" % color_expr_html(expr.ptr, loc_db)
                else:
                    o = "0x0(%s)" % color_expr_html(expr.ptr, loc_db)
            elif isinstance(expr.ptr, ExprInt):
                o = "@%s" % color_expr_html(expr.ptr, loc_db)
            elif isinstance(expr.ptr, ExprOp):
                o = "%s(%s)" % (
                    color_expr_html(expr.ptr.args[1], loc_db),
                    color_expr_html(expr.ptr.args[0], loc_db)
                )
        else:
            raise NotImplementedError('unknown instance expr = %s' % type(expr))
        return o


    def dstflow2label(self, loc_db):
        expr = self.args[0]
        if not isinstance(expr, ExprInt):
            return
        if self.name == "call":
            addr = int(expr)
        else:
            addr = (int(expr) + int(self.offset))  & int(expr.mask)

        loc_key = loc_db.get_or_create_offset_location(addr)
        self.args[0] = ExprLoc(loc_key, expr.size)

    def breakflow(self):
        if self.name in conditional_branch + unconditional_branch:
            return True
        if self.name.startswith('ret'):
            return True
        if self.name.startswith('int'):
            return True
        if self.name.startswith('mov') and self.args[1] == PC:
            return True
        return self.name in ['call']

    def splitflow(self):
        if self.name in conditional_branch:
            return True
        if self.name in unconditional_branch:
            return False
        return self.name in ['call']

    def setdstflow(self, a):
        return

    def is_subcall(self):
        return self.name in ['call']

    def getdstflow(self, loc_db):
        return [self.args[0]]

    def get_symbol_size(self, symbol, loc_db):
        return 16

    def fixDstOffset(self):
        e = self.args[0]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, ExprInt):
            # raise ValueError('dst must be int or label')
            log.warning('dynamic dst %r', e)
            return

        # Call argument is an absolute offset
        # Other offsets are relative to instruction offset
        if self.name != "call":
            self.args[0] =  ExprInt(int(e) - self.offset, 16)

    def get_info(self, c):
        pass

    def __str__(self):
        o = super(instruction_msp430, self).__str__()
        return o

    def get_args_expr(self):
        args = []
        for a in self.args:
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

    def decoded2bytes(self, result):
        tmp = super(mn_msp430, self).decoded2bytes(result)
        out = []
        for x in tmp:
            o = b""
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

    def getnextflow(self, loc_db):
        raise NotImplementedError('not fully functional')


def addop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_msp430,), dct)


class bw_mn(bs_mod_name):
    prio = 5
    mn_mod = ['.w', '.b']


class msp430_sreg_arg(reg_noarg, msp430_arg):
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
                self.expr = ExprInt(0, size)
            else:
                self.expr = e
        elif self.parent.a_s.value == 0b01:
            if e == SR:
                self.expr = ExprMem(ExprInt(self.parent.off_s.value, 16), size)
            elif e == R3:
                self.expr = ExprInt(1, size)
            else:
                self.expr = ExprMem(
                    e + ExprInt(self.parent.off_s.value, 16), size)
        elif self.parent.a_s.value == 0b10:
            if e == SR:
                self.expr = ExprInt(4, size)
            elif e == R3:
                self.expr = ExprInt(2, size)
            else:
                self.expr = ExprMem(e, size)
        elif self.parent.a_s.value == 0b11:
            if e == SR:
                self.expr = ExprInt(8, size)
            elif e == R3:
                if self.parent.size.value == 0:
                    self.expr = ExprInt(0xffff, size)
                else:
                    self.expr = ExprInt(0xff, size)
            elif e == PC:
                self.expr = ExprInt(self.parent.off_s.value, size)
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
            v = int(e)
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
            if isinstance(e.ptr, ExprId):
                self.parent.a_s.value = 0b10
                self.value = self.reg_info.expr.index(e.ptr)
            elif isinstance(e.ptr, ExprInt):
                self.parent.a_s.value = 0b01
                self.value = self.reg_info.expr.index(SR)
                self.parent.off_s.value = int(e.ptr)
            elif isinstance(e.ptr, ExprOp):
                self.parent.a_s.value = 0b01
                self.value = self.reg_info.expr.index(e.ptr.args[0])
                self.parent.off_s.value = int(e.ptr.args[1])
            else:
                raise NotImplementedError(
                    'unknown instance e.ptr = %s' % type(e.ptr))
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
                x = ExprInt(self.parent.off_d.value, 16)
            else:
                x = e + ExprInt(self.parent.off_d.value, 16)
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
            if isinstance(e.ptr, ExprId):
                r, i = e.ptr, ExprInt(0, 16)
            elif isinstance(e.ptr, ExprOp):
                r, i = e.ptr.args[0], e.ptr.args[1]
            elif isinstance(e.ptr, ExprInt):
                r, i = SR, e.ptr
            else:
                raise NotImplementedError(
                    'unknown instance e.arg = %s' % type(e.ptr))
            self.parent.a_d.value = 1
            self.value = self.reg_info.expr.index(r)
            self.parent.off_d.value = int(i)
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
        return super(bs_cond_off_s, self).encode()

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


class msp430_offs(imm_noarg, msp430_arg):
    parser = base_expr

    def int2expr(self, v):
        if v & ~self.intmask != 0:
            return None
        return ExprInt(v, 16)

    def decodeval(self, v):
        v <<= 1
        v += self.parent.l
        return v

    def encodeval(self, v):
        plen = self.parent.l + self.l
        assert(plen % 8 == 0)
        v -= plen // 8
        if v % 2 != 0:
            return False
        return v >> 1

    def decode(self, v):
        v = v & self.lmask
        if (1 << (self.l - 1)) & v:
            v |= ~0 ^ self.lmask
        v = self.decodeval(v)
        self.expr = ExprInt(v, 16)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
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

# Offset must be decoded in last position to have final instruction len
offimm = bs(l=10, cls=(msp430_offs,), fname="offs", order=-1)

bs_f2_jcc = bs_name(l=3, name={'jnz': 0, 'jz': 1, 'jnc': 2, 'jc': 3, 'jn': 4,
                               'jge': 5, 'jl': 6, 'jmp': 7})
addop("f2_3", [bs('001'), bs_f2_jcc, offimm])

