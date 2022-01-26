#-*- coding:utf-8 -*-

from builtins import range
import re
import struct
import logging
from collections import defaultdict


from future.utils import viewitems, viewvalues

import pyparsing

from miasm.core.utils import decode_hex
import miasm.expression.expression as m2_expr
from miasm.core.bin_stream import bin_stream, bin_stream_str
from miasm.core.utils import Disasm_Exception
from miasm.expression.simplifications import expr_simp


from miasm.core.asm_ast import AstNode, AstInt, AstId, AstOp
from miasm.core import utils
from future.utils import with_metaclass

log = logging.getLogger("cpuhelper")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


class bitobj(object):

    def __init__(self, s=b""):
        if not s:
            bits = []
        else:
            bits = [int(x) for x in bin(int(encode_hex(s), 16))[2:]]
            if len(bits) % 8:
                bits = [0 for x in range(8 - (len(bits) % 8))] + bits
        self.bits = bits
        self.offset = 0

    def __len__(self):
        return len(self.bits) - self.offset

    def getbits(self, n):
        if not n:
            return 0
        if n > len(self.bits) - self.offset:
            raise ValueError('not enough bits %r %r' % (n, len(self.bits)))
        b = self.bits[self.offset:self.offset + n]
        b = int("".join(str(x) for x in b), 2)
        self.offset += n
        return b

    def putbits(self, b, n):
        if not n:
            return
        bits = list(bin(b)[2:])
        bits = [int(x) for x in bits]
        bits = [0 for x in range(n - len(bits))] + bits
        self.bits += bits

    def tostring(self):
        if len(self.bits) % 8:
            raise ValueError(
                'num bits must be 8 bit aligned: %d' % len(self.bits)
            )
        b = int("".join(str(x) for x in self.bits), 2)
        b = "%X" % b
        b = '0' * (len(self.bits) // 4 - len(b)) + b
        b = decode_hex(b.encode())
        return b

    def reset(self):
        self.offset = 0

    def copy_state(self):
        b = self.__class__()
        b.bits = self.bits
        b.offset = self.offset
        return b


def literal_list(l):
    l = l[:]
    l.sort()
    l = l[::-1]
    o = pyparsing.Literal(l[0])
    for x in l[1:]:
        o |= pyparsing.Literal(x)
    return o


class reg_info(object):

    def __init__(self, reg_str, reg_expr):
        self.str = reg_str
        self.expr = reg_expr
        self.parser = literal_list(reg_str).setParseAction(self.cb_parse)

    def cb_parse(self, tokens):
        assert len(tokens) == 1
        i = self.str.index(tokens[0])
        reg = self.expr[i]
        result = AstId(reg)
        return result

    def reg2expr(self, s):
        i = self.str.index(s[0])
        return self.expr[i]

    def expr2regi(self, e):
        return self.expr.index(e)


class reg_info_dct(object):

    def __init__(self, reg_expr):
        self.dct_str_inv = dict((v.name, k) for k, v in viewitems(reg_expr))
        self.dct_expr = reg_expr
        self.dct_expr_inv = dict((v, k) for k, v in viewitems(reg_expr))
        reg_str = [v.name for v in viewvalues(reg_expr)]
        self.parser = literal_list(reg_str).setParseAction(self.cb_parse)

    def cb_parse(self, tokens):
        assert len(tokens) == 1
        i = self.dct_str_inv[tokens[0]]
        reg = self.dct_expr[i]
        result = AstId(reg)
        return result

    def reg2expr(self, s):
        i = self.dct_str_inv[s[0]]
        return self.dct_expr[i]

    def expr2regi(self, e):
        return self.dct_expr_inv[e]


def gen_reg(reg_name, sz=32):
    """Gen reg expr and parser"""
    reg = m2_expr.ExprId(reg_name, sz)
    reginfo = reg_info([reg_name], [reg])
    return reg, reginfo


def gen_reg_bs(reg_name, reg_info, base_cls):
    """
    Generate:
        class bs_reg_name(base_cls):
            reg = reg_info

        bs_reg_name = bs(l=0, cls=(bs_reg_name,))
    """

    bs_name = "bs_%s" % reg_name
    cls = type(bs_name, base_cls, {'reg': reg_info})

    bs_obj = bs(l=0, cls=(cls,))

    return cls, bs_obj


def gen_regs(rnames, env, sz=32):
    regs_str = []
    regs_expr = []
    regs_init = []
    for rname in rnames:
        r = m2_expr.ExprId(rname, sz)
        r_init = m2_expr.ExprId(rname+'_init', sz)
        regs_str.append(rname)
        regs_expr.append(r)
        regs_init.append(r_init)
        env[rname] = r

    reginfo = reg_info(regs_str, regs_expr)
    return regs_expr, regs_init, reginfo


LPARENTHESIS = pyparsing.Literal("(")
RPARENTHESIS = pyparsing.Literal(")")


def int2expr(tokens):
    v = tokens[0]
    return (m2_expr.ExprInt, v)


def parse_op(tokens):
    v = tokens[0]
    return (m2_expr.ExprOp, v)


def parse_id(tokens):
    v = tokens[0]
    return (m2_expr.ExprId, v)


def ast_parse_op(tokens):
    if len(tokens) == 1:
        return tokens[0]
    if len(tokens) == 2:
        if tokens[0] in ['-', '+', '!']:
            return m2_expr.ExprOp(tokens[0], tokens[1])
    if len(tokens) == 3:
        if tokens[1] == '-':
            # a - b => a + (-b)
            tokens[1] = '+'
            tokens[2] = - tokens[2]
        return m2_expr.ExprOp(tokens[1], tokens[0], tokens[2])
    tokens = tokens[::-1]
    while len(tokens) >= 3:
        o1, op, o2 = tokens.pop(), tokens.pop(), tokens.pop()
        if op == '-':
            # a - b => a + (-b)
            op = '+'
            o2 = - o2
        e = m2_expr.ExprOp(op, o1, o2)
        tokens.append(e)
    if len(tokens) != 1:
        raise NotImplementedError('strange op')
    return tokens[0]


def ast_id2expr(a):
    return m2_expr.ExprId(a, 32)


def ast_int2expr(a):
    return m2_expr.ExprInt(a, 32)


def neg_int(tokens):
    x = -tokens[0]
    return x


integer = pyparsing.Word(pyparsing.nums).setParseAction(lambda tokens: int(tokens[0]))
hex_word = pyparsing.Literal('0x') + pyparsing.Word(pyparsing.hexnums)
hex_int = pyparsing.Combine(hex_word).setParseAction(lambda tokens: int(tokens[0], 16))

# str_int = (Optional('-') + (hex_int | integer))
str_int_pos = (hex_int | integer)
str_int_neg = (pyparsing.Suppress('-') + \
                   (hex_int | integer)).setParseAction(neg_int)

str_int = str_int_pos | str_int_neg
str_int.setParseAction(int2expr)

logicop = pyparsing.oneOf('& | ^ >> << <<< >>>')
signop = pyparsing.oneOf('+ -')
multop = pyparsing.oneOf('* / %')
plusop = pyparsing.oneOf('+ -')


##########################

def literal_list(l):
    l = l[:]
    l.sort()
    l = l[::-1]
    o = pyparsing.Literal(l[0])
    for x in l[1:]:
        o |= pyparsing.Literal(x)
    return o


def cb_int(tokens):
    assert len(tokens) == 1
    integer = AstInt(tokens[0])
    return integer


def cb_parse_id(tokens):
    assert len(tokens) == 1
    reg = tokens[0]
    return AstId(reg)


def cb_op_not(tokens):
    tokens = tokens[0]
    assert len(tokens) == 2
    assert tokens[0] == "!"
    result = AstOp("!", tokens[1])
    return result


def merge_ops(tokens, op):
    args = []
    if len(tokens) >= 3:
        args = [tokens.pop(0)]
        i = 0
        while i < len(tokens):
            op_tmp = tokens[i]
            arg = tokens[i+1]
            i += 2
            if op_tmp != op:
                raise ValueError("Bad operator")
            args.append(arg)
    result = AstOp(op, *args)
    return result


def cb_op_and(tokens):
    result = merge_ops(tokens[0], "&")
    return result


def cb_op_xor(tokens):
    result = merge_ops(tokens[0], "^")
    return result


def cb_op_sign(tokens):
    assert len(tokens) == 1
    op, value = tokens[0]
    return -value


def cb_op_div(tokens):
    tokens = tokens[0]
    assert len(tokens) == 3
    assert tokens[1] == "/"
    result = AstOp("/", tokens[0], tokens[2])
    return result


def cb_op_plusminus(tokens):
    tokens = tokens[0]
    if len(tokens) == 3:
        # binary op
        assert isinstance(tokens[0], AstNode)
        assert isinstance(tokens[2], AstNode)
        op, args = tokens[1], [tokens[0], tokens[2]]
    elif len(tokens) > 3:
        args = [tokens.pop(0)]
        i = 0
        while i < len(tokens):
            op = tokens[i]
            arg = tokens[i+1]
            i += 2
            if op == '-':
                arg = -arg
            elif op == '+':
                pass
            else:
                raise ValueError("Bad operator")
            args.append(arg)
        op = '+'
    else:
        raise ValueError("Parsing error")
    assert all(isinstance(arg, AstNode) for arg in args)
    result = AstOp(op, *args)
    return result


def cb_op_mul(tokens):
    tokens = tokens[0]
    assert len(tokens) == 3
    assert isinstance(tokens[0], AstNode)
    assert isinstance(tokens[2], AstNode)

    # binary op
    op, args = tokens[1], [tokens[0], tokens[2]]
    result = AstOp(op, *args)
    return result


integer = pyparsing.Word(pyparsing.nums).setParseAction(lambda tokens: int(tokens[0]))
hex_word = pyparsing.Literal('0x') + pyparsing.Word(pyparsing.hexnums)
hex_int = pyparsing.Combine(hex_word).setParseAction(lambda tokens: int(tokens[0], 16))

str_int_pos = (hex_int | integer)

str_int = str_int_pos
str_int.setParseAction(cb_int)

notop = pyparsing.oneOf('!')
andop = pyparsing.oneOf('&')
orop = pyparsing.oneOf('|')
xorop = pyparsing.oneOf('^')
shiftop = pyparsing.oneOf('>> <<')
rotop = pyparsing.oneOf('<<< >>>')
signop = pyparsing.oneOf('+ -')
mulop = pyparsing.oneOf('*')
plusop = pyparsing.oneOf('+ -')
divop = pyparsing.oneOf('/')


variable = pyparsing.Word(pyparsing.alphas + "_$.", pyparsing.alphanums + "_")
variable.setParseAction(cb_parse_id)
operand = str_int | variable

base_expr = pyparsing.operatorPrecedence(operand,
                               [(notop,   1, pyparsing.opAssoc.RIGHT, cb_op_not),
                                (andop, 2, pyparsing.opAssoc.RIGHT, cb_op_and),
                                (xorop, 2, pyparsing.opAssoc.RIGHT, cb_op_xor),
                                (signop,  1, pyparsing.opAssoc.RIGHT, cb_op_sign),
                                (mulop,  2, pyparsing.opAssoc.RIGHT, cb_op_mul),
                                (divop,  2, pyparsing.opAssoc.RIGHT, cb_op_div),
                                (plusop,  2, pyparsing.opAssoc.LEFT, cb_op_plusminus),
                                ])


default_prio = 0x1337


def isbin(s):
    return re.match('[0-1]+$', s)


def int2bin(i, l):
    s = '0' * l + bin(i)[2:]
    return s[-l:]


def myror32(v, r):
    return ((v & 0xFFFFFFFF) >> r) | ((v << (32 - r)) & 0xFFFFFFFF)


def myrol32(v, r):
    return ((v & 0xFFFFFFFF) >> (32 - r)) | ((v << r) & 0xFFFFFFFF)


class bs(object):
    all_new_c = {}
    prio = default_prio

    def __init__(self, strbits=None, l=None, cls=None,
                 fname=None, order=0, flen=None, **kargs):
        if fname is None:
            fname = hex(id(str((strbits, l, cls, fname, order, flen, kargs))))
        if strbits is None:
            strbits = ""  # "X"*l
        elif l is None:
            l = len(strbits)
        if strbits and isbin(strbits):
            value = int(strbits, 2)
        elif 'default_val' in kargs:
            value = int(kargs['default_val'], 2)
        else:
            value = None
        allbits = list(strbits)
        allbits.reverse()
        fbits = 0
        fmask = 0
        while allbits:
            a = allbits.pop()
            if a == " ":
                continue
            fbits <<= 1
            fmask <<= 1
            if a in '01':
                a = int(a)
                fbits |= a
                fmask |= 1
        lmask = (1 << l) - 1
        # gen conditional field
        if cls:
            for b in cls:
                if 'flen' in b.__dict__:
                    flen = getattr(b, 'flen')

        self.strbits = strbits
        self.l = l
        self.cls = cls
        self.fname = fname
        self.order = order
        self.fbits = fbits
        self.fmask = fmask
        self.flen = flen
        self.value = value
        self.kargs = kargs

    lmask = property(lambda self:(1 << self.l) - 1)

    def __getitem__(self, item):
        return getattr(self, item)

    def __repr__(self):
        o = self.__class__.__name__
        if self.fname:
            o += "_%s" % self.fname
        o += "_%(strbits)s" % self
        if self.cls:
            o += '_' + '_'.join([x.__name__ for x in self.cls])
        return o

    def gen(self, parent):
        c_name = 'nbsi'
        if self.cls:
            c_name += '_' + '_'.join([x.__name__ for x in self.cls])
            bases = list(self.cls)
        else:
            bases = []
        # bsi added at end of list
        # used to use first function of added class
        bases += [bsi]
        k = c_name, tuple(bases)
        if k in self.all_new_c:
            new_c = self.all_new_c[k]
        else:
            new_c = type(c_name, tuple(bases), {})
            self.all_new_c[k] = new_c
        c = new_c(parent,
                  self.strbits, self.l, self.cls,
                  self.fname, self.order, self.lmask, self.fbits,
                  self.fmask, self.value, self.flen, **self.kargs)
        return c

    def check_fbits(self, v):
        return v & self.fmask == self.fbits

    @classmethod
    def flen(cls, v):
        raise NotImplementedError('not fully functional')


class dum_arg(object):

    def __init__(self, e=None):
        self.expr = e


class bsopt(bs):

    def ispresent(self):
        return True


class bsi(object):

    def __init__(self, parent, strbits, l, cls, fname, order,
                 lmask, fbits, fmask, value, flen, **kargs):
        self.parent = parent
        self.strbits = strbits
        self.l = l
        self.cls = cls
        self.fname = fname
        self.order = order
        self.fbits = fbits
        self.fmask = fmask
        self.flen = flen
        self.value = value
        self.kargs = kargs
        self.__dict__.update(self.kargs)

    lmask = property(lambda self:(1 << self.l) - 1)

    def decode(self, v):
        self.value = v & self.lmask
        return True

    def encode(self):
        return True

    def clone(self):
        s = self.__class__(self.parent,
                           self.strbits, self.l, self.cls,
                           self.fname, self.order, self.lmask, self.fbits,
                           self.fmask, self.value, self.flen, **self.kargs)
        s.__dict__.update(self.kargs)
        if hasattr(self, 'expr'):
            s.expr = self.expr
        return s

    def __hash__(self):
        kargs = []
        for k, v in list(viewitems(self.kargs)):
            if isinstance(v, list):
                v = tuple(v)
            kargs.append((k, v))
        l = [self.strbits, self.l, self.cls,
             self.fname, self.order, self.lmask, self.fbits,
             self.fmask, self.value]  # + kargs

        return hash(tuple(l))


class bs_divert(object):
    prio = default_prio

    def __init__(self, **kargs):
        self.args = kargs

    def __getattr__(self, item):
        if item in self.__dict__:
            return self.__dict__[item]
        elif item in self.args:
            return self.args.get(item)
        else:
            raise AttributeError


class bs_name(bs_divert):
    prio = 1

    def divert(self, i, candidates):
        out = []
        for cls, _, bases, dct, fields in candidates:
            for new_name, value in viewitems(self.args['name']):
                nfields = fields[:]
                s = int2bin(value, self.args['l'])
                args = dict(self.args)
                args.update({'strbits': s})
                f = bs(**args)
                nfields[i] = f
                ndct = dict(dct)
                ndct['name'] = new_name
                out.append((cls, new_name, bases, ndct, nfields))
        return out


class bs_mod_name(bs_divert):
    prio = 2

    def divert(self, i, candidates):
        out = []
        for cls, _, bases, dct, fields in candidates:
            tab = self.args['mn_mod']
            if isinstance(tab, list):
                tmp = {}
                for j, v in enumerate(tab):
                    tmp[j] = v
                tab = tmp
            for value, new_name in viewitems(tab):
                nfields = fields[:]
                s = int2bin(value, self.args['l'])
                args = dict(self.args)
                args.update({'strbits': s})
                f = bs(**args)
                nfields[i] = f
                ndct = dict(dct)
                ndct['name'] = self.modname(ndct['name'], value)
                out.append((cls, new_name, bases, ndct, nfields))
        return out

    def modname(self, name, i):
        return name + self.args['mn_mod'][i]


class bs_cond(bsi):
    pass


class bs_swapargs(bs_divert):

    def divert(self, i, candidates):
        out = []
        for cls, name, bases, dct, fields in candidates:
            # args not permuted
            ndct = dict(dct)
            nfields = fields[:]
            # gen fix field
            f = gen_bsint(0, self.args['l'], self.args)
            nfields[i] = f
            out.append((cls, name, bases, ndct, nfields))

            # args permuted
            ndct = dict(dct)
            nfields = fields[:]
            ap = ndct['args_permut'][:]
            a = ap.pop(0)
            b = ap.pop(0)
            ndct['args_permut'] = [b, a] + ap
            # gen fix field
            f = gen_bsint(1, self.args['l'], self.args)
            nfields[i] = f

            out.append((cls, name, bases, ndct, nfields))
        return out


class m_arg(object):

    def fromstring(self, text, loc_db, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
            self.expr = e
            return start, stop
        try:
            v, start, stop = next(self.parser.scanString(text))
        except StopIteration:
            return None, None
        arg = v[0]
        expr = self.asm_ast_to_expr(arg, loc_db)
        self.expr = expr
        return start, stop

    def asm_ast_to_expr(self, arg, loc_db, **kwargs):
        raise NotImplementedError("Virtual")


class m_reg(m_arg):
    prio = default_prio

    @property
    def parser(self):
        return self.reg.parser

    def decode(self, v):
        self.expr = self.reg.expr[0]
        return True

    def encode(self):
        return self.expr == self.reg.expr[0]


class reg_noarg(object):
    reg_info = None
    parser = None

    def fromstring(self, text, loc_db, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
            self.expr = e
            return start, stop
        try:
            v, start, stop = next(self.parser.scanString(text))
        except StopIteration:
            return None, None
        arg = v[0]
        expr = self.parses_to_expr(arg, loc_db)
        self.expr = expr
        return start, stop

    def decode(self, v):
        v = v & self.lmask
        if v >= len(self.reg_info.expr):
            return False
        self.expr = self.reg_info.expr[v]
        return True

    def encode(self):
        if not self.expr in self.reg_info.expr:
            log.debug("cannot encode reg %r", self.expr)
            return False
        self.value = self.reg_info.expr.index(self.expr)
        return True

    def check_fbits(self, v):
        return v & self.fmask == self.fbits


class mn_prefix(object):
    pass


def swap16(v):
    return struct.unpack('<H', struct.pack('>H', v))[0]


def swap32(v):
    return struct.unpack('<I', struct.pack('>I', v))[0]


def perm_inv(p):
    o = [None for x in range(len(p))]
    for i, x in enumerate(p):
        o[x] = i
    return o


def gen_bsint(value, l, args):
    s = int2bin(value, l)
    args = dict(args)
    args.update({'strbits': s})
    f = bs(**args)
    return f

total_scans = 0


def branch2nodes(branch, nodes=None):
    if nodes is None:
        nodes = []
    for k, v in viewitems(branch):
        if not isinstance(v, dict):
            continue
        for k2 in v:
            nodes.append((k, k2))
        branch2nodes(v, nodes)


def factor_one_bit(tree):
    if isinstance(tree, set):
        return tree
    new_keys = defaultdict(lambda: defaultdict(dict))
    if len(tree) == 1:
        return tree
    for k, v in viewitems(tree):
        if k == "mn":
            new_keys[k] = v
            continue
        l, fmask, fbits, fname, flen = k
        if flen is not None or l <= 1:
            new_keys[k] = v
            continue
        cfmask = fmask >> (l - 1)
        nfmask = fmask & ((1 << (l - 1)) - 1)
        cfbits = fbits >> (l - 1)
        nfbits = fbits & ((1 << (l - 1)) - 1)
        ck = 1, cfmask, cfbits, None, flen
        nk = l - 1, nfmask, nfbits, fname, flen
        if nk in new_keys[ck]:
            raise NotImplementedError('not fully functional')
        new_keys[ck][nk] = v
    for k, v in list(viewitems(new_keys)):
        new_keys[k] = factor_one_bit(v)
    # try factor sons
    if len(new_keys) != 1:
        return new_keys
    subtree = next(iter(viewvalues(new_keys)))
    if len(subtree) != 1:
        return new_keys
    if next(iter(subtree)) == 'mn':
        return new_keys

    return new_keys


def factor_fields(tree):
    if not isinstance(tree, dict):
        return tree
    if len(tree) != 1:
        return tree
    # merge
    k1, v1 = next(iter(viewitems(tree)))
    if k1 == "mn":
        return tree
    l1, fmask1, fbits1, fname1, flen1 = k1
    if fname1 is not None:
        return tree
    if flen1 is not None:
        return tree

    if not isinstance(v1, dict):
        return tree
    if len(v1) != 1:
        return tree
    k2, v2 = next(iter(viewitems(v1)))
    if k2 == "mn":
        return tree
    l2, fmask2, fbits2, fname2, flen2 = k2
    if fname2 is not None:
        return tree
    if flen2 is not None:
        return tree
    l = l1 + l2
    fmask = (fmask1 << l2) | fmask2
    fbits = (fbits1 << l2) | fbits2
    fname = fname2
    flen = flen2
    k = l, fmask, fbits, fname, flen
    new_keys = {k: v2}
    return new_keys


def factor_fields_all(tree):
    if not isinstance(tree, dict):
        return tree
    new_keys = {}
    for k, v in viewitems(tree):
        v = factor_fields(v)
        new_keys[k] = factor_fields_all(v)
    return new_keys


def graph_tree(tree):
    nodes = []
    branch2nodes(tree, nodes)

    out = """
          digraph G {
          """
    for a, b in nodes:
        if b == 'mn':
            continue
        out += "%s -> %s;\n" % (id(a), id(b))
    out += "}"
    open('graph.txt', 'w').write(out)


def add_candidate_to_tree(tree, c):
    branch = tree
    for f in c.fields:
        if f.l == 0:
            continue
        node = f.l, f.fmask, f.fbits, f.fname, f.flen

        if not node in branch:
            branch[node] = {}
        branch = branch[node]
    if not 'mn' in branch:
        branch['mn'] = set()
    branch['mn'].add(c)


def add_candidate(bases, c):
    add_candidate_to_tree(bases[0].bintree, c)


def getfieldby_name(fields, fname):
    f = [x for x in fields if hasattr(x, 'fname') and x.fname == fname]
    if len(f) != 1:
        raise ValueError('more than one field with name: %s' % fname)
    return f[0]


def getfieldindexby_name(fields, fname):
    for i, f in enumerate(fields):
        if hasattr(f, 'fname') and f.fname == fname:
            return f, i
    return None


class metamn(type):

    def __new__(mcs, name, bases, dct):
        if name == "cls_mn" or name.startswith('mn_'):
            return type.__new__(mcs, name, bases, dct)
        alias = dct.get('alias', False)

        fields = bases[0].mod_fields(dct['fields'])
        if not 'name' in dct:
            dct["name"] = bases[0].getmn(name)
        if 'args' in dct:
            # special case for permuted arguments
            o = []
            p = []
            for i, a in enumerate(dct['args']):
                o.append((i, a))
                if a in fields:
                    p.append((fields.index(a), a))
            p.sort()
            p = [x[1] for x in p]
            p = [dct['args'].index(x) for x in p]
            dct['args_permut'] = perm_inv(p)
        # order fields
        f_ordered = [x for x in enumerate(fields)]
        f_ordered.sort(key=lambda x: (x[1].prio, x[0]))
        candidates = bases[0].gen_modes(mcs, name, bases, dct, fields)
        for i, fc in f_ordered:
            if isinstance(fc, bs_divert):
                candidates = fc.divert(i, candidates)
        for cls, name, bases, dct, fields in candidates:
            ndct = dict(dct)
            fields = [f for f in fields if f]
            ndct['fields'] = fields
            ndct['mn_len'] = sum([x.l for x in fields])
            c = type.__new__(cls, name, bases, ndct)
            c.alias = alias
            c.check_mnemo(fields)
            c.num = bases[0].num
            bases[0].num += 1
            bases[0].all_mn.append(c)
            mode = dct['mode']
            bases[0].all_mn_mode[mode].append(c)
            bases[0].all_mn_name[c.name].append(c)
            i = c()
            i.init_class()
            bases[0].all_mn_inst[c].append(i)
            add_candidate(bases, c)
            # gen byte lookup
            o = ""
            for f in i.fields_order:
                if not isinstance(f, bsi):
                    raise ValueError('f is not bsi')
                if f.l == 0:
                    continue
                o += f.strbits
        return c


class instruction(object):
    __slots__ = ["name", "mode", "args",
                 "l", "b", "offset", "data",
                 "additional_info", "delayslot"]

    def __init__(self, name, mode, args, additional_info=None):
        self.name = name
        self.mode = mode
        self.args = args
        self.additional_info = additional_info
        self.offset = None
        self.l = None
        self.b = None
        self.delayslot = 0

    def gen_args(self, args):
        out = ', '.join([str(x) for x in args])
        return out

    def __str__(self):
        return self.to_string()

    def to_string(self, loc_db=None):
        o = "%-10s " % self.name
        args = []
        for i, arg in enumerate(self.args):
            if not isinstance(arg, m2_expr.Expr):
                raise ValueError('zarb arg type')
            x = self.arg2str(arg, i, loc_db)
            args.append(x)
        o += self.gen_args(args)
        return o

    def to_html(self, loc_db=None):
        out = "%-10s " % self.name
        out = '<font color="%s">%s</font>' % (utils.COLOR_MNEMO, out)

        args = []
        for i, arg in enumerate(self.args):
            if not isinstance(arg, m2_expr.Expr):
                raise ValueError('zarb arg type')
            x = self.arg2html(arg, i, loc_db)
            args.append(x)
        out += self.gen_args(args)
        return out

    def get_asm_offset(self, expr):
        return m2_expr.ExprInt(self.offset, expr.size)

    def get_asm_next_offset(self, expr):
        return m2_expr.ExprInt(self.offset+self.l, expr.size)

    def resolve_args_with_symbols(self, loc_db):
        args_out = []
        for expr in self.args:
            # try to resolve symbols using loc_db (0 for default value)
            loc_keys = m2_expr.get_expr_locs(expr)
            fixed_expr = {}
            for exprloc in loc_keys:
                loc_key = exprloc.loc_key
                names = loc_db.get_location_names(loc_key)
                # special symbols
                if '$' in names:
                    fixed_expr[exprloc] = self.get_asm_offset(exprloc)
                    continue
                if '_' in names:
                    fixed_expr[exprloc] = self.get_asm_next_offset(exprloc)
                    continue
                arg_int = loc_db.get_location_offset(loc_key)
                if arg_int is not None:
                    fixed_expr[exprloc] = m2_expr.ExprInt(arg_int, exprloc.size)
                    continue
                if not names:
                    raise ValueError('Unresolved symbol: %r' % exprloc)

                offset = loc_db.get_location_offset(loc_key)
                if offset is None:
                    raise ValueError(
                        'The offset of loc_key "%s" cannot be determined' % names
                    )
                else:
                    # Fix symbol with its offset
                    size = exprloc.size
                    if size is None:
                        default_size = self.get_symbol_size(exprloc, loc_db)
                        size = default_size
                    value = m2_expr.ExprInt(offset, size)
                fixed_expr[exprloc] = value

            expr = expr.replace_expr(fixed_expr)
            expr = expr_simp(expr)
            args_out.append(expr)
        return args_out

    def get_info(self, c):
        return


class cls_mn(with_metaclass(metamn, object)):
    args_symb = []
    instruction = instruction
    # Block's offset alignment
    alignment = 1

    @classmethod
    def guess_mnemo(cls, bs, attrib, pre_dis_info, offset):
        candidates = []

        candidates = set()

        fname_values = pre_dis_info
        todo = [
            (dict(fname_values), branch, offset * 8)
            for branch in list(viewitems(cls.bintree))
        ]
        for fname_values, branch, offset_b in todo:
            (l, fmask, fbits, fname, flen), vals = branch

            if flen is not None:
                l = flen(attrib, fname_values)
            if l is not None:
                try:
                    v = cls.getbits(bs, attrib, offset_b, l)
                except IOError:
                    # Raised if offset is out of bound
                    continue
                offset_b += l
                if v & fmask != fbits:
                    continue
                if fname is not None and not fname in fname_values:
                    fname_values[fname] = v
            for nb, v in viewitems(vals):
                if 'mn' in nb:
                    candidates.update(v)
                else:
                    todo.append((dict(fname_values), (nb, v), offset_b))

        return [c for c in candidates]

    def reset_class(self):
        for f in self.fields_order:
            if f.strbits and isbin(f.strbits):
                f.value = int(f.strbits, 2)
            elif 'default_val' in f.kargs:
                f.value = int(f.kargs['default_val'], 2)
            else:
                f.value = None
            if f.fname:
                setattr(self, f.fname, f)

    def init_class(self):
        args = []
        fields_order = []
        to_decode = []
        off = 0
        for i, fc in enumerate(self.fields):
            f = fc.gen(self)
            f.offset = off
            off += f.l
            fields_order.append(f)
            to_decode.append((i, f))

            if isinstance(f, m_arg):
                args.append(f)
            if f.fname:
                setattr(self, f.fname, f)
        if hasattr(self, 'args_permut'):
            args = [args[self.args_permut[i]]
                    for i in range(len(self.args_permut))]
        to_decode.sort(key=lambda x: (x[1].order, x[0]))
        to_decode = [fields_order.index(f[1]) for f in to_decode]
        self.args = args
        self.fields_order = fields_order
        self.to_decode = to_decode

    def add_pre_dis_info(self, prefix=None):
        return True

    @classmethod
    def getbits(cls, bs, attrib, offset_b, l):
        return bs.getbits(offset_b, l)

    @classmethod
    def getbytes(cls, bs, offset, l):
        return bs.getbytes(offset, l)

    @classmethod
    def pre_dis(cls, v_o, attrib, offset):
        return {}, v_o, attrib, offset, 0

    def post_dis(self):
        return self

    @classmethod
    def check_mnemo(cls, fields):
        pass

    @classmethod
    def mod_fields(cls, fields):
        return fields

    @classmethod
    def dis(cls, bs_o, mode_o = None, offset=0):
        if not isinstance(bs_o, bin_stream):
            bs_o = bin_stream_str(bs_o)

        bs_o.enter_atomic_mode()

        offset_o = offset
        try:
            pre_dis_info, bs, mode, offset, prefix_len = cls.pre_dis(
                bs_o, mode_o, offset)
        except:
            bs_o.leave_atomic_mode()
            raise
        candidates = cls.guess_mnemo(bs, mode, pre_dis_info, offset)
        if not candidates:
            bs_o.leave_atomic_mode()
            raise Disasm_Exception('cannot disasm (guess) at %X' % offset)

        out = []
        out_c = []
        if hasattr(bs, 'getlen'):
            bs_l = bs.getlen()
        else:
            bs_l = len(bs)

        alias = False
        for c in candidates:
            log.debug("*" * 40, mode, c.mode)
            log.debug(c.fields)

            c = cls.all_mn_inst[c][0]

            c.reset_class()
            c.mode = mode

            if not c.add_pre_dis_info(pre_dis_info):
                continue

            todo = {}
            getok = True
            fname_values = dict(pre_dis_info)
            offset_b = offset * 8

            total_l = 0
            for i, f in enumerate(c.fields_order):
                if f.flen is not None:
                    l = f.flen(mode, fname_values)
                else:
                    l = f.l
                if l is not None:
                    total_l += l
                    f.l = l
                    f.is_present = True
                    log.debug("FIELD %s %s %s %s", f.__class__, f.fname,
                              offset_b, l)
                    if bs_l * 8 - offset_b < l:
                        getok = False
                        break
                    try:
                        bv = cls.getbits(bs, mode, offset_b, l)
                    except:
                        bs_o.leave_atomic_mode()
                        raise
                    offset_b += l
                    if not f.fname in fname_values:
                        fname_values[f.fname] = bv
                    todo[i] = bv
                else:
                    f.is_present = False
                    todo[i] = None

            if not getok:
                continue

            c.l = prefix_len + total_l // 8
            for i in c.to_decode:
                f = c.fields_order[i]
                if f.is_present:
                    ret = f.decode(todo[i])
                    if not ret:
                        log.debug("cannot decode %r", f)
                        break

            if not ret:
                continue
            for a in c.args:
                a.expr = expr_simp(a.expr)

            c.b = cls.getbytes(bs, offset_o, c.l)
            c.offset = offset_o
            c = c.post_dis()
            if c is None:
                continue
            c_args = [a.expr for a in c.args]
            instr = cls.instruction(c.name, mode, c_args,
                                    additional_info=c.additional_info())
            instr.l = prefix_len + total_l // 8
            instr.b = cls.getbytes(bs, offset_o, instr.l)
            instr.offset = offset_o
            instr.get_info(c)
            if c.alias:
                alias = True
            out.append(instr)
            out_c.append(c)

        bs_o.leave_atomic_mode()

        if not out:
            raise Disasm_Exception('cannot disasm at %X' % offset_o)
        if len(out) != 1:
            if not alias:
                log.warning('dis multiple args ret default')

            for i, o in enumerate(out_c):
                if o.alias:
                    return out[i]
            raise NotImplementedError(
                'Multiple disas: \n' +
                "\n".join(str(x) for x in out)
            )
        return out[0]

    @classmethod
    def fromstring(cls, text, loc_db, mode = None):
        global total_scans
        name = re.search('(\S+)', text).groups()
        if not name:
            raise ValueError('cannot find name', text)
        name = name[0]

        if not name in cls.all_mn_name:
            raise ValueError('unknown name', name)
        clist = [x for x in cls.all_mn_name[name]]
        out = []
        out_args = []
        parsers = defaultdict(dict)

        for cc in clist:
            for c in cls.get_cls_instance(cc, mode):
                args_expr = []
                args_str = text[len(name):].strip(' ')

                start = 0
                cannot_parse = False
                len_o = len(args_str)

                for i, f in enumerate(c.args):
                    start_i = len_o - len(args_str)
                    if type(f.parser) == tuple:
                        parser = f.parser
                    else:
                        parser = (f.parser,)
                    for p in parser:
                        if p in parsers[(i, start_i)]:
                            continue
                        try:
                            total_scans += 1
                            v, start, stop = next(p.scanString(args_str))
                        except StopIteration:
                            v, start, stop = [None], None, None
                        if start != 0:
                            v, start, stop = [None], None, None
                        if v != [None]:
                            v = f.asm_ast_to_expr(v[0], loc_db)
                        if v is None:
                            v, start, stop = [None], None, None
                        parsers[(i, start_i)][p] = v, start, stop
                    start, stop = f.fromstring(args_str, loc_db, parsers[(i, start_i)])
                    if start != 0:
                        log.debug("cannot fromstring %r", args_str)
                        cannot_parse = True
                        break
                    if f.expr is None:
                        raise NotImplementedError('not fully functional')
                    f.expr = expr_simp(f.expr)
                    args_expr.append(f.expr)
                    args_str = args_str[stop:].strip(' ')
                    if args_str.startswith(','):
                        args_str = args_str[1:]
                    args_str = args_str.strip(' ')
                if args_str:
                    cannot_parse = True
                if cannot_parse:
                    continue

                out.append(c)
                out_args.append(args_expr)
                break

        if len(out) == 0:
            raise ValueError('cannot fromstring %r' % text)
        if len(out) != 1:
            log.debug('fromstring multiple args ret default')
        c = out[0]
        c_args = out_args[0]

        instr = cls.instruction(c.name, mode, c_args,
                                additional_info=c.additional_info())
        return instr

    def dup_info(self, infos):
        return

    @classmethod
    def get_cls_instance(cls, cc, mode, infos=None):
        c = cls.all_mn_inst[cc][0]

        c.reset_class()
        c.add_pre_dis_info()
        c.dup_info(infos)

        c.mode = mode
        yield c

    @classmethod
    def asm(cls, instr, loc_db=None):
        """
        Re asm instruction by searching mnemo using name and args. We then
        can modify args and get the hex of a modified instruction
        """
        clist = cls.all_mn_name[instr.name]
        clist = [x for x in clist]
        vals = []
        candidates = []
        args = instr.resolve_args_with_symbols(loc_db)

        for cc in clist:

            for c in cls.get_cls_instance(
                cc, instr.mode, instr.additional_info):

                cannot_parse = False
                if len(c.args) != len(instr.args):
                    continue

                # only fix args expr
                for i in range(len(c.args)):
                    c.args[i].expr = args[i]

                v = c.value(instr.mode)
                if not v:
                    log.debug("cannot encode %r", c)
                    cannot_parse = True
                if cannot_parse:
                    continue
                vals += v
                candidates.append((c, v))
        if len(vals) == 0:
            raise ValueError(
                'cannot asm %r %r' %
                (instr.name, [str(x) for x in instr.args])
            )
        if len(vals) != 1:
            log.debug('asm multiple args ret default')

        vals = cls.filter_asm_candidates(instr, candidates)
        return vals

    @classmethod
    def filter_asm_candidates(cls, instr, candidates):
        o = []
        for _, v in candidates:
            o += v
        o.sort(key=len)
        return o

    def value(self, mode):
        todo = [(0, 0, [(x, self.fields_order[x]) for x in self.to_decode[::-1]])]

        result = []
        done = []

        while todo:
            index, cur_len, to_decode = todo.pop()
            # TEST XXX
            for _, f in to_decode:
                setattr(self, f.fname, f)
            if (index, [x[1].value for x in to_decode]) in done:
                continue
            done.append((index, [x[1].value for x in to_decode]))

            can_encode = True
            for i, f in to_decode[index:]:
                f.parent.l = cur_len
                ret = f.encode()
                if not ret:
                    log.debug('cannot encode %r', f)
                    can_encode = False
                    break

                if f.value is not None and f.l:
                    if f.value > f.lmask:
                        log.debug('cannot encode %r', f)
                        can_encode = False
                        break
                    cur_len += f.l
                index += 1
                if ret is True:
                    continue

                for _ in ret:
                    o = []
                    if ((index, cur_len, [xx[1].value for xx in to_decode]) in todo or
                        (index, cur_len, [xx[1].value for xx in to_decode]) in done):
                        raise NotImplementedError('not fully functional')

                    for p, f in to_decode:
                        fnew = f.clone()
                        o.append((p, fnew))
                    todo.append((index, cur_len, o))
                can_encode = False

                break
            if not can_encode:
                continue
            result.append(to_decode)

        return self.decoded2bytes(result)

    def encodefields(self, decoded):
        bits = bitobj()
        for _, f in decoded:
            setattr(self, f.fname, f)

            if f.value is None:
                continue
            bits.putbits(f.value, f.l)

        return bits.tostring()

    def decoded2bytes(self, result):
        if not result:
            return []

        out = []
        for decoded in result:
            decoded.sort()

            o = self.encodefields(decoded)
            if o is None:
                continue
            out.append(o)
        out = list(set(out))
        return out

    def gen_args(self, args):
        out = ', '.join([str(x) for x in args])
        return out

    def args2str(self):
        args = []
        for arg in self.args:
            # XXX todo test
            if not (isinstance(arg, m2_expr.Expr) or
                    isinstance(arg.expr, m2_expr.Expr)):
                raise ValueError('zarb arg type')
            x = str(arg)
            args.append(x)
        return args

    def __str__(self):
        o = "%-10s " % self.name
        args = []
        for arg in self.args:
            # XXX todo test
            if not (isinstance(arg, m2_expr.Expr) or
                    isinstance(arg.expr, m2_expr.Expr)):
                raise ValueError('zarb arg type')
            x = str(arg)
            args.append(x)

        o += self.gen_args(args)
        return o

    def parse_prefix(self, v):
        return 0

    def set_dst_symbol(self, loc_db):
        dst = self.getdstflow(loc_db)
        args = []
        for d in dst:
            if isinstance(d, m2_expr.ExprInt):
                l = loc_db.get_or_create_offset_location(int(d))

                a = m2_expr.ExprId(l.name, d.size)
            else:
                a = d
            args.append(a)
        self.args_symb = args

    def getdstflow(self, loc_db):
        return [self.args[0].expr]


class imm_noarg(object):
    intsize = 32
    intmask = (1 << intsize) - 1

    def int2expr(self, v):
        if (v & ~self.intmask) != 0:
            return None
        return m2_expr.ExprInt(v, self.intsize)

    def expr2int(self, e):
        if not isinstance(e, m2_expr.ExprInt):
            return None
        v = int(e)
        if v & ~self.intmask != 0:
            return None
        return v

    def fromstring(self, text, loc_db, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
        else:
            try:
                e, start, stop = next(self.parser.scanString(text))
            except StopIteration:
                return None, None
        if e == [None]:
            return None, None

        assert(m2_expr.is_expr(e))
        self.expr = e
        if self.expr is None:
            log.debug('cannot fromstring int %r', text)
            return None, None
        return start, stop

    def decodeval(self, v):
        return v

    def encodeval(self, v):
        return v

    def decode(self, v):
        v = v & self.lmask
        v = self.decodeval(v)
        e = self.int2expr(v)
        if not e:
            return False
        self.expr = e
        return True

    def encode(self):
        v = self.expr2int(self.expr)
        if v is None:
            return False
        v = self.encodeval(v)
        if v is False:
            return False
        self.value = v
        return True


class imm08_noarg(object):
    int2expr = lambda self, x: m2_expr.ExprInt(x, 8)


class imm16_noarg(object):
    int2expr = lambda self, x: m2_expr.ExprInt(x, 16)


class imm32_noarg(object):
    int2expr = lambda self, x: m2_expr.ExprInt(x, 32)


class imm64_noarg(object):
    int2expr = lambda self, x: m2_expr.ExprInt(x, 64)


class int32_noarg(imm_noarg):
    intsize = 32
    intmask = (1 << intsize) - 1

    def decode(self, v):
        v = sign_ext(v, self.l, self.intsize)
        v = self.decodeval(v)
        self.expr = self.int2expr(v)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        v = int(self.expr)
        if sign_ext(v & self.lmask, self.l, self.intsize) != v:
            return False
        v = self.encodeval(v & self.lmask)
        if v is False:
            return False
        self.value = v & self.lmask
        return True

class bs8(bs):
    prio = default_prio

    def __init__(self, v, cls=None, fname=None, **kargs):
        super(bs8, self).__init__(int2bin(v, 8), 8,
                                  cls=cls, fname=fname, **kargs)




def swap_uint(size, i):
    if size == 8:
        return i & 0xff
    elif size == 16:
        return struct.unpack('<H', struct.pack('>H', i & 0xffff))[0]
    elif size == 32:
        return struct.unpack('<I', struct.pack('>I', i & 0xffffffff))[0]
    elif size == 64:
        return struct.unpack('<Q', struct.pack('>Q', i & 0xffffffffffffffff))[0]
    raise ValueError('unknown int len %r' % size)


def swap_sint(size, i):
    if size == 8:
        return i
    elif size == 16:
        return struct.unpack('<h', struct.pack('>H', i & 0xffff))[0]
    elif size == 32:
        return struct.unpack('<i', struct.pack('>I', i & 0xffffffff))[0]
    elif size == 64:
        return struct.unpack('<q', struct.pack('>Q', i & 0xffffffffffffffff))[0]
    raise ValueError('unknown int len %r' % size)


def sign_ext(v, s_in, s_out):
    assert(s_in <= s_out)
    v &= (1 << s_in) - 1
    sign_in = v & (1 << (s_in - 1))
    if not sign_in:
        return v
    m = (1 << (s_out)) - 1
    m ^= (1 << s_in) - 1
    v |= m
    return v
