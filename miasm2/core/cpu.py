#!/usr/bin/env python
#-*- coding:utf-8 -*-

import re
import struct
import logging
from collections import defaultdict

import pyparsing

import miasm2.expression.expression as m2_expr
from miasm2.core import asmbloc
from miasm2.core.bin_stream import bin_stream, bin_stream_str
from miasm2.core.utils import Disasm_Exception
from miasm2.expression.simplifications import expr_simp

log = logging.getLogger("cpuhelper")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


class bitobj:

    def __init__(self, s=""):
        if not s:
            bits = []
        else:
            bits = list(bin(int(str(s).encode('hex'), 16))[2:])
            bits = [int(x) for x in bits]
            if len(bits) % 8:
                bits = [0 for x in xrange(8 - (len(bits) % 8))] + bits
            bits = ['0' for x in xrange(len(s) * 8 - len(bits))] + bits
        self.bits = bits
        self.offset = 0

    def __len__(self):
        return len(self.bits) - self.offset

    def getbits(self, n):
        if not n:
            return 0
        o = 0
        if n > len(self.bits) - self.offset:
            raise ValueError('not enought bits %r %r' % (n, len(self.bits)))
        b = self.bits[self.offset:self.offset + n]
        b = int("".join([str(x) for x in b]), 2)
        self.offset += n
        return b

    def putbits(self, b, n):
        if not n:
            return
        bits = list(bin(b)[2:])
        bits = [int(x) for x in bits]
        bits = [0 for x in xrange(n - len(bits))] + bits
        self.bits += bits

    def tostring(self):
        if len(self.bits) % 8:
            raise ValueError(
                'num bits must be 8 bit aligned: %d' % len(self.bits))
        b = int("".join([str(x) for x in self.bits]), 2)
        b = "%X" % b
        b = '0' * (len(self.bits) / 4 - len(b)) + b
        b = b.decode('hex')
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


class reg_info:

    def __init__(self, reg_str, reg_expr):
        self.str = reg_str
        self.expr = reg_expr
        self.parser = literal_list(reg_str).setParseAction(self.reg2expr)

    def reg2expr(self, s):
        i = self.str.index(s[0])
        return self.expr[i]

    def expr2regi(self, e):
        return self.expr.index(e)


def gen_reg(rname, env, sz=32):
    """
    Gen reg expr and parser
    Equivalent to:
        PC = ExprId('PC')
        reg_pc_str = ['PC']
        reg_pc_expr = [ExprId(x, sz) for x in reg_pc_str]
        regpc = reg_info(reg_pc_str, reg_pc_expr)

        class bs_rname(m_reg):
            reg = regi_rname

        bsrname = bs(l=0, cls=(bs_rname,))

    """
    rnamel = rname.lower()
    r = m2_expr.ExprId(rname, sz)
    reg_str = [rname]
    reg_expr = [r]
    regi = reg_info(reg_str, reg_expr)
    # define as global val
    cname = "bs_" + rnamel
    c = type(cname, (m_reg,), {'reg': regi})
    env[rname] = r
    env["regi_" + rnamel] = regi
    env[cname] = c
    env["bs" + rnamel] = bs(l=0, cls=(c,))
    return r, regi


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


def int2expr(t):
    v = t[0]
    return (m2_expr.ExprInt, v)


def parse_op(t):
    v = t[0]
    return (m2_expr.ExprOp, v)


def parse_id(t):
    v = t[0]
    return (m2_expr.ExprId, v)


def ast_parse_op(t):
    if len(t) == 1:
        return t[0]
    if len(t) == 2:
        if t[0] in ['-', '+', '!']:
            return m2_expr.ExprOp(t[0], t[1])
    if len(t) == 3:
        args = [t[0], t[2]]
        if t[1] == '-':
            # a - b => a + (-b)
            t[1] = '+'
            t[2] = - t[2]
        return m2_expr.ExprOp(t[1], t[0], t[2])
    t = t[::-1]
    while len(t) >= 3:
        o1, op, o2 = t.pop(), t.pop(), t.pop()
        if op == '-':
            # a - b => a + (-b)
            op = '+'
            o2 = - o2
        e = m2_expr.ExprOp(op, o1, o2)
        t.append(e)
    if len(t) != 1:
        raise NotImplementedError('strange op')
    return t[0]


def ast_id2expr(a):
    return m2_expr.ExprId(a, 32)


def ast_int2expr(a):
    return m2_expr.ExprInt32(a)


def ast_raw2expr(a, my_id2expr, my_int2expr):
    assert(isinstance(a, tuple))
    if a[0] is m2_expr.ExprId:
        e = my_id2expr(a[1])
    elif a[0] is m2_expr.ExprInt:
        e = my_int2expr(a[1])
    elif a[0] is m2_expr.ExprOp:
        out = []
        for x in a[1]:
            if isinstance(x, tuple):
                x = ast_raw2expr(x, my_id2expr, my_int2expr)
            out.append(x)
        e = ast_parse_op(out)
    else:
        raise TypeError('unknown type')
    return e


def ast_get_ids(a):
    assert(isinstance(a, tuple))
    if a[0] is m2_expr.ExprId:
        return set([a[1]])
    elif a[0] is m2_expr.ExprInt:
        return set()
    elif a[0] is m2_expr.ExprOp:
        out = set()
        for x in a[1]:
            if isinstance(x, tuple):
                out.update(ast_get_ids(x))
        return out
    raise TypeError('unknown type')


def _extract_ast_core(a):
    assert(isinstance(a, tuple))
    if a[0] in [m2_expr.ExprInt, m2_expr.ExprId]:
        return a
    elif a[0] is m2_expr.ExprOp:
        out = []
        for x in a[1]:
            if isinstance(x, tuple):
                x = _extract_ast_core(x)
            out.append(x)
        return tuple([a[0]] + [out])
    else:
        raise TypeError('unknown type')


def extract_ast_core(v, my_id2expr, my_int2expr):
    ast_tokens = _extract_ast_core(v)
    ids = ast_get_ids(ast_tokens)
    ids_expr = [my_id2expr(x) for x in ids]
    sizes = set([i.size for i in ids_expr])

    if len(sizes) == 0:
        pass
    elif len(sizes) == 1:
        size = sizes.pop()
        my_int2expr = lambda x: m2_expr.ExprInt_fromsize(size, x)
    else:
        raise ValueError('multiple sizes in ids')
    e = ast_raw2expr(ast_tokens, my_id2expr, my_int2expr)
    return e


class parse_ast:

    def __init__(self, id2expr, int2expr, extract_ast=extract_ast_core):
        self.id2expr = id2expr
        self.int2expr = int2expr
        self.extract_ast_core = extract_ast

    def __call__(self, v):
        v = v[0]
        if isinstance(v, m2_expr.Expr):
            return v
        return self.extract_ast_core(v, self.id2expr, self.int2expr)


def neg_int(t):
    x = -t[0]
    return x


integer = pyparsing.Word(pyparsing.nums).setParseAction(lambda _a, _b, t:
                                                            int(t[0]))
hex_word = pyparsing.Literal('0x') + pyparsing.Word(pyparsing.hexnums)
hex_int = pyparsing.Combine(hex_word).setParseAction(lambda _a, _b, t:
                                                         int(t[0], 16))

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


def gen_base_expr():
    variable = pyparsing.Word(pyparsing.alphas + "_$.",
                              pyparsing.alphanums + "_")
    variable.setParseAction(parse_id)
    operand = str_int | variable
    base_expr = pyparsing.operatorPrecedence(operand,
                                   [("!", 1, pyparsing.opAssoc.RIGHT, parse_op),
                                    (logicop, 2, pyparsing.opAssoc.RIGHT,
                                     parse_op),
                                    (signop, 1, pyparsing.opAssoc.RIGHT,
                                     parse_op),
                                    (multop, 2, pyparsing.opAssoc.LEFT,
                                     parse_op),
                                    (plusop, 2, pyparsing.opAssoc.LEFT,
                                     parse_op),
                                    ])
    return variable, operand, base_expr


variable, operand, base_expr = gen_base_expr()

my_var_parser = parse_ast(ast_id2expr, ast_int2expr)
base_expr.setParseAction(my_var_parser)

default_prio = 0x1337


def isbin(s):
    return re.match('[0-1]+$', s)


def int2bin(i, l):
    s = '0' * l + bin(i)[2:]
    return s[-l:]


def myror32(v, r):
    return ((v & 0xFFFFFFFFL) >> r) | ((v << (32 - r)) & 0xFFFFFFFFL)


def myrol32(v, r):
    return ((v & 0xFFFFFFFFL) >> (32 - r)) | ((v << r) & 0xFFFFFFFFL)


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
        self.lmask = lmask
        self.fbits = fbits
        self.fmask = fmask
        self.flen = flen
        self.value = value
        self.kargs = kargs

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
        self.lmask = lmask
        self.fbits = fbits
        self.fmask = fmask
        self.flen = flen
        self.value = value
        self.kargs = kargs
        self.__dict__.update(self.kargs)

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
        for k, v in self.kargs.items():
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
        for candidate in candidates:
            cls, name, bases, dct, fields = candidate
            for new_name, value in self.args['name'].items():
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
        for candidate in candidates:
            cls, name, bases, dct, fields = candidate
            tab = self.args['mn_mod']
            if isinstance(tab, list):
                tmp = {}
                for j, v in enumerate(tab):
                    tmp[j] = v
                tab = tmp
            for value, new_name in tab.items():
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

    def fromstring(self, s, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
            self.expr = e
            return start, stop
        try:
            v, start, stop = self.parser.scanString(s).next()
        except StopIteration:
            return None, None
        self.expr = v[0]
        return start, stop


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

    def fromstring(self, s, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
            self.expr = e
            return start, stop
        try:
            v, start, stop = self.parser.scanString(s).next()
        except StopIteration:
            return None, None
        self.expr = v[0]
        return start, stop

    def decode(self, v):
        v = v & self.lmask
        if v >= len(self.reg_info.expr):
            return False
        self.expr = self.reg_info.expr[v]
        return True

    def encode(self):
        if not self.expr in self.reg_info.expr:
            log.debug("cannot encode reg %r" % self.expr)
            return False
        self.value = self.reg_info.expr.index(self.expr)
        if self.value > self.lmask:
            log.debug("cannot encode field value %x %x" %
                      (self.value, self.lmask))
            return False
        return True

    def check_fbits(self, v):
        return v & self.fmask == self.fbits


class mn_prefix:

    def __init__(self):
        b = None


def swap16(v):
    return struct.unpack('<H', struct.pack('>H', v))[0]


def swap32(v):
    return struct.unpack('<I', struct.pack('>I', v))[0]


def perm_inv(p):
    o = [None for x in xrange(len(p))]
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
        node = []
    for k, v in branch.items():
        if not isinstance(v, dict):
            continue
        for k2 in v.keys():
            nodes.append((k, k2))
        branch2nodes(v, nodes)


def factor_one_bit(tree):
    if isinstance(tree, set):
        return tree
    new_keys = defaultdict(lambda: defaultdict(dict))
    if len(tree) == 1:
        return tree
    for k, v in tree.items():
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
    for k, v in new_keys.items():
        new_keys[k] = factor_one_bit(v)
    # try factor sons
    if len(new_keys) != 1:
        return new_keys
    subtree = new_keys.values()[0]
    if len(subtree) != 1:
        return new_keys
    if subtree.keys()[0] == 'mn':
        return new_keys

    return new_keys


def factor_fields(tree):
    if not isinstance(tree, dict):
        return tree
    if len(tree) != 1:
        return tree
    # merge
    k1, v1 = tree.items()[0]
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
    k2, v2 = v1.items()[0]
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
    for k, v in tree.items():
        v = factor_fields(v)
        new_keys[k] = factor_fields_all(v)
    return new_keys


def factor_tree(tree):
    new_keys = {}
    i = 1
    min_len = min([x[0] for x in tree.keys()])
    while i < min_len:

        i += 1


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
    f = filter(lambda x: hasattr(x, 'fname') and x.fname == fname, fields)
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
            off = 0
            o = ""
            for f in i.fields_order:
                if not isinstance(f, bsi):
                    raise ValueError('f is not bsi')
                if f.l == 0:
                    continue
                o += f.strbits
        return c


class instruction(object):

    def __init__(self, name, mode, args, additional_info=None):
        self.name = name
        self.mode = mode
        self.args = args
        self.additional_info = additional_info

    def gen_args(self, args):
        out = ', '.join([str(x) for x in args])
        return out

    def __str__(self):
        o = "%-10s " % self.name
        args = []
        for i, arg in enumerate(self.args):
            if not isinstance(arg, m2_expr.Expr):
                raise ValueError('zarb arg type')
            x = self.arg2str(arg, pos = i)
            args.append(x)
        o += self.gen_args(args)
        return o

    def get_asm_offset(self, x):
        return m2_expr.ExprInt_from(x, self.offset)

    def resolve_args_with_symbols(self, symbols=None):
        if symbols is None:
            symbols = {}
        args_out = []
        for a in self.args:
            e = a
            # try to resolve symbols using symbols (0 for default value)
            ids = m2_expr.get_expr_ids(e)
            fixed_ids = {}
            for x in ids:
                if isinstance(x.name, asmbloc.asm_label):
                    name = x.name.name
                    if not name in symbols:
                        raise ValueError('unresolved symbol! %r' % x)
                else:
                    name = x.name
                # special symbol
                if name == '$':
                    fixed_ids[x] = self.get_asm_offset(x)
                    continue
                if not name in symbols:
                    continue
                if symbols[name].offset is None:
                    default_size = self.get_symbol_size(x, symbols)
                    # default value
                    value = m2_expr.ExprInt_fromsize(default_size, 0)
                else:
                    size = x.size
                    if size is None:
                        default_size = self.get_symbol_size(x, symbols)
                        size = default_size
                    value = m2_expr.ExprInt_fromsize(size, symbols[name].offset)
                fixed_ids[x] = value
            e = e.replace_expr(fixed_ids)
            e = expr_simp(e)
            args_out.append(e)
        return args_out

    def get_info(self, c):
        return


class cls_mn(object):
    __metaclass__ = metamn
    args_symb = []
    instruction = instruction

    @classmethod
    def guess_mnemo(cls, bs, attrib, pre_dis_info, offset):
        candidates = []

        candidates = set()

        fname_values = pre_dis_info
        todo = [(dict(fname_values), branch, offset * 8)
                for branch in cls.bintree.items()]
        cpt = 0
        if hasattr(bs, 'getlen'):
            bs_l = bs.getlen()
        else:
            bs_l = len(bs)
        for fname_values, branch, offset_b in todo:
            (l, fmask, fbits, fname, flen), vals = branch
            cpt += 1

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
            for nb, v in vals.items():
                if 'mn' in nb:
                    candidates.update(v)
                else:
                    todo.append((dict(fname_values), (nb, v), offset_b))

        candidates = [c for c in candidates]

        if not candidates:
            raise Disasm_Exception('cannot disasm (guess) at %X' % offset)
        return candidates

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
                    for i in xrange(len(self.args_permut))]
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

        offset_o = offset
        pre_dis_info, bs, mode, offset, prefix_len = cls.pre_dis(
            bs_o, mode_o, offset)
        candidates = cls.guess_mnemo(bs, mode, pre_dis_info, offset)
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

            args = []
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
                    log.debug("FIELD %s %s %s %s" % (f.__class__,
                                                     f.fname,
                                                     offset_b, l))
                    if bs_l * 8 - offset_b < l:
                        getok = False
                        break
                    bv = cls.getbits(bs, mode, offset_b, l)
                    offset_b += l
                    if not f.fname in fname_values:
                        fname_values[f.fname] = bv
                    todo[i] = bv
                else:
                    f.is_present = False
                    todo[i] = None

            if not getok:
                continue

            for i in c.to_decode:
                f = c.fields_order[i]
                if f.is_present:
                    ret = f.decode(todo[i])
                    if not ret:
                        log.debug("cannot decode %r" % (f))
                        break

            if not ret:
                continue
            for a in c.args:
                a.expr = expr_simp(a.expr)

            c.l = prefix_len + total_l / 8
            c.b = cls.getbytes(bs, offset, total_l / 8)
            c.offset = offset_o
            c = c.post_dis()
            if c is None:
                continue
            c_args = [a.expr for a in c.args]
            instr = cls.instruction(c.name, mode, c_args,
                                    additional_info=c.additional_info())
            instr.l = prefix_len + total_l / 8
            instr.b = cls.getbytes(bs, offset, total_l / 8)
            instr.offset = offset_o
            instr.get_info(c)
            if c.alias:
                alias = True
            out.append(instr)
            out_c.append(c)
        if not out:
            raise Disasm_Exception('cannot disasm at %X' % offset_o)
        if len(out) != 1:
            if not alias:
                log.warning('dis multiple args ret default')

            assert(len(out) == 2)
            for i, o in enumerate(out_c):
                if o.alias:
                    return out[i]
            raise NotImplementedError('not fully functional')
        return out[0]

    @classmethod
    def fromstring(cls, s, mode = None):
        global total_scans
        name = re.search('(\S+)', s).groups()
        if not name:
            raise ValueError('cannot find name', s)
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
                args_str = s[len(name):].strip(' ')

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
                            v, start, stop = p.scanString(args_str).next()
                        except StopIteration:
                            v, start, stop = [None], None, None
                        if start != 0:
                            v, start, stop = [None], None, None
                        parsers[(i, start_i)][p] = v[0], start, stop

                    start, stop = f.fromstring(args_str, parsers[(i, start_i)])
                    if start != 0:
                        log.debug("cannot fromstring %r" % (args_str))
                        cannot_parse = True
                        break
                    if f.expr is None:
                        raise NotImplementedError('not fully functional')
                    f.expr = expr_simp(f.expr)
                    args_expr.append(f.expr)
                    a = args_str[start:stop]
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
            raise ValueError('cannot fromstring %r' % s)
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
    def asm(cls, instr, symbols=None):
        """
        Re asm instruction by searching mnemo using name and args. We then
        can modify args and get the hex of a modified instruction
        """
        clist = cls.all_mn_name[instr.name]
        clist = [x for x in clist]
        vals = []
        candidates = []
        args = instr.resolve_args_with_symbols(symbols)

        for cc in clist:

            for c in cls.get_cls_instance(
                cc, instr.mode, instr.additional_info):

                cannot_parse = False
                if len(c.args) != len(instr.args):
                    continue

                # only fix args expr
                for i in xrange(len(c.args)):
                    c.args[i].expr = args[i]

                v = c.value(instr.mode)
                if not v:
                    log.debug("cannot encode %r" % (c))
                    cannot_parse = True
                if cannot_parse:
                    continue
                vals += v
                candidates.append((c, v))
        if len(vals) == 0:
            raise ValueError('cannot asm %r %r' %
                             (instr.name, [str(x) for x in instr.args]))
        if len(vals) != 1:
            log.debug('asm multiple args ret default')

        vals = cls.filter_asm_candidates(instr, candidates)
        return vals

    @classmethod
    def filter_asm_candidates(cls, instr, candidates):
        o = []
        for c, v in candidates:
            o += v
        o.sort(key=len)
        return o

    def value(self, mode):
        todo = [(0, [(x, self.fields_order[x]) for x in self.to_decode[::-1]])]

        result = []
        done = []
        cpt = 0

        while todo:
            index, to_decode = todo.pop()
            # TEST XXX
            for i, f in to_decode:
                setattr(self, f.fname, f)
            if (index, [x[1].value for x in to_decode]) in done:
                continue
            done.append((index, [x[1].value for x in to_decode]))

            cpt += 1
            can_encode = True
            for i, f in to_decode[index:]:
                ret = f.encode()
                if not ret:
                    log.debug('cannot encode %r' % f)
                    can_encode = False
                    break
                index += 1
                if ret is True:
                    continue

                gcpt = 0
                for i in ret:
                    gcpt += 1
                    o = []
                    if ((index, [xx[1].value for xx in to_decode]) in todo or
                        (index, [xx[1].value for xx in to_decode]) in done):
                        raise NotImplementedError('not fully functional')

                    for p, f in to_decode:
                        fnew = f.clone()
                        o.append((p, fnew))
                    todo.append((index, o))
                can_encode = False

                break
            if not can_encode:
                continue
            result.append(to_decode)

        return self.decoded2bytes(result)

    def encodefields(self, decoded):
        bits = bitobj()
        for p, f in decoded:
            setattr(self, f.fname, f)

            if f.value is None:
                continue
            bits.putbits(f.value, f.l)

        xx = bits.tostring()
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

    def set_dst_symbol(self, symbol_pool):
        dst = self.getdstflow(symbol_pool)
        args = []
        for d in dst:
            if isinstance(d, m2_expr.ExprInt):
                l = symbol_pool.getby_offset_create(int(d.arg))

                a = m2_expr.ExprId(l.name, d.size)
            else:
                a = d
            args.append(a)
        self.args_symb = args

    def getdstflow(self, symbol_pool):
        return [self.args[0].expr]


class imm_noarg(object):
    intsize = 32
    intmask = (1 << intsize) - 1

    def int2expr(self, v):
        if (v & ~self.intmask) != 0:
            return None
        return m2_expr.ExprInt_fromsize(self.intsize, v)

    def expr2int(self, e):
        if not isinstance(e, m2_expr.ExprInt):
            return None
        v = int(e.arg)
        if v & ~self.intmask != 0:
            return None
        return v

    def fromstring(self, s, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
        else:
            try:
                e, start, stop = self.parser.scanString(s).next()
            except StopIteration:
                return None, None
        if e is None:
            return None, None

        assert(isinstance(e, m2_expr.Expr))
        if isinstance(e, tuple):
            self.expr = self.int2expr(e[1])
        elif isinstance(e, m2_expr.Expr):
            self.expr = e
        else:
            raise TypeError('zarb expr')
        if self.expr is None:
            log.debug('cannot fromstring int %r' % s)
            return None, None
        return start, stop

    def decodeval(self, v):
        return v

    def encodeval(self, v):
        if v > self.lmask:
            return False
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
    int2expr = lambda self, x: m2_expr.ExprInt08(x)


class imm16_noarg(object):
    int2expr = lambda self, x: m2_expr.ExprInt16(x)


class imm32_noarg(object):
    int2expr = lambda self, x: m2_expr.ExprInt32(x)


class imm64_noarg(object):
    int2expr = lambda self, x: m2_expr.ExprInt64(x)


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
        v = int(self.expr.arg)
        if sign_ext(v & self.lmask, self.l, self.intsize) != v:
            return False
        v = self.encodeval(v & self.lmask)
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
