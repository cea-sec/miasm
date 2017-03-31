#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# These module implements Miasm IR components and basic operations related.
# IR components are :
#  - ExprInt
#  - ExprId
#  - ExprAff
#  - ExprCond
#  - ExprMem
#  - ExprOp
#  - ExprSlice
#  - ExprCompose
#


import itertools
from operator import itemgetter
from miasm2.expression.modint import mod_size2uint, is_modint, size2mask, \
    define_uint
from miasm2.core.graph import DiGraph
import warnings

# Define tokens
TOK_INF = "<"
TOK_INF_SIGNED = TOK_INF + "s"
TOK_INF_UNSIGNED = TOK_INF + "u"
TOK_INF_EQUAL = "<="
TOK_INF_EQUAL_SIGNED = TOK_INF_EQUAL + "s"
TOK_INF_EQUAL_UNSIGNED = TOK_INF_EQUAL + "u"
TOK_EQUAL = "=="
TOK_POS = "pos"
TOK_POS_STRICT = "Spos"

# Hashing constants
EXPRINT = 1
EXPRID = 2
EXPRAFF = 3
EXPRCOND = 4
EXPRMEM = 5
EXPROP = 6
EXPRSLICE = 5
EXPRCOMPOSE = 5


def visit_chk(visitor):
    "Function decorator launching callback on Expression visit"
    def wrapped(e, cb, test_visit=lambda x: True):
        if (test_visit is not None) and (not test_visit(e)):
            return e
        e_new = visitor(e, cb, test_visit)
        if e_new is None:
            return None
        e_new2 = cb(e_new)
        return e_new2
    return wrapped


# Expression display


class DiGraphExpr(DiGraph):

    """Enhanced graph for Expression diplay
    Expression are displayed as a tree with node and edge labeled
    with only relevant information"""

    def node2str(self, node):
        if isinstance(node, ExprOp):
            return node.op
        elif isinstance(node, ExprId):
            return node.name
        elif isinstance(node, ExprMem):
            return "@%d" % node.size
        elif isinstance(node, ExprCompose):
            return "{ %d }" % node.size
        elif isinstance(node, ExprCond):
            return "? %d" % node.size
        elif isinstance(node, ExprSlice):
            return "[%d:%d]" % (node.start, node.stop)
        return str(node)

    def edge2str(self, nfrom, nto):
        if isinstance(nfrom, ExprCompose):
            for i in nfrom.args:
                if i[0] == nto:
                    return "[%s, %s]" % (i[1], i[2])
        elif isinstance(nfrom, ExprCond):
            if nfrom.cond == nto:
                return "?"
            elif nfrom.src1 == nto:
                return "True"
            elif nfrom.src2 == nto:
                return "False"

        return ""


# IR definitions

class Expr(object):

    "Parent class for Miasm Expressions"

    __slots__ = ["__hash", "__repr", "__size"]

    all_exprs = set()
    args2expr = {}
    canon_exprs = set()
    use_singleton = True

    def set_size(self, value):
        raise ValueError('size is not mutable')

    def __init__(self):
        self.__hash = None
        self.__repr = None
        self.__size = None

    size = property(lambda self: self.__size)

    @staticmethod
    def get_object(cls, args):
        if not cls.use_singleton:
            return object.__new__(cls, args)

        expr = Expr.args2expr.get((cls, args))
        if expr is None:
            expr = object.__new__(cls, args)
            Expr.args2expr[(cls, args)] = expr
        return expr

    def get_is_canon(self):
        return self in Expr.canon_exprs

    def set_is_canon(self, value):
        assert(value is True)
        Expr.canon_exprs.add(self)

    is_canon = property(get_is_canon, set_is_canon)

    # Common operations

    def __str__(self):
        raise NotImplementedError("Abstract Method")

    def __getitem__(self, i):
        if not isinstance(i, slice):
            raise TypeError("Expression: Bad slice: %s" % i)
        start, stop, step = i.indices(self.size)
        if step != 1:
            raise ValueError("Expression: Bad slice: %s" % i)
        return ExprSlice(self, start, stop)

    def get_size(self):
        raise DeprecationWarning("use X.size instead of X.get_size()")

    def is_function_call(self):
        """Returns true if the considered Expr is a function call
        """
        return False

    def __repr__(self):
        if self.__repr is None:
            self.__repr = self._exprrepr()
        return self.__repr

    def __hash__(self):
        if self.__hash is None:
            self.__hash = self._exprhash()
        return self.__hash

    def __eq__(self, other):
        if self is other:
            return True
        elif self.use_singleton:
            # In case of Singleton, pointer comparison is sufficient
            # Avoid computation of hash and repr
            return False

        if self.__class__ is not other.__class__:
            return False
        if hash(self) != hash(other):
            return False
        return repr(self) == repr(other)

    def __ne__(self, a):
        return not self.__eq__(a)

    def __add__(self, a):
        return ExprOp('+', self, a)

    def __sub__(self, a):
        return ExprOp('+', self, ExprOp('-', a))

    def __div__(self, a):
        return ExprOp('/', self, a)

    def __mod__(self, a):
        return ExprOp('%', self, a)

    def __mul__(self, a):
        return ExprOp('*', self, a)

    def __lshift__(self, a):
        return ExprOp('<<', self, a)

    def __rshift__(self, a):
        return ExprOp('>>', self, a)

    def __xor__(self, a):
        return ExprOp('^', self, a)

    def __or__(self, a):
        return ExprOp('|', self, a)

    def __and__(self, a):
        return ExprOp('&', self, a)

    def __neg__(self):
        return ExprOp('-', self)

    def __pow__(self, a):
        return ExprOp("**",self, a)

    def __invert__(self):
        return ExprOp('^', self, self.mask)

    def copy(self):
        "Deep copy of the expression"
        return self.visit(lambda x: x)

    def __deepcopy__(self, _):
        return self.copy()

    def replace_expr(self, dct=None):
        """Find and replace sub expression using dct
        @dct: dictionary of Expr -> *
        """
        if dct is None:
            dct = {}

        def my_replace(e, dct):
            if e in dct:
                return dct[e]
            return e

        return self.visit(lambda e: my_replace(e, dct))

    def canonize(self):
        "Canonize the Expression"

        def must_canon(e):
            return not e.is_canon

        def canonize_visitor(e):
            if e.is_canon:
                return e
            if isinstance(e, ExprOp):
                if e.is_associative():
                    # ((a+b) + c) => (a + b + c)
                    args = []
                    for arg in e.args:
                        if isinstance(arg, ExprOp) and e.op == arg.op:
                            args += arg.args
                        else:
                            args.append(arg)
                    args = canonize_expr_list(args)
                    new_e = ExprOp(e.op, *args)
                else:
                    new_e = e
            else:
                new_e = e
            new_e.is_canon = True
            return new_e

        return self.visit(canonize_visitor, must_canon)

    def msb(self):
        "Return the Most Significant Bit"
        s = self.size
        return self[s - 1:s]

    def zeroExtend(self, size):
        """Zero extend to size
        @size: int
        """
        assert(self.size <= size)
        if self.size == size:
            return self
        ad_size = size - self.size
        n = ExprInt(0, ad_size)
        return ExprCompose(self, n)

    def signExtend(self, size):
        """Sign extend to size
        @size: int
        """
        assert(self.size <= size)
        if self.size == size:
            return self
        ad_size = size - self.size
        c = ExprCompose(self,
                        ExprCond(self.msb(),
                                 ExprInt(size2mask(ad_size), ad_size),
                                 ExprInt(0, ad_size)))
        return c

    def graph_recursive(self, graph):
        """Recursive method used by graph
        @graph: miasm2.core.graph.DiGraph instance
        Update @graph instance to include sons
        This is an Abstract method"""

        raise ValueError("Abstract method")

    def graph(self):
        """Return a DiGraph instance standing for Expr tree
        Instance's display functions have been override for better visibility
        Wrapper on graph_recursive"""

        # Create recursively the graph
        graph = DiGraphExpr()
        self.graph_recursive(graph)

        return graph

    def set_mask(self, value):
        raise ValueError('mask is not mutable')

    mask = property(lambda self: ExprInt(-1, self.size))

    def is_int(self, value=None):
        return False

    def is_id(self, name=None):
        return False

    def is_aff(self):
        return False

    def is_cond(self):
        return False

    def is_mem(self):
        return False

    def is_op(self, op=None):
        return False

    def is_slice(self, start=None, stop=None):
        return False

    def is_compose(self):
        return False

    def is_op_segm(self):
        """Returns True if is ExprOp and op == 'segm'"""
        return False

    def is_mem_segm(self):
        """Returns True if is ExprMem and ptr is_op_segm"""
        return False

class ExprInt(Expr):

    """An ExprInt represent a constant in Miasm IR.

    Some use cases:
     - Constant 0x42
     - Constant -0x30
     - Constant 0x12345678 on 32bits
     """

    __slots__ = Expr.__slots__ + ["__arg"]


    def __init__(self, arg, size):
        """Create an ExprInt from a modint or num/size
        @arg: 'intable' number
        @size: int size"""
        super(ExprInt, self).__init__()
        # Work is done in __new__

    size = property(lambda self: self.__size)
    arg = property(lambda self: self.__arg)

    def __reduce__(self):
        state = int(self.__arg), self.__size
        return self.__class__, state

    def __new__(cls, arg, size):
        """Create an ExprInt from a modint or num/size
        @arg: 'intable' number
        @size: int size"""

        if is_modint(arg):
            assert size == arg.size
        # Avoid a common blunder
        assert not isinstance(arg, ExprInt)

        # Ensure arg is always a moduint
        arg = int(arg)
        if size not in mod_size2uint:
            define_uint(size)
        arg = mod_size2uint[size](arg)

        # Get the Singleton instance
        expr = Expr.get_object(cls, (arg, size))

        # Save parameters (__init__ is called with parameters unchanged)
        expr.__arg = arg
        expr.__size = expr.__arg.size
        return expr

    def __get_int(self):
        "Return self integer representation"
        return int(self.__arg & size2mask(self.__size))

    def __str__(self):
        if self.__arg < 0:
            return str("-0x%X" % (- self.__get_int()))
        else:
            return str("0x%X" % self.__get_int())

    def get_r(self, mem_read=False, cst_read=False):
        if cst_read:
            return set([self])
        else:
            return set()

    def get_w(self):
        return set()

    def _exprhash(self):
        return hash((EXPRINT, self.__arg, self.__size))

    def _exprrepr(self):
        return "%s(0x%X, %d)" % (self.__class__.__name__, self.__get_int(),
                                 self.__size)

    def __contains__(self, e):
        return self == e

    @visit_chk
    def visit(self, cb, tv=None):
        return self

    def copy(self):
        return ExprInt(self.__arg, self.__size)

    def depth(self):
        return 1

    def graph_recursive(self, graph):
        graph.add_node(self)

    def __int__(self):
        return int(self.arg)

    def __long__(self):
        return long(self.arg)

    def is_int(self, value=None):
        if value is not None and self.__arg != value:
            return False
        return True


class ExprId(Expr):

    """An ExprId represent an identifier in Miasm IR.

    Some use cases:
     - EAX register
     - 'start' offset
     - variable v1
     """

    __slots__ = Expr.__slots__ + ["__name"]

    def __init__(self, name, size=32):
        """Create an identifier
        @name: str, identifier's name
        @size: int, identifier's size
        """
        super(ExprId, self).__init__()

        self.__name, self.__size = name, size

    size = property(lambda self: self.__size)
    name = property(lambda self: self.__name)

    def __reduce__(self):
        state = self.__name, self.__size
        return self.__class__, state

    def __new__(cls, name, size=32):
        return Expr.get_object(cls, (name, size))

    def __str__(self):
        return str(self.__name)

    def get_r(self, mem_read=False, cst_read=False):
        return set([self])

    def get_w(self):
        return set([self])

    def _exprhash(self):
        # TODO XXX: hash size ??
        return hash((EXPRID, self.__name, self.__size))

    def _exprrepr(self):
        return "%s(%r, %d)" % (self.__class__.__name__, self.__name, self.__size)

    def __contains__(self, e):
        return self == e

    @visit_chk
    def visit(self, cb, tv=None):
        return self

    def copy(self):
        return ExprId(self.__name, self.__size)

    def depth(self):
        return 1

    def graph_recursive(self, graph):
        graph.add_node(self)

    def is_id(self, name=None):
        if name is not None and self.__name != name:
            return False
        return True


class ExprAff(Expr):

    """An ExprAff represent an affection from an Expression to another one.

    Some use cases:
     - var1 <- 2
    """

    __slots__ = Expr.__slots__ + ["__dst", "__src"]

    def __init__(self, dst, src):
        """Create an ExprAff for dst <- src
        @dst: Expr, affectation destination
        @src: Expr, affectation source
        """

        super(ExprAff, self).__init__()

        if dst.size != src.size:
            raise ValueError(
                "sanitycheck: ExprAff args must have same size! %s" %
                             ([(str(arg), arg.size) for arg in [dst, src]]))

        self.__size = self.dst.size

    size = property(lambda self: self.__size)
    dst = property(lambda self: self.__dst)
    src = property(lambda self: self.__src)


    def __reduce__(self):
        state = self.__dst, self.__src
        return self.__class__, state

    def __new__(cls, dst, src):
        if isinstance(dst, ExprSlice):
            # Complete the source with missing slice parts
            new_dst = dst.arg
            rest = [(ExprSlice(dst.arg, r[0], r[1]), r[0], r[1])
                    for r in dst.slice_rest()]
            all_a = [(src, dst.start, dst.stop)] + rest
            all_a.sort(key=lambda x: x[1])
            args = [expr for (expr, _, _) in all_a]
            new_src = ExprCompose(*args)
        else:
            new_dst, new_src = dst, src
        expr = Expr.get_object(cls, (new_dst, new_src))
        expr.__dst, expr.__src = new_dst, new_src
        return expr

    def __str__(self):
        return "%s = %s" % (str(self.__dst), str(self.__src))

    def get_r(self, mem_read=False, cst_read=False):
        elements = self.__src.get_r(mem_read, cst_read)
        if isinstance(self.__dst, ExprMem) and mem_read:
            elements.update(self.__dst.arg.get_r(mem_read, cst_read))
        return elements

    def get_w(self):
        if isinstance(self.__dst, ExprMem):
            return set([self.__dst])  # [memreg]
        else:
            return self.__dst.get_w()

    def _exprhash(self):
        return hash((EXPRAFF, hash(self.__dst), hash(self.__src)))

    def _exprrepr(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.__dst, self.__src)

    def __contains__(self, expr):
        return (self == expr or
                self.__src.__contains__(expr) or
                self.__dst.__contains__(expr))

    @visit_chk
    def visit(self, cb, tv=None):
        dst, src = self.__dst.visit(cb, tv), self.__src.visit(cb, tv)
        if dst == self.__dst and src == self.__src:
            return self
        else:
            return ExprAff(dst, src)

    def copy(self):
        return ExprAff(self.__dst.copy(), self.__src.copy())

    def depth(self):
        return max(self.__src.depth(), self.__dst.depth()) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in [self.__src, self.__dst]:
            arg.graph_recursive(graph)
            graph.add_uniq_edge(self, arg)

    def is_aff(self):
        return True


class ExprCond(Expr):

    """An ExprCond stand for a condition on an Expr

    Use cases:
     - var1 < var2
     - min(var1, var2)
     - if (cond) then ... else ...
    """

    __slots__ = Expr.__slots__ + ["__cond", "__src1", "__src2"]

    def __init__(self, cond, src1, src2):
        """Create an ExprCond
        @cond: Expr, condition
        @src1: Expr, value if condition is evaled to not zero
        @src2: Expr, value if condition is evaled zero
        """

        super(ExprCond, self).__init__()

        self.__cond, self.__src1, self.__src2 = cond, src1, src2
        assert(src1.size == src2.size)
        self.__size = self.src1.size

    size = property(lambda self: self.__size)
    cond = property(lambda self: self.__cond)
    src1 = property(lambda self: self.__src1)
    src2 = property(lambda self: self.__src2)

    def __reduce__(self):
        state = self.__cond, self.__src1, self.__src2
        return self.__class__, state

    def __new__(cls, cond, src1, src2):
        return Expr.get_object(cls, (cond, src1, src2))

    def __str__(self):
        return "(%s?(%s,%s))" % (str(self.__cond), str(self.__src1), str(self.__src2))

    def get_r(self, mem_read=False, cst_read=False):
        out_src1 = self.src1.get_r(mem_read, cst_read)
        out_src2 = self.src2.get_r(mem_read, cst_read)
        return self.cond.get_r(mem_read,
                               cst_read).union(out_src1).union(out_src2)

    def get_w(self):
        return set()

    def _exprhash(self):
        return hash((EXPRCOND, hash(self.cond),
                     hash(self.__src1), hash(self.__src2)))

    def _exprrepr(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__,
                                   self.__cond, self.__src1, self.__src2)

    def __contains__(self, e):
        return (self == e or
                self.cond.__contains__(e) or
                self.src1.__contains__(e) or
                self.src2.__contains__(e))

    @visit_chk
    def visit(self, cb, tv=None):
        cond = self.__cond.visit(cb, tv)
        src1 = self.__src1.visit(cb, tv)
        src2 = self.__src2.visit(cb, tv)
        if (cond == self.__cond and
            src1 == self.__src1 and
                src2 == self.__src2):
            return self
        return ExprCond(cond, src1, src2)

    def copy(self):
        return ExprCond(self.__cond.copy(),
                        self.__src1.copy(),
                        self.__src2.copy())

    def depth(self):
        return max(self.__cond.depth(),
                   self.__src1.depth(),
                   self.__src2.depth()) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in [self.__cond, self.__src1, self.__src2]:
            arg.graph_recursive(graph)
            graph.add_uniq_edge(self, arg)

    def is_cond(self):
        return True


class ExprMem(Expr):

    """An ExprMem stand for a memory access

    Use cases:
     - Memory read
     - Memory write
    """

    __slots__ = Expr.__slots__ + ["__arg"]

    def __init__(self, arg, size=32):
        """Create an ExprMem
        @arg: Expr, memory access address
        @size: int, memory access size
        """

        super(ExprMem, self).__init__()

        if not isinstance(arg, Expr):
            raise ValueError(
                'ExprMem: arg must be an Expr (not %s)' % type(arg))

        self.__arg, self.__size = arg, size

    size = property(lambda self: self.__size)
    arg = property(lambda self: self.__arg)

    def __reduce__(self):
        state = self.__arg, self.__size
        return self.__class__, state

    def __new__(cls, arg, size=32):
        return Expr.get_object(cls, (arg, size))

    def __str__(self):
        return "@%d[%s]" % (self.size, str(self.arg))

    def get_r(self, mem_read=False, cst_read=False):
        if mem_read:
            return set(self.__arg.get_r(mem_read, cst_read).union(set([self])))
        else:
            return set([self])

    def get_w(self):
        return set([self])  # [memreg]

    def _exprhash(self):
        return hash((EXPRMEM, hash(self.__arg), self.__size))

    def _exprrepr(self):
        return "%s(%r, %r)" % (self.__class__.__name__,
                               self.__arg, self.__size)

    def __contains__(self, expr):
        return self == expr or self.__arg.__contains__(expr)

    @visit_chk
    def visit(self, cb, tv=None):
        arg = self.__arg.visit(cb, tv)
        if arg == self.__arg:
            return self
        return ExprMem(arg, self.size)

    def copy(self):
        arg = self.arg.copy()
        return ExprMem(arg, size=self.size)

    def is_mem_segm(self):
        """Returns True if is ExprMem and ptr is_op_segm"""
        return self.__arg.is_op_segm()

    def depth(self):
        return self.__arg.depth() + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        self.__arg.graph_recursive(graph)
        graph.add_uniq_edge(self, self.__arg)

    def is_mem(self):
        return True


class ExprOp(Expr):

    """An ExprOp stand for an operation between Expr

    Use cases:
     - var1 XOR var2
     - var1 + var2 + var3
     - parity bit(var1)
    """

    __slots__ = Expr.__slots__ + ["__op", "__args"]

    def __init__(self, op, *args):
        """Create an ExprOp
        @op: str, operation
        @*args: Expr, operand list
        """

        super(ExprOp, self).__init__()

        sizes = set([arg.size for arg in args])

        if len(sizes) != 1:
            # Special cases : operande sizes can differ
            if op not in ["segm"]:
                raise ValueError(
                    "sanitycheck: ExprOp args must have same size! %s" %
                                 ([(str(arg), arg.size) for arg in args]))

        if not isinstance(op, str):
            raise ValueError("ExprOp: 'op' argument must be a string")

        assert isinstance(args, tuple)
        self.__op, self.__args = op, args

        # Set size for special cases
        if self.__op in [
                '==', 'parity', 'fcom_c0', 'fcom_c1', 'fcom_c2', 'fcom_c3',
                'fxam_c0', 'fxam_c1', 'fxam_c2', 'fxam_c3',
                "access_segment_ok", "load_segment_limit_ok", "bcdadd_cf",
                "ucomiss_zf", "ucomiss_pf", "ucomiss_cf"]:
            sz = 1
        elif self.__op in [TOK_INF, TOK_INF_SIGNED,
                           TOK_INF_UNSIGNED, TOK_INF_EQUAL,
                           TOK_INF_EQUAL_SIGNED, TOK_INF_EQUAL_UNSIGNED,
                           TOK_EQUAL, TOK_POS,
                           TOK_POS_STRICT,
                           ]:
            sz = 1
        elif self.__op in ['mem_16_to_double', 'mem_32_to_double',
                           'mem_64_to_double', 'mem_80_to_double',
                           'int_16_to_double', 'int_32_to_double',
                           'int_64_to_double', 'int_80_to_double']:
            sz = 64
        elif self.__op in ['double_to_mem_16', 'double_to_int_16',
                           'float_trunc_to_int_16', 'double_trunc_to_int_16']:
            sz = 16
        elif self.__op in ['double_to_mem_32', 'double_to_int_32',
                           'float_trunc_to_int_32', 'double_trunc_to_int_32',
                           'double_to_float']:
            sz = 32
        elif self.__op in ['double_to_mem_64', 'double_to_int_64',
                           'float_trunc_to_int_64', 'double_trunc_to_int_64',
                           'float_to_double']:
            sz = 64
        elif self.__op in ['double_to_mem_80', 'double_to_int_80',
                           'float_trunc_to_int_80',
                           'double_trunc_to_int_80']:
            sz = 80
        elif self.__op in ['segm']:
            sz = self.__args[1].size
        else:
            if None in sizes:
                sz = None
            else:
                # All arguments have the same size
                sz = list(sizes)[0]

        self.__size = sz

    size = property(lambda self: self.__size)
    op = property(lambda self: self.__op)
    args = property(lambda self: self.__args)

    def __reduce__(self):
        state = tuple([self.__op] + list(self.__args))
        return self.__class__, state

    def __new__(cls, op, *args):
        return Expr.get_object(cls, (op, args))

    def __str__(self):
        if self.is_associative():
            return '(' + self.__op.join([str(arg) for arg in self.__args]) + ')'
        if (self.__op.startswith('call_func_') or
            self.__op == 'cpuid' or
            len(self.__args) > 2 or
                self.__op in ['parity', 'segm']):
            return self.__op + '(' + ', '.join([str(arg) for arg in self.__args]) + ')'
        if len(self.__args) == 2:
            return ('(' + str(self.__args[0]) +
                    ' ' + self.op + ' ' + str(self.__args[1]) + ')')
        else:
            return reduce(lambda x, y: x + ' ' + str(y),
                          self.__args,
                          '(' + str(self.__op)) + ')'

    def get_r(self, mem_read=False, cst_read=False):
        return reduce(lambda elements, arg:
                      elements.union(arg.get_r(mem_read, cst_read)), self.__args, set())

    def get_w(self):
        raise ValueError('op cannot be written!', self)

    def _exprhash(self):
        h_hargs = [hash(arg) for arg in self.__args]
        return hash((EXPROP, self.__op, tuple(h_hargs)))

    def _exprrepr(self):
        return "%s(%r, %s)" % (self.__class__.__name__, self.__op,
                               ', '.join(repr(arg) for arg in self.__args))

    def __contains__(self, e):
        if self == e:
            return True
        for arg in self.__args:
            if arg.__contains__(e):
                return True
        return False

    def is_function_call(self):
        return self.__op.startswith('call')

    def is_associative(self):
        "Return True iff current operation is associative"
        return (self.__op in ['+', '*', '^', '&', '|'])

    def is_commutative(self):
        "Return True iff current operation is commutative"
        return (self.__op in ['+', '*', '^', '&', '|'])

    @visit_chk
    def visit(self, cb, tv=None):
        args = [arg.visit(cb, tv) for arg in self.__args]
        modified = any([arg[0] != arg[1] for arg in zip(self.__args, args)])
        if modified:
            return ExprOp(self.__op, *args)
        return self

    def copy(self):
        args = [arg.copy() for arg in self.__args]
        return ExprOp(self.__op, *args)

    def depth(self):
        depth = [arg.depth() for arg in self.__args]
        return max(depth) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in self.__args:
            arg.graph_recursive(graph)
            graph.add_uniq_edge(self, arg)

    def is_op(self, op=None):
        if op is None:
            return True
        return self.op == op

    def is_op_segm(self):
        """Returns True if is ExprOp and op == 'segm'"""
        return self.is_op('segm')

class ExprSlice(Expr):

    __slots__ = Expr.__slots__ + ["__arg", "__start", "__stop"]

    def __init__(self, arg, start, stop):
        super(ExprSlice, self).__init__()

        assert(start < stop)
        self.__arg, self.__start, self.__stop = arg, start, stop
        self.__size = self.__stop - self.__start

    size = property(lambda self: self.__size)
    arg = property(lambda self: self.__arg)
    start = property(lambda self: self.__start)
    stop = property(lambda self: self.__stop)

    def __reduce__(self):
        state = self.__arg, self.__start, self.__stop
        return self.__class__, state

    def __new__(cls, arg, start, stop):
        return Expr.get_object(cls, (arg, start, stop))

    def __str__(self):
        return "%s[%d:%d]" % (str(self.__arg), self.__start, self.__stop)

    def get_r(self, mem_read=False, cst_read=False):
        return self.__arg.get_r(mem_read, cst_read)

    def get_w(self):
        return self.__arg.get_w()

    def _exprhash(self):
        return hash((EXPRSLICE, hash(self.__arg), self.__start, self.__stop))

    def _exprrepr(self):
        return "%s(%r, %d, %d)" % (self.__class__.__name__, self.__arg,
                                   self.__start, self.__stop)

    def __contains__(self, expr):
        if self == expr:
            return True
        return self.__arg.__contains__(expr)

    @visit_chk
    def visit(self, cb, tv=None):
        arg = self.__arg.visit(cb, tv)
        if arg == self.__arg:
            return self
        return ExprSlice(arg, self.__start, self.__stop)

    def copy(self):
        return ExprSlice(self.__arg.copy(), self.__start, self.__stop)

    def depth(self):
        return self.__arg.depth() + 1

    def slice_rest(self):
        "Return the completion of the current slice"
        size = self.__arg.size
        if self.__start >= size or self.__stop > size:
            raise ValueError('bad slice rest %s %s %s' %
                             (size, self.__start, self.__stop))

        if self.__start == self.__stop:
            return [(0, size)]

        rest = []
        if self.__start != 0:
            rest.append((0, self.__start))
        if self.__stop < size:
            rest.append((self.__stop, size))

        return rest

    def graph_recursive(self, graph):
        graph.add_node(self)
        self.__arg.graph_recursive(graph)
        graph.add_uniq_edge(self, self.__arg)

    def is_slice(self, start=None, stop=None):
        if start is not None and self.__start != start:
            return False
        if stop is not None and self.__stop != stop:
            return False
        return True


class ExprCompose(Expr):

    """
    Compose is like a hambuger. It concatenate Expressions
    """

    __slots__ = Expr.__slots__ + ["__args"]

    def __init__(self, *args):
        """Create an ExprCompose
        The ExprCompose is contiguous and starts at 0
        @args: [Expr, Expr, ...]
        DEPRECATED:
        @args: [(Expr, int, int), (Expr, int, int), ...]
        """

        super(ExprCompose, self).__init__()
        assert isinstance(args, tuple)
        self.__args = args
        self.__size = sum([arg.size for arg in args])

    size = property(lambda self: self.__size)
    args = property(lambda self: self.__args)

    def __reduce__(self):
        state = self.__args
        return self.__class__, state

    def __new__(cls, *args):
        return Expr.get_object(cls, args)

    def __str__(self):
        return '{' + ', '.join(["%s %s %s" % (arg, idx, idx + arg.size) for idx, arg in self.iter_args()]) + '}'

    def get_r(self, mem_read=False, cst_read=False):
        return reduce(lambda elements, arg:
                      elements.union(arg.get_r(mem_read, cst_read)), self.__args, set())

    def get_w(self):
        return reduce(lambda elements, arg:
                      elements.union(arg.get_w()), self.__args, set())

    def _exprhash(self):
        h_args = [EXPRCOMPOSE] + [hash(arg) for arg in self.__args]
        return hash(tuple(h_args))

    def _exprrepr(self):
        return "%s%r" % (self.__class__.__name__, self.__args)

    def __contains__(self, e):
        if self == e:
            return True
        for arg in self.__args:
            if arg == e:
                return True
            if arg.__contains__(e):
                return True
        return False

    @visit_chk
    def visit(self, cb, tv=None):
        args = [arg.visit(cb, tv) for arg in self.__args]
        modified = any([arg != arg_new for arg, arg_new in zip(self.__args, args)])
        if modified:
            return ExprCompose(*args)
        return self

    def copy(self):
        args = [arg.copy() for arg in self.__args]
        return ExprCompose(*args)

    def depth(self):
        depth = [arg.depth() for arg in self.__args]
        return max(depth) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in self.args:
            arg.graph_recursive(graph)
            graph.add_uniq_edge(self, arg)

    def iter_args(self):
        index = 0
        for arg in self.__args:
            yield index, arg
            index += arg.size

    def is_compose(self):
        return True

# Expression order for comparaison
expr_order_dict = {ExprId: 1,
                   ExprCond: 2,
                   ExprMem: 3,
                   ExprOp: 4,
                   ExprSlice: 5,
                   ExprCompose: 7,
                   ExprInt: 8,
                   }


def compare_exprs_compose(e1, e2):
    # Sort by start bit address, then expr, then stop but address
    x = cmp(e1[1], e2[1])
    if x:
        return x
    x = compare_exprs(e1[0], e2[0])
    if x:
        return x
    x = cmp(e1[2], e2[2])
    return x


def compare_expr_list_compose(l1_e, l2_e):
    # Sort by list elements in incremental order, then by list size
    for i in xrange(min(len(l1_e), len(l2_e))):
        x = compare_exprs(l1_e[i], l2_e[i])
        if x:
            return x
    return cmp(len(l1_e), len(l2_e))


def compare_expr_list(l1_e, l2_e):
    # Sort by list elements in incremental order, then by list size
    for i in xrange(min(len(l1_e), len(l2_e))):
        x = compare_exprs(l1_e[i], l2_e[i])
        if x:
            return x
    return cmp(len(l1_e), len(l2_e))


def compare_exprs(e1, e2):
    """Compare 2 expressions for canonization
    @e1: Expr
    @e2: Expr
    0  => ==
    1  => e1 > e2
    -1 => e1 < e2
    """
    c1 = e1.__class__
    c2 = e2.__class__
    if c1 != c2:
        return cmp(expr_order_dict[c1], expr_order_dict[c2])
    if e1 == e2:
        return 0
    if c1 == ExprInt:
        ret = cmp(e1.size, e2.size)
        if ret != 0:
            return ret
        return cmp(e1.arg, e2.arg)
    elif c1 == ExprId:
        x = cmp(e1.name, e2.name)
        if x:
            return x
        return cmp(e1.size, e2.size)
    elif c1 == ExprAff:
        raise NotImplementedError(
            "Comparaison from an ExprAff not yet implemented")
    elif c2 == ExprCond:
        x = compare_exprs(e1.cond, e2.cond)
        if x:
            return x
        x = compare_exprs(e1.src1, e2.src1)
        if x:
            return x
        x = compare_exprs(e1.src2, e2.src2)
        return x
    elif c1 == ExprMem:
        x = compare_exprs(e1.arg, e2.arg)
        if x:
            return x
        return cmp(e1.size, e2.size)
    elif c1 == ExprOp:
        if e1.op != e2.op:
            return cmp(e1.op, e2.op)
        return compare_expr_list(e1.args, e2.args)
    elif c1 == ExprSlice:
        x = compare_exprs(e1.arg, e2.arg)
        if x:
            return x
        x = cmp(e1.start, e2.start)
        if x:
            return x
        x = cmp(e1.stop, e2.stop)
        return x
    elif c1 == ExprCompose:
        return compare_expr_list_compose(e1.args, e2.args)
    raise NotImplementedError(
        "Comparaison between %r %r not implemented" % (e1, e2))


def canonize_expr_list(l):
    l = list(l)
    l.sort(cmp=compare_exprs)
    return l


def canonize_expr_list_compose(l):
    l = list(l)
    l.sort(cmp=compare_exprs_compose)
    return l

# Generate ExprInt with common size


def ExprInt1(i):
    warnings.warn('DEPRECATION WARNING: use ExprInt(i, 1) instead of '\
                  'ExprInt1(i))')
    return ExprInt(i, 1)


def ExprInt8(i):
    warnings.warn('DEPRECATION WARNING: use ExprInt(i, 8) instead of '\
                  'ExprInt8(i))')
    return ExprInt(i, 8)


def ExprInt16(i):
    warnings.warn('DEPRECATION WARNING: use ExprInt(i, 16) instead of '\
                  'ExprInt16(i))')
    return ExprInt(i, 16)


def ExprInt32(i):
    warnings.warn('DEPRECATION WARNING: use ExprInt(i, 32) instead of '\
                  'ExprInt32(i))')
    return ExprInt(i, 32)


def ExprInt64(i):
    warnings.warn('DEPRECATION WARNING: use ExprInt(i, 64) instead of '\
                  'ExprInt64(i))')
    return ExprInt(i, 64)


def ExprInt_from(e, i):
    "Generate ExprInt with size equal to expression"
    warnings.warn('DEPRECATION WARNING: use ExprInt(i, expr.size) instead of'\
                  'ExprInt_from(expr, i))')
    return ExprInt(i, e.size)


def get_expr_ids_visit(e, ids):
    if isinstance(e, ExprId):
        ids.add(e)
    return e


def get_expr_ids(e):
    ids = set()
    e.visit(lambda x: get_expr_ids_visit(x, ids))
    return ids


def test_set(e, v, tks, result):
    """Test if v can correspond to e. If so, update the context in result.
    Otherwise, return False
    @e : Expr
    @v : Expr
    @tks : list of ExprId, available jokers
    @result : dictionary of ExprId -> Expr, current context
    """

    if not v in tks:
        return e == v
    if v in result and result[v] != e:
        return False
    result[v] = e
    return result


def MatchExpr(e, m, tks, result=None):
    """Try to match m expression with e expression with tks jokers.
    Result is output dictionary with matching joker values.
    @e : Expr to test
    @m : Targetted Expr
    @tks : list of ExprId, available jokers
    @result : dictionary of ExprId -> Expr, output matching context
    """

    if result is None:
        result = {}

    if m in tks:
        # m is a Joker
        return test_set(e, m, tks, result)

    if isinstance(e, ExprInt):
        return test_set(e, m, tks, result)

    elif isinstance(e, ExprId):
        return test_set(e, m, tks, result)

    elif isinstance(e, ExprOp):

        # e need to be the same operation than m
        if not isinstance(m, ExprOp):
            return False
        if e.op != m.op:
            return False
        if len(e.args) != len(m.args):
            return False

        # Perform permutation only if the current operation is commutative
        if e.is_commutative():
            permutations = itertools.permutations(e.args)
        else:
            permutations = [e.args]

        # For each permutations of arguments
        for permut in permutations:
            good = True
            # We need to use a copy of result to not override it
            myresult = dict(result)
            for a1, a2 in zip(permut, m.args):
                r = MatchExpr(a1, a2, tks, myresult)
                # If the current permutation do not match EVERY terms
                if r is False:
                    good = False
                    break
            if good is True:
                # We found a possibility
                for k, v in myresult.items():
                    # Updating result in place (to keep pointer in recursion)
                    result[k] = v
                return result
        return False

    # Recursive tests

    elif isinstance(e, ExprMem):
        if not isinstance(m, ExprMem):
            return False
        if e.size != m.size:
            return False
        return MatchExpr(e.arg, m.arg, tks, result)

    elif isinstance(e, ExprSlice):
        if not isinstance(m, ExprSlice):
            return False
        if e.start != m.start or e.stop != m.stop:
            return False
        return MatchExpr(e.arg, m.arg, tks, result)

    elif isinstance(e, ExprCond):
        if not isinstance(m, ExprCond):
            return False
        r = MatchExpr(e.cond, m.cond, tks, result)
        if r is False:
            return False
        r = MatchExpr(e.src1, m.src1, tks, result)
        if r is False:
            return False
        r = MatchExpr(e.src2, m.src2, tks, result)
        if r is False:
            return False
        return result

    elif isinstance(e, ExprCompose):
        if not isinstance(m, ExprCompose):
            return False
        for a1, a2 in zip(e.args, m.args):
            r = MatchExpr(a1, a2, tks, result)
            if r is False:
                return False
        return result

    elif isinstance(e, ExprAff):
        if not isinstance(m, ExprAff):
            return False
        r = MatchExpr(e.src, m.src, tks, result)
        if r is False:
            return False
        r = MatchExpr(e.dst, m.dst, tks, result)
        if r is False:
            return False
        return result

    else:
        raise NotImplementedError("MatchExpr: Unknown type: %s" % type(e))


def SearchExpr(e, m, tks, result=None):
    # TODO XXX: to test
    if result is None:
        result = set()

    def visit_search(e, m, tks, result):
        r = {}
        MatchExpr(e, m, tks, r)
        if r:
            result.add(tuple(r.items()))
        return e
    e.visit(lambda x: visit_search(x, m, tks, result))


def get_rw(exprs):
    o_r = set()
    o_w = set()
    for e in exprs:
        o_r.update(e.get_r(mem_read=True))
    for e in exprs:
        o_w.update(e.get_w())
    return o_r, o_w


def get_list_rw(exprs, mem_read=False, cst_read=True):
    """
    return list of read/write reg/cst/mem for each expressions
    """
    list_rw = []
    # cst_num = 0
    for e in exprs:
        o_r = set()
        o_w = set()
        # get r/w
        o_r.update(e.get_r(mem_read=mem_read, cst_read=cst_read))
        if isinstance(e.dst, ExprMem):
            o_r.update(e.dst.arg.get_r(mem_read=mem_read, cst_read=cst_read))
        o_w.update(e.get_w())
        # each cst is indexed
        o_r_rw = set()
        for r in o_r:
            o_r_rw.add(r)
        o_r = o_r_rw
        list_rw.append((o_r, o_w))

    return list_rw


def get_expr_ops(e):
    def visit_getops(e, out=None):
        if out is None:
            out = set()
        if isinstance(e, ExprOp):
            out.add(e.op)
        return e
    ops = set()
    e.visit(lambda x: visit_getops(x, ops))
    return ops


def get_expr_mem(e):
    def visit_getmem(e, out=None):
        if out is None:
            out = set()
        if isinstance(e, ExprMem):
            out.add(e)
        return e
    ops = set()
    e.visit(lambda x: visit_getmem(x, ops))
    return ops
