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
from miasm2.expression.modint import *
from miasm2.core.graph import DiGraph

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

    is_term = False   # Terminal expression
    is_simp = False   # Expression already simplified
    is_canon = False  # Expression already canonised
    is_eval = False   # Expression already evalued

    def set_size(self, value):
        raise ValueError('size is not mutable')

    def __init__(self, arg):
        self.arg = arg

    size = property(lambda self: self._size)

    # Common operations

    def __str__(self):
        return str(self.arg)

    def __getitem__(self, i):
        if not isinstance(i, slice):
            raise TypeError("Expression: Bad slice: %s" % i)
        start, stop, step = i.indices(self.size)
        if step != 1:
            raise ValueError("Expression: Bad slice: %s" % i)
        return ExprSlice(self, start, stop)

    def get_size(self):
        raise DeprecationWarning("use X.size instead of X.get_size()")

    def get_r(self, mem_read=False, cst_read=False):
        return self.arg.get_r(mem_read, cst_read)

    def get_w(self):
        return self.arg.get_w()

    def __repr__(self):
        return "<%s_%d_0x%x>" % (self.__class__.__name__, self.size, id(self))

    def __hash__(self):
        return self._hash

    def __eq__(self, a):
        if isinstance(a, Expr):
            return hash(self) == hash(a)
        else:
            return False

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

    def __invert__(self):
        s = self.size
        return ExprOp('^', self, ExprInt(mod_size2uint[s](size2mask(s))))

    def copy(self):
        "Deep copy of the expression"
        return self.visit(lambda x: x)

    def replace_expr(self, dct=None):
        """Find and replace sub expression using dct
        @dct: dictionnary of Expr -> *
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
            elif isinstance(e, ExprCompose):
                new_e = ExprCompose(canonize_expr_list_compose(e.args))
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
        n = ExprInt_fromsize(ad_size, 0)
        return ExprCompose([(self, 0, self.size),
                            (n, self.size, size)])

    def signExtend(self, size):
        """Sign extend to size
        @size: int
        """
        assert(self.size <= size)
        if self.size == size:
            return self
        ad_size = size - self.size
        c = ExprCompose([(self, 0, self.size),
                         (ExprCond(self.msb(),
                                   ExprInt_fromsize(
                                       ad_size, size2mask(ad_size)),
                                   ExprInt_fromsize(ad_size, 0)),
                          self.size, size)
                         ])
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

    mask = property(lambda self: ExprInt_fromsize(self.size, -1))


class ExprInt(Expr):

    """An ExprInt represent a constant in Miasm IR.

    Some use cases:
     - Constant 0x42
     - Constant -0x30
     - Constant 0x12345678 on 32bits
     """

    def __init__(self, arg):
        """Create an ExprInt from a numpy int
        @arg: numpy int"""

        if not is_modint(arg):
            raise ValueError('arg must by numpy int! %s' % arg)

        self._arg = arg
        self._size = self.arg.size
        self._hash = self._exprhash()

    arg = property(lambda self: self._arg)

    def __get_int(self):
        "Return self integer representation"
        return int(self._arg & size2mask(self._size))

    def __str__(self):
        if self._arg < 0:
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
        return hash((EXPRINT, self._arg, self._size))

    def __contains__(self, e):
        return self == e

    def __repr__(self):
        return Expr.__repr__(self)[:-1] + " 0x%X>" % self.__get_int()

    @visit_chk
    def visit(self, cb, tv=None):
        return self

    def copy(self):
        return ExprInt(self._arg)

    def depth(self):
        return 1

    def graph_recursive(self, graph):
        graph.add_node(self)


class ExprId(Expr):

    """An ExprId represent an identifier in Miasm IR.

    Some use cases:
     - EAX register
     - 'start' offset
     - variable v1
     """

    def __init__(self, name, size=32):
        """Create an identifier
        @name: str, identifier's name
        @size: int, identifier's size
        """

        self._name, self._size = name, size
        self._hash = self._exprhash()

    name = property(lambda self: self._name)

    def __str__(self):
        return str(self._name)

    def get_r(self, mem_read=False, cst_read=False):
        return set([self])

    def get_w(self):
        return set([self])

    def _exprhash(self):
        # TODO XXX: hash size ??
        return hash((EXPRID, self._name, self._size))

    def __contains__(self, e):
        return self == e

    def __repr__(self):
        return Expr.__repr__(self)[:-1] + " %s>" % self._name

    @visit_chk
    def visit(self, cb, tv=None):
        return self

    def copy(self):
        return ExprId(self._name, self._size)

    def depth(self):
        return 1

    def graph_recursive(self, graph):
        graph.add_node(self)


class ExprAff(Expr):

    """An ExprAff represent an affection from an Expression to another one.

    Some use cases:
     - var1 <- 2
    """

    def __init__(self, dst, src):
        """Create an ExprAff for dst <- src
        @dst: Expr, affectation destination
        @src: Expr, affectation source
        """
        if dst.size != src.size:
            raise ValueError(
                "sanitycheck: ExprAff args must have same size! %s" %
                             ([(str(arg), arg.size) for arg in [dst, src]]))

        if isinstance(dst, ExprSlice):
            # Complete the source with missing slice parts
            self._dst = dst.arg
            rest = [(ExprSlice(dst.arg, r[0], r[1]), r[0], r[1])
                    for r in dst.slice_rest()]
            all_a = [(src, dst.start, dst.stop)] + rest
            all_a.sort(key=lambda x: x[1])
            self._src = ExprCompose(all_a)

        else:
            self._dst, self._src = dst, src

        self._size = self.dst.size
        self._hash = self._exprhash()

    dst = property(lambda self: self._dst)
    src = property(lambda self: self._src)

    def __str__(self):
        return "%s = %s" % (str(self._dst), str(self._src))

    def get_r(self, mem_read=False, cst_read=False):
        elements = self._src.get_r(mem_read, cst_read)
        if isinstance(self._dst, ExprMem):
            elements.update(self._dst.arg.get_r(mem_read, cst_read))
        return elements

    def get_w(self):
        if isinstance(self._dst, ExprMem):
            return set([self._dst])  # [memreg]
        else:
            return self._dst.get_w()

    def _exprhash(self):
        return hash((EXPRAFF, hash(self._dst), hash(self._src)))

    def __contains__(self, e):
        return self == e or self._src.__contains__(e) or self._dst.__contains__(e)

    # XXX /!\ for hackish expraff to slice
    def get_modified_slice(self):
        """Return an Expr list of extra expressions needed during the
        object instanciation"""

        dst = self._dst
        if not isinstance(self._src, ExprCompose):
            raise ValueError("Get mod slice not on expraff slice", str(self))
        modified_s = []
        for arg in self._src.args:
            if (not isinstance(arg[0], ExprSlice) or
                    arg[0].arg != dst or
                    arg[1] != arg[0].start or
                    arg[2] != arg[0].stop):
                # If x is not the initial expression
                modified_s.append(arg)
        return modified_s

    @visit_chk
    def visit(self, cb, tv=None):
        dst, src = self._dst.visit(cb, tv), self._src.visit(cb, tv)
        if dst == self._dst and src == self._src:
            return self
        else:
            return ExprAff(dst, src)

    def copy(self):
        return ExprAff(self._dst.copy(), self._src.copy())

    def depth(self):
        return max(self._src.depth(), self._dst.depth()) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in [self._src, self._dst]:
            arg.graph_recursive(graph)
            graph.add_uniq_edge(self, arg)


class ExprCond(Expr):

    """An ExprCond stand for a condition on an Expr

    Use cases:
     - var1 < var2
     - min(var1, var2)
     - if (cond) then ... else ...
    """

    def __init__(self, cond, src1, src2):
        """Create an ExprCond
        @cond: Expr, condition
        @src1: Expr, value if condition is evaled to not zero
        @src2: Expr, value if condition is evaled zero
        """

        assert(src1.size == src2.size)

        self._cond, self._src1, self._src2 = cond, src1, src2
        self._size = self.src1.size
        self._hash = self._exprhash()

    cond = property(lambda self: self._cond)
    src1 = property(lambda self: self._src1)
    src2 = property(lambda self: self._src2)

    def __str__(self):
        return "(%s?(%s,%s))" % (str(self._cond), str(self._src1), str(self._src2))

    def get_r(self, mem_read=False, cst_read=False):
        out_src1 = self._src1.get_r(mem_read, cst_read)
        out_src2 = self._src2.get_r(mem_read, cst_read)
        return self._cond.get_r(mem_read,
                                cst_read).union(out_src1).union(out_src2)

    def get_w(self):
        return set()

    def _exprhash(self):
        return hash((EXPRCOND, hash(self.cond),
                     hash(self._src1), hash(self._src2)))

    def __contains__(self, e):
        return (self == e or
                self._cond.__contains__(e) or
                self._src1.__contains__(e) or
                self._src2.__contains__(e))

    @visit_chk
    def visit(self, cb, tv=None):
        cond = self._cond.visit(cb, tv)
        src1 = self._src1.visit(cb, tv)
        src2 = self._src2.visit(cb, tv)
        if (cond == self._cond and
            src1 == self._src1 and
            src2 == self._src2):
            return self
        return ExprCond(cond, src1, src2)

    def copy(self):
        return ExprCond(self._cond.copy(),
                        self._src1.copy(),
                        self._src2.copy())

    def depth(self):
        return max(self._cond.depth(),
                   self._src1.depth(),
                   self._src2.depth()) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in [self._cond, self._src1, self._src2]:
            arg.graph_recursive(graph)
            graph.add_uniq_edge(self, arg)


class ExprMem(Expr):

    """An ExprMem stand for a memory access

    Use cases:
     - Memory read
     - Memory write
    """

    def __init__(self, arg, size=32):
        """Create an ExprMem
        @arg: Expr, memory access address
        @size: int, memory access size
        """
        if not isinstance(arg, Expr):
            raise ValueError(
                'ExprMem: arg must be an Expr (not %s)' % type(arg))

        self._arg, self._size = arg, size
        self._hash = self._exprhash()

    arg = property(lambda self: self._arg)

    def __str__(self):
        return "@%d[%s]" % (self._size, str(self._arg))

    def get_r(self, mem_read=False, cst_read=False):
        if mem_read:
            return set(self._arg.get_r(mem_read, cst_read).union(set([self])))
        else:
            return set([self])

    def get_w(self):
        return set([self])  # [memreg]

    def _exprhash(self):
        return hash((EXPRMEM, hash(self._arg), self._size))

    def __contains__(self, e):
        return self == e or self._arg.__contains__(e)

    @visit_chk
    def visit(self, cb, tv=None):
        arg = self._arg.visit(cb, tv)
        if arg == self._arg:
            return self
        return ExprMem(arg, self._size)

    def copy(self):
        arg = self._arg.copy()
        return ExprMem(arg, size=self._size)

    def is_op_segm(self):
        return isinstance(self._arg, ExprOp) and self._arg.op == 'segm'

    def depth(self):
        return self._arg.depth() + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        self._arg.graph_recursive(graph)
        graph.add_uniq_edge(self, self._arg)


class ExprOp(Expr):

    """An ExprOp stand for an operation between Expr

    Use cases:
     - var1 XOR var2
     - var1 + var2 + var3
     - parity bit(var1)
    """

    def __init__(self, op, *args):
        """Create an ExprOp
        @op: str, operation
        @*args: Expr, operand list
        """

        sizes = set([arg.size for arg in args])

        if len(sizes) != 1:
            # Special cases : operande sizes can differ
            if op not in ["segm"]:
                raise ValueError(
                    "sanitycheck: ExprOp args must have same size! %s" %
                                 ([(str(arg), arg.size) for arg in args]))

        if not isinstance(op, str):
            raise ValueError("ExprOp: 'op' argument must be a string")

        self._op, self._args = op, tuple(args)

        # Set size for special cases
        if self._op in [
                '==', 'parity', 'fcom_c0', 'fcom_c1', 'fcom_c2', 'fcom_c3',
                "access_segment_ok", "load_segment_limit_ok", "bcdadd_cf",
                "ucomiss_zf", "ucomiss_pf", "ucomiss_cf"]:
            sz = 1
        elif self._op in [TOK_INF, TOK_INF_SIGNED,
                          TOK_INF_UNSIGNED, TOK_INF_EQUAL,
                          TOK_INF_EQUAL_SIGNED, TOK_INF_EQUAL_UNSIGNED,
                          TOK_EQUAL, TOK_POS,
                          TOK_POS_STRICT,
                          ]:
            sz = 1
        elif self._op in ['mem_16_to_double', 'mem_32_to_double',
                          'mem_64_to_double', 'mem_80_to_double',
                          'int_16_to_double', 'int_32_to_double',
                          'int_64_to_double', 'int_80_to_double']:
            sz = 64
        elif self._op in ['double_to_mem_16', 'double_to_int_16', 'double_trunc_to_int_16']:
            sz = 16
        elif self._op in ['double_to_mem_32', 'double_to_int_32', 'double_trunc_to_int_32']:
            sz = 32
        elif self._op in ['double_to_mem_64', 'double_to_int_64', 'double_trunc_to_int_64']:
            sz = 64
        elif self._op in ['double_to_mem_80', 'double_to_int_80', 'double_trunc_to_int_80']:
            sz = 80
        elif self._op in ['segm']:
            sz = self._args[1].size
        else:
            if None in sizes:
                sz = None
            else:
                # All arguments have the same size
                sz = list(sizes)[0]

        self._size = sz
        self._hash = self._exprhash()

    op = property(lambda self: self._op)
    args = property(lambda self: self._args)

    def __str__(self):
        if self.is_associative():
            return '(' + self._op.join([str(arg) for arg in self._args]) + ')'
        if len(self._args) == 2:
            return ('(' + str(self._args[0]) +
                    ' ' + self.op + ' ' + str(self._args[1]) + ')')
        elif len(self._args) > 2:
            return self._op + '(' + ', '.join([str(arg) for arg in self._args]) + ')'
        else:
            return reduce(lambda x, y: x + ' ' + str(y),
                          self._args,
                          '(' + str(self._op)) + ')'

    def get_r(self, mem_read=False, cst_read=False):
        return reduce(lambda elements, arg:
                      elements.union(arg.get_r(mem_read, cst_read)), self._args, set())

    def get_w(self):
        raise ValueError('op cannot be written!', self)

    def _exprhash(self):
        h_hargs = [hash(arg) for arg in self._args]
        return hash((EXPROP, self._op, tuple(h_hargs)))

    def __contains__(self, e):
        if self == e:
            return True
        for arg in self._args:
            if arg.__contains__(e):
                return True
        return False

    def is_associative(self):
        "Return True iff current operation is associative"
        return (self._op in ['+', '*', '^', '&', '|'])

    def is_commutative(self):
        "Return True iff current operation is commutative"
        return (self._op in ['+', '*', '^', '&', '|'])

    @visit_chk
    def visit(self, cb, tv=None):
        args = [arg.visit(cb, tv) for arg in self._args]
        modified = any([arg[0] != arg[1] for arg in zip(self._args, args)])
        if modified:
            return ExprOp(self._op, *args)
        return self

    def copy(self):
        args = [arg.copy() for arg in self._args]
        return ExprOp(self._op, *args)

    def depth(self):
        depth = [arg.depth() for arg in self._args]
        return max(depth) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in self._args:
            arg.graph_recursive(graph)
            graph.add_uniq_edge(self, arg)


class ExprSlice(Expr):

    def __init__(self, arg, start, stop):
        assert(start < stop)

        self._arg, self._start, self._stop = arg, start, stop
        self._size = self._stop - self._start
        self._hash = self._exprhash()

    arg = property(lambda self: self._arg)
    start = property(lambda self: self._start)
    stop = property(lambda self: self._stop)

    def __str__(self):
        return "%s[%d:%d]" % (str(self._arg), self._start, self._stop)

    def get_r(self, mem_read=False, cst_read=False):
        return self._arg.get_r(mem_read, cst_read)

    def get_w(self):
        return self._arg.get_w()

    def _exprhash(self):
        return hash((EXPRSLICE, hash(self._arg), self._start, self._stop))

    def __contains__(self, e):
        if self == e:
            return True
        return self._arg.__contains__(e)

    @visit_chk
    def visit(self, cb, tv=None):
        arg = self._arg.visit(cb, tv)
        if arg == self._arg:
            return self
        return ExprSlice(arg, self._start, self._stop)

    def copy(self):
        return ExprSlice(self._arg.copy(), self._start, self._stop)

    def depth(self):
        return self._arg.depth() + 1

    def slice_rest(self):
        "Return the completion of the current slice"
        size = self._arg.size
        if self._start >= size or self._stop > size:
            raise ValueError('bad slice rest %s %s %s' %
                             (size, self._start, self._stop))

        if self._start == self._stop:
            return [(0, size)]

        rest = []
        if self._start != 0:
            rest.append((0, self._start))
        if self._stop < size:
            rest.append((self._stop, size))

        return rest

    def graph_recursive(self, graph):
        graph.add_node(self)
        self._arg.graph_recursive(graph)
        graph.add_uniq_edge(self, self._arg)


class ExprCompose(Expr):

    """
    Compose is like a hambuger.
    It's arguments are tuple of:  (Expression, start, stop)
    start and stop are intergers, determining Expression position in the compose.

    Burger Example:
    ExprCompose([(salad, 0, 3), (cheese, 3, 10), (beacon, 10, 16)])
    In the example, salad.size == 3.
    """

    def __init__(self, args):
        """Create an ExprCompose
        The ExprCompose is contiguous and starts at 0
        @args: tuple(Expr, int, int)
        """

        last_stop = 0
        args = sorted(args, key=itemgetter(1))
        for e, start, stop in args:
            if e.size != stop - start:
                raise ValueError(
                    "sanitycheck: ExprCompose args must have correct size!" +
                    " %r %r %r" % (e, e.size, stop - start))
            if last_stop != start:
                raise ValueError(
                    "sanitycheck: ExprCompose args must be contiguous!" +
                    " %r" % (args))
            last_stop = stop

        # Transform args to lists
        o = []
        for e, a, b in args:
            assert(a >= 0 and b >= 0)
            o.append(tuple([e, a, b]))
        self._args = tuple(o)

        self._size = self._args[-1][2]
        self._hash = self._exprhash()

    args = property(lambda self: self._args)

    def __str__(self):
        return '{' + ', '.join(['%s,%d,%d' %
                                (str(arg[0]), arg[1], arg[2]) for arg in self._args]) + '}'

    def get_r(self, mem_read=False, cst_read=False):
        return reduce(lambda elements, arg:
                      elements.union(arg[0].get_r(mem_read, cst_read)), self._args, set())

    def get_w(self):
        return reduce(lambda elements, arg:
                      elements.union(arg[0].get_w()), self._args, set())

    def _exprhash(self):
        h_args = [EXPRCOMPOSE] + [(hash(arg[0]), arg[1], arg[2])
                                  for arg in self._args]
        return hash(tuple(h_args))

    def __contains__(self, e):
        if self == e:
            return True
        for arg in self._args:
            if arg == e:
                return True
            if arg[0].__contains__(e):
                return True
        return False

    @visit_chk
    def visit(self, cb, tv=None):
        args = [(arg[0].visit(cb, tv), arg[1], arg[2]) for arg in self._args]
        modified = any([arg[0] != arg[1] for arg in zip(self._args, args)])
        if modified:
            return ExprCompose(args)
        return self

    def copy(self):
        args = [(arg[0].copy(), arg[1], arg[2]) for arg in self._args]
        return ExprCompose(args)

    def depth(self):
        depth = [arg[0].depth() for arg in self._args]
        return max(depth) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in self.args:
            arg[0].graph_recursive(graph)
            graph.add_uniq_edge(self, arg[0])


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
        x = compare_exprs_compose(l1_e[i], l2_e[i])
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
    return ExprInt(uint1(i))


def ExprInt8(i):
    return ExprInt(uint8(i))


def ExprInt16(i):
    return ExprInt(uint16(i))


def ExprInt32(i):
    return ExprInt(uint32(i))


def ExprInt64(i):
    return ExprInt(uint64(i))


def ExprInt_from(e, i):
    "Generate ExprInt with size equal to expression"
    return ExprInt(mod_size2uint[e.size](i))


def ExprInt_fromsize(size, i):
    "Generate ExprInt with a given size"
    return ExprInt(mod_size2uint[size](i))


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
    @result : dictionnary of ExprId -> Expr, current context
    """

    if not v in tks:
        return e == v
    if v in result and result[v] != e:
        return False
    result[v] = e
    return result


def MatchExpr(e, m, tks, result=None):
    """Try to match m expression with e expression with tks jokers.
    Result is output dictionnary with matching joker values.
    @e : Expr to test
    @m : Targetted Expr
    @tks : list of ExprId, available jokers
    @result : dictionnary of ExprId -> Expr, output matching context
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
            if a1[1] != a2[1] or a1[2] != a2[2]:
                return False
            r = MatchExpr(a1[0], a2[0], tks, result)
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
            # if isinstance(r, ExprInt):
            #    r = ExprOp('cst_%d'%cst_num, r)
            #    cst_num += 1
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
