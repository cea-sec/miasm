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
#  - ExprLoc
#  - ExprAssign
#  - ExprCond
#  - ExprMem
#  - ExprOp
#  - ExprSlice
#  - ExprCompose
#


import warnings
import itertools
from miasm2.expression.modint import mod_size2uint, is_modint, size2mask, \
    define_uint
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
EXPRLOC = 3
EXPRASSIGN = 4
EXPRCOND = 5
EXPRMEM = 6
EXPROP = 7
EXPRSLICE = 8
EXPRCOMPOSE = 9


priorities_list = [
    [ '+' ],
    [ '*', '/', '%'  ],
    [ '**' ],
    [ '-' ],	# Unary '-', associativity with + not handled
]

# dictionary from 'op' to priority, derived from above
priorities = dict((op, prio)
                  for prio, l in enumerate(priorities_list)
                  for op in l)
PRIORITY_MAX = len(priorities_list) - 1

def should_parenthesize_child(child, parent):
    if (isinstance(child, ExprId) or isinstance(child, ExprInt) or
        isinstance(child, ExprCompose) or isinstance(child, ExprMem) or
        isinstance(child, ExprSlice)):
        return False
    elif isinstance(child, ExprOp) and not child.is_infix():
        return False
    elif (isinstance(child, ExprCond) or isinstance(parent, ExprSlice)):
        return True
    elif (isinstance(child, ExprOp) and isinstance(parent, ExprOp)):
        pri_child = priorities.get(child.op, -1)
        pri_parent = priorities.get(parent.op, PRIORITY_MAX + 1)
        return pri_child < pri_parent
    else:
        return True

def str_protected_child(child, parent):
    return ("(%s)" % child) if should_parenthesize_child(child, parent) else str(child)

def visit_chk(visitor):
    "Function decorator launching callback on Expression visit"
    def wrapped(expr, callback, test_visit=lambda x: True):
        if (test_visit is not None) and (not test_visit(expr)):
            return expr
        expr_new = visitor(expr, callback, test_visit)
        if expr_new is None:
            return None
        expr_new2 = callback(expr_new)
        return expr_new2
    return wrapped


# Expression display


class DiGraphExpr(DiGraph):

    """Enhanced graph for Expression display
    Expression are displayed as a tree with node and edge labeled
    with only relevant information"""

    def node2str(self, node):
        if isinstance(node, ExprOp):
            return node.op
        elif isinstance(node, ExprId):
            return node.name
        elif isinstance(node, ExprLoc):
            return "%s" % node.loc_key
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



class LocKey(object):
    def __init__(self, key):
        self._key = key

    key = property(lambda self: self._key)

    def __hash__(self):
        return hash(self._key)

    def __eq__(self, other):
        if self is other:
            return True
        if self.__class__ is not other.__class__:
            return False
        return self.key == other.key

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "<%s %d>" % (self.__class__.__name__, self._key)

    def __str__(self):
        return "loc_key_%d" % self.key

# IR definitions

class Expr(object):

    "Parent class for Miasm Expressions"

    __slots__ = ["_hash", "_repr", "_size"]

    args2expr = {}
    canon_exprs = set()
    use_singleton = True

    def set_size(self, _):
        raise ValueError('size is not mutable')

    def __init__(self, size):
        """Instantiate an Expr with size @size
        @size: int
        """
        # Common attribute
        self._size = size

        # Lazy cache needs
        self._hash = None
        self._repr = None

    size = property(lambda self: self._size)

    @staticmethod
    def get_object(expr_cls, args):
        if not expr_cls.use_singleton:
            return object.__new__(expr_cls, args)

        expr = Expr.args2expr.get((expr_cls, args))
        if expr is None:
            expr = object.__new__(expr_cls, args)
            Expr.args2expr[(expr_cls, args)] = expr
        return expr

    def get_is_canon(self):
        return self in Expr.canon_exprs

    def set_is_canon(self, value):
        assert value is True
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
        if self._repr is None:
            self._repr = self._exprrepr()
        return self._repr

    def __hash__(self):
        if self._hash is None:
            self._hash = self._exprhash()
        return self._hash

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

    def __ne__(self, other):
        return not self.__eq__(other)

    def __add__(self, other):
        return ExprOp('+', self, other)

    def __sub__(self, other):
        return ExprOp('+', self, ExprOp('-', other))

    def __div__(self, other):
        return ExprOp('/', self, other)

    def __mod__(self, other):
        return ExprOp('%', self, other)

    def __mul__(self, other):
        return ExprOp('*', self, other)

    def __lshift__(self, other):
        return ExprOp('<<', self, other)

    def __rshift__(self, other):
        return ExprOp('>>', self, other)

    def __xor__(self, other):
        return ExprOp('^', self, other)

    def __or__(self, other):
        return ExprOp('|', self, other)

    def __and__(self, other):
        return ExprOp('&', self, other)

    def __neg__(self):
        return ExprOp('-', self)

    def __pow__(self, other):
        return ExprOp("**", self, other)

    def __invert__(self):
        return ExprOp('^', self, self.mask)

    def copy(self):
        "Deep copy of the expression"
        return self.visit(lambda x: x)

    def __deepcopy__(self, _):
        return self.copy()

    def replace_expr(self, dct):
        """Find and replace sub expression using dct
        @dct: dictionary associating replaced Expr to its new Expr value
        """
        return self.visit(lambda expr: dct.get(expr, expr))

    def canonize(self):
        "Canonize the Expression"

        def must_canon(expr):
            return not expr.is_canon

        def canonize_visitor(expr):
            if expr.is_canon:
                return expr
            if isinstance(expr, ExprOp):
                if expr.is_associative():
                    # ((a+b) + c) => (a + b + c)
                    args = []
                    for arg in expr.args:
                        if isinstance(arg, ExprOp) and expr.op == arg.op:
                            args += arg.args
                        else:
                            args.append(arg)
                    args = canonize_expr_list(args)
                    new_e = ExprOp(expr.op, *args)
                else:
                    new_e = expr
            else:
                new_e = expr
            new_e.is_canon = True
            return new_e

        return self.visit(canonize_visitor, must_canon)

    def msb(self):
        "Return the Most Significant Bit"
        return self[self.size - 1:self.size]

    def zeroExtend(self, size):
        """Zero extend to size
        @size: int
        """
        assert self.size <= size
        if self.size == size:
            return self
        return ExprOp('zeroExt_%d' % size, self)

    def signExtend(self, size):
        """Sign extend to size
        @size: int
        """
        assert self.size <= size
        if self.size == size:
            return self
        return ExprOp('signExt_%d' % size, self)

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

    def is_loc(self, label=None):
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

    __slots__ = Expr.__slots__ + ["_arg"]


    def __init__(self, arg, size):
        """Create an ExprInt from a modint or num/size
        @arg: 'intable' number
        @size: int size"""
        super(ExprInt, self).__init__(size)
        # Work for ._arg is done in __new__

    arg = property(lambda self: self._arg)

    def __reduce__(self):
        state = int(self._arg), self._size
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
        expr._arg = arg
        return expr

    def _get_int(self):
        "Return self integer representation"
        return int(self._arg & size2mask(self._size))

    def __str__(self):
        if self._arg < 0:
            return str("-0x%X" % (- self._get_int()))
        else:
            return str("0x%X" % self._get_int())

    def get_r(self, mem_read=False, cst_read=False):
        if cst_read:
            return set([self])
        else:
            return set()

    def get_w(self):
        return set()

    def _exprhash(self):
        return hash((EXPRINT, self._arg, self._size))

    def _exprrepr(self):
        return "%s(0x%X, %d)" % (self.__class__.__name__, self._get_int(),
                                 self._size)

    def __contains__(self, expr):
        return self == expr

    @visit_chk
    def visit(self, callback, test_visit=None):
        return self

    def copy(self):
        return ExprInt(self._arg, self._size)

    def depth(self):
        return 1

    def graph_recursive(self, graph):
        graph.add_node(self)

    def __int__(self):
        return int(self.arg)

    def __long__(self):
        return long(self.arg)

    def is_int(self, value=None):
        if value is not None and self._arg != value:
            return False
        return True


class ExprId(Expr):

    """An ExprId represent an identifier in Miasm IR.

    Some use cases:
     - EAX register
     - 'start' offset
     - variable v1
     """

    __slots__ = Expr.__slots__ + ["_name"]

    def __init__(self, name, size=None):
        """Create an identifier
        @name: str, identifier's name
        @size: int, identifier's size
        """
        if size is None:
            warnings.warn('DEPRECATION WARNING: size is a mandatory argument: use ExprId(name, SIZE)')
            size = 32
        assert isinstance(name, str)
        super(ExprId, self).__init__(size)
        self._name = name

    name = property(lambda self: self._name)

    def __reduce__(self):
        state = self._name, self._size
        return self.__class__, state

    def __new__(cls, name, size=None):
        if size is None:
            warnings.warn('DEPRECATION WARNING: size is a mandatory argument: use ExprId(name, SIZE)')
            size = 32
        return Expr.get_object(cls, (name, size))

    def __str__(self):
        return str(self._name)

    def get_r(self, mem_read=False, cst_read=False):
        return set([self])

    def get_w(self):
        return set([self])

    def _exprhash(self):
        return hash((EXPRID, self._name, self._size))

    def _exprrepr(self):
        return "%s(%r, %d)" % (self.__class__.__name__, self._name, self._size)

    def __contains__(self, expr):
        return self == expr

    @visit_chk
    def visit(self, callback, test_visit=None):
        return self

    def copy(self):
        return ExprId(self._name, self._size)

    def depth(self):
        return 1

    def graph_recursive(self, graph):
        graph.add_node(self)

    def is_id(self, name=None):
        if name is not None and self._name != name:
            return False
        return True


class ExprLoc(Expr):

    """An ExprLoc represent a Label in Miasm IR.
    """

    __slots__ = Expr.__slots__ + ["_loc_key"]

    def __init__(self, loc_key, size):
        """Create an identifier
        @loc_key: int, label loc_key
        @size: int, identifier's size
        """
        assert isinstance(loc_key, LocKey)
        super(ExprLoc, self).__init__(size)
        self._loc_key = loc_key

    loc_key= property(lambda self: self._loc_key)

    def __reduce__(self):
        state = self._loc_key, self._size
        return self.__class__, state

    def __new__(cls, loc_key, size):
        return Expr.get_object(cls, (loc_key, size))

    def __str__(self):
        return str(self._loc_key)

    def get_r(self, mem_read=False, cst_read=False):
        return set()

    def get_w(self):
        return set()

    def _exprhash(self):
        return hash((EXPRLOC, self._loc_key, self._size))

    def _exprrepr(self):
        return "%s(%r, %d)" % (self.__class__.__name__, self._loc_key, self._size)

    def __contains__(self, expr):
        return self == expr

    @visit_chk
    def visit(self, callback, test_visit=None):
        return self

    def copy(self):
        return ExprLoc(self._loc_key, self._size)

    def depth(self):
        return 1

    def graph_recursive(self, graph):
        graph.add_node(self)

    def is_loc(self, loc_key=None):
        if loc_key is not None and self._loc_key != loc_key:
            return False
        return True


class ExprAssign(Expr):

    """An ExprAssign represent an assignment from an Expression to another one.

    Some use cases:
     - var1 <- 2
    """

    __slots__ = Expr.__slots__ + ["_dst", "_src"]

    def __init__(self, dst, src):
        """Create an ExprAssign for dst <- src
        @dst: Expr, assignment destination
        @src: Expr, assignment source
        """
        # dst & src must be Expr
        assert isinstance(dst, Expr)
        assert isinstance(src, Expr)

        if dst.size != src.size:
            raise ValueError(
                "sanitycheck: ExprAssign args must have same size! %s" %
                ([(str(arg), arg.size) for arg in [dst, src]]))

        super(ExprAssign, self).__init__(self.dst.size)

    dst = property(lambda self: self._dst)
    src = property(lambda self: self._src)


    def __reduce__(self):
        state = self._dst, self._src
        return self.__class__, state

    def __new__(cls, dst, src):
        if dst.is_slice() and dst.arg.size == src.size:
            new_dst, new_src = dst.arg, src
        elif dst.is_slice():
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
        expr._dst, expr._src = new_dst, new_src
        return expr

    def __str__(self):
        return "%s = %s" % (str(self._dst), str(self._src))

    def get_r(self, mem_read=False, cst_read=False):
        elements = self._src.get_r(mem_read, cst_read)
        if isinstance(self._dst, ExprMem) and mem_read:
            elements.update(self._dst.ptr.get_r(mem_read, cst_read))
        return elements

    def get_w(self):
        if isinstance(self._dst, ExprMem):
            return set([self._dst])  # [memreg]
        else:
            return self._dst.get_w()

    def _exprhash(self):
        return hash((EXPRASSIGN, hash(self._dst), hash(self._src)))

    def _exprrepr(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self._dst, self._src)

    def __contains__(self, expr):
        return (self == expr or
                self._src.__contains__(expr) or
                self._dst.__contains__(expr))

    @visit_chk
    def visit(self, callback, test_visit=None):
        dst, src = self._dst.visit(callback, test_visit), self._src.visit(callback, test_visit)
        if dst == self._dst and src == self._src:
            return self
        else:
            return ExprAssign(dst, src)

    def copy(self):
        return ExprAssign(self._dst.copy(), self._src.copy())

    def depth(self):
        return max(self._src.depth(), self._dst.depth()) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in [self._src, self._dst]:
            arg.graph_recursive(graph)
            graph.add_uniq_edge(self, arg)

    def is_aff(self):
        return True


class ExprAff(ExprAssign):
    """
    DEPRECATED class.
    Use ExprAssign instead of ExprAff
    """

    def __init__(self, dst, src):
        warnings.warn('DEPRECATION WARNING: use ExprAssign instead of ExprAff')
        super(ExprAff, self).__init__(dst, src)


class ExprCond(Expr):

    """An ExprCond stand for a condition on an Expr

    Use cases:
     - var1 < var2
     - min(var1, var2)
     - if (cond) then ... else ...
    """

    __slots__ = Expr.__slots__ + ["_cond", "_src1", "_src2"]

    def __init__(self, cond, src1, src2):
        """Create an ExprCond
        @cond: Expr, condition
        @src1: Expr, value if condition is evaled to not zero
        @src2: Expr, value if condition is evaled zero
        """

        # cond, src1, src2 must be Expr
        assert isinstance(cond, Expr)
        assert isinstance(src1, Expr)
        assert isinstance(src2, Expr)

        self._cond, self._src1, self._src2 = cond, src1, src2
        assert src1.size == src2.size
        super(ExprCond, self).__init__(self.src1.size)

    cond = property(lambda self: self._cond)
    src1 = property(lambda self: self._src1)
    src2 = property(lambda self: self._src2)

    def __reduce__(self):
        state = self._cond, self._src1, self._src2
        return self.__class__, state

    def __new__(cls, cond, src1, src2):
        return Expr.get_object(cls, (cond, src1, src2))

    def __str__(self):
        return "%s?(%s,%s)" % (str_protected_child(self._cond, self), str(self._src1), str(self._src2))

    def get_r(self, mem_read=False, cst_read=False):
        out_src1 = self.src1.get_r(mem_read, cst_read)
        out_src2 = self.src2.get_r(mem_read, cst_read)
        return self.cond.get_r(mem_read,
                               cst_read).union(out_src1).union(out_src2)

    def get_w(self):
        return set()

    def _exprhash(self):
        return hash((EXPRCOND, hash(self.cond),
                     hash(self._src1), hash(self._src2)))

    def _exprrepr(self):
        return "%s(%r, %r, %r)" % (self.__class__.__name__,
                                   self._cond, self._src1, self._src2)

    def __contains__(self, expr):
        return (self == expr or
                self.cond.__contains__(expr) or
                self.src1.__contains__(expr) or
                self.src2.__contains__(expr))

    @visit_chk
    def visit(self, callback, test_visit=None):
        cond = self._cond.visit(callback, test_visit)
        src1 = self._src1.visit(callback, test_visit)
        src2 = self._src2.visit(callback, test_visit)
        if cond == self._cond and src1 == self._src1 and src2 == self._src2:
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

    def is_cond(self):
        return True


class ExprMem(Expr):

    """An ExprMem stand for a memory access

    Use cases:
     - Memory read
     - Memory write
    """

    __slots__ = Expr.__slots__ + ["_ptr"]

    def __init__(self, ptr, size=None):
        """Create an ExprMem
        @ptr: Expr, memory access address
        @size: int, memory access size
        """
        if size is None:
            warnings.warn('DEPRECATION WARNING: size is a mandatory argument: use ExprMem(ptr, SIZE)')
            size = 32

        # ptr must be Expr
        assert isinstance(ptr, Expr)
        assert isinstance(size, (int, long))

        if not isinstance(ptr, Expr):
            raise ValueError(
                'ExprMem: ptr must be an Expr (not %s)' % type(ptr))

        super(ExprMem, self).__init__(size)
        self._ptr = ptr

    def get_arg(self):
        warnings.warn('DEPRECATION WARNING: use exprmem.ptr instead of exprmem.arg')
        return self.ptr

    def set_arg(self, value):
        warnings.warn('DEPRECATION WARNING: use exprmem.ptr instead of exprmem.arg')
        self.ptr = value

    ptr = property(lambda self: self._ptr)
    arg = property(get_arg, set_arg)

    def __reduce__(self):
        state = self._ptr, self._size
        return self.__class__, state

    def __new__(cls, ptr, size=None):
        if size is None:
            warnings.warn('DEPRECATION WARNING: size is a mandatory argument: use ExprMem(ptr, SIZE)')
            size = 32

        return Expr.get_object(cls, (ptr, size))

    def __str__(self):
        return "@%d[%s]" % (self.size, str(self.ptr))

    def get_r(self, mem_read=False, cst_read=False):
        if mem_read:
            return set(self._ptr.get_r(mem_read, cst_read).union(set([self])))
        else:
            return set([self])

    def get_w(self):
        return set([self])  # [memreg]

    def _exprhash(self):
        return hash((EXPRMEM, hash(self._ptr), self._size))

    def _exprrepr(self):
        return "%s(%r, %r)" % (self.__class__.__name__,
                               self._ptr, self._size)

    def __contains__(self, expr):
        return self == expr or self._ptr.__contains__(expr)

    @visit_chk
    def visit(self, callback, test_visit=None):
        ptr = self._ptr.visit(callback, test_visit)
        if ptr == self._ptr:
            return self
        return ExprMem(ptr, self.size)

    def copy(self):
        ptr = self.ptr.copy()
        return ExprMem(ptr, size=self.size)

    def is_mem_segm(self):
        """Returns True if is ExprMem and ptr is_op_segm"""
        return self._ptr.is_op_segm()

    def depth(self):
        return self._ptr.depth() + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        self._ptr.graph_recursive(graph)
        graph.add_uniq_edge(self, self._ptr)

    def is_mem(self):
        return True


class ExprOp(Expr):

    """An ExprOp stand for an operation between Expr

    Use cases:
     - var1 XOR var2
     - var1 + var2 + var3
     - parity bit(var1)
    """

    __slots__ = Expr.__slots__ + ["_op", "_args"]

    def __init__(self, op, *args):
        """Create an ExprOp
        @op: str, operation
        @*args: Expr, operand list
        """

        # args must be Expr
        assert all(isinstance(arg, Expr) for arg in args)

        sizes = set([arg.size for arg in args])

        if len(sizes) != 1:
            # Special cases : operande sizes can differ
            if op not in [
                    "segm",
                    "FLAG_EQ_ADDWC", "FLAG_EQ_SUBWC",
                    "FLAG_SIGN_ADDWC", "FLAG_SIGN_SUBWC",
                    "FLAG_ADDWC_CF", "FLAG_ADDWC_OF",
                    "FLAG_SUBWC_CF", "FLAG_SUBWC_OF",

            ]:
                raise ValueError(
                    "sanitycheck: ExprOp args must have same size! %s" %
                    ([(str(arg), arg.size) for arg in args]))

        if not isinstance(op, str):
            raise ValueError("ExprOp: 'op' argument must be a string")

        assert isinstance(args, tuple)
        self._op, self._args = op, args

        # Set size for special cases
        if self._op in [
                TOK_EQUAL, 'parity', 'fcom_c0', 'fcom_c1', 'fcom_c2', 'fcom_c3',
                'fxam_c0', 'fxam_c1', 'fxam_c2', 'fxam_c3',
                "access_segment_ok", "load_segment_limit_ok", "bcdadd_cf",
                "ucomiss_zf", "ucomiss_pf", "ucomiss_cf",
                "ucomisd_zf", "ucomisd_pf", "ucomisd_cf"]:
            size = 1
        elif self._op in [TOK_INF, TOK_INF_SIGNED,
                           TOK_INF_UNSIGNED, TOK_INF_EQUAL,
                           TOK_INF_EQUAL_SIGNED, TOK_INF_EQUAL_UNSIGNED,
                           TOK_EQUAL, TOK_POS,
                           TOK_POS_STRICT,
                          ]:
            size = 1
        elif self._op.startswith("fp_to_sint"):
            size = int(self._op[len("fp_to_sint"):])
        elif self._op.startswith("fpconvert_fp"):
            size = int(self._op[len("fpconvert_fp"):])
        elif self._op in [
                "FLAG_ADD_CF", "FLAG_SUB_CF",
                "FLAG_ADD_OF", "FLAG_SUB_OF",
                "FLAG_EQ", "FLAG_EQ_CMP",
                "FLAG_SIGN_SUB", "FLAG_SIGN_ADD",
                "FLAG_EQ_AND",
                "FLAG_EQ_ADDWC", "FLAG_EQ_SUBWC",
                "FLAG_SIGN_ADDWC", "FLAG_SIGN_SUBWC",
                "FLAG_ADDWC_CF", "FLAG_ADDWC_OF",
                "FLAG_SUBWC_CF", "FLAG_SUBWC_OF",
        ]:
            size = 1

        elif self._op.startswith('signExt_'):
            size = int(self._op[8:])
        elif self._op.startswith('zeroExt_'):
            size = int(self._op[8:])
        elif self._op in ['segm']:
            size = self._args[1].size
        else:
            if None in sizes:
                size = None
            else:
                # All arguments have the same size
                size = list(sizes)[0]

        super(ExprOp, self).__init__(size)

    op = property(lambda self: self._op)
    args = property(lambda self: self._args)

    def __reduce__(self):
        state = tuple([self._op] + list(self._args))
        return self.__class__, state

    def __new__(cls, op, *args):
        return Expr.get_object(cls, (op, args))

    def __str__(self):
        if self._op == '-':		# Unary minus
            return '-' + str_protected_child(self._args[0], self)
        if self.is_associative() or self.is_infix():
            return (' ' + self._op + ' ').join([str_protected_child(arg, self)
                                                for arg in self._args])
        return (self._op + '(' +
                ', '.join([str(arg) for arg in self._args]) + ')')

    def get_r(self, mem_read=False, cst_read=False):
        return reduce(lambda elements, arg:
                      elements.union(arg.get_r(mem_read, cst_read)), self._args, set())

    def get_w(self):
        raise ValueError('op cannot be written!', self)

    def _exprhash(self):
        h_hargs = [hash(arg) for arg in self._args]
        return hash((EXPROP, self._op, tuple(h_hargs)))

    def _exprrepr(self):
        return "%s(%r, %s)" % (self.__class__.__name__, self._op,
                               ', '.join(repr(arg) for arg in self._args))

    def __contains__(self, expr):
        if self == expr:
            return True
        for arg in self._args:
            if arg.__contains__(expr):
                return True
        return False

    def is_function_call(self):
        return self._op.startswith('call')

    def is_infix(self):
        return self._op in [
            '-', '+', '*', '^', '&', '|', '>>', '<<',
            'a>>', '>>>', '<<<', '/', '%', '**',
            TOK_INF_UNSIGNED,
            TOK_INF_SIGNED,
            TOK_INF_EQUAL_UNSIGNED,
            TOK_INF_EQUAL_SIGNED,
            TOK_EQUAL
        ]

    def is_associative(self):
        "Return True iff current operation is associative"
        return (self._op in ['+', '*', '^', '&', '|'])

    def is_commutative(self):
        "Return True iff current operation is commutative"
        return (self._op in ['+', '*', '^', '&', '|'])

    @visit_chk
    def visit(self, callback, test_visit=None):
        args = [arg.visit(callback, test_visit) for arg in self._args]
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

    def is_op(self, op=None):
        if op is None:
            return True
        return self.op == op

    def is_op_segm(self):
        """Returns True if is ExprOp and op == 'segm'"""
        return self.is_op('segm')

class ExprSlice(Expr):

    __slots__ = Expr.__slots__ + ["_arg", "_start", "_stop"]

    def __init__(self, arg, start, stop):

        # arg must be Expr
        assert isinstance(arg, Expr)
        assert isinstance(start, (int, long))
        assert isinstance(stop, (int, long))
        assert start < stop

        self._arg, self._start, self._stop = arg, start, stop
        super(ExprSlice, self).__init__(self._stop - self._start)

    arg = property(lambda self: self._arg)
    start = property(lambda self: self._start)
    stop = property(lambda self: self._stop)

    def __reduce__(self):
        state = self._arg, self._start, self._stop
        return self.__class__, state

    def __new__(cls, arg, start, stop):
        return Expr.get_object(cls, (arg, start, stop))

    def __str__(self):
        return "%s[%d:%d]" % (str_protected_child(self._arg, self), self._start, self._stop)

    def get_r(self, mem_read=False, cst_read=False):
        return self._arg.get_r(mem_read, cst_read)

    def get_w(self):
        return self._arg.get_w()

    def _exprhash(self):
        return hash((EXPRSLICE, hash(self._arg), self._start, self._stop))

    def _exprrepr(self):
        return "%s(%r, %d, %d)" % (self.__class__.__name__, self._arg,
                                   self._start, self._stop)

    def __contains__(self, expr):
        if self == expr:
            return True
        return self._arg.__contains__(expr)

    @visit_chk
    def visit(self, callback, test_visit=None):
        arg = self._arg.visit(callback, test_visit)
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

    def is_slice(self, start=None, stop=None):
        if start is not None and self._start != start:
            return False
        if stop is not None and self._stop != stop:
            return False
        return True


class ExprCompose(Expr):

    """
    Compose is like a hambuger. It concatenate Expressions
    """

    __slots__ = Expr.__slots__ + ["_args"]

    def __init__(self, *args):
        """Create an ExprCompose
        The ExprCompose is contiguous and starts at 0
        @args: [Expr, Expr, ...]
        DEPRECATED:
        @args: [(Expr, int, int), (Expr, int, int), ...]
        """

        # args must be Expr
        assert all(isinstance(arg, Expr) for arg in args)

        assert isinstance(args, tuple)
        self._args = args
        super(ExprCompose, self).__init__(sum(arg.size for arg in args))

    args = property(lambda self: self._args)

    def __reduce__(self):
        state = self._args
        return self.__class__, state

    def __new__(cls, *args):
        return Expr.get_object(cls, args)

    def __str__(self):
        return '{' + ', '.join(["%s %s %s" % (arg, idx, idx + arg.size) for idx, arg in self.iter_args()]) + '}'

    def get_r(self, mem_read=False, cst_read=False):
        return reduce(lambda elements, arg:
                      elements.union(arg.get_r(mem_read, cst_read)), self._args, set())

    def get_w(self):
        return reduce(lambda elements, arg:
                      elements.union(arg.get_w()), self._args, set())

    def _exprhash(self):
        h_args = [EXPRCOMPOSE] + [hash(arg) for arg in self._args]
        return hash(tuple(h_args))

    def _exprrepr(self):
        return "%s%r" % (self.__class__.__name__, self._args)

    def __contains__(self, expr):
        if self == expr:
            return True
        for arg in self._args:
            if arg == expr:
                return True
            if arg.__contains__(expr):
                return True
        return False

    @visit_chk
    def visit(self, callback, test_visit=None):
        args = [arg.visit(callback, test_visit) for arg in self._args]
        modified = any([arg != arg_new for arg, arg_new in zip(self._args, args)])
        if modified:
            return ExprCompose(*args)
        return self

    def copy(self):
        args = [arg.copy() for arg in self._args]
        return ExprCompose(*args)

    def depth(self):
        depth = [arg.depth() for arg in self._args]
        return max(depth) + 1

    def graph_recursive(self, graph):
        graph.add_node(self)
        for arg in self.args:
            arg.graph_recursive(graph)
            graph.add_uniq_edge(self, arg)

    def iter_args(self):
        index = 0
        for arg in self._args:
            yield index, arg
            index += arg.size

    def is_compose(self):
        return True

# Expression order for comparison
EXPR_ORDER_DICT = {ExprId: 1,
                   ExprLoc: 2,
                   ExprCond: 3,
                   ExprMem: 4,
                   ExprOp: 5,
                   ExprSlice: 6,
                   ExprCompose: 7,
                   ExprInt: 8,
                  }


def compare_exprs_compose(expr1, expr2):
    # Sort by start bit address, then expr, then stop but address
    ret = cmp(expr1[1], expr2[1])
    if ret:
        return ret
    ret = compare_exprs(expr1[0], expr2[0])
    if ret:
        return ret
    ret = cmp(expr1[2], expr2[2])
    return ret


def compare_expr_list_compose(l1_e, l2_e):
    # Sort by list elements in incremental order, then by list size
    for i in xrange(min(len(l1_e), len(l2_e))):
        ret = compare_exprs(l1_e[i], l2_e[i])
        if ret:
            return ret
    return cmp(len(l1_e), len(l2_e))


def compare_expr_list(l1_e, l2_e):
    # Sort by list elements in incremental order, then by list size
    for i in xrange(min(len(l1_e), len(l2_e))):
        ret = compare_exprs(l1_e[i], l2_e[i])
        if ret:
            return ret
    return cmp(len(l1_e), len(l2_e))


def compare_exprs(expr1, expr2):
    """Compare 2 expressions for canonization
    @expr1: Expr
    @expr2: Expr
    0  => ==
    1  => expr1 > expr2
    -1 => expr1 < expr2
    """
    cls1 = expr1.__class__
    cls2 = expr2.__class__
    if cls1 != cls2:
        return cmp(EXPR_ORDER_DICT[cls1], EXPR_ORDER_DICT[cls2])
    if expr1 == expr2:
        return 0
    if cls1 == ExprInt:
        ret = cmp(expr1.size, expr2.size)
        if ret != 0:
            return ret
        return cmp(expr1.arg, expr2.arg)
    elif cls1 == ExprId:
        ret = cmp(expr1.name, expr2.name)
        if ret:
            return ret
        return cmp(expr1.size, expr2.size)
    elif cls1 == ExprLoc:
        ret = cmp(expr1.loc_key, expr2.loc_key)
        if ret:
            return ret
        return cmp(expr1.size, expr2.size)
    elif cls1 == ExprAssign:
        raise NotImplementedError(
            "Comparison from an ExprAssign not yet implemented")
    elif cls2 == ExprCond:
        ret = compare_exprs(expr1.cond, expr2.cond)
        if ret:
            return ret
        ret = compare_exprs(expr1.src1, expr2.src1)
        if ret:
            return ret
        ret = compare_exprs(expr1.src2, expr2.src2)
        return ret
    elif cls1 == ExprMem:
        ret = compare_exprs(expr1.ptr, expr2.ptr)
        if ret:
            return ret
        return cmp(expr1.size, expr2.size)
    elif cls1 == ExprOp:
        if expr1.op != expr2.op:
            return cmp(expr1.op, expr2.op)
        return compare_expr_list(expr1.args, expr2.args)
    elif cls1 == ExprSlice:
        ret = compare_exprs(expr1.arg, expr2.arg)
        if ret:
            return ret
        ret = cmp(expr1.start, expr2.start)
        if ret:
            return ret
        ret = cmp(expr1.stop, expr2.stop)
        return ret
    elif cls1 == ExprCompose:
        return compare_expr_list_compose(expr1.args, expr2.args)
    raise NotImplementedError(
        "Comparison between %r %r not implemented" % (expr1, expr2))


def canonize_expr_list(expr_list):
    expr_list = list(expr_list)
    expr_list.sort(cmp=compare_exprs)
    return expr_list


def canonize_expr_list_compose(expr_list):
    expr_list = list(expr_list)
    expr_list.sort(cmp=compare_exprs_compose)
    return expr_list

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


def ExprInt_from(expr, i):
    "Generate ExprInt with size equal to expression"
    warnings.warn('DEPRECATION WARNING: use ExprInt(i, expr.size) instead of'\
                  'ExprInt_from(expr, i))')
    return ExprInt(i, expr.size)


def get_expr_ids_visit(expr, ids):
    """Visitor to retrieve ExprId in @expr
    @expr: Expr"""
    if expr.is_id():
        ids.add(expr)
    return expr


def get_expr_locs_visit(expr, locs):
    """Visitor to retrieve ExprLoc in @expr
    @expr: Expr"""
    if expr.is_loc():
        locs.add(expr)
    return expr


def get_expr_ids(expr):
    """Retrieve ExprId in @expr
    @expr: Expr"""
    ids = set()
    expr.visit(lambda x: get_expr_ids_visit(x, ids))
    return ids


def get_expr_locs(expr):
    """Retrieve ExprLoc in @expr
    @expr: Expr"""
    locs = set()
    expr.visit(lambda x: get_expr_locs_visit(x, locs))
    return locs


def test_set(expr, pattern, tks, result):
    """Test if v can correspond to e. If so, update the context in result.
    Otherwise, return False
    @expr : Expr to match
    @pattern : pattern Expr
    @tks : list of ExprId, available jokers
    @result : dictionary of ExprId -> Expr, current context
    """

    if not pattern in tks:
        return expr == pattern
    if pattern in result and result[pattern] != expr:
        return False
    result[pattern] = expr
    return result


def match_expr(expr, pattern, tks, result=None):
    """Try to match the @pattern expression with the pattern @expr with @tks jokers.
    Result is output dictionary with matching joker values.
    @expr : Expr pattern
    @pattern : Targeted Expr to match
    @tks : list of ExprId, available jokers
    @result : dictionary of ExprId -> Expr, output matching context
    """

    if result is None:
        result = {}

    if pattern in tks:
        # pattern is a Joker
        return test_set(expr, pattern, tks, result)

    if expr.is_int():
        return test_set(expr, pattern, tks, result)

    elif expr.is_id():
        return test_set(expr, pattern, tks, result)

    elif expr.is_loc():
        return test_set(expr, pattern, tks, result)

    elif expr.is_op():

        # expr need to be the same operation than pattern
        if not pattern.is_op():
            return False
        if expr.op != pattern.op:
            return False
        if len(expr.args) != len(pattern.args):
            return False

        # Perform permutation only if the current operation is commutative
        if expr.is_commutative():
            permutations = itertools.permutations(expr.args)
        else:
            permutations = [expr.args]

        # For each permutations of arguments
        for permut in permutations:
            good = True
            # We need to use a copy of result to not override it
            myresult = dict(result)
            for sub_expr, sub_pattern in zip(permut, pattern.args):
                ret = match_expr(sub_expr, sub_pattern, tks, myresult)
                # If the current permutation do not match EVERY terms
                if ret is False:
                    good = False
                    break
            if good is True:
                # We found a possibility
                for joker, value in myresult.items():
                    # Updating result in place (to keep pointer in recursion)
                    result[joker] = value
                return result
        return False

    # Recursive tests

    elif expr.is_mem():
        if not pattern.is_mem():
            return False
        if expr.size != pattern.size:
            return False
        return match_expr(expr.ptr, pattern.ptr, tks, result)

    elif expr.is_slice():
        if not pattern.is_slice():
            return False
        if expr.start != pattern.start or expr.stop != pattern.stop:
            return False
        return match_expr(expr.arg, pattern.arg, tks, result)

    elif expr.is_cond():
        if not pattern.is_cond():
            return False
        if match_expr(expr.cond, pattern.cond, tks, result) is False:
            return False
        if match_expr(expr.src1, pattern.src1, tks, result) is False:
            return False
        if match_expr(expr.src2, pattern.src2, tks, result) is False:
            return False
        return result

    elif expr.is_compose():
        if not pattern.is_compose():
            return False
        for sub_expr, sub_pattern in zip(expr.args, pattern.args):
            if  match_expr(sub_expr, sub_pattern, tks, result) is False:
                return False
        return result

    elif expr.is_aff():
        if not pattern.is_aff():
            return False
        if match_expr(expr.src, pattern.src, tks, result) is False:
            return False
        if match_expr(expr.dst, pattern.dst, tks, result) is False:
            return False
        return result

    else:
        raise NotImplementedError("match_expr: Unknown type: %s" % type(expr))


def MatchExpr(expr, pattern, tks, result=None):
    warnings.warn('DEPRECATION WARNING: use match_expr instead of MatchExpr')
    return match_expr(expr, pattern, tks, result)


def get_rw(exprs):
    o_r = set()
    o_w = set()
    for expr in exprs:
        o_r.update(expr.get_r(mem_read=True))
    for expr in exprs:
        o_w.update(expr.get_w())
    return o_r, o_w


def get_list_rw(exprs, mem_read=False, cst_read=True):
    """Return list of read/write reg/cst/mem for each @exprs
    @exprs: list of expressions
    @mem_read: walk though memory accesses
    @cst_read: retrieve constants
    """
    list_rw = []
    # cst_num = 0
    for expr in exprs:
        o_r = set()
        o_w = set()
        # get r/w
        o_r.update(expr.get_r(mem_read=mem_read, cst_read=cst_read))
        if isinstance(expr.dst, ExprMem):
            o_r.update(expr.dst.arg.get_r(mem_read=mem_read, cst_read=cst_read))
        o_w.update(expr.get_w())
        # each cst is indexed
        o_r_rw = set()
        for read in o_r:
            o_r_rw.add(read)
        o_r = o_r_rw
        list_rw.append((o_r, o_w))

    return list_rw


def get_expr_ops(expr):
    """Retrieve operators of an @expr
    @expr: Expr"""
    def visit_getops(expr, out=None):
        if out is None:
            out = set()
        if isinstance(expr, ExprOp):
            out.add(expr.op)
        return expr
    ops = set()
    expr.visit(lambda x: visit_getops(x, ops))
    return ops


def get_expr_mem(expr):
    """Retrieve memory accesses of an @expr
    @expr: Expr"""
    def visit_getmem(expr, out=None):
        if out is None:
            out = set()
        if isinstance(expr, ExprMem):
            out.add(expr)
        return expr
    ops = set()
    expr.visit(lambda x: visit_getmem(x, ops))
    return ops


def _expr_compute_cf(op1, op2):
    """
    Get carry flag of @op1 - @op2
    Ref: x86 cf flag
    @op1: Expression
    @op2: Expression
    """
    res = op1 - op2
    cf = (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))).msb()
    return cf

def _expr_compute_of(op1, op2):
    """
    Get overflow flag of @op1 - @op2
    Ref: x86 of flag
    @op1: Expression
    @op2: Expression
    """
    res = op1 - op2
    of = (((op1 ^ res) & (op1 ^ op2))).msb()
    return of

def _expr_compute_zf(op1, op2):
    """
    Get zero flag of @op1 - @op2
    @op1: Expression
    @op2: Expression
    """
    res = op1 - op2
    zf = ExprCond(res,
                  ExprInt(0, 1),
                  ExprInt(1, 1))
    return zf


def _expr_compute_nf(op1, op2):
    """
    Get negative (or sign) flag of @op1 - @op2
    @op1: Expression
    @op2: Expression
    """
    res = op1 - op2
    nf = res.msb()
    return nf


def expr_is_equal(op1, op2):
    """
    if op1 == op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    zf = _expr_compute_zf(op1, op2)
    return zf


def expr_is_not_equal(op1, op2):
    """
    if op1 != op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    zf = _expr_compute_zf(op1, op2)
    return ~zf


def expr_is_unsigned_greater(op1, op2):
    """
    UNSIGNED cmp
    if op1 > op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    cf = _expr_compute_cf(op1, op2)
    zf = _expr_compute_zf(op1, op2)
    return ~(cf | zf)


def expr_is_unsigned_greater_or_equal(op1, op2):
    """
    Unsigned cmp
    if op1 >= op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    cf = _expr_compute_cf(op1, op2)
    return ~cf


def expr_is_unsigned_lower(op1, op2):
    """
    Unsigned cmp
    if op1 < op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    cf = _expr_compute_cf(op1, op2)
    return cf


def expr_is_unsigned_lower_or_equal(op1, op2):
    """
    Unsigned cmp
    if op1 <= op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    cf = _expr_compute_cf(op1, op2)
    zf = _expr_compute_zf(op1, op2)
    return cf | zf


def expr_is_signed_greater(op1, op2):
    """
    Signed cmp
    if op1 > op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    nf = _expr_compute_nf(op1, op2)
    of = _expr_compute_of(op1, op2)
    zf = _expr_compute_zf(op1, op2)
    return ~(zf | (nf ^ of))


def expr_is_signed_greater_or_equal(op1, op2):
    """
    Signed cmp
    if op1 > op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    nf = _expr_compute_nf(op1, op2)
    of = _expr_compute_of(op1, op2)
    return ~(nf ^ of)


def expr_is_signed_lower(op1, op2):
    """
    Signed cmp
    if op1 < op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    nf = _expr_compute_nf(op1, op2)
    of = _expr_compute_of(op1, op2)
    return nf ^ of


def expr_is_signed_lower_or_equal(op1, op2):
    """
    Signed cmp
    if op1 <= op2:
       Return ExprInt(1, 1)
    else:
       Return ExprInt(0, 1)
    """

    nf = _expr_compute_nf(op1, op2)
    of = _expr_compute_of(op1, op2)
    zf = _expr_compute_zf(op1, op2)
    return zf | (nf ^ of)

# sign bit | exponent | significand
size_to_IEEE754_info = {
    16: {
        "exponent": 5,
        "significand": 10,
    },
    32: {
        "exponent": 8,
        "significand": 23,
    },
    64: {
        "exponent": 11,
        "significand": 52,
    },
}

def expr_is_NaN(expr):
    """Return 1 or 0 on 1 bit if expr represent a NaN value according to IEEE754
    """
    info = size_to_IEEE754_info[expr.size]
    exponent = expr[info["significand"]: info["significand"] + info["exponent"]]

    # exponent is full of 1s and significand is not NULL
    return ExprCond(exponent - ExprInt(-1, exponent.size),
                    ExprInt(0, 1),
                    ExprCond(expr[:info["significand"]], ExprInt(1, 1),
                             ExprInt(0, 1)))


def expr_is_infinite(expr):
    """Return 1 or 0 on 1 bit if expr represent an infinite value according to
    IEEE754
    """
    info = size_to_IEEE754_info[expr.size]
    exponent = expr[info["significand"]: info["significand"] + info["exponent"]]

    # exponent is full of 1s and significand is NULL
    return ExprCond(exponent - ExprInt(-1, exponent.size),
                    ExprInt(0, 1),
                    ExprCond(expr[:info["significand"]], ExprInt(0, 1),
                             ExprInt(1, 1)))


def expr_is_IEEE754_zero(expr):
    """Return 1 or 0 on 1 bit if expr represent a zero value according to
    IEEE754
    """
    # Sign is the msb
    expr_no_sign = expr[:expr.size - 1]
    return ExprCond(expr_no_sign, ExprInt(0, 1), ExprInt(1, 1))


def expr_is_IEEE754_denormal(expr):
    """Return 1 or 0 on 1 bit if expr represent a denormalized value according
    to IEEE754
    """
    info = size_to_IEEE754_info[expr.size]
    exponent = expr[info["significand"]: info["significand"] + info["exponent"]]
    # exponent is full of 0s
    return ExprCond(exponent, ExprInt(0, 1), ExprInt(1, 1))


def expr_is_qNaN(expr):
    """Return 1 or 0 on 1 bit if expr represent a qNaN (quiet) value according to
    IEEE754
    """
    info = size_to_IEEE754_info[expr.size]
    significand_top = expr[info["significand"]: info["significand"] + 1]
    return expr_is_NaN(expr) & significand_top


def expr_is_sNaN(expr):
    """Return 1 or 0 on 1 bit if expr represent a sNaN (signalling) value according
    to IEEE754
    """
    info = size_to_IEEE754_info[expr.size]
    significand_top = expr[info["significand"]: info["significand"] + 1]
    return expr_is_NaN(expr) & ~significand_top


def expr_is_float_lower(op1, op2):
    """Return 1 on 1 bit if @op1 < @op2, 0 otherwise.
    /!\ Assume @op1 and @op2 are not NaN
    Comparison is the floating point one, defined in IEEE754
    """
    sign1, sign2 = op1.msb(), op2.msb()
    magn1, magn2 = op1[:-1], op2[:-1]
    return ExprCond(sign1 ^ sign2,
                    # Sign different, only the sign matters
                    sign1, # sign1 ? op1 < op2 : op1 >= op2
                    # Sign equals, the result is inversed for negatives
                    sign1 ^ (expr_is_unsigned_lower(magn1, magn2)))


def expr_is_float_equal(op1, op2):
    """Return 1 on 1 bit if @op1 == @op2, 0 otherwise.
    /!\ Assume @op1 and @op2 are not NaN
    Comparison is the floating point one, defined in IEEE754
    """
    sign1, sign2 = op1.msb(), op2.msb()
    magn1, magn2 = op1[:-1], op2[:-1]
    return ExprCond(magn1 ^ magn2,
                    ExprInt(0, 1),
                    ExprCond(magn1,
                             # magn1 == magn2, are the signal equals?
                             ~(sign1 ^ sign2),
                             # Special case: -0.0 == +0.0
                             ExprInt(1, 1))
                    )
