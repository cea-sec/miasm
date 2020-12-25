from __future__ import print_function

from future.utils import viewitems

from miasm.ir.symbexec import SymbolicExecutionEngine, StateEngine
from miasm.expression.simplifications import expr_simp
from miasm.expression.expression import ExprId, ExprMem


class SymbolicStateCTypes(StateEngine):
    """Store C types of symbols"""

    def __init__(self, symbols):
        tmp = {}
        for expr, types in viewitems(symbols):
            tmp[expr] = frozenset(types)
        self._symbols = frozenset(viewitems(tmp))

    def __hash__(self):
        return hash((self.__class__, self._symbols))

    def __str__(self):
        out = []
        for dst, src in sorted(self._symbols):
            out.append("%s = %s" % (dst, src))
        return "\n".join(out)

    def __eq__(self, other):
        if self is other:
            return True
        if self.__class__ != other.__class__:
            return False
        return self.symbols == other.symbols

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        for dst, src in self._symbols:
            yield dst, src

    def merge(self, other):
        """Merge two symbolic states
        The resulting types are the union of types of both states.
        @other: second symbolic state
        """
        symb_a = self.symbols
        symb_b = other.symbols
        symbols = {}
        for expr in set(symb_a).union(set(symb_b)):
            ctypes = symb_a.get(expr, set()).union(symb_b.get(expr, set()))
            if ctypes:
                symbols[expr] = ctypes
        return self.__class__(symbols)

    @property
    def symbols(self):
        """Return the dictionary of known symbols'types"""
        return dict(self._symbols)


class SymbExecCType(SymbolicExecutionEngine):
    """Engine of C types propagation
    WARNING: avoid memory aliases here!
    """

    StateEngine = SymbolicStateCTypes
    OBJC_INTERNAL = "___OBJC___"

    def __init__(self, lifter,
                 symbols,
                 chandler,
                 sb_expr_simp=expr_simp):
        self.chandler = chandler

        super(SymbExecCType, self).__init__(lifter,
                                            {},
                                            sb_expr_simp)
        self.symbols = dict(symbols)

    def get_state(self):
        """Return the current state of the SymbolicEngine"""
        return self.StateEngine(self.symbols)

    def eval_assignblk(self, assignblk):
        """
        Evaluate AssignBlock on the current state
        @assignblk: AssignBlock instance
        """
        pool_out = {}
        for dst, src in viewitems(assignblk):
            objcs = self.chandler.expr_to_types(src, self.symbols)
            if isinstance(dst, ExprMem):
                continue
            elif isinstance(dst, ExprId):
                pool_out[dst] = frozenset(objcs)
            else:
                raise ValueError("Unsupported assignment", str(dst))
        return pool_out

    def eval_expr(self, expr, eval_cache=None):
        return frozenset(self.chandler.expr_to_types(expr, self.symbols))

    def apply_change(self, dst, src):
        if src is None:
            if dst in self.symbols:
                del self.symbols[dst]
        else:
            self.symbols[dst] = src

    def del_mem_above_stack(self, stack_ptr):
        """No stack deletion"""
        return

    def dump_id(self):
        """
        Dump modififed registers symbols only
        """
        for expr, expr_types in sorted(viewitems(self.symbols)):
            if not expr.is_mem():
                print(expr)
                for expr_type in expr_types:
                    print('\t', expr_type)

    def dump_mem(self):
        """
        Dump modififed memory symbols
        """
        for expr, value in sorted(viewitems(self.symbols)):
            if expr.is_mem():
                print(expr, value)
