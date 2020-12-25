from future.utils import viewitems

from miasm.ir.symbexec import SymbolicExecutionEngine, StateEngine
from miasm.expression.simplifications import expr_simp
from miasm.expression.expression import ExprId, ExprInt, ExprSlice,\
    ExprMem, ExprCond, ExprCompose, ExprOp


TOPSTR = "TOP"

def exprid_top(expr):
    """Return a TOP expression (ExprId("TOP") of size @expr.size
    @expr: expression to replace with TOP
    """
    return ExprId(TOPSTR, expr.size)


class SymbolicStateTop(StateEngine):

    def __init__(self, dct, regstop):
        self._symbols = frozenset(viewitems(dct))
        self._regstop = frozenset(regstop)

    def __hash__(self):
        return hash((self.__class__, self._symbols, self._regstop))

    def __str__(self):
        out = []
        for dst, src in sorted(self._symbols):
            out.append("%s = %s" % (dst, src))
        for dst in self._regstop:
            out.append('TOP %s' %dst)
        return "\n".join(out)

    def __eq__(self, other):
        if self is other:
            return True
        if self.__class__ != other.__class__:
            return False
        return (self.symbols == other.symbols and
                self.regstop == other.regstop)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __iter__(self):
        for dst, src in self._symbols:
            yield dst, src

    def merge(self, other):
        """Merge two symbolic states
        Only equal expressions are kept in both states
        @other: second symbolic state
        """
        symb_a = self.symbols
        symb_b = other.symbols
        intersection = set(symb_a).intersection(symb_b)
        diff = set(symb_a).union(symb_b).difference(intersection)
        symbols = {}
        regstop = set()
        for dst in diff:
            if dst.is_id():
                regstop.add(dst)
        for dst in intersection:
            if symb_a[dst] == symb_b[dst]:
                symbols[dst] = symb_a[dst]
            else:
                regstop.add(dst)
        return self.__class__(symbols, regstop)

    @property
    def symbols(self):
        """Return the dictionary of known symbols"""
        return dict(self._symbols)

    @property
    def regstop(self):
        """Return the set of expression with TOP values"""
        return self._regstop

class SymbExecTopNoMem(SymbolicExecutionEngine):
    """
    Symbolic execution, include TOP value.
    ExprMem are not propagated.
    Any computation involving a TOP will generate TOP.
    """

    StateEngine = SymbolicStateTop

    def __init__(self, lifter, state, regstop,
                 sb_expr_simp=expr_simp):
        known_symbols = dict(state)
        super(SymbExecTopNoMem, self).__init__(lifter, known_symbols,
                                               sb_expr_simp)
        self.regstop = set(regstop)

    def get_state(self):
        """Return the current state of the SymbolicEngine"""
        return self.StateEngine(self.symbols, self.regstop)

    def eval_expr(self, expr, eval_cache=None):
        if expr in self.regstop:
            return exprid_top(expr)
        if eval_cache is None:
            eval_cache = {}
        ret = self.apply_expr_on_state_visit_cache(expr, self.symbols, eval_cache)
        return ret

    def manage_mem(self, expr, state, cache, level):
        ptr = self.apply_expr_on_state_visit_cache(expr.arg, state, cache, level+1)
        ret = ExprMem(ptr, expr.size)
        ret = self.get_mem_state(ret)
        if ret.is_mem() and not ret.arg.is_int() and ret.arg == ptr:
            ret = exprid_top(expr)
        assert expr.size == ret.size
        return ret


    def eval_exprid(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprId using the current state"""
        if expr in self.regstop:
            ret = exprid_top(expr)
        else:
            ret = self.symbols.read(expr)
        return ret

    def eval_exprloc(self, expr, **kwargs):
        offset = self.lifter.loc_db.get_location_offset(expr.loc_key)
        if offset is not None:
            ret = ExprInt(offset, expr.size)
        else:
            ret = expr
        return ret

    def eval_exprcond(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprCond using the current state"""
        cond = self.eval_expr_visitor(expr.cond, **kwargs)
        src1 = self.eval_expr_visitor(expr.src1, **kwargs)
        src2 = self.eval_expr_visitor(expr.src2, **kwargs)
        if cond.is_id(TOPSTR) or src1.is_id(TOPSTR) or src2.is_id(TOPSTR):
            ret = exprid_top(expr)
        else:
            ret = ExprCond(cond, src1, src2)
        return ret

    def eval_exprslice(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprSlice using the current state"""
        arg = self.eval_expr_visitor(expr.arg, **kwargs)
        if arg.is_id(TOPSTR):
            ret = exprid_top(expr)
        else:
            ret = ExprSlice(arg, expr.start, expr.stop)
        return ret

    def eval_exprop(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprOp using the current state"""
        args = []
        for oarg in expr.args:
            arg = self.eval_expr_visitor(oarg, **kwargs)
            if arg.is_id(TOPSTR):
                return exprid_top(expr)
            args.append(arg)
        ret = ExprOp(expr.op, *args)
        return ret

    def eval_exprcompose(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprCompose using the current state"""
        args = []
        for arg in expr.args:
            arg = self.eval_expr_visitor(arg, **kwargs)
            if arg.is_id(TOPSTR):
                return exprid_top(expr)
            args.append(arg)
        ret = ExprCompose(*args)
        return ret

    def apply_change(self, dst, src):
        eval_cache = {}
        if dst.is_mem():
            # If Write to TOP, forget all memory information
            ret = self.eval_expr(dst.arg, eval_cache)
            if ret.is_id(TOPSTR):
                to_del = set()
                for dst_tmp in self.symbols:
                    if dst_tmp.is_mem():
                        to_del.add(dst_tmp)
                for dst_to_del in to_del:
                    del self.symbols[dst_to_del]
            return
        src_o = self.expr_simp(src)

        # Force update. Ex:
        # EBX += 1 (state: EBX = EBX+1)
        # EBX -= 1 (state: EBX = EBX, must be updated)
        if dst in self.regstop:
            self.regstop.discard(dst)
        self.symbols[dst] = src_o

        if dst == src_o:
            # Avoid useless X = X information
            del self.symbols[dst]

        if src_o.is_id(TOPSTR):
            if dst in self.symbols:
                del self.symbols[dst]
            self.regstop.add(dst)

class SymbExecTop(SymbExecTopNoMem):
    """
    Symbolic execution, include TOP value.
    ExprMem are propagated.
    Any computation involving a TOP will generate TOP.
    WARNING: avoid memory aliases here!
    """

    def manage_mem(self, expr, state, cache, level):
        ptr = self.apply_expr_on_state_visit_cache(expr.arg, state, cache, level+1)
        ret = ExprMem(ptr, expr.size)
        ret = self.get_mem_state(ret)
        assert expr.size == ret.size
        return ret
