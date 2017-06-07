from miasm2.ir.symbexec import SymbolicExecutionEngine, StateEngine
from miasm2.expression.simplifications import expr_simp
from miasm2.expression.expression import ExprId, ExprInt, ExprSlice,\
    ExprMem, ExprCond, ExprCompose, ExprOp
from miasm2.core import asmblock


TOPSTR = "TOP"

def exprid_top(expr):
    """Return a TOP expression (ExprId("TOP") of size @expr.size
    @expr: expression to replace with TOP
    """
    return ExprId(TOPSTR, expr.size)


class SymbolicStateTop(StateEngine):

    def __init__(self, dct, regstop):
        self._symbols = frozenset(dct.items())
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
        intersection = set(symb_a.keys()).intersection(symb_b.keys())
        diff = set(symb_a.keys()).union(symb_b.keys()).difference(intersection)
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
        """Return the dictionnary of known symbols"""
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

    def __init__(self, ir_arch, state, regstop,
                 func_read=None,
                 func_write=None,
                 sb_expr_simp=expr_simp):
        known_symbols = dict(state)
        super(SymbExecTopNoMem, self).__init__(ir_arch, known_symbols,
                                               func_read,
                                               func_write,
                                               sb_expr_simp)
        self.regstop = set(regstop)

    def get_state(self):
        """Return the current state of the SymbolicEngine"""
        return self.StateEngine(self.symbols, self.regstop)

    def eval_expr(self, expr, eval_cache=None):
        if expr in self.regstop:
            return exprid_top(expr)
        ret = self.apply_expr_on_state(expr, eval_cache)
        return ret

    def manage_mem(self, expr, state, cache, level):
        ptr = self.apply_expr_on_state_visit_cache(expr.arg, state, cache, level+1)
        ret = ExprMem(ptr, expr.size)
        ret = self.get_mem_state(ret)
        if ret.is_mem() and not ret.arg.is_int() and ret.arg == ptr:
            ret = exprid_top(expr)
        assert expr.size == ret.size
        return ret

    def apply_expr_on_state_visit_cache(self, expr, state, cache, level=0):
        """
        Deep First evaluate nodes:
            1. evaluate node's sons
            2. simplify
        """

        if expr in cache:
            ret = cache[expr]
        elif expr in state:
            return state[expr]
        elif expr.is_int():
            ret = expr
        elif expr.is_id():
            if isinstance(expr.name, asmblock.asm_label) and expr.name.offset is not None:
                ret = ExprInt(expr.name.offset, expr.size)
            elif expr in self.regstop:
                ret = exprid_top(expr)
            else:
                ret = state.get(expr, expr)
        elif expr.is_mem():
            ret = self.manage_mem(expr, state, cache, level)
        elif expr.is_cond():
            cond = self.apply_expr_on_state_visit_cache(expr.cond, state, cache, level+1)
            src1 = self.apply_expr_on_state_visit_cache(expr.src1, state, cache, level+1)
            src2 = self.apply_expr_on_state_visit_cache(expr.src2, state, cache, level+1)
            if cond.is_id(TOPSTR) or src1.is_id(TOPSTR) or src2.is_id(TOPSTR):
                ret = exprid_top(expr)
            else:
                ret = ExprCond(cond, src1, src2)
        elif expr.is_slice():
            arg = self.apply_expr_on_state_visit_cache(expr.arg, state, cache, level+1)
            if arg.is_id(TOPSTR):
                ret = exprid_top(expr)
            else:
                ret = ExprSlice(arg, expr.start, expr.stop)
        elif expr.is_op():
            args = []
            for oarg in expr.args:
                arg = self.apply_expr_on_state_visit_cache(oarg, state, cache, level+1)
                assert oarg.size == arg.size
                if arg.is_id(TOPSTR):
                    return exprid_top(expr)
                args.append(arg)
            ret = ExprOp(expr.op, *args)
        elif expr.is_compose():
            args = []
            for arg in expr.args:
                arg = self.apply_expr_on_state_visit_cache(arg, state, cache, level+1)
                if arg.is_id(TOPSTR):
                    return exprid_top(expr)

                args.append(arg)
            ret = ExprCompose(*args)
        else:
            raise TypeError("Unknown expr type")
        ret = self.expr_simp(ret)
        assert expr.size == ret.size
        cache[expr] = ret
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
