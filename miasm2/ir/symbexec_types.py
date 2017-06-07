from miasm2.ir.symbexec import SymbolicExecutionEngine, StateEngine
from miasm2.expression.simplifications import expr_simp
from miasm2.expression.expression import ExprId, ExprInt, ExprSlice,\
    ExprMem, ExprCond, ExprCompose, ExprOp

from miasm2.core.ctypesmngr import CTypeId


class SymbolicStateCTypes(StateEngine):
    """Store C types of symbols"""

    def __init__(self, dct, infos_types):
        self._symbols = frozenset(dct.items())
        self._infos_types = frozenset(infos_types.items())

    def __hash__(self):
        return hash((self.__class__, self._symbols, self._infos_types))

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
        return (self.symbols == other.symbols and
                self.infos_types == other.infos_types)

    def __iter__(self):
        for dst, src in self._symbols:
            yield dst, src

    def merge(self, other):
        """Merge two symbolic states
        Only expressions with equal C types in both states are kept.
        @other: second symbolic state
        """
        symb_a = self.symbols
        symb_b = other.symbols
        types_a = set(self.infos_types.items())
        types_b = set(other.infos_types.items())
        intersection = set(symb_a.keys()).intersection(symb_b.keys())
        symbols = {}
        infos_types = dict(types_a.intersection(types_b))
        for dst in intersection:
            if symb_a[dst] == symb_b[dst]:
                symbols[dst] = symb_a[dst]
        return self.__class__(symbols, infos_types)

    @property
    def symbols(self):
        """Return the dictionnary of known symbols'types"""
        return dict(self._symbols)

    @property
    def infos_types(self):
        """Return known types of the state"""
        return dict(self._infos_types)


class SymbExecCType(SymbolicExecutionEngine):
    """Engine of C types propagation
    WARNING: avoid memory aliases here!
    """

    StateEngine = SymbolicStateCTypes
    OBJC_INTERNAL = "___OBJC___"

    def __init__(self, ir_arch,
                 symbols, infos_types,
                 chandler,
                 func_read=None,
                 func_write=None,
                 sb_expr_simp=expr_simp):
        self.chandler = chandler
        self.infos_types = dict(infos_types)
        super(SymbExecCType, self).__init__(ir_arch,
                                            {},
                                            func_read,
                                            func_write,
                                            sb_expr_simp)
        self.symbols = dict(symbols)
        offset_types = []
        for name in [('int',), ('long',),
                     ('long', 'long'),
                     ('char',), ('short',),

                     ('unsigned', 'char',), ('unsigned', 'short',),
                     ('unsigned', 'int',), ('unsigned', 'long',),
                     ('unsigned', 'long', 'long')]:
            objc = self.chandler.type_analyzer.types_mngr.get_objc(CTypeId(*name))
            offset_types.append(objc)
        self.offset_types = offset_types

    def is_type_offset(self, objc):
        """Return True if @objc is char/short/int/long"""
        return objc in self.offset_types

    def get_tpye_int_by_size(self, size):
        """Return a char/short/int/long type with the size equal to @size
        @size: size in bit"""

        for objc in self.offset_types:
            if objc.size == size / 8:
                return objc
        return None

    def is_offset_list(self, types, size):
        """Return the corresponding char/short/int/long type of @size, if every
        types in the list @types are type offset
        @types: a list of c types
        @size: size in bit"""

        for arg_type in types:
            if not self.is_type_offset(arg_type):
                return None
        objc = self.get_tpye_int_by_size(size)
        if objc:
            return objc
        # default size
        objc = self.offset_types[0]
        return objc

    def apply_expr_on_state_visit_cache(self, expr, state, cache, level=0):
        """
        Deep First evaluate nodes:
            1. evaluate node's sons
            2. simplify
        """

        expr = self.expr_simp(expr)

        if expr in cache:
            return cache[expr]
        elif expr in state:
            return state[expr]
        elif isinstance(expr, ExprInt):
            objc = self.get_tpye_int_by_size(expr.size)
            if objc is None:
                objc = self.chandler.type_analyzer.types_mngr.get_objc(CTypeId('int'))
            return objc
        elif isinstance(expr, ExprId):
            if expr in state:
                return state[expr]
            return None
        elif isinstance(expr, ExprMem):
            ptr = self.apply_expr_on_state_visit_cache(expr.arg, state, cache, level + 1)
            if ptr is None:
                return None
            self.chandler.type_analyzer.expr_types[self.OBJC_INTERNAL] = ptr
            ptr_expr = ExprId(self.OBJC_INTERNAL, expr.arg.size)
            objcs = self.chandler.expr_to_types(ExprMem(ptr_expr, expr.size))
            if objcs is None:
                return None
            objc = objcs[0]
            return objc
        elif isinstance(expr, ExprCond):
            src1 = self.apply_expr_on_state_visit_cache(expr.src1, state, cache, level + 1)
            src2 = self.apply_expr_on_state_visit_cache(expr.src2, state, cache, level + 1)
            types = [src1, src2]
            objc = self.is_offset_list(types, expr.size)
            if objc:
                return objc
            return None
        elif isinstance(expr, ExprSlice):
            objc = self.get_tpye_int_by_size(expr.size)
            if objc is None:
                # default size
                objc = self.offset_types[0]
            return objc
        elif isinstance(expr, ExprOp):
            args = []
            types = []
            for oarg in expr.args:
                arg = self.apply_expr_on_state_visit_cache(oarg, state, cache, level + 1)
                types.append(arg)
            if None in types:
                return None
            objc = self.is_offset_list(types, expr.size)
            if objc:
                return objc
            # Find Base + int
            if expr.op != '+':
                return None
            args = list(expr.args)
            if args[-1].is_int():
                offset = args.pop()
                types.pop()
            if len(args) == 1:
                arg, arg_type = args.pop(), types.pop()
                self.chandler.type_analyzer.expr_types[self.OBJC_INTERNAL] = arg_type
                ptr_expr = ExprId(self.OBJC_INTERNAL, arg.size)
                objc = self.chandler.expr_to_types(ptr_expr + offset)
                objc = objc[0]
                return objc
            return None
        elif isinstance(expr, ExprCompose):
            types = set()
            for oarg in expr.args:
                arg = self.apply_expr_on_state_visit_cache(oarg, state, cache, level + 1)
                types.add(arg)
            objc = self.is_offset_list(types, expr.size)
            if objc:
                return objc
            return None
        else:
            raise TypeError("Unknown expr type")

    def get_state(self):
        """Return the current state of the SymbolicEngine"""
        return self.StateEngine(self.symbols, self.infos_types)

    def eval_ir_expr(self, assignblk):
        """
        Evaluate AssignBlock on the current state
        @assignblk: AssignBlock instance
        """
        pool_out = {}
        eval_cache = {}
        for dst, src in assignblk.iteritems():
            src = self.eval_expr(src, eval_cache)
            if isinstance(dst, ExprMem):
                continue
            elif isinstance(dst, ExprId):
                pool_out[dst] = src
            else:
                raise ValueError("affected zarb", str(dst))
        return pool_out.iteritems()

    def apply_change(self, dst, src):
        objc = src
        if objc is None and dst in self.symbols:
            del self.symbols[dst]
        else:
            self.symbols[dst] = objc

    def del_mem_above_stack(self, stack_ptr):
        """No stack deletion"""
        return
