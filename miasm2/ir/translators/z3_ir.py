import logging
import operator

import z3

import miasm2.expression.expression as m2_expr
from miasm2.ir.translators.translator import Translator

log = logging.getLogger("translator_z3")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARNING)

class Z3Mem(object):
    """Memory abstration for TranslatorZ3. Will have one memory space for each
    addressing size used.

    For example, if memory is accessed via 32 bits values and 16 bits values,
    these access will not occur in the same address space.
    """
    default_bits = 32

    def __init__(self, endianness="<", name="mem"):
        self.endianness = endianness
        self.mems = {} # Address size -> memory z3.Array
        self.name = name

    def __getitem__(self, addr):
        size = addr.size()
        try:
            mem = self.mems[size]
        except KeyError:
            self.mems[size] = z3.Array(self.name + str(size),
                                        z3.BitVecSort(size),
                                        z3.BitVecSort(8))
            mem = self.mems[size]
        return mem[addr]

    def is_little_endian(self):
        return self.endianness == "<"

    def is_big_endian(self):
        return not self.is_little_endian()


class TranslatorZ3(Translator):
    """Translate a Miasm expression to an equivalent z3 python binding
    expression. Memory is abstracted via z3.Array (see Z3Mem).
    """

    # Implemented language
    __LANG__ = "z3"
    # Operations translation
    trivial_ops = ["+", "-", "/", "%", "&", "^", "|", "*", "<<"]
    _cache = None
    _mem = None

    @classmethod
    def from_ExprInt(cls, expr):
        return z3.BitVecVal(expr.arg.arg, expr.size)

    @classmethod
    def from_ExprId(cls, expr):
        return z3.BitVec(expr.name, expr.size)

    @classmethod
    def from_ExprMem(cls, expr):
        # FIXME: size issues
        if expr.size % 8 != 0:
            size = ((expr.size / 8) + 1) * 8
        else:
            size = expr.size
        addr = cls.from_expr(expr.arg)
        res = cls._mem[addr]
        if cls._mem.is_little_endian():
            for i in xrange(1, size/8):
                res = z3.Concat(cls._mem[addr+i], res)
        else:
            for i in xrange(1, size/8):
                res = z3.Concat(res, cls._mem[addr+i])
        if size == expr.size:
            return res
        else:
            return z3.Extract(expr.size-1, 0, res)

    @classmethod
    def from_ExprSlice(cls, expr):
        res = cls.from_expr(expr.arg)
        res = z3.Extract(expr.stop-1, expr.start, res)
        return res

    @classmethod
    def from_ExprCompose(cls, expr):
        # TODO: Bad size for res, should be initialized properly
        res = None
        args = sorted(expr.args, key=operator.itemgetter(2)) # sort by start off
        for subexpr, start, stop in args:
            sube = cls.from_expr(subexpr)
            e = z3.Extract(stop-start-1, 0, sube)
            if res:
                res = z3.Concat(e, res)
            else:
                res = e
        return res

    @classmethod
    def from_ExprCond(cls, expr):
        cond = cls.from_expr(expr.cond)
        src1 = cls.from_expr(expr.src1)
        src2 = cls.from_expr(expr.src2)
        return z3.If(cond != 0, src1, src2)

    @classmethod
    def from_ExprOp(cls, expr):
        args = map(cls.from_expr, expr.args)
        res = args[0]
        for arg in args[1:]:
            if expr.op in cls.trivial_ops:
                res = eval("res %s arg" % expr.op)
            elif expr.op == ">>":
                res = z3.LShR(res, arg)
            elif expr.op == "a>>":
                res = res >> arg
            elif expr.op == "a<<":
                res = res << arg
            else:
                raise NotImplementedError("Unsupported OP yet: %s" % expr.op)
        return res

    @classmethod
    def from_ExprAff(cls, expr):
        src = cls.from_expr(expr.src)
        dst = cls.from_expr(expr.dst)
        return (src == dst)

    @classmethod
    def from_expr(cls, expr, endianness="<"):
        del_cache = False
        del_mem = False
        if cls._cache is None:
            cls._cache = {}
            del_cache = True
        if cls._mem is None:
            cls._mem = Z3Mem(endianness)
            del_mem = True

        try:
            if expr in cls._cache:
                return cls._cache[expr]
            else:
                return super(TranslatorZ3, cls).from_expr(expr)
        finally:
            if del_cache:
                cls._cache = None
            if del_mem:
                cls._mem = None

# Register the class
Translator.register(TranslatorZ3)

if __name__ == '__main__':
    from miasm2.expression.expression import *
    e = ExprId('x', 32)
    ez3 = Translator.to_language('z3').from_expr(e)
    print ez3
    assert ez3 == z3.BitVec('x', 32)

    four = ExprInt32(4)
    five = ExprInt32(5)
    e2 = (e + five + four) * five
    ez3 = Translator.to_language('z3').from_expr(e2)
    print z3.simplify(ez3)

    emem = ExprMem(ExprInt32(0xdeadbeef), size=32)
    emem2 = ExprMem(ExprInt32(0xfee1dead), size=32)
    e3 = (emem + e) * ExprInt32(2) * emem2
    ez3 = Translator.to_language('z3').from_expr(e3)
    print z3.simplify(ez3)

    e4 = emem * ExprInt32(5)
    ez3 = Translator.to_language('z3').from_expr(e4)
    print z3.simplify(ez3)
    solver = z3.Solver()
    solver.add(ez3 == 10)
    solver.check()
    print solver.model()

    ez3 = TranslatorZ3.from_expr(e4, endianness=">")
    print z3.simplify(ez3)
    solver = z3.Solver()
    solver.add(ez3 == 10)
    solver.check()
    print solver.model()

    e5 = ExprSlice(ExprCompose(((e, 0, 32), (four, 32, 64))), 0, 32) * five
    ez3 = Translator.to_language('z3').from_expr(e5)
    print ez3
    print z3.simplify(ez3)

