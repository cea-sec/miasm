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
    """Memory abstration for TranslatorZ3. Memory elements are only accessed,
    never written. To give a concrete value for a given memory cell in a solver,
    add "mem32.get(address, size) == <value>" constraints to your equation.
    The endianness of memory accesses is handled accordingly to the "endianness"
    attribute.

    Note: Will have one memory space for each addressing size used.
    For example, if memory is accessed via 32 bits values and 16 bits values,
    these access will not occur in the same address space.
    """

    def __init__(self, endianness="<", name="mem"):
        """Initializes a Z3Mem object with a given @name and @endianness.
        @endianness: Endianness of memory representation. '<' for little endian,
            '>' for big endian.
        @name: name of memory Arrays generated. They will be named
            name+str(address size) (for example mem32, mem16...).
        """
        if endianness not in ['<', '>']:
            raise ValueError("Endianness should be '>' (big) or '<' (little)")
        self.endianness = endianness
        self.mems = {} # Address size -> memory z3.Array
        self.name = name

    def get_mem_array(self, size):
        """Returns a z3 Array used internally to represent memory for addresses
        of size @size.
        @size: integer, size in bit of addresses in the memory to get.
        Return a z3 Array: BitVecSort(size) -> BitVecSort(8).
        """
        try:
            mem = self.mems[size]
        except KeyError:
            # Lazy instanciation
            self.mems[size] = z3.Array(self.name + str(size),
                                        z3.BitVecSort(size),
                                        z3.BitVecSort(8))
            mem = self.mems[size]
        return mem

    def __getitem__(self, addr):
        """One byte memory access. Different address sizes with the same value
        will result in different memory accesses.
        @addr: a z3 BitVec, the address to read.
        Return a z3 BitVec of size 8 bits representing a memory access.
        """
        size = addr.size()
        mem = self.get_mem_array(size)
        return mem[addr]

    def get(self, addr, size):
        """ Memory access at address @addr of size @size.
        @addr: a z3 BitVec, the address to read.
        @size: int, size of the read in bits.
        Return a z3 BitVec of size @size representing a memory access.
        """
        original_size = size
        if original_size % 8 != 0:
            # Size not aligned on 8bits -> read more than size and extract after
            size = ((original_size / 8) + 1) * 8
        res = self[addr]
        if self.is_little_endian():
            for i in xrange(1, size/8):
                res = z3.Concat(self[addr+i], res)
        else:
            for i in xrange(1, size/8):
                res = z3.Concat(res, self[addr+i])
        if size == original_size:
            return res
        else:
            # Size not aligned, extract right sized result
            return z3.Extract(original_size-1, 0, res)

    def is_little_endian(self):
        """True if this memory is little endian."""
        return self.endianness == "<"

    def is_big_endian(self):
        """True if this memory is big endian."""
        return not self.is_little_endian()


class TranslatorZ3(Translator):
    """Translate a Miasm expression to an equivalent z3 python binding
    expression. Memory is abstracted via z3.Array (see Z3Mem).
    The result of from_expr will be a z3 Expr.

    If you want to interract with the memory abstraction after the translation,
    you can instanciate your own Z3Mem, that will be equivalent to the one
    used by TranslatorZ3.
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
        addr = cls.from_expr(expr.arg)
        return cls._mem.get(addr, expr.size)

    @classmethod
    def from_ExprSlice(cls, expr):
        res = cls.from_expr(expr.arg)
        res = z3.Extract(expr.stop-1, expr.start, res)
        return res

    @classmethod
    def from_ExprCompose(cls, expr):
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
        # This mess is just to handle cache and Z3Mem instance management
        # Might be improved in the future
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
            # Clean cache and Z3Mem if this call is the root call
            if del_cache:
                cls._cache = None
            if del_mem:
                cls._mem = None

# Register the class
Translator.register(TranslatorZ3)

if __name__ == '__main__':

    # Some examples of use/unit tests.

    from miasm2.expression.expression import *

    def equiv(z3_expr1, z3_expr2):
        s = z3.Solver()
        s.add(z3.Not(z3_expr1 == z3_expr2))
        return s.check() == z3.unsat

    def check_interp(interp, constraints, bits=32, valbits=8):
        """Checks that a list of @constraints (addr, value) (as python ints)
        match a z3 FuncInterp (@interp).
        """
        constraints = dict((addr,
                            z3.BitVecVal(val, valbits))
                           for addr, val in constraints)
        l = interp.as_list()
        for entry in l:
            if not isinstance(entry, list) or len(entry) < 2:
                continue
            addr, value = entry[0], entry[1]
            if addr.as_long() in constraints:
                assert equiv(value, constraints[addr.as_long()])

    # equiv short test
    assert equiv(z3.BitVec('a', 32) + z3.BitVecVal(3, 32) - z3.BitVecVal(1, 32),
                 z3.BitVec('a', 32) + z3.BitVecVal(2, 32))

    # --------------------------------------------------------------------------
    e = ExprId('x', 32)
    ez3 = Translator.to_language('z3').from_expr(e)
    print ez3

    z3_e = z3.BitVec('x', 32)
    assert equiv(ez3, z3_e)

    # --------------------------------------------------------------------------
    four = ExprInt32(4)
    five = ExprInt32(5)
    e2 = (e + five + four) * five
    ez3 = Translator.to_language('z3').from_expr(e2)
    print z3.simplify(ez3)

    z3_four = z3.BitVecVal(4, 32)
    z3_five = z3.BitVecVal(5, 32)
    z3_e2 = (z3_e + z3_five + z3_four) * z3_five
    assert equiv(ez3, z3_e2)

    # --------------------------------------------------------------------------
    emem = ExprMem(ExprInt32(0xdeadbeef), size=32)
    emem2 = ExprMem(ExprInt32(0xfee1dead), size=32)
    e3 = (emem + e) * ExprInt32(2) * emem2
    ez3 = Translator.to_language('z3').from_expr(e3)
    print z3.simplify(ez3)

    mem = Z3Mem()
    z3_emem = mem.get(z3.BitVecVal(0xdeadbeef, 32), 32)
    z3_emem2 = mem.get(z3.BitVecVal(0xfee1dead, 32), 32)
    z3_e3 = (z3_emem + z3_e) * z3.BitVecVal(2, 32) * z3_emem2
    assert equiv(ez3, z3_e3)

    # --------------------------------------------------------------------------
    e4 = emem * five
    ez3 = Translator.to_language('z3').from_expr(e4)
    print z3.simplify(ez3)

    z3_e4 = z3_emem * z3_five
    assert equiv(ez3, z3_e4)

    # Solve constraint and check endianness
    solver = z3.Solver()
    solver.add(ez3 == 10)
    solver.check()
    model = solver.model()
    check_interp(model[mem.get_mem_array(32)],
                 [(0xdeadbeef, 2), (0xdeadbeef + 3, 0)])

    # --------------------------------------------------------------------------
    ez3 = TranslatorZ3.from_expr(e4, endianness=">")
    print z3.simplify(ez3)

    memb = Z3Mem(endianness=">")
    z3_emem = memb.get(z3.BitVecVal(0xdeadbeef, 32), 32)
    z3_e4 = z3_emem * z3_five
    assert equiv(ez3, z3_e4)

    # Solve constraint and check endianness
    solver = z3.Solver()
    solver.add(ez3 == 10)
    solver.check()
    model = solver.model()
    check_interp(model[memb.get_mem_array(32)],
                 [(0xdeadbeef, 0), (0xdeadbeef + 3, 2)])

    # --------------------------------------------------------------------------
    e5 = ExprSlice(ExprCompose(((e, 0, 32), (four, 32, 64))), 0, 32) * five
    ez3 = Translator.to_language('z3').from_expr(e5)
    print ez3

    z3_e5 = z3.Extract(31, 0, z3.Concat(z3_four, z3_e)) * z3_five
    assert equiv(ez3, z3_e5)

