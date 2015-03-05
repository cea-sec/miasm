import logging
import operator

import z3

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
                ret = super(TranslatorZ3, cls).from_expr(expr)
                cls._cache[expr] = ret
                return ret
        finally:
            # Clean cache and Z3Mem if this call is the root call
            if del_cache:
                cls._cache = None
            if del_mem:
                cls._mem = None

# Register the class
Translator.register(TranslatorZ3)
