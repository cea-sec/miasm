from builtins import map
from builtins import range
import imp
import logging

# Raise an ImportError if z3 is not available WITHOUT actually importing it
imp.find_module("z3")

from miasm.ir.translators.translator import Translator

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
        # Import z3 only on demand
        global z3
        import z3

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
            # Lazy instantiation
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
            size = ((original_size // 8) + 1) * 8
        res = self[addr]
        if self.is_little_endian():
            for i in range(1, size // 8):
                res = z3.Concat(self[addr+i], res)
        else:
            for i in range(1, size //8):
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


class Z3MemStateful(object):
    import z3
    """
    Global memory modelling as one large z3 array with low level reads and writes.
    Memory access is modelled as 8 byte access per read/write. Addresses have size @size.

    Thus, memory access is a map from <address size> -> 8 byte.

    The structure of that class is adapted/based on class "Z3Mem" from
    miasm2/ir/translators/z3_ir.py.
    Especially the structure (or methods) of endianess (is_little_endian, is_big_endian), alignment and
    read access (Z3Mem.get) are used.
    """

    def __init__(self, size, endianness="<"):
        """
        Initialises global memory
        :param size: address size of memory entries
        :param endianness: "<" for little endian, ">" for big endian
        """
        # Import z3 only on demand
        global z3
        import z3
        self.endianness = endianness
        self.size = size

    def is_little_endian(self):
        """True if this memory is little endian."""
        return self.endianness == "<"

    def is_big_endian(self):
        """True if this memory is big endian."""
        return not self.is_little_endian()

    def gen_mem(self, mem="M", size=None):
        """
        Generates a z3 array that maps @self.size bitvecs to 8 byte bitvecs
        :param mem: name of memory as string
        :param size: memory address size
        :return: z3 array
        """
        if not size:
            size = self.size
        return z3.Array(mem, z3.BitVecSort(size), z3.BitVecSort(8))

    def read(self, mem, addr, size):
        """
        Reads a value in 8 byte steps from a z3 array
        :param mem:  current z3 memory array
        :param addr: memory address as z3 bitvec
        :param size: size of the read value
        :return: value in memory at address @addr
        """
        size = size.as_long()
        original_size = size

        if original_size % 8 != 0:
            # Size not aligned on 8bits -> read more than size and extract after
            size = ((original_size / 8) + 1) * 8

        res = z3.Select(mem, addr)

        if self.is_little_endian():
            for i in xrange(1, size / 8):
                res = z3.Concat(z3.Select(mem, addr + i), res)
        else:
            for i in xrange(1, size / 8):
                res = z3.Concat(res, z3.Select(mem, addr + i))

        if size == original_size:
            return z3.simplify(res)
        else:
            return z3.Extract(original_size - 1, 0, res)

    def write(self, mem, addr, v, size):
        """
        Writes a value in 8 byte steps into a z3 array
        :param mem: current z3 memory array
        :param addr: memory address as z3 bitvec
        :param v: value to be written
        :param size: size of value
        :return: updated z3 memory array
        """
        size = size.as_long()
        original_size = size

        if original_size % 8 != 0:
            # align size to 8 bits
            size = ((original_size / 8) + 1) * 8

        if self.is_little_endian():
            mem = z3.Store(mem, addr, z3.Extract(7, 0, v))
            for i in xrange(2, size / 8 + 1):
                mem = z3.Store(mem, addr + i - 1, z3.Extract(8 * i - 1, 8 * (i - 1), v))
        else:
            mem = z3.Store(mem, addr, z3.Extract(self.size - 1, self.size - 8, v))
            for i in xrange((size / 8) - 1, 0, -1):
                mem = z3.Store(mem, addr + (-i % (size / 8)), z3.Extract(8 * i - 1, 8 * (i - 1), v))

        return z3.simplify(mem)




class TranslatorZ3(Translator):
    """Translate a Miasm expression to an equivalent z3 python binding
    expression. Memory is abstracted via z3.Array (see Z3Mem).
    The result of from_expr will be a z3 Expr.

    If you want to interact with the memory abstraction after the translation,
    you can instantiate your own Z3Mem, that will be equivalent to the one
    used by TranslatorZ3.
    """

    # Implemented language
    __LANG__ = "z3"
    # Operations translation
    trivial_ops = ["+", "-", "/", "%", "&", "^", "|", "*", "<<"]

    def __init__(self, endianness="<", loc_db=None, stateful_mem=False, mem_size=64, **kwargs):
        """Instance a Z3 translator
        @endianness: (optional) memory endianness
        """
        # Import z3 only on demand
        global z3
        import z3

        super(TranslatorZ3, self).__init__(**kwargs)
        self.stateful_mem = stateful_mem
        if self.stateful_mem:
            self._mem = Z3MemStateful(mem_size, endianness)
        else:
            self._mem = Z3Mem(endianness)
        self.loc_db = loc_db

    def from_ExprInt(self, expr):
        return z3.BitVecVal(expr.arg.arg, expr.size)

    def from_ExprId(self, expr):
        if self.stateful_mem and isinstance(expr.name, str) and expr.name.split(".")[0] == "M":
            return self._mem.gen_mem(str(expr.name))
        else:
            return z3.BitVec(str(expr), expr.size)

    def from_ExprLoc(self, expr):
        if self.loc_db is None:
            # No loc_db, fallback to default name
            return z3.BitVec(str(expr), expr.size)
        loc_key = expr.loc_key
        offset = self.loc_db.get_location_offset(loc_key)
        if offset is not None:
            return z3.BitVecVal(offset, expr.size)
        # fallback to default name
        return z3.BitVec(str(loc_key), expr.size)

    def from_ExprMem(self, expr):
        if self.stateful_mem:
            addr = self.from_expr(expr.ptr)
            size = z3.IntVal(expr.size)
            mem = self._mem.gen_mem()
            return self._mem.read(mem, addr, size)
        else:
            addr = self.from_expr(expr.ptr)
            return self._mem.get(addr, expr.size)

    def from_ExprSlice(self, expr):
        res = self.from_expr(expr.arg)
        res = z3.Extract(expr.stop-1, expr.start, res)
        return res

    def from_ExprCompose(self, expr):
        res = None
        for arg in expr.args:
            e = z3.Extract(arg.size-1, 0, self.from_expr(arg))
            if res != None:
                res = z3.Concat(e, res)
            else:
                res = e
        return res

    def from_ExprCond(self, expr):
        cond = self.from_expr(expr.cond)
        src1 = self.from_expr(expr.src1)
        src2 = self.from_expr(expr.src2)
        return z3.If(cond != 0, src1, src2)

    def _abs(self, z3_value):
        return z3.If(z3_value >= 0,z3_value,-z3_value)

    def _sdivC(self, num, den):
        """Divide (signed) @num by @den (z3 values) as C would
        See modint.__div__ for implementation choice
        """
        result_sign = z3.If(num * den >= 0,
                            z3.BitVecVal(1, num.size()),
                            z3.BitVecVal(-1, num.size()),
        )
        return z3.UDiv(self._abs(num), self._abs(den)) * result_sign

    def from_ExprOp(self, expr):
        args = list(map(self.from_expr, expr.args))
        res = args[0]

        if len(args) > 1:
            for arg in args[1:]:
                if expr.op in self.trivial_ops:
                    res = eval("res %s arg" % expr.op)
                elif expr.op == ">>":
                    res = z3.LShR(res, arg)
                elif expr.op == "a>>":
                    res = res >> arg
                elif expr.op == "<<<":
                    res = z3.RotateLeft(res, arg)
                elif expr.op == ">>>":
                    res = z3.RotateRight(res, arg)
                elif expr.op == "sdiv":
                    res = self._sdivC(res, arg)
                elif expr.op == "udiv":
                    res = z3.UDiv(res, arg)
                elif expr.op == "smod":
                    res = res - (arg * (self._sdivC(res, arg)))
                elif expr.op == "umod":
                    res = z3.URem(res, arg)
                elif expr.op == "==":
                    res = z3.If(
                        args[0] == args[1],
                        z3.BitVecVal(1, 1),
                        z3.BitVecVal(0, 1)
                    )
                elif expr.op == "<u":
                    res = z3.If(
                        z3.ULT(args[0], args[1]),
                        z3.BitVecVal(1, 1),
                        z3.BitVecVal(0, 1)
                    )
                elif expr.op == "<s":
                    res = z3.If(
                        args[0] < args[1],
                        z3.BitVecVal(1, 1),
                        z3.BitVecVal(0, 1)
                    )
                elif expr.op == "<=u":
                    res = z3.If(
                        z3.ULE(args[0], args[1]),
                        z3.BitVecVal(1, 1),
                        z3.BitVecVal(0, 1)
                    )
                elif expr.op == "<=s":
                    res = z3.If(
                        args[0] <= args[1],
                        z3.BitVecVal(1, 1),
                        z3.BitVecVal(0, 1)
                    )
                elif expr.op == "mem_read":
                    mem = self._mem.gen_mem(str(args[0]))
                    addr = args[1]
                    size = args[2]
                    res = self._mem.read(mem, addr, size)
                elif expr.op == "mem_write":
                    mem = self._mem.gen_mem(str(args[0]))
                    addr = args[1]
                    val = args[2]
                    size = args[3]
                    res = self._mem.write(mem, addr, val, size)
                else:
                    raise NotImplementedError("Unsupported OP yet: %s" % expr.op)
        elif expr.op == 'parity':
            arg = z3.Extract(7, 0, res)
            res = z3.BitVecVal(1, 1)
            for i in range(8):
                res = res ^ z3.Extract(i, i, arg)
        elif expr.op == '-':
            res = -res
        elif expr.op == "cnttrailzeros":
            size = expr.size
            src = res
            res = z3.If(src == 0, size, src)
            for i in range(size - 1, -1, -1):
                res = z3.If((src & (1 << i)) != 0, i, res)
        elif expr.op == "cntleadzeros":
            size = expr.size
            src = res
            res = z3.If(src == 0, size, src)
            for i in range(size, 0, -1):
                index = - i % size
                out = size - (index + 1)
                res = z3.If((src & (1 << index)) != 0, out, res)
        elif expr.op.startswith("zeroExt"):
            arg, = expr.args
            res = z3.ZeroExt(expr.size - arg.size, self.from_expr(arg))
        elif expr.op.startswith("signExt"):
            arg, = expr.args
            res = z3.SignExt(expr.size - arg.size, self.from_expr(arg))
        else:
            raise NotImplementedError("Unsupported OP yet: %s" % expr.op)

        return res

    def from_ExprAssign(self, expr):
        src = self.from_expr(expr.src)
        dst = self.from_expr(expr.dst)
        return (src == dst)


# Register the class
Translator.register(TranslatorZ3)
