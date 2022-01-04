from __future__ import print_function
from builtins import range
import logging
try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping

from future.utils import viewitems

from miasm.expression.expression import ExprOp, ExprId, ExprLoc, ExprInt, \
    ExprMem, ExprCompose, ExprSlice, ExprCond
from miasm.expression.simplifications import expr_simp_explicit
from miasm.ir.ir import AssignBlock

log = logging.getLogger("symbexec")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)


def get_block(lifter, ircfg, mdis, addr):
    """Get IRBlock at address @addr"""
    loc_key = ircfg.get_or_create_loc_key(addr)
    if not loc_key in ircfg.blocks:
        offset = mdis.loc_db.get_location_offset(loc_key)
        block = mdis.dis_block(offset)
        lifter.add_asmblock_to_ircfg(block, ircfg)
    irblock = ircfg.get_block(loc_key)
    if irblock is None:
        raise LookupError('No block found at that address: %s' % lifter.loc_db.pretty_str(loc_key))
    return irblock


class StateEngine(object):
    """Stores an Engine state"""

    def merge(self, other):
        """Generate a new state, representing the merge of self and @other
        @other: a StateEngine instance"""

        raise NotImplementedError("Abstract method")


class SymbolicState(StateEngine):
    """Stores a SymbolicExecutionEngine state"""

    def __init__(self, dct):
        self._symbols = frozenset(viewitems(dct))

    def __hash__(self):
        return hash((self.__class__, self._symbols))

    def __eq__(self, other):
        if self is other:
            return True
        if self.__class__ != other.__class__:
            return False
        return self.symbols == other.symbols

    def __ne__(self, other):
        return not self == other

    def __iter__(self):
        for dst, src in self._symbols:
            yield dst, src

    def iteritems(self):
        """Iterate on stored memory/values"""
        return self.__iter__()

    def merge(self, other):
        """Merge two symbolic states
        Only equal expressions are kept in both states
        @other: second symbolic state
        """

        symb_a = self.symbols
        symb_b = other.symbols
        intersection = set(symb_a).intersection(set(symb_b))
        out = {}
        for dst in intersection:
            if symb_a[dst] == symb_b[dst]:
                out[dst] = symb_a[dst]
        return self.__class__(out)

    @property
    def symbols(self):
        """Return the dictionary of known symbols"""
        return dict(self._symbols)


INTERNAL_INTBASE_NAME = "__INTERNAL_INTBASE__"


def get_expr_base_offset(expr):
    """Return a couple representing the symbolic/concrete part of an addition
    expression.

    If there is no symbolic part, ExprId(INTERNAL_INTBASE_NAME) is used
    If there is not concrete part, 0 is used
    @expr: Expression instance

    """
    if expr.is_int():
        internal_intbase = ExprId(INTERNAL_INTBASE_NAME, expr.size)
        return internal_intbase, int(expr)

    if not expr.is_op('+'):
        return expr, 0
    if expr.args[-1].is_int():
        args, offset = expr.args[:-1], int(expr.args[-1])
        if len(args) == 1:
            return args[0], offset
        return ExprOp('+', *args), offset
    return expr, 0


class MemArray(MutableMapping):
    """Link between base and its (offset, Expr)

    Given an expression (say *base*), this structure will store every memory
    content relatively to an integer offset from *base*.

    The value associated to a given offset is a description of the slice of a
    stored expression. The slice size depends on the configuration of the
    MemArray. For example, for a slice size of 8 bits, the assignment:
    - @32[EAX+0x10] = EBX

    will store for the base EAX:
    - 0x10: (EBX, 0)
    - 0x11: (EBX, 1)
    - 0x12: (EBX, 2)
    - 0x13: (EBX, 3)

    If the *base* is EAX+EBX, this structure can store the following contents:
    - @32[EAX+EBX]
    - @8[EAX+EBX+0x100]
    But not:
    - @32[EAX+0x10] (which is stored in another MemArray based on EAX)
    - @32[EAX+EBX+ECX] (which is stored in another MemArray based on
      EAX+EBX+ECX)

    """

    def __init__(self, base, expr_simp=expr_simp_explicit):
        self._base = base
        self.expr_simp = expr_simp
        self._mask = int(base.mask)
        self._offset_to_expr = {}

    @property
    def base(self):
        """Expression representing the symbolic base address"""
        return self._base

    @property
    def mask(self):
        """Mask offset"""
        return self._mask

    def __contains__(self, offset):
        return offset in self._offset_to_expr

    def __getitem__(self, offset):
        assert 0 <= offset <= self._mask
        return self._offset_to_expr.__getitem__(offset)

    def __setitem__(self, offset, value):
        raise RuntimeError("Use write api to update keys")

    def __delitem__(self, offset):
        assert 0 <= offset <= self._mask
        return self._offset_to_expr.__delitem__(offset)

    def __iter__(self):
        for offset, _ in viewitems(self._offset_to_expr):
            yield offset

    def __len__(self):
        return len(self._offset_to_expr)

    def __repr__(self):
        out = []
        out.append("Base: %s" % self.base)
        for offset, (index, value) in sorted(viewitems(self._offset_to_expr)):
            out.append("%16X %d %s" % (offset, index, value))
        return '\n'.join(out)

    def copy(self):
        """Copy object instance"""
        obj = MemArray(self.base, self.expr_simp)
        obj._offset_to_expr = self._offset_to_expr.copy()
        return obj

    @staticmethod
    def offset_to_ptr(base, offset):
        """
        Return an expression representing the @base + @offset
        @base: symbolic base address
        @offset: relative offset integer to the @base address
        """
        if base.is_id(INTERNAL_INTBASE_NAME):
            ptr = ExprInt(offset, base.size)
        elif offset == 0:
            ptr = base
        else:
            ptr = base + ExprInt(offset, base.size)
        return ptr.canonize()

    def read(self, offset, size):
        """
        Return memory at @offset with @size as an Expr list
        @offset: integer (in bytes)
        @size: integer (in bits), byte aligned

        Consider the following state:
        - 0x10: (EBX, 0)
        - 0x11: (EBX, 1)
        - 0x12: (EBX, 2)
        - 0x13: (EBX, 3)

        A read at 0x10 of 32 bits should return: EBX
        """

        assert size % 8 == 0
        # Parts is (Expr's offset, size, Expr)
        parts = []
        for index in range(size // 8):
            # Wrap read:
            # @32[EAX+0xFFFFFFFF] is ok and will read at 0xFFFFFFFF, 0, 1, 2
            request_offset = (offset + index) & self._mask
            if request_offset in self._offset_to_expr:
                # Known memory portion
                off, data = self._offset_to_expr[request_offset]
                parts.append((off, 1, data))
                continue

            # Unknown memory portion
            ptr = self.offset_to_ptr(self.base, request_offset)
            data = ExprMem(ptr, 8)
            parts.append((0, 1, data))

        # Group similar data
        # XXX TODO: only little endian here
        index = 0
        while index + 1 < len(parts):
            off_a, size_a, data_a = parts[index]
            off_b, size_b, data_b = parts[index+1]
            if data_a == data_b and off_a + size_a == off_b:
                # Read consecutive bytes of a variable
                # [(0, 8, x), (1, 8, x)] => (0, 16, x)
                parts[index:index+2] = [(off_a, size_a + size_b, data_a)]
                continue
            if data_a.is_int() and data_b.is_int():
                # Read integer parts
                # [(0, 8, 0x11223344), (1, 8, 0x55667788)] => (0, 16, 0x7744)
                int1 = self.expr_simp(data_a[off_a*8:(off_a+size_a)*8])
                int2 = self.expr_simp(data_b[off_b*8:(off_b+size_b)*8])
                assert int1.is_int() and int2.is_int()
                int1, int2 = int(int1), int(int2)
                result = ExprInt((int2 << (size_a * 8)) | int1, (size_a + size_b) * 8)
                parts[index:index+2] = [(0, size_a + size_b, result)]
                continue
            if data_a.is_mem() and data_b.is_mem():
                # Read consecutive bytes of a memory variable
                ptr_base_a, ptr_offset_a = get_expr_base_offset(data_a.ptr)
                ptr_base_b, ptr_offset_b = get_expr_base_offset(data_b.ptr)
                if ptr_base_a != ptr_base_b:
                    index += 1
                    continue
                if (ptr_offset_a + off_a + size_a) & self._mask == (ptr_offset_b + off_b) & self._mask:
                    assert size_a <= data_a.size // 8 - off_a
                    assert size_b <= data_b.size // 8 - off_b
                    # Successive comparable symbolic pointers
                    # [(0, 8, @8[ptr]), (0, 8, @8[ptr+1])] => (0, 16, @16[ptr])
                    ptr = self.offset_to_ptr(ptr_base_a, (ptr_offset_a + off_a) & self._mask)

                    data = ExprMem(ptr, (size_a + size_b) * 8)
                    parts[index:index+2] = [(0, size_a + size_b, data)]

                    continue

            index += 1

        # Slice data
        read_mem = []
        for off, bytesize, data in parts:
            if data.size // 8 != bytesize:
                data = data[off * 8: (off + bytesize) * 8]
            read_mem.append(data)

        return read_mem

    def write(self, offset, expr):
        """
        Write @expr at @offset
        @offset: integer (in bytes)
        @expr: Expr instance value
        """
        assert expr.size % 8 == 0
        assert offset <= self._mask
        for index in range(expr.size // 8):
            # Wrap write:
            # @32[EAX+0xFFFFFFFF] is ok and will write at 0xFFFFFFFF, 0, 1, 2
            request_offset = (offset + index) & self._mask
            # XXX TODO: only little endian here
            self._offset_to_expr[request_offset] = (index, expr)

            tmp = self.expr_simp(expr[index * 8: (index + 1) * 8])
            # Special case: Simplify slice of pointer (simplification is ok
            # here, as we won't store the simplified expression)
            if tmp.is_slice() and tmp.arg.is_mem() and tmp.start % 8 == 0:
                new_ptr = self.expr_simp(
                    tmp.arg.ptr + ExprInt(tmp.start // 8, tmp.arg.ptr.size)
                )
                tmp = ExprMem(new_ptr, tmp.stop - tmp.start)
            # Test if write to original value
            if tmp.is_mem():
                src_ptr, src_off = get_expr_base_offset(tmp.ptr)
                if src_ptr == self.base and src_off == request_offset:
                    del self._offset_to_expr[request_offset]


    def _get_variable_parts(self, index, known_offsets, forward=True):
        """
        Find consecutive memory parts representing the same variable. The part
        starts at offset known_offsets[@index] and search is in offset direction
        determined by @forward
        Return the number of consecutive parts of the same variable.

        @index: index of the memory offset in known_offsets
        @known_offsets: sorted offsets
        @forward: Search in offset growing direction if True, else in reverse
        order
        """

        offset = known_offsets[index]
        value_byte_index, value = self._offset_to_expr[offset]
        assert value.size % 8 == 0

        if forward:
            start, end, step = value_byte_index + 1, value.size // 8, 1
        else:
            start, end, step = value_byte_index - 1, -1, -1

        partnum = 1
        for value_offset in range(start, end, step):
            offset += step
            # Check if next part is in known_offsets
            next_index = index + step * partnum
            if not 0 <= next_index < len(known_offsets):
                break

            offset_next = known_offsets[next_index]
            if offset_next != offset:
                break

            # Check if next part is a part of the searched value
            byte_index, value_next = self._offset_to_expr[offset_next]
            if byte_index != value_offset:
                break
            if value != value_next:
                break
            partnum += 1

        return partnum


    def _build_value_at_offset(self, value, offset, start, length):
        """
        Return a couple. The first element is the memory Expression representing
        the value at @offset, the second is its value.  The value is truncated
        at byte @start with @length

        @value: Expression to truncate
        @offset: offset in bytes of the variable (integer)
        @start: value's byte offset (integer)
        @length: length in bytes (integer)
        """

        ptr = self.offset_to_ptr(self.base, offset)
        size = length * 8
        if start == 0 and size == value.size:
            result = value
        else:
            result = self.expr_simp(value[start * 8: start * 8 + size])

        return ExprMem(ptr, size), result


    def memory(self):
        """
        Iterate on stored memory/values

        The goal here is to group entities.

        Consider the following state:
        EAX + 0x10 = (0, EDX)
        EAX + 0x11 = (1, EDX)
        EAX + 0x12 = (2, EDX)
        EAX + 0x13 = (3, EDX)

        The function should return:
        @32[EAX + 0x10] = EDX
        """

        if not self._offset_to_expr:
            return
        known_offsets = sorted(self._offset_to_expr)
        index = 0
        # Test if the first element is the continuation of the last byte. If
        # yes, merge and output it first.
        min_int = 0
        max_int = (1 << self.base.size) - 1
        limit_index = len(known_offsets)

        first_element = None
        # Special case where a variable spreads on max_int/min_int
        if known_offsets[0] == min_int and known_offsets[-1] == max_int:
            min_offset, max_offset = known_offsets[0], known_offsets[-1]
            min_byte_index, min_value = self._offset_to_expr[min_offset]
            max_byte_index, max_value = self._offset_to_expr[max_offset]
            if min_value == max_value and max_byte_index + 1 == min_byte_index:
                # Look for current variable start
                partnum_before = self._get_variable_parts(len(known_offsets) - 1, known_offsets, False)
                # Look for current variable end
                partnum_after = self._get_variable_parts(0, known_offsets)

                partnum = partnum_before + partnum_after
                offset = known_offsets[-partnum_before]
                index_value, value = self._offset_to_expr[offset]

                mem, result = self._build_value_at_offset(value, offset, index_value, partnum)
                first_element = mem, result
                index = partnum_after
                limit_index = len(known_offsets) - partnum_before

        # Special cases are done, walk and merge variables
        while index < limit_index:
            offset = known_offsets[index]
            index_value, value = self._offset_to_expr[offset]
            partnum = self._get_variable_parts(index, known_offsets)
            mem, result = self._build_value_at_offset(value, offset, index_value, partnum)
            yield mem, result
            index += partnum

        if first_element is not None:
            yield first_element

    def dump(self):
        """Display MemArray content"""
        for mem, value in self.memory():
            print("%s = %s" % (mem, value))


class MemSparse(object):
    """Link a symbolic memory pointer to its MemArray.

    For each symbolic memory object, this object will extract the memory pointer
    *ptr*. It then splits *ptr* into a symbolic and an integer part. For
    example, the memory @[ESP+4] will give ESP+4 for *ptr*. *ptr* is then split
    into its base ESP and its offset 4. Each symbolic base address uses a
    different MemArray.

    Example:
    - @32[EAX+EBX]
    - @8[EAX+EBX+0x100]
    Will be stored in the same MemArray with a EAX+EBX base

    """

    def __init__(self, addrsize, expr_simp=expr_simp_explicit):
        """
        @addrsize: size (in bits) of the addresses manipulated by the MemSparse
        @expr_simp: an ExpressionSimplifier instance
        """
        self.addrsize = addrsize
        self.expr_simp = expr_simp
        self.base_to_memarray = {}

    def __contains__(self, expr):
        """
        Return True if the whole @expr is present
        For partial check, use 'contains_partial'
        """
        if not expr.is_mem():
            return False
        ptr = expr.ptr
        base, offset = get_expr_base_offset(ptr)
        memarray = self.base_to_memarray.get(base, None)
        if memarray is None:
            return False
        for i in range(expr.size // 8):
            if offset + i not in memarray:
                return False
        return True

    def contains_partial(self, expr):
        """
        Return True if a part of @expr is present in memory
        """
        if not expr.is_mem():
            return False
        ptr = expr.ptr
        base, offset = get_expr_base_offset(ptr)
        memarray = self.base_to_memarray.get(base, None)
        if memarray is None:
            return False
        for i in range(expr.size // 8):
            if offset + i in memarray:
                return True
        return False

    def clear(self):
        """Reset the current object content"""
        self.base_to_memarray.clear()

    def copy(self):
        """Copy the current object instance"""
        base_to_memarray = {}
        for base, memarray in viewitems(self.base_to_memarray):
            base_to_memarray[base] = memarray.copy()
        obj = MemSparse(self.addrsize, self.expr_simp)
        obj.base_to_memarray = base_to_memarray
        return obj

    def __delitem__(self, expr):
        """
        Delete a value @expr *fully* present in memory
        For partial delete, use delete_partial
        """
        ptr = expr.ptr
        base, offset = get_expr_base_offset(ptr)
        memarray = self.base_to_memarray.get(base, None)
        if memarray is None:
            raise KeyError
        # Check if whole entity is in the MemArray before deleting it
        for i in range(expr.size // 8):
            if (offset + i) & memarray.mask not in memarray:
                raise KeyError
        for i in range(expr.size // 8):
            del memarray[(offset + i) & memarray.mask]

    def delete_partial(self, expr):
        """
        Delete @expr from memory. Skip parts of @expr which are not present in
        memory.
        """
        ptr = expr.ptr
        base, offset = get_expr_base_offset(ptr)
        memarray = self.base_to_memarray.get(base, None)
        if memarray is None:
            raise KeyError
        # Check if whole entity is in the MemArray before deleting it
        for i in range(expr.size // 8):
            real_offset = (offset + i) & memarray.mask
            if real_offset in memarray:
                del memarray[real_offset]

    def read(self, ptr, size):
        """
        Return the value associated with the Expr at address @ptr
        @ptr: Expr representing the memory address
        @size: memory size (in bits), byte aligned
        """
        assert size % 8 == 0
        base, offset = get_expr_base_offset(ptr)
        memarray = self.base_to_memarray.get(base, None)
        if memarray is not None:
            mems = memarray.read(offset, size)
            ret = mems[0] if len(mems) == 1 else ExprCompose(*mems)
        else:
            ret = ExprMem(ptr, size)
        return ret

    def write(self, ptr, expr):
        """
        Update the corresponding Expr @expr at address @ptr
        @ptr: Expr representing the memory address
        @expr: Expr instance
        """
        assert ptr.size == self.addrsize
        base, offset = get_expr_base_offset(ptr)
        memarray = self.base_to_memarray.get(base, None)
        if memarray is None:
            memarray = MemArray(base, self.expr_simp)
            self.base_to_memarray[base] = memarray
        memarray.write(offset, expr)

    def iteritems(self):
        """Iterate on stored memory variables and their values."""
        for _, memarray in viewitems(self.base_to_memarray):
            for mem, value in memarray.memory():
                yield mem, value

    def items(self):
        """Return stored memory variables and their values."""
        return list(self.iteritems())

    def dump(self):
        """Display MemSparse content"""
        for mem, value in viewitems(self):
            print("%s = %s" % (mem, value))

    def __repr__(self):
        out = []
        for _, memarray in sorted(viewitems(self.base_to_memarray)):
            out.append(repr(memarray))
        return '\n'.join(out)


class SymbolMngr(object):
    """Symbolic store manager (IDs and MEMs)"""

    def __init__(self, init=None, addrsize=None, expr_simp=expr_simp_explicit):
        assert addrsize is not None
        if init is None:
            init = {}
        self.addrsize = addrsize
        self.expr_simp = expr_simp
        self.symbols_id = {}
        self.symbols_mem = MemSparse(addrsize, expr_simp)
        self.mask = (1 << addrsize) - 1
        for expr, value in viewitems(init):
            self.write(expr, value)

    def __contains__(self, expr):
        if expr.is_id():
            return self.symbols_id.__contains__(expr)
        if expr.is_mem():
            return self.symbols_mem.__contains__(expr)
        return False

    def __getitem__(self, expr):
        return self.read(expr)

    def __setitem__(self, expr, value):
        self.write(expr, value)

    def __delitem__(self, expr):
        if expr.is_id():
            del self.symbols_id[expr]
        elif expr.is_mem():
            del self.symbols_mem[expr]
        else:
            raise TypeError("Bad source expr")

    def copy(self):
        """Copy object instance"""
        obj = SymbolMngr(self, addrsize=self.addrsize, expr_simp=self.expr_simp)
        return obj

    def clear(self):
        """Forget every variables values"""
        self.symbols_id.clear()
        self.symbols_mem.clear()

    def read(self, src):
        """
        Return the value corresponding to Expr @src
        @src: ExprId or ExprMem instance
        """
        if src.is_id():
            return self.symbols_id.get(src, src)
        elif src.is_mem():
            # Only byte aligned accesses are supported for now
            assert src.size % 8 == 0
            return self.symbols_mem.read(src.ptr, src.size)
        else:
            raise TypeError("Bad source expr")

    def write(self, dst, src):
        """
        Update @dst with @src expression
        @dst: ExprId or ExprMem instance
        @src: Expression instance
        """
        assert dst.size == src.size
        if dst.is_id():
            if dst == src:
                if dst in self.symbols_id:
                    del self.symbols_id[dst]
            else:
                self.symbols_id[dst] = src
        elif dst.is_mem():
            # Only byte aligned accesses are supported for now
            assert dst.size % 8 == 0
            self.symbols_mem.write(dst.ptr, src)
        else:
            raise TypeError("Bad destination expr")

    def dump(self, ids=True, mems=True):
        """Display memory content"""
        if ids:
            for variable, value in self.ids():
                print('%s = %s' % (variable, value))
        if mems:
            for mem, value in self.memory():
                print('%s = %s' % (mem, value))

    def __repr__(self):
        out = []
        for variable, value in viewitems(self):
            out.append('%s = %s' % (variable, value))
        return "\n".join(out)

    def iteritems(self):
        """ExprId/ExprMem iteritems of the current state"""
        for variable, value in self.ids():
            yield variable, value
        for variable, value in self.memory():
            yield variable, value

    def items(self):
        """Return variables/values of the current state"""
        return list(self.iteritems())

    def __iter__(self):
        for expr, _ in self.iteritems():
            yield expr

    def ids(self):
        """Iterate on variables and their values."""
        for expr, value in viewitems(self.symbols_id):
            yield expr, value

    def memory(self):
        """Iterate on memory variables and their values."""
        for mem, value in viewitems(self.symbols_mem):
            yield mem, value

    def keys(self):
        """Variables of the current state"""
        return list(self)


def merge_ptr_read(known, ptrs):
    """
    Merge common memory parts in a multiple byte memory.
    @ptrs: memory bytes list
    @known: ptrs' associated boolean for present/unpresent memory part in the
    store
    """
    assert known
    out = []
    known.append(None)
    ptrs.append(None)
    last, value, size = known[0], ptrs[0], 8
    for index, part in enumerate(known[1:], 1):
        if part == last:
            size += 8
        else:
            out.append((last, value, size))
            last, value, size = part, ptrs[index], 8
    return out


class SymbolicExecutionEngine(object):
    """
    Symbolic execution engine
    Allow IR code emulation in symbolic domain


    Examples:
        from miasm.ir.symbexec import SymbolicExecutionEngine
        from miasm.ir.ir import AssignBlock

        lifter = Lifter_X86_32()

        init_state = {
            lifter.arch.regs.EAX: lifter.arch.regs.EBX,
            ExprMem(id_x+ExprInt(0x10, 32), 32): id_a,
        }

        sb_exec = SymbolicExecutionEngine(lifter, init_state)

        >>> sb_exec.dump()
        EAX                = a
        @32[x + 0x10]      = a
        >>> sb_exec.dump(mems=False)
        EAX                = a

        >>> print sb_exec.eval_expr(lifter.arch.regs.EAX + lifter.arch.regs.ECX)
        EBX + ECX

    Inspecting state:
        - dump
        - modified
    State manipulation:
        - '.state' (rw)

    Evaluation (read only):
        - eval_expr
        - eval_assignblk
    Evaluation with state update:
        - eval_updt_expr
        - eval_updt_assignblk
        - eval_updt_irblock

    Start a symbolic execution based on provisioned '.lifter' blocks:
        - run_block_at
        - run_at
    """

    StateEngine = SymbolicState

    def __init__(self, lifter, state=None,
                 sb_expr_simp=expr_simp_explicit):

        self.expr_to_visitor = {
            ExprInt: self.eval_exprint,
            ExprId: self.eval_exprid,
            ExprLoc: self.eval_exprloc,
            ExprMem: self.eval_exprmem,
            ExprSlice: self.eval_exprslice,
            ExprCond: self.eval_exprcond,
            ExprOp: self.eval_exprop,
            ExprCompose: self.eval_exprcompose,
        }

        if state is None:
            state = {}

        self.symbols = SymbolMngr(addrsize=lifter.addrsize, expr_simp=sb_expr_simp)

        for dst, src in viewitems(state):
            self.symbols.write(dst, src)

        self.lifter = lifter
        self.expr_simp = sb_expr_simp

    @property
    def ir_arch(self):
        warnings.warn('DEPRECATION WARNING: use ".lifter" instead of ".ir_arch"')
        return self.lifter

    def get_state(self):
        """Return the current state of the SymbolicEngine"""
        state = self.StateEngine(dict(self.symbols))
        return state

    def set_state(self, state):
        """Restaure the @state of the engine
        @state: StateEngine instance
        """
        self.symbols = SymbolMngr(addrsize=self.lifter.addrsize, expr_simp=self.expr_simp)
        for dst, src in viewitems(dict(state)):
            self.symbols[dst] = src

    state = property(get_state, set_state)

    def eval_expr_visitor(self, expr, cache=None):
        """
        [DEV]: Override to change the behavior of an Expr evaluation.
        This function recursively applies 'eval_expr*' to @expr.
        This function uses @cache to speedup re-evaluation of expression.
        """
        if cache is None:
            cache = {}

        ret = cache.get(expr, None)
        if ret is not None:
            return ret

        new_expr = self.expr_simp(expr)
        ret = cache.get(new_expr, None)
        if ret is not None:
            return ret

        func = self.expr_to_visitor.get(new_expr.__class__, None)
        if func is None:
            raise TypeError("Unknown expr type")

        ret = func(new_expr, cache=cache)
        ret = self.expr_simp(ret)
        assert ret is not None

        cache[expr] = ret
        cache[new_expr] = ret
        return ret

    def eval_exprint(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprInt using the current state"""
        return expr

    def eval_exprid(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprId using the current state"""
        ret = self.symbols.read(expr)
        return ret

    def eval_exprloc(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprLoc using the current state"""
        offset = self.lifter.loc_db.get_location_offset(expr.loc_key)
        if offset is not None:
            ret = ExprInt(offset, expr.size)
        else:
            ret = expr
        return ret

    def eval_exprmem(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprMem using the current state
        This function first evaluate the memory pointer value.
        Override 'mem_read' to modify the effective memory accesses
        """
        ptr = self.eval_expr_visitor(expr.ptr, **kwargs)
        mem = ExprMem(ptr, expr.size)
        ret = self.mem_read(mem)
        return ret

    def eval_exprcond(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprCond using the current state"""
        cond = self.eval_expr_visitor(expr.cond, **kwargs)
        src1 = self.eval_expr_visitor(expr.src1, **kwargs)
        src2 = self.eval_expr_visitor(expr.src2, **kwargs)
        ret = ExprCond(cond, src1, src2)
        return ret

    def eval_exprslice(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprSlice using the current state"""
        arg = self.eval_expr_visitor(expr.arg, **kwargs)
        ret = ExprSlice(arg, expr.start, expr.stop)
        return ret

    def eval_exprop(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprOp using the current state"""
        args = []
        for oarg in expr.args:
            arg = self.eval_expr_visitor(oarg, **kwargs)
            args.append(arg)
        ret = ExprOp(expr.op, *args)
        return ret

    def eval_exprcompose(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprCompose using the current state"""
        args = []
        for arg in expr.args:
            args.append(self.eval_expr_visitor(arg, **kwargs))
        ret = ExprCompose(*args)
        return ret

    def eval_expr(self, expr, eval_cache=None):
        """
        Evaluate @expr
        @expr: Expression instance to evaluate
        @cache: None or dictionary linking variables to their values
        """
        if eval_cache is None:
            eval_cache = {}
        ret = self.eval_expr_visitor(expr, cache=eval_cache)
        assert ret is not None
        return ret

    def modified(self, init_state=None, ids=True, mems=True):
        """
        Return the modified variables.
        @init_state: a base dictionary linking variables to their initial values
        to diff. Can be None.
        @ids: track ids only
        @mems: track mems only
        """
        if init_state is None:
            init_state = {}
        if ids:
            for variable, value in viewitems(self.symbols.symbols_id):
                if variable in init_state and init_state[variable] == value:
                    continue
                yield variable, value
        if mems:
            for mem, value in self.symbols.memory():
                if mem in init_state and init_state[mem] == value:
                    continue
                yield mem, value

    def dump(self, ids=True, mems=True):
        """
        Display modififed variables
        @ids: display modified ids
        @mems: display modified memory
        """

        for variable, value in self.modified(None, ids, mems):
            print("%-18s" % variable, "=", "%s" % value)

    def eval_assignblk(self, assignblk):
        """
        Evaluate AssignBlock using the current state

        Returns a dictionary containing modified keys associated to their values

        @assignblk: AssignBlock instance
        """
        pool_out = {}
        eval_cache = {}
        for dst, src in viewitems(assignblk):
            src = self.eval_expr(src, eval_cache)
            if dst.is_mem():
                ptr = self.eval_expr(dst.ptr, eval_cache)
                # Test if mem lookup is known
                tmp = ExprMem(ptr, dst.size)
                pool_out[tmp] = src
            elif dst.is_id():
                pool_out[dst] = src
            else:
                raise ValueError("Unknown destination type", str(dst))

        return pool_out

    def apply_change(self, dst, src):
        """
        Apply @dst = @src on the current state WITHOUT evaluating both side
        @dst: Expr, destination
        @src: Expr, source
        """
        if dst.is_mem():
            self.mem_write(dst, src)
        else:
            self.symbols.write(dst, src)

    def eval_updt_assignblk(self, assignblk):
        """
        Apply an AssignBlock on the current state
        @assignblk: AssignBlock instance
        """
        mem_dst = []
        dst_src = self.eval_assignblk(assignblk)
        for dst, src in viewitems(dst_src):
            self.apply_change(dst, src)
            if dst.is_mem():
                mem_dst.append(dst)
        return mem_dst

    def eval_updt_irblock(self, irb, step=False):
        """
        Symbolic execution of the @irb on the current state
        @irb: irbloc instance
        @step: display intermediate steps
        """
        for assignblk in irb:
            if step:
                print('Instr', assignblk.instr)
                print('Assignblk:')
                print(assignblk)
                print('_' * 80)
            self.eval_updt_assignblk(assignblk)
            if step:
                self.dump(mems=False)
                self.dump(ids=False)
                print('_' * 80)
        dst = self.eval_expr(self.lifter.IRDst)

        return dst

    def run_block_at(self, ircfg, addr, step=False):
        """
        Symbolic execution of the block at @addr
        @addr: address to execute (int or ExprInt or label)
        @step: display intermediate steps
        """
        irblock = ircfg.get_block(addr)
        if irblock is not None:
            addr = self.eval_updt_irblock(irblock, step=step)
        return addr

    def run_at(self, ircfg, addr, lbl_stop=None, step=False):
        """
        Symbolic execution starting at @addr
        @addr: address to execute (int or ExprInt or label)
        @lbl_stop: LocKey to stop execution on
        @step: display intermediate steps
        """
        while True:
            irblock = ircfg.get_block(addr)
            if irblock is None:
                break
            if irblock.loc_key == lbl_stop:
                break
            addr = self.eval_updt_irblock(irblock, step=step)
        return addr

    def del_mem_above_stack(self, stack_ptr):
        """
        Remove all stored memory values with following properties:
        * pointer based on initial stack value
        * pointer below current stack pointer
        """
        stack_ptr = self.eval_expr(stack_ptr)
        base, stk_offset = get_expr_base_offset(stack_ptr)
        memarray = self.symbols.symbols_mem.base_to_memarray.get(base, None)
        if memarray:
            to_del = set()
            for offset in memarray:
                if ((offset - stk_offset) & int(stack_ptr.mask)) >> (stack_ptr.size - 1) != 0:
                    to_del.add(offset)

            for offset in to_del:
                del memarray[offset]

    def eval_updt_expr(self, expr):
        """
        Evaluate @expr and apply side effect if needed (ie. if expr is an
        assignment). Return the evaluated value
        """

        # Update value if needed
        if expr.is_assign():
            ret = self.eval_expr(expr.src)
            self.eval_updt_assignblk(AssignBlock([expr]))
        else:
            ret = self.eval_expr(expr)

        return ret

    def mem_read(self, expr):
        """
        [DEV]: Override to modify the effective memory reads

        Read symbolic value at ExprMem @expr
        @expr: ExprMem
        """
        return self.symbols.read(expr)

    def mem_write(self, dst, src):
        """
        [DEV]: Override to modify the effective memory writes

        Write symbolic value @src at ExprMem @dst
        @dst: destination ExprMem
        @src: source Expression
        """
        self.symbols.write(dst, src)
