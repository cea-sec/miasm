"""This module provides classes to manipulate pure C types as well as their
representation in memory. A typical usecase is to use this module to
easily manipylate structures backed by a VmMngr object (a miasm sandbox virtual
memory):

    class ListNode(MemStruct):
        fields = [
            ("next", Ptr("<I", Self())),
            ("data", Ptr("<I", Void())),
        ]

    class LinkedList(MemStruct):
        fields = [
            ("head", Ptr("<I", ListNode)),
            ("tail", Ptr("<I", ListNode)),
            ("size", Num("<I")),
        ]

    link = LinkedList(vm, addr1)
    link.memset()
    node = ListNode(vm, addr2)
    node.memset()
    link.head = node.get_addr()
    link.tail = node.get_addr()
    link.size += 1
    assert link.head.deref == node
    data = Num("<I").lval(vm, addr3)
    data.val = 5
    node.data = data.get_addr()
    # see examples/jitter/types.py for more info


It provides two families of classes, Type-s (Num, Ptr, Str...) and their
associated MemType-s. A Type subclass instance represents a fully defined C
type. A MemType subclass instance represents a C LValue (or variable): it is
a type attached to the memory. Available types are:

    - Num: for number (float or int) handling
    - Ptr: a pointer to another Type
    - Struct: equivalent to a C struct definition
    - Union: similar to union in C, list of Types at the same offset in a
      structure; the union has the size of the biggest Type (~ Struct with all
      the fields at offset 0)
    - Array: an array of items of the same type; can have a fixed size or
      not (e.g. char[3] vs char* used as an array in C)
    - BitField: similar to C bitfields, a list of
      [(<field_name>, <number_of_bits>),]; creates fields that correspond to
      certain bits of the field; analogous to a Union of Bits (see Bits below)
    - Str: a character string, with an encoding; not directly mapped to a C
      type, it is a higher level notion provided for ease of use
    - Void: analogous to C void, can be a placeholder in void*-style cases.
    - Self: special marker to reference a Struct inside itself (FIXME: to
      remove?)

And some less common types:

    - Bits: mask only some bits of a Num
    - RawStruct: abstraction over a simple struct pack/unpack (no mapping to a
      standard C type)

For each type, the `.lval` property returns a MemType subclass that
allows to access the field in memory.


The easiest way to use the API to declare and manipulate new structures is to
subclass MemStruct and define a list of (<field_name>, <field_definition>):

    class MyStruct(MemStruct):
        fields = [
            # Scalar field: just struct.pack field with one value
            ("num", Num("I")),
            ("flags", Num("B")),
            # Ptr fields contain two fields: "val", for the numerical value,
            # and "deref" to get the pointed object
            ("other", Ptr("I", OtherStruct)),
            # Ptr to a variable length String
            ("s", Ptr("I", Str())),
            ("i", Ptr("I", Num("I"))),
        ]

And access the fields:

    mstruct = MyStruct(jitter.vm, addr)
    mstruct.num = 3
    assert mstruct.num == 3
    mstruct.other.val = addr2
    # Also works:
    mstruct.other = addr2
    mstruct.other.deref = OtherStruct(jitter.vm, addr)

MemUnion and MemBitField can also be subclassed, the `fields` field being
in the format expected by, respectively, Union and BitField.

The `addr` argument can be omited if an allocator is set, in which case the
structure will be automatically allocated in memory:

    my_heap = miasm2.os_dep.common.heap()
    # the allocator is a func(VmMngr) -> integer_address
    set_allocator(my_heap)

Note that some structures (e.g. MemStr or MemArray) do not have a static
size and cannot be allocated automatically.
"""

import logging
import struct

log = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)

# ALLOCATOR is a function(vm, size) -> allocated_address
# TODO: as a MemType class attribute
ALLOCATOR = None

# Cache for dynamically generated MemTypes
DYN_MEM_STRUCT_CACHE = {}

def set_allocator(alloc_func):
    """Set an allocator for this module; allows to instanciate statically sized
    MemTypes (i.e. sizeof() is implemented) without specifying the address
    (the object is allocated by @alloc_func in the vm.

    @alloc_func: func(VmMngr) -> integer_address
    """
    global ALLOCATOR
    ALLOCATOR = alloc_func


# Helpers

def indent(s, size=4):
    """Indent a string with @size spaces"""
    return ' '*size + ('\n' + ' '*size).join(s.split('\n'))


# FIXME: copied from miasm2.os_dep.common and fixed
def get_str_ansi(vm, addr, max_char=None):
    """Get a null terminated ANSI encoded string from a VmMngr.

    @vm: VmMngr instance
    @max_char: max number of characters to get in memory
    """
    l = 0
    tmp = addr
    while ((max_char is None or l < max_char) and
           vm.get_mem(tmp, 1) != "\x00"):
        tmp += 1
        l += 1
    return vm.get_mem(addr, l).decode("latin1")


# TODO: get_raw_str_utf16 for length calculus
def get_str_utf16(vm, addr, max_char=None):
    """Get a (double) null terminated utf16 little endian encoded string from
    a VmMngr. This encoding is mainly used in Windows.

    FIXME: the implementation do not work with codepoints that are encoded on
    more than 2 bytes in utf16.

    @vm: VmMngr instance
    @max_char: max number of bytes to get in memory
    """
    l = 0
    tmp = addr
    # TODO: test if fetching per page rather than 2 byte per 2 byte is worth it?
    while ((max_char is None or l < max_char) and
           vm.get_mem(tmp, 2) != "\x00\x00"):
        tmp += 2
        l += 2
    s = vm.get_mem(addr, l)
    return s.decode('utf-16le')


def set_str_ansi(vm, addr, s):
    """Encode a string to null terminated ascii/ansi and set it in a VmMngr
    memory.

    @vm: VmMngr instance
    @addr: start address to serialize the string to
        s: the str to serialize
    """
    vm.set_mem(addr, s + "\x00")


def set_str_utf16(vm, addr, s):
    """Same as set_str_ansi with (double) null terminated utf16 encoding."""
    s = (s + '\x00').encode('utf-16le')
    vm.set_mem(addr, s)


# Type classes

class Type(object):
    """Base class to provide methods to describe a type, as well as how to set
    and get fields from virtual mem.

    Each Type subclass is linked to a MemType subclass (e.g. Struct to
    MemStruct, Ptr to MemPtr, etc.).

    When nothing is specified, MemValue is used to access the type in memory.
    MemValue instances have one `.val` field, setting and getting it call
    the set and get of the Type.

    Subclasses can either override _pack and _unpack, or get and set if data
    serialization requires more work (see Struct implementation for an example).

    TODO: move any trace of vm and addr out of these classes?
    """

    _self_type = None

    def _pack(self, val):
        """Serializes the python value @val to a raw str"""
        raise NotImplementedError()

    def _unpack(self, raw_str):
        """Deserializes a raw str to an object representing the python value
        of this field.
        """
        raise NotImplementedError()

    def set(self, vm, addr, val):
        """Set a VmMngr memory from a value.

        @vm: VmMngr instance
        @addr: the start adress in memory to set
        @val: the python value to serialize in @vm at @addr
        """
        raw = self._pack(val)
        vm.set_mem(addr, raw)

    def get(self, vm, addr):
        """Get the python value of a field from a VmMngr memory at @addr."""
        raw = vm.get_mem(addr, self.size())
        return self._unpack(raw)

    @property
    def lval(self):
        """Returns a class with a (vm, addr) constructor that allows to
        interact with this type in memory.

        In compilation terms, it returns a class allowing to instanciate an
        lvalue of this type.

        @return: a MemType subclass.
        """
        if self in DYN_MEM_STRUCT_CACHE:
            return DYN_MEM_STRUCT_CACHE[self]
        pinned_type = self._build_pinned_type()
        DYN_MEM_STRUCT_CACHE[self] = pinned_type
        return pinned_type

    def _build_pinned_type(self):
        """Builds the MemType subclass allowing to interract with this type.

        Called by self.lval when it is not in cache.
        """
        pinned_base_class = self._get_pinned_base_class()
        pinned_type = type("Mem%r" % self, (pinned_base_class,),
                           {'_type': self})
        return pinned_type

    def _get_pinned_base_class(self):
        """Return the MemType subclass that maps this type in memory"""
        return MemValue

    def _get_self_type(self):
        """Used for the Self trick."""
        return self._self_type

    def _set_self_type(self, self_type):
        """If this field refers to MemSelf/Self, replace it with @self_type
        (a MemType subclass) when using it. Generally not used outside this
        module.
        """
        self._self_type = self_type

    def size(self):
        """Return the size in bytes of the serialized version of this field"""
        raise NotImplementedError()

    def __len__(self):
        return self.size()

    def __neq__(self, other):
        return not self == other


class RawStruct(Type):
    """Dumb struct.pack/unpack field. Mainly used to factorize code.

    Value is a tuple corresponding to the struct @fmt passed to the constructor.
    """

    def __init__(self, fmt):
        self._fmt = fmt

    def _pack(self, fields):
        return struct.pack(self._fmt, *fields)

    def _unpack(self, raw_str):
        return struct.unpack(self._fmt, raw_str)

    def size(self):
        return struct.calcsize(self._fmt)

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self._fmt)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self._fmt == other._fmt

    def __hash__(self):
        return hash((self.__class__, self._fmt))


class Num(RawStruct):
    """Represents a number (integer or float). The number is encoded with
    a struct-style format which must represent only one value.

    TODO: use u32, i16, etc. for format.
    """

    def _pack(self, number):
        return super(Num, self)._pack([number])

    def _unpack(self, raw_str):
        upck = super(Num, self)._unpack(raw_str)
        if len(upck) != 1:
            raise ValueError("Num format string unpacks to multiple values, "
                             "should be 1")
        return upck[0]


class Ptr(Num):
    """Special case of number of which value indicates the address of a
    MemType.

    Mapped to MemPtr (see its doc for more info):
        
        assert isinstance(mystruct.ptr, MemPtr)
        mystruct.ptr = 0x4000 # Assign the Ptr numeric value
        mystruct.ptr.val = 0x4000 # Also assigns the Ptr numeric value
        assert isinstance(mystruct.ptr.val, int) # Get the Ptr numeric value
        mystruct.ptr.deref # Get the pointed MemType
        mystruct.ptr.deref = other # Set the pointed MemType
    """

    def __init__(self, fmt, dst_type, *type_args, **type_kwargs):
        """
        @fmt: (str) Num compatible format that will be the Ptr representation
            in memory
        @dst_type: (MemType or Type) the MemType this Ptr points to.
            If a Type is given, it is transformed into a MemType with
            TheType.lval.
        *type_args, **type_kwargs: arguments to pass to the the pointed
            MemType when instanciating it (e.g. for MemStr encoding or
            MemArray field_type).
        """
        if (not isinstance(dst_type, Type) and
                not (isinstance(dst_type, type) and
                        issubclass(dst_type, MemType)) and
                not dst_type == MemSelf):
            raise ValueError("dst_type of Ptr must be a MemType type, a "
                             "Type instance, the MemSelf marker or a class "
                             "name.")
        super(Ptr, self).__init__(fmt)
        if isinstance(dst_type, Type):
            # Patch the field to propagate the MemSelf replacement
            dst_type._get_self_type = lambda: self._get_self_type()
            # dst_type cannot be patched here, since _get_self_type of the outer
            # class has not yet been set. Patching dst_type involves calling
            # dst_type.lval, which will only return a type that does not point
            # on MemSelf but on the right class only when _get_self_type of the
            # outer class has been replaced by _MetaMemStruct.
            # In short, dst_type = dst_type.lval is not valid here, it is done
            # lazily in _fix_dst_type
        self._dst_type = dst_type
        self._type_args = type_args
        self._type_kwargs = type_kwargs

    def _fix_dst_type(self):
        if self._dst_type == MemSelf:
            if self._get_self_type() is not None:
                self._dst_type = self._get_self_type()
            else:
                raise ValueError("Unsupported usecase for MemSelf, sorry")
        if isinstance(self._dst_type, Type):
            self._dst_type = self._dst_type.lval

    @property
    def dst_type(self):
        """Return the type (MemType subtype) this Ptr points to."""
        self._fix_dst_type()
        return self._dst_type

    def set(self, vm, addr, val):
        """A Ptr field can be set with a MemPtr or an int"""
        if isinstance(val, MemType) and isinstance(val.get_type(), Ptr):
            self.set_val(vm, addr, val.val)
        else:
            super(Ptr, self).set(vm, addr, val)

    def get(self, vm, addr):
        return self.lval(vm, addr)

    def get_val(self, vm, addr):
        """Get the numeric value of a Ptr"""
        return super(Ptr, self).get(vm, addr)

    def set_val(self, vm, addr, val):
        """Set the numeric value of a Ptr"""
        return super(Ptr, self).set(vm, addr, val)

    def deref_get(self, vm, addr):
        """Deserializes the data in @vm (VmMngr) at @addr to self.dst_type.
        Equivalent to a pointer dereference rvalue in C.
        """
        dst_addr = self.get_val(vm, addr)
        return self.dst_type(vm, dst_addr,
                             *self._type_args, **self._type_kwargs)

    def deref_set(self, vm, addr, val):
        """Serializes the @val MemType subclass instance in @vm (VmMngr) at
        @addr. Equivalent to a pointer dereference assignment in C.
        """
        # Sanity check
        if self.dst_type != val.__class__:
            log.warning("Original type was %s, overriden by value of type %s",
                        self._dst_type.__name__, val.__class__.__name__)

        # Actual job
        dst_addr = self.get_val(vm, addr)
        vm.set_mem(dst_addr, str(val))

    def _get_pinned_base_class(self):
        return MemPtr

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.dst_type.get_type())

    def __eq__(self, other):
        return super(Ptr, self).__eq__(other) and \
                self.dst_type == other.dst_type and \
                self._type_args == other._type_args and \
                self._type_kwargs == other._type_kwargs

    def __hash__(self):
        return hash((super(Ptr, self).__hash__(), self.dst_type,
            self._type_args))


class Struct(Type):
    """Equivalent to a C struct type. Composed of a name, and a
    (<field_name (str)>, <Type_subclass_instance>) list describing the fields
    of the struct.

    Mapped to MemStruct.

    NOTE: The `.lval` property of Struct creates classes on the fly. If an
    equivalent structure is created by subclassing MemStruct, an exception
    is raised to prevent creating multiple classes designating the same type.

    Example:
        s = Struct("Toto", [("f1", Num("I")), ("f2", Num("I"))])

        Toto1 = s.lval

        # This raises an exception, because it describes the same structure as
        # Toto1
        class Toto(MemStruct):
            fields = [("f1", Num("I")), ("f2", Num("I"))]
    """

    def __init__(self, name, fields):
        self.name = name
        # fields is immutable
        self._fields = tuple(fields)
        self._gen_fields()

    def _gen_fields(self):
        """Precompute useful metadata on self.fields."""
        self._fields_desc = {}
        offset = 0
        for name, field in self._fields:
            # For reflexion
            field._set_self_type(self)
            self._fields_desc[name] = {"field": field, "offset": offset}
            offset += field.size()

    @property
    def fields(self):
        return self._fields

    def set(self, vm, addr, val):
        raw = str(val)
        vm.set_mem(addr, raw)

    def get(self, vm, addr):
        return self.lval(vm, addr)

    def get_field(self, vm, addr, name):
        """Get a field value by @name and base structure @addr in @vm VmMngr."""
        if name not in self._fields_desc:
            raise ValueError("'%s' type has no field '%s'" % (self, name))
        field = self.get_field_type(name)
        offset = self.get_offset(name)
        return field.get(vm, addr + offset)

    def set_field(self, vm, addr, name, val):
        """Set a field value by @name and base structure @addr in @vm VmMngr.
        @val is the python value corresponding to this field type.
        """
        if name not in self._fields_desc:
            raise AttributeError("'%s' object has no attribute '%s'"
                                 % (self.__class__.__name__, name))
        field = self.get_field_type(name)
        offset = self.get_offset(name)
        field.set(vm, addr + offset, val)

    def size(self):
        return sum(field.size() for _, field in self.fields)

    def get_offset(self, field_name):
        """
        @field_name: (str, optional) the name of the field to get the
            offset of
        """
        if field_name not in self._fields_desc:
            raise ValueError("This structure has no %s field" % field_name)
        return self._fields_desc[field_name]['offset']

    def get_field_type(self, name):
        """Return the Type subclass instance describing field @name."""
        return self._fields_desc[name]['field']

    def _get_pinned_base_class(self):
        return MemStruct

    def __repr__(self):
        return "struct %s" % self.name

    def __eq__(self, other):
        return self.__class__ == other.__class__ and \
                self.fields == other.fields and \
                self.name == other.name

    def __hash__(self):
        # Only hash name, not fields, because if a field is a Ptr to this
        # Struct type, an infinite loop occurs
        return hash((self.__class__, self.name))


class Union(Struct):
    """Represents a C union.
    
    Allows to put multiple fields at the same offset in a MemStruct,
    similar to unions in C. The Union will have the size of the largest of its
    fields.

    Mapped to MemUnion.

    Example:

        class Example(MemStruct):
            fields = [("uni", Union([
                                  ("f1", Num("<B")),
                                  ("f2", Num("<H"))
                              ])
                     )]

        ex = Example(vm, addr)
        ex.uni.f2 = 0x1234
        assert ex.uni.f1 == 0x34
    """

    def __init__(self, field_list):
        """@field_list: a [(name, field)] list, see the class doc"""
        super(Union, self).__init__("union", field_list)

    def size(self):
        return max(field.size() for _, field in self.fields)

    def get_offset(self, field_name):
        return 0

    def _get_pinned_base_class(self):
        return MemUnion

    def __repr__(self):
        fields_repr = ', '.join("%s: %r" % (name, field)
                                for name, field in self.fields)
        return "%s(%s)" % (self.__class__.__name__, fields_repr)


class Array(Type):
    """An array (contiguous sequence) of a Type subclass elements.

    Can be sized (similar to something like the char[10] type in C) or unsized
    if no @array_len is given to the constructor (similar to char* used as an
    array).

    Mapped to MemArray or MemSizedArray, depending on if the Array is
    sized or not.

    Getting an array field actually returns a MemSizedArray. Setting it is
    possible with either a list or a MemSizedArray instance. Examples of
    syntax:

        class Example(MemStruct):
            fields = [("array", Array(Num("B"), 4))]

        mystruct = Example(vm, addr)
        mystruct.array[3] = 27
        mystruct.array = [1, 4, 8, 9]
        mystruct.array = MemSizedArray(vm, addr2, Num("B"), 4)
    """

    def __init__(self, field_type, array_len=None):
        self.field_type = field_type
        self.array_len = array_len

    def _set_self_type(self, self_type):
        super(Array, self)._set_self_type(self_type)
        self.field_type._set_self_type(self_type)

    def set(self, vm, addr, val):
        # MemSizedArray assignment
        if isinstance(val, MemSizedArray):
            if val.array_len != self.array_len or len(val) != self.size():
                raise ValueError("Size mismatch in MemSizedArray assignment")
            raw = str(val)
            vm.set_mem(addr, raw)

        # list assignment
        elif isinstance(val, list):
            if len(val) != self.array_len:
                raise ValueError("Size mismatch in MemSizedArray assignment ")
            offset = 0
            for elt in val:
                self.field_type.set(vm, addr + offset, elt)
                offset += self.field_type.size()

        else:
            raise RuntimeError(
                "Assignment only implemented for list and MemSizedArray")

    def get(self, vm, addr):
        return self.lval(vm, addr)

    def size(self):
        if self.is_sized():
            return self.get_offset(self.array_len)
        else:
            raise ValueError("%s is unsized, use an array with a fixed "
                             "array_len instead." % self)

    def get_offset(self, idx):
        """Returns the offset of the item at index @idx."""
        return self.field_type.size() * idx

    def get_item(self, vm, addr, idx):
        """Get the item(s) at index @idx.

        @idx: int, long or slice
        """
        if isinstance(idx, slice):
            res = []
            idx = self._normalize_slice(idx)
            for i in xrange(idx.start, idx.stop, idx.step):
                res.append(self.field_type.get(vm, addr + self.get_offset(i)))
            return res
        else:
            return self.field_type.get(vm, addr + self.get_offset(idx))

    def set_item(self, vm, addr, idx, item):
        """Sets one or multiple items in this array (@idx can be an int, long
        or slice).
        """
        if isinstance(idx, slice):
            idx = self._normalize_slice(idx)
            if len(item) != len(xrange(idx.start, idx.stop, idx.step)):
                raise ValueError("Mismatched lengths in slice assignment")
            # TODO: izip
            for i, val in zip(xrange(idx.start, idx.stop, idx.step), item):
                self.field_type.set(vm, addr + self.get_offset(i), val)
        else:
            self.field_type.set(vm, addr + self.get_offset(idx), item)

    def is_sized(self):
        """True if this is a sized array (non None self.array_len), False
        otherwise.
        """
        return self.array_len is not None

    def _normalize_idx(self, idx):
        # Noop for this type
        if self.is_sized() and idx < 0:
            return self.get_size() - idx
        return idx

    def _normalize_slice(self, slice_):
        start = slice_.start if slice_.start is not None else 0
        stop = slice_.stop if slice_.stop is not None else self.get_size()
        step = slice_.step if slice_.step is not None else 1
        return slice(start, stop, step)

    def _check_bounds(self, idx):
        idx = self._normalize_idx(idx)
        if not isinstance(idx, (int, long)):
            raise ValueError("index must be an int or a long")
        if idx < 0 or (self.is_sized() and idx >= self.size()):
            raise IndexError("Index %s out of bounds" % idx)

    def _get_pinned_base_class(self):
        if self.is_sized():
            return MemSizedArray
        else:
            return MemArray

    def __repr__(self):
        return "%r[%s]" % (self.field_type, self.array_len or "unsized")

    def __eq__(self, other):
        return self.__class__ == other.__class__ and \
                self.field_type == other.field_type and \
                self.array_len == other.array_len

    def __hash__(self):
        return hash((self.__class__, self.field_type, self.array_len))


class Bits(Type):
    """Helper class for BitField, not very useful on its own. Represents some
    bits of a Num.

    The @backing_num is used to know how to serialize/deserialize data in vm,
    but getting/setting this fields only affects bits from @bit_offset to
    @bit_offset + @bits. Masking and shifting is handled by the class, the aim
    is to provide a transparent way to set and get some bits of a num.
    """

    def __init__(self, backing_num, bits, bit_offset):
        if not isinstance(backing_num, Num):
            raise ValueError("backing_num should be a Num instance")
        self._num = backing_num
        self._bits = bits
        self._bit_offset = bit_offset

    def set(self, vm, addr, val):
        val_mask = (1 << self._bits) - 1
        val_shifted = (val & val_mask) << self._bit_offset
        num_size = self._num.size() * 8

        full_num_mask = (1 << num_size) - 1
        num_mask = (~(val_mask << self._bit_offset)) & full_num_mask

        num_val = self._num.get(vm, addr)
        res_val = (num_val & num_mask) | val_shifted
        self._num.set(vm, addr, res_val)

    def get(self, vm, addr):
        val_mask = (1 << self._bits) - 1
        num_val = self._num.get(vm, addr)
        res_val = (num_val >> self._bit_offset) & val_mask
        return res_val

    def size(self):
        return self._num.size()

    @property
    def bit_size(self):
        """Number of bits read/written by this class"""
        return self._bits

    @property
    def bit_offset(self):
        """Offset in bits (beginning at 0, the LSB) from which to read/write
        bits.
        """
        return self._bit_offset

    def __repr__(self):
        return "%s%r(%d:%d)" % (self.__class__.__name__, self._num,
                                self._bit_offset, self._bit_offset + self._bits)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and \
                self._num == other._num and self._bits == other._bits and \
                self._bit_offset == other._bit_offset

    def __hash__(self):
        return hash((self.__class__, self._num, self._bits, self._bit_offset))


class BitField(Union):
    """A C-like bitfield.

    Constructed with a list [(<field_name>, <number_of_bits>)] and a
    @backing_num. The @backing_num is a Num instance that determines the total
    size of the bitfield and the way the bits are serialized/deserialized (big
    endian int, little endian short...). Can be seen (and implemented) as a
    Union of Bits fields.

    Mapped to MemBitField.

    Creates fields that allow to access the bitfield fields easily. Example:

        class Example(MemStruct):
            fields = [("bf", BitField(Num("B"), [
                                ("f1", 2),
                                ("f2", 4),
                                ("f3", 1)
                             ])
                     )]

        ex = Example(vm, addr)
        ex.memset()
        ex.f2 = 2
        ex.f1 = 5 # 5 does not fit on two bits, it will be binarily truncated
        assert ex.f1 == 3
        assert ex.f2 == 2
        assert ex.f3 == 0 # previously memset()
        assert ex.bf == 3 + 2 << 2
    """

    def __init__(self, backing_num, bit_list):
        """@backing num: Num intance, @bit_list: [(name, n_bits)]"""
        self._num = backing_num
        fields = []
        offset = 0
        for name, bits in bit_list:
            fields.append((name, Bits(self._num, bits, offset)))
            offset += bits
        if offset > self._num.size() * 8:
            raise ValueError("sum of bit lengths is > to the backing num size")
        super(BitField, self).__init__(fields)

    def set(self, vm, addr, val):
        self._num.set(vm, addr, val)

    def _get_pinned_base_class(self):
        return MemBitField

    def __eq__(self, other):
        return self.__class__ == other.__class__ and \
                self._num == other._num and super(BitField, self).__eq__(other)

    def __hash__(self):
        return hash((super(BitField, self).__hash__(), self._num))

    def __repr__(self):
        fields_repr = ', '.join("%s: %r" % (name, field.bit_size)
                                for name, field in self.fields)
        return "%s(%s)" % (self.__class__.__name__, fields_repr)


class Str(Type):
    """A string type that handles encoding. This type is unsized (no static
    size).

    The @encoding is passed to the constructor, and is currently either null
    terminated "ansi" (latin1) or (double) null terminated "utf16". Be aware
    that the utf16 implementation is a bit buggy...

    Mapped to MemStr.
    """

    def __init__(self, encoding="ansi"):
        # TODO: encoding as lambda
        if encoding not in ["ansi", "utf16"]:
            raise NotImplementedError("Only 'ansi' and 'utf16' are implemented")
        self._enc = encoding

    def get(self, vm, addr):
        """Set the string value in memory"""
        if self._enc == "ansi":
            get_str = get_str_ansi
        elif self._enc == "utf16":
            get_str = get_str_utf16
        else:
            raise NotImplementedError("Only 'ansi' and 'utf16' are implemented")
        return get_str(vm, addr)

    def set(self, vm, addr, s):
        """Get the string value from memory"""
        if self._enc == "ansi":
            set_str = set_str_ansi
        elif self._enc == "utf16":
            set_str = set_str_utf16
        else:
            raise NotImplementedError("Only 'ansi' and 'utf16' are implemented")
        set_str(vm, addr, s)

    def size(self):
        """This type is unsized."""
        raise ValueError("Str is unsized")

    @property
    def enc(self):
        """This Str's encoding name (as a str)."""
        return self._enc

    def _get_pinned_base_class(self):
        return MemStr

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self.enc)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self._enc == other._enc

    def __hash__(self):
        return hash((self.__class__, self._enc))


class Void(Type):
    """Represents the C void type.
    
    Mapped to MemVoid.
    """

    def _build_pinned_type(self):
        return MemVoid

    def __eq__(self, other):
        return self.__class__ == other.__class__

    def __hash__(self):
        return hash(self.__class__)


class Self(Void):
    """Special marker to reference a type inside itself.
    
    Mapped to MemSelf.

    Example:
        class ListNode(MemStruct):
            fields = [
                ("next", Ptr("<I", Self())),
                ("data", Ptr("<I", Void())),
            ]
    """

    def _build_pinned_type(self):
        return MemSelf


# MemType classes

class _MetaMemType(type):
    def __repr__(cls):
        return cls.__name__


class _MetaMemStruct(_MetaMemType):
    """MemStruct metaclass. Triggers the magic that generates the class
    fields from the cls.fields list.

    Just calls MemStruct.gen_fields() if the fields class attribute has been
    set, the actual implementation can seen be there.
    """

    def __init__(cls, name, bases, dct):
        super(_MetaMemStruct, cls).__init__(name, bases, dct)
        if cls.fields is not None:
            cls.fields = tuple(cls.fields)
        # Am I able to generate fields? (if not, let the user do it manually
        # later)
        if cls.get_type() is not None or cls.fields is not None:
            cls.gen_fields()


class MemType(object):
    """Base class for classes that allow to map python objects to C types in
    virtual memory.

    Globally, MemTypes are not meant to be used directly: specialized
    subclasses are generated by Type(...).lval and should be used instead.
    The main exception is MemStruct, which you may want to subclass yourself
    for syntactic ease.
    """
    __metaclass__ = _MetaMemType

    _type = None

    def __init__(self, vm, addr=None, type_=None):
        global ALLOCATOR
        self._vm = vm
        if addr is None:
            if ALLOCATOR is None:
                raise ValueError("Cannot provide None address to MemType() if"
                                 "%s.set_allocator has not been called."
                                 % __name__)
            self._addr = ALLOCATOR(vm, self.get_size())
        else:
            self._addr = addr
        if type_ is not None:
            self._type = type_
        if self._type is None:
            raise ValueError("Subclass MemType and define cls._type or pass "
                             "a type to the constructor")

    def get_addr(self, field=None):
        """Return the address of this MemType or one of its fields.

        @field: (str, optional) used by subclasses to specify the name or index
            of the field to get the address of
        """
        if field is not None:
            raise NotImplementedError("Getting a field's address is not "
                                      "implemented for this class.")
        return self._addr

    @classmethod
    def get_type(cls):
        """Returns the Type subclass instance representing the C type of this
        MemType.
        """
        return cls._type

    @classmethod
    def sizeof(cls):
        """Return the static size of this type. By default, it is the size
        of the underlying Type.
        """
        return cls._type.size()

    def get_size(self):
        """Return the dynamic size of this structure (e.g. the size of an
        instance). Defaults to sizeof for this base class.

        For example, MemStr defines get_size but not sizeof, as an instance
        has a fixed size (at least its value has), but all the instance do not
        have the same size.
        """
        return self.sizeof()

    def memset(self, byte='\x00'):
        """Fill the memory space of this MemType with @byte ('\x00' by
        default). The size is retrieved with self.get_size() (dynamic size).
        """
        # TODO: multibyte patterns
        if not isinstance(byte, str) or not len(byte) == 1:
            raise ValueError("byte must be a 1-lengthed str")
        self._vm.set_mem(self.get_addr(), byte * self.get_size())

    def cast(self, other_type):
        """Cast this MemType to another MemType (same address, same vm,
        but different type). Return the casted MemType.

        @other_type: either a Type instance (other_type.lval is used) or a
            MemType subclass
        """
        if isinstance(other_type, Type):
            other_type = other_type.lval
        return other_type(self._vm, self.get_addr())

    def cast_field(self, field, other_type, *type_args, **type_kwargs):
        """ABSTRACT: Same as cast, but the address of the returned MemType
        is the address at which @field is in the current MemType.

        @field: field specification, for example its name for a struct, or an
            index in an array. See the subclass doc.
        @other_type: either a Type instance (other_type.lval is used) or a
            MemType subclass
        """
        raise NotImplementedError("Abstract")

    def raw(self):
        """Raw binary (str) representation of the MemType as it is in
        memory.
        """
        return self._vm.get_mem(self.get_addr(), self.get_size())

    def __len__(self):
        return self.get_size()

    def __str__(self):
        return self.raw()

    def __repr__(self):
        return "Mem%r" % self._type

    def __eq__(self, other):
        return self.__class__ == other.__class__ and \
                self.get_type() == other.get_type() and \
                str(self) == str(other)

    def __ne__(self, other):
        return not self == other


class MemValue(MemType):
    """Simple MemType that gets and sets the Type through the `.val`
    attribute.
    """

    @property
    def val(self):
        return self._type.get(self._vm, self._addr)

    @val.setter
    def val(self, value):
        self._type.set(self._vm, self._addr, value)

    def __repr__(self):
        return "%r: %r" % (self.__class__, self.val)


class MemStruct(MemType):
    """Base class to easily implement VmMngr backed C-like structures in miasm.
    Represents a structure in virtual memory.

    The mechanism is the following:
        - set a "fields" class field to be a list of
          (<field_name (str)>, <Type_subclass_instance>)
        - instances of this class will have properties to interract with these
          fields.

    Example:
        class MyStruct(MemStruct):
            fields = [
                # Scalar field: just struct.pack field with one value
                ("num", Num("I")),
                ("flags", Num("B")),
                # Ptr fields contain two fields: "val", for the numerical value,
                # and "deref" to get the pointed object
                ("other", Ptr("I", OtherStruct)),
                # Ptr to a variable length String
                ("s", Ptr("I", Str())),
                ("i", Ptr("I", Num("I"))),
            ]

        mstruct = MyStruct(vm, addr)

        # Field assignment modifies virtual memory
        mstruct.num = 3
        assert mstruct.num == 3
        memval = struct.unpack("I", vm.get_mem(mstruct.get_addr(),
                                                      4))[0]
        assert memval == mstruct.num

        # Memset sets the whole structure
        mstruct.memset()
        assert mstruct.num == 0
        mstruct.memset('\x11')
        assert mstruct.num == 0x11111111

        other = OtherStruct(vm, addr2)
        mstruct.other = other.get_addr()
        assert mstruct.other.val == other.get_addr()
        assert mstruct.other.deref == other
        assert mstruct.other.deref.foo == 0x1234

    Note that:
        MyStruct = Struct("MyStruct", <same fields>).lval
    is equivalent to the previous MyStruct declaration.

    See the various Type-s doc for more information. See MemStruct.gen_fields
    doc for more information on how to handle recursive types and cyclic
    dependencies.
    """
    __metaclass__ = _MetaMemStruct
    fields = None

    def get_addr(self, field_name=None):
        """
        @field_name: (str, optional) the name of the field to get the
            address of
        """
        if field_name is not None:
            offset = self._type.get_offset(field_name)
        else:
            offset = 0
        return self._addr + offset

    def get_field(self, name):
        """Get a field value by name.

        useless most of the time since fields are accessible via self.<name>.
        """
        return self._type.get_field(self._vm, self.get_addr(), name)

    def set_field(self, name, val):
        """Set a field value by name. @val is the python value corresponding to
        this field type.

        useless most of the time since fields are accessible via self.<name>.
        """
        return self._type.set_field(self._vm, self.get_addr(), name, val)

    def cast_field(self, field, other_type):
        """In this implementation, @field is a field name"""
        if isinstance(other_type, Type):
            other_type = other_type.lval
        return other_type(self._vm, self.get_addr(field))

    # Field generation method, voluntarily public to be able to gen fields
    # after class definition
    @classmethod
    def gen_fields(cls, fields=None):
        """Generate the fields of this class (so that they can be accessed with
        self.<field_name>) from a @fields list, as described in the class doc.

        Useful in case of a type cyclic dependency. For example, the following
        is not possible in python:

            class A(MemStruct):
                fields = [("b", Ptr("I", B))]

            class B(MemStruct):
                fields = [("a", Ptr("I", A))]

        With gen_fields, the following is the legal equivalent:

            class A(MemStruct):
                pass

            class B(MemStruct):
                fields = [("a", Ptr("I", A))]

            A.gen_fields([("b", Ptr("I", B))])
        """
        if fields is not None:
            if cls.fields is not None:
                raise ValueError("Cannot regen fields of a class. Setting "
                                 "cls.fields at class definition and calling "
                                 "gen_fields are mutually exclusive.")
            cls.fields = fields

        if cls._type is None:
            if cls.fields is None:
                raise ValueError("Cannot create a MemStruct subclass without"
                                 " a cls._type or a cls.fields")
            cls._type = cls._gen_type(cls.fields)

        if cls._type in DYN_MEM_STRUCT_CACHE:
            # FIXME: Maybe a warning would be better?
            raise RuntimeError("Another MemType has the same type as this "
                               "one. Use it instead.")

        # Register this class so that another one will not be created when
        # calling cls._type.lval
        DYN_MEM_STRUCT_CACHE[cls._type] = cls

        cls._gen_attributes()

    @classmethod
    def _gen_attributes(cls):
        # Generate self.<name> getter and setters
        for name, field in cls._type.fields:
            setattr(cls, name, property(
                lambda self, name=name: self.get_field(name),
                lambda self, val, name=name: self.set_field(name, val)
            ))

    @classmethod
    def _gen_type(cls, fields):
        return Struct(cls.__name__, fields)

    def __repr__(self):
        out = []
        for name, field in self._type.fields:
            val_repr = repr(self.get_field(name))
            if '\n' in val_repr:
                val_repr = '\n' + indent(val_repr, 4)
            out.append("%s: %r = %s" % (name, field, val_repr))
        return '%r:\n' % self.__class__ + indent('\n'.join(out), 2)


class MemUnion(MemStruct):
    """Same as MemStruct but all fields have a 0 offset in the struct."""
    @classmethod
    def _gen_type(cls, fields):
        return Union(fields)


class MemBitField(MemUnion):
    """MemUnion of Bits(...) fields."""
    @classmethod
    def _gen_type(cls, fields):
        return BitField(fields)


class MemSelf(MemStruct):
    """Special Marker class for reference to current class in a Ptr or Array
    (mostly Array of Ptr). See Self doc.
    """
    def __repr__(self):
        return self.__class__.__name__


class MemVoid(MemType):
    """Placeholder for e.g. Ptr to an undetermined type. Useful mostly when
    casted to another type. Allows to implement C's "void*" pattern.
    """
    _type = Void()

    def __repr__(self):
        return self.__class__.__name__


class MemPtr(MemValue):
    """Mem version of a Ptr, provides two properties:
        - val, to set and get the numeric value of the Ptr
        - deref, to set and get the pointed type
    """
    @property
    def val(self):
        return self._type.get_val(self._vm, self._addr)

    @val.setter
    def val(self, value):
        return self._type.set_val(self._vm, self._addr, value)

    @property
    def deref(self):
        return self._type.deref_get(self._vm, self._addr)

    @deref.setter
    def deref(self, val):
        return self._type.deref_set(self._vm, self._addr, val)

    def __repr__(self):
        return "*%s" % hex(self.val)


class MemStr(MemValue):
    """Implements a string representation in memory.

    The string value can be got or set (with python str/unicode) through the
    self.val attribute. String encoding/decoding is handled by the class,

    This type is dynamically sized only (get_size is implemented, not sizeof).
    """

    def get_size(self):
        """This get_size implementation is quite unsafe: it reads the string
        underneath to determine the size, it may therefore read a lot of memory
        and provoke mem faults (analogous to strlen).
        """
        val = self.val
        if self.get_type().enc == "ansi":
            return len(val) + 1
        elif self.get_type().enc == "utf16":
            # FIXME: real encoding...
            return len(val) * 2 + 2
        else:
            raise NotImplementedError("Only 'ansi' and 'utf16' are implemented")

    def raw(self):
        raw = self._vm.get_mem(self.get_addr(), self.get_size())
        return raw

    def __repr__(self):
        return "%r: %r" % (self.__class__, self.val)


class MemArray(MemType):
    """An unsized array of type @field_type (a Type subclass instance).
    This class has no static or dynamic size.

    It can be indexed for setting and getting elements, example:

        array = Array(Num("I")).lval(vm, addr))
        array[2] = 5
        array[4:8] = [0, 1, 2, 3]
        print array[20]
    """

    @property
    def field_type(self):
        """Return the Type subclass instance that represents the type of
        this MemArray items.
        """
        return self.get_type().field_type

    def get_addr(self, idx=0):
        return self._addr + self.get_type().get_offset(idx)

    def __getitem__(self, idx):
        return self.get_type().get_item(self._vm, self._addr, idx)

    def __setitem__(self, idx, item):
        self.get_type().set_item(self._vm, self._addr, idx, item)

    def raw(self):
        raise ValueError("%s is unsized, which prevents from getting its full "
                         "raw representation. Use MemSizedArray instead." %
                         self.__class__)

    def __repr__(self):
        return "[%r, ...] [%r]" % (self[0], self.field_type)


class MemSizedArray(MemArray):
    """A fixed size MemArray.

    This type is dynamically sized. Generate a fixed @field_type and @array_len
    array which has a static size by using Array(type, size).lval.
    """

    @property
    def array_len(self):
        """The length, in number of elements, of this array."""
        return self.get_type().array_len

    def get_size(self):
        return self.get_type().size()

    def __iter__(self):
        for i in xrange(self.get_type().array_len):
            yield self[i]

    def raw(self):
        return self._vm.get_mem(self.get_addr(), self.get_size())

    def __repr__(self):
        item_reprs = [repr(item) for item in self]
        if self.array_len > 0 and '\n' in item_reprs[0]:
            items = '\n' + indent(',\n'.join(item_reprs), 2) + '\n'
        else:
            items = ', '.join(item_reprs)
        return "[%s] [%r; %s]" % (items, self.field_type, self.array_len)

