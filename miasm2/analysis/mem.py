"""This module provides classes to manipulate C structures backed by a VmMngr
object (a miasm VM virtual memory).

The main idea is to declare the fields of the structure in the class:

    # FIXME: "I" => "u32"
    class MyStruct(MemStruct):
        fields = [
            # Integer field: just struct.pack fields with one value
            ("num", Num("I")),
            ("flags", Num("B")),
            # Ptr fields are Num, but they can also be dereferenced
            # (self.deref_<field>). Deref can be read and set.
            ("other", Ptr("I", OtherStruct)),
            # Ptr to a variable length String
            ("s", Ptr("I", MemStr)),
            ("i", Ptr("I", Num("I"))),
        ]

And access the fields:

    mstruct = MyStruct(jitter.vm, addr)
    mstruct.num = 3
    assert mstruct.num == 3
    mstruct.other = addr2
    mstruct.deref_other = OtherStruct(jitter.vm, addr)

The `addr` argument can be omited if an allocator is set, in which case the
structure will be automatically allocated in memory:

    my_heap = miasm2.os_dep.common.heap()
    set_allocator(my_heap)

Note that some structures (e.g. MemStr or MemArray) do not have a static size
and cannot be allocated automatically.


As you saw previously, to use this module, you just have to inherit from
MemStruct and define a list of (<field_name>, <field_definition>). Availabe
MemField classes are:

    - Num: for number (float or int) handling
    - Struct: abstraction over a simple struct pack/unpack
    - Ptr: a pointer to another MemStruct instance
    - Inline: include another MemStruct as a field (equivalent to having a
      struct field into another struct in C)
    - Array: a fixed size array of MemFields (points)
    - Union: similar to `union` in C, list of MemFields at the same offset in a
      structure; the union has the size of the biggest MemField
    - BitField: similar to C bitfields, a list of
      [(<field_name), (number_of_bits)]; creates fields that correspond to
      certain bits of the field

A MemField always has a fixed size in memory.


Some special memory structures are already implemented; they all are subclasses
of MemStruct with a custom implementation:

    - MemSelf: this class is just a special marker to reference a MemStruct
      subclass inside itself. Works with Ptr and Array (e.g. Ptr(_, MemSelf)
      for a pointer the same type as the class who uses this kind of field)
    - MemVoid: empty MemStruct, placeholder to be casted to an implemented
      MemStruct subclass
    - MemStr: represents a string in memory; the encoding can be passed to the
      constructor (null terminated ascii/ansi or null terminated utf16)
    - MemArray: an unsized array of MemField; unsized here means that there is
      no defined sized for this array, equivalent to a int* or char*-style table
      in C. It cannot be allocated automatically, since it has no known size
    - MemSizedArray: a sized MemArray, can be automatically allocated in memory
      and allows more operations than MemArray
    - mem: a function that dynamically generates a MemStruct subclass from a
      MemField. This class has only one field named "value".

A MemStruct do not always have a static size (cls.sizeof()) nor a dynamic size
(self.get_size()).
"""

import logging
import struct

log = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)

# allocator is a function(vm, size) -> allocated_address
allocator = None

def set_allocator(alloc_func):
    """Sets an allocator for this module; allows to instanciate statically sized
    MemStructs (i.e. sizeof() is implemented) without specifying the address
    (the object is allocated by @alloc_func in the vm.

    Args:
        alloc_func: func(VmMngr) -> integer_address
    """
    global allocator
    allocator = alloc_func


# Helpers

def indent(s, size=4):
    """Indents a string with @size spaces"""
    return ' '*size + ('\n' + ' '*size).join(s.split('\n'))


# FIXME: copied from miasm2.os_dep.common and fixed
def get_str_ansi(vm, addr, max_char=None):
    """Gets a null terminated ANSI encoded string from a VmMngr.

    Args:
        vm: VmMngr instance
        max_char: max number of characters to get in memory
    """
    l = 0
    tmp = addr
    while ((max_char is None or l < max_char) and
           vm.get_mem(tmp, 1) != "\x00"):
        tmp += 1
        l += 1
    return vm.get_mem(addr, l)


# TODO: get_raw_str_utf16 for length calculus
def get_str_utf16(vm, addr, max_char=None):
    """Gets a (double) null terminated utf16 little endian encoded string from
    a VmMngr. This encoding is mainly used in Windows.

    FIXME: the implementation do not work with codepoints that are encoded on
    more than 2 bytes in utf16.

    Args:
        vm: VmMngr instance
        max_char: max number of bytes to get in memory
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
    """Encodes a string to null terminated ascii/ansi and sets it in a VmMngr
    memory.

    Args:
        vm: VmMngr instance
        addr: start address to serialize the string to
        s: the str to serialize
    """
    vm.set_mem(addr, s + "\x00")


def set_str_utf16(vm, addr, s):
    """Same as set_str_ansi with (double) null terminated utf16 encoding."""
    s = (s + '\x00').encode('utf-16le')
    vm.set_mem(addr, s)


# MemField to MemStruct helper

# TODO: cache generated types
def mem(field):
    """Generates a MemStruct subclass from a field. The field's value can
    be accessed through self.value or self.deref_value if field is a Ptr.
    """
    fields = [("value", field)]
    # Build a type to contain the field type
    mem_type = type("Mem%r" % field, (MemStruct,), {'fields': fields})
    return mem_type


# MemField classes

class MemField(object):
    """Base class to provide methods to set and get fields from virtual mem.

    Subclasses can either override _pack and _unpack, or get and set if data
    serialization requires more work (see Inline implementation for an example).
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

        Args:
            vm: VmMngr instance
            addr: the start adress in memory to set
            val: the python value to serialize in @vm at @addr
        """
        raw = self._pack(val)
        vm.set_mem(addr, raw)

    def get(self, vm, addr):
        """Get the python value of a field from a VmMngr memory at @addr."""
        raw = vm.get_mem(addr, self.size())
        return self._unpack(raw)

    def _get_self_type(self):
        return self._self_type

    def _set_self_type(self, self_type):
        """If this field refers to MemSelf, replace it with @self_type (a
        MemStruct subclass) when using it. Generally not used outside the lib.
        """
        self._self_type = self_type

    def size(self):
        """Returns the size in bytes of the serialized version of this field"""
        raise NotImplementedError()

    def __len__(self):
        return self.size()


class Struct(MemField):
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


class Num(Struct):
    """Represents a number (integer or float). The number is encoded with
    a struct-style format which must represent only one value.

    TODO: use u32, i16, etc. for format.
    """

    def _pack(self, number):
        return super(Num, self)._pack([number])

    def _unpack(self, raw_str):
        upck = super(Num, self)._unpack(raw_str)
        if len(upck) > 1:
            raise ValueError("Num format string unpacks to multiple values, "
                             "should be 1")
        return upck[0]


class Ptr(Num):
    """Special case of number of which value indicates the address of a
    MemStruct. Provides deref_<field> as well as <field> when used, to set and
    get the pointed MemStruct.
    """

    def __init__(self, fmt, dst_type, *type_args, **type_kwargs):
        if not isinstance(dst_type, MemField) and\
                not (isinstance(dst_type, type) and\
                        issubclass(dst_type, MemStruct)) and\
                not dst_type == MemSelf:
            raise ValueError("dst_type of Ptr must be a MemStruct type, a "
                             "MemField instance, the MemSelf marker or a class "
                             "name.")
        super(Ptr, self).__init__(fmt)
        if isinstance(dst_type, MemField):
            # Patch the field to propagate the MemSelf replacement
            dst_type._get_self_type = lambda: self._get_self_type()
            dst_type = mem(dst_type)
        self._dst_type = dst_type
        self._type_args = type_args
        self._type_kwargs = type_kwargs

    def _fix_dst_type(self):
        if self._dst_type == MemSelf:
            if self._get_self_type() is not None:
                self._dst_type = self._get_self_type()
            else:
                raise ValueError("Unsupported usecase for MemSelf, sorry")

    @property
    def dst_type(self):
        """Returns the type (MemStruct subtype) this Ptr points to."""
        self._fix_dst_type()
        return self._dst_type

    def deref_get(self, vm, addr):
        """Deserializes the data in @vm (VmMngr) at @addr to self.dst_type.
        Equivalent to a pointer dereference rvalue in C.
        """
        return self.dst_type(vm, addr, *self._type_args, **self._type_kwargs)

    def deref_set(self, vm, addr, val):
        """Serializes the @val MemStruct subclass instance in @vm (VmMngr) at
        @addr. Equivalent to a pointer dereference assignment in C.
        """
        # Sanity check
        if self.dst_type != val.__class__:
            log.warning("Original type was %s, overriden by value of type %s",
                        self._dst_type.__name__, val.__class__.__name__)

        # Actual job
        vm.set_mem(addr, str(val))

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self._dst_type)


class Inline(MemField):
    """Field used to inline a MemStruct in another MemStruct. Equivalent to
    having a struct field in a C struct.

    Concretely:

        class MyStructClass(MemStruct):
            fields = [("f1", Num("I")), ("f2", Num("I"))]

        class Example(MemStruct):
            fields = [("mystruct", Inline(MyStructClass))]

        ex = Example(vm, addr)
        ex.mystruct.f2 = 3 # inlined structure field access
        ex.mystruct = MyStructClass(vm, addr2) # struct copy

    It can be seen like a bridge to use a MemStruct as a MemField

    TODO: make the Inline implicit when setting a field to be a MemStruct
    """

    def __init__(self, inlined_type, *type_args, **type_kwargs):
        if not issubclass(inlined_type, MemStruct):
            raise ValueError("inlined type if Inline must be a MemStruct")
        self._il_type = inlined_type
        self._type_args = type_args
        self._type_kwargs = type_kwargs

    def set(self, vm, addr, val):
        raw = str(val)
        vm.set_mem(addr, raw)

    def get(self, vm, addr):
        return self._il_type(vm, addr)

    def size(self):
        return self._il_type.sizeof()

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self._il_type)


class Array(MemField):
    """A fixed size array (contiguous sequence) of a MemField subclass
    elements. Similar to something like the char[10] type in C.

    Getting an array field actually returns a MemSizedArray. Setting it is
    possible with either a list or a MemSizedArray instance. Examples of syntax:

        class Example(MemStruct):
            fields = [("array", Array(Num("B"), 4))]

        mystruct = Example(vm, addr)
        mystruct.array[3] = 27
        mystruct.array = [1, 4, 8, 9]
        mystruct.array = MemSizedArray(vm, addr2, Num("B"), 4)
    """

    def __init__(self, field_type, length):
        self._field_type = field_type
        self._array_len = length

    def _set_self_type(self, self_type):
        super(Array, self)._set_self_type(self_type)
        self._field_type._set_self_type(self_type)

    def set(self, vm, addr, val):
        # MemSizedArray assignment
        if isinstance(val, MemSizedArray):
            if val.array_len != self._array_len or len(val) != self.size():
                raise ValueError("Size mismatch in MemSizedArray assignment")
            raw = str(val)
            vm.set_mem(addr, raw)

        # list assignment
        elif isinstance(val, list):
            if len(val) != self._array_len:
                raise ValueError("Size mismatch in MemSizedArray assignment ")
            offset = 0
            for elt in val:
                self._field_type.set(vm, addr + offset, elt)
                offset += self._field_type.size()

        else:
            raise NotImplementedError(
                    "Assignment only implemented for list and MemSizedArray")

    def get(self, vm, addr):
        return MemSizedArray(vm, addr, self._field_type, self._array_len)

    def size(self):
        return self._field_type.size() * self._array_len

    def __repr__(self):
        return "%r[%s]" % (self._field_type, self._array_len)


class Union(MemField):
    """Allows to put multiple fields at the same offset in a MemStruct, similar
    to unions in C. The Union will have the size of the largest of its fields.

    Example:

        class Example(MemStruct):
            fields = [("uni", Union([
                                  ("f1", Num("<B")),
                                  ("f2", Num("<H"))
                              ])
                     )]

        ex = Example(vm, addr)
        ex.f2 = 0x1234
        assert ex.f1 == 0x34
        assert ex.uni == '\x34\x12'
        assert ex.get_addr("f1") == ex.get_addr("f2")
    """

    def __init__(self, field_list):
        """field_list is a [(name, field)] list, see the class doc"""
        self.field_list = field_list

    def size(self):
        return max(field.size() for _, field in self.field_list)

    def set(self, vm, addr, val):
        if not isinstance(val, str) or not len(str) == self.size():
            raise ValueError("Union can only be set with raw str of the Union's"
                             " size")
        vm.set_mem(vm, addr, val)

    def get(self, vm, addr):
        return vm.get_mem(addr, self.size())

    def __repr__(self):
        fields_repr = ', '.join("%s: %r" % (name, field)
                                for name, field in self.field_list)
        return "%s(%s)" % (self.__class__.__name__, fields_repr)


class Bits(MemField):
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

class BitField(Union):
    """A C-like bitfield.

    Constructed with a list [(<field_name>, <number_of_bits>)] and a
    @backing_num. The @backing_num is a Num instance that determines the total
    size of the bitfield and the way the bits are serialized/deserialized (big
    endian int, little endian short...). Can be seen (and implemented) as a
    Union of Bits fields.

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

    def get(self, vm, addr):
        return self._num.get(vm, addr)


# MemStruct classes

class _MetaMemStruct(type):

    def __init__(cls, name, bases, dct):
        super(_MetaMemStruct, cls).__init__(name, bases, dct)
        cls.gen_fields()

    def __repr__(cls):
        return cls.__name__


class MemStruct(object):
    __metaclass__ = _MetaMemStruct

    fields = []

    _size = None

    # Classic usage methods

    def __init__(self, vm, addr=None, *args, **kwargs):
        global allocator
        super(MemStruct, self).__init__(*args, **kwargs)
        self._vm = vm
        if addr is None:
            if allocator is None:
                raise ValueError("Cannot provide None address to MemStruct() if"
                                 "%s.allocator is not set." % __name__)
            self._addr = allocator(vm, self.get_size())
        else:
            self._addr = addr

    def get_addr(self, field_name=None):
        if field_name is not None:
            offset = self._attrs[field_name]['offset']
        else:
            offset = 0
        return self._addr + offset

    @classmethod
    def sizeof(cls):
        if cls._size is None:
            return sum(a["field"].size() for a in cls._attrs.itervalues())
        return cls._size

    def get_size(self):
        return self.sizeof()

    def get_field_type(self, name):
        return self._attrs[name]['field']

    def get_attr(self, attr):
        if attr not in self._attrs:
            raise AttributeError("'%s' object has no attribute '%s'"
                                 % (self.__class__.__name__, attr))
        field = self._attrs[attr]["field"]
        offset = self._attrs[attr]["offset"]
        return field.get(self._vm, self.get_addr() + offset)

    def set_attr(self, attr, val):
        if attr not in self._attrs:
            raise AttributeError("'%s' object has no attribute '%s'"
                                 % (self.__class__.__name__, attr))
        field = self._attrs[attr]["field"]
        offset = self._attrs[attr]["offset"]
        field.set(self._vm, self.get_addr() + offset, val)

    def deref_attr(self, attr):
        addr = self.get_attr(attr)
        field = self._attrs[attr]["field"]
        assert isinstance(field, Ptr),\
               "Programming error: field should be a Ptr"
        return field.deref_get(self._vm, addr)

    def set_deref_attr(self, attr, val):
        addr = self.get_attr(attr)
        field = self._attrs[attr]["field"]
        assert isinstance(field, Ptr),\
               "Programming error: field should be a Ptr"
        field.deref_set(self._vm, addr, val)

    def memset(self, byte='\x00'):
        """memset(0)"""
        if not isinstance(byte, str) or not len(byte) == 1:
            raise ValueError("byte must be a 1-lengthed str")
        self._vm.set_mem(self.get_addr(), byte * self.get_size())

    def cast(self, other_type, *type_args, **type_kwargs):
        return self.cast_field(None, other_type, *type_args, **type_kwargs)

    def cast_field(self, field_name, other_type, *type_args, **type_kwargs):
        return other_type(self._vm, self.get_addr(field_name),
                          *type_args, **type_kwargs)

    def __len__(self):
        return self.get_size()

    def __str__(self):
        attrs = sorted(self._attrs.itervalues(), key=lambda a: a["offset"])
        out = []
        for attr in attrs:
            field = attr["field"]
            offset = attr["offset"]
            out.append(self._vm.get_mem(self.get_addr() + offset, field.size()))
        return ''.join(out)

    def __repr__(self):
        attrs = sorted(self._attrs.iteritems(), key=lambda a: a[1]["offset"])
        out = []
        for name, attr in attrs:
            field = attr["field"]
            val_repr = repr(self.get_attr(name))
            if '\n' in val_repr:
                val_repr = '\n' + indent(val_repr, 4)
            out.append("%s: %r = %s" % (name, field, val_repr))
        return '%r:\n' % self.__class__ + indent('\n'.join(out), 2)

    def __eq__(self, other):
        # Do not test class equality, because of dynamically generated fields
        # self.__class__ == other.__class__ and
        # Could test attrs?
        # TODO: self._attrs == other._attrs and
        return str(self) == str(other)

    def __ne__(self, other):
        return not (self == other)

    # Field generation methods, voluntarily public

    @classmethod
    def gen_fields(cls, fields=None):
        if fields is None:
            fields = cls.fields
        cls._attrs = {}
        offset = 0
        for name, field in cls.fields:
            # For reflexion
            field._set_self_type(cls)
            cls.gen_attr(name, field, offset)
            offset += field.size()
        cls._size = offset

    @classmethod
    def gen_attr(cls, name, field, offset):
        # FIXME: move to gen_simple_arg?
        cls._attrs[name] = {"field": field, "offset": offset}
        cls._gen_simple_attr(name, field, offset)
        if isinstance(field, Union):
            cls._gen_union_attr(field, offset)

    @classmethod
    def _gen_simple_attr(cls, name, field, offset):
        # Generate self.<name> getter and setter
        setattr(cls, name, property(
            # default parameter allow to bind the value of name for a given
            # loop iteration
            lambda self, name=name: self.get_attr(name),
            lambda self, val, name=name: self.set_attr(name, val)
        ))

        # Generate self.deref_<name> getter and setter if this field is a
        # Ptr
        if isinstance(field, Ptr):
            setattr(cls, "deref_%s" % name, property(
                lambda self, name=name: self.deref_attr(name),
                lambda self, val, name=name: self.set_deref_attr(name, val)
            ))

    @classmethod
    def _gen_union_attr(cls, union_field, offset):
        if not isinstance(union_field, Union):
            raise ValueError("field should be an Union instance")
        for name, field in union_field.field_list:
            cls.gen_attr(name, field, offset)


class MemSelf(MemStruct):
    """Special Marker class for reference to current class in a Ptr."""
    pass


class MemVoid(MemStruct):
    def __repr__(self):
        return self.__class__.__name__


# This does not use _MetaMemStruct features, impl is custom for strings,
# because they are unsized. The only memory field is self.value.
class MemStr(MemStruct):
    def __init__(self, vm, addr, encoding="ansi"):
        # TODO: encoding as lambda
        if encoding not in ["ansi", "utf16"]:
            raise NotImplementedError("Only 'ansi' and 'utf16' are implemented")
        super(MemStr, self).__init__(vm, addr)
        self._enc = encoding

    @property
    def value(self):
        if self._enc == "ansi":
            get_str = get_str_ansi
        elif self._enc == "utf16":
            get_str = get_str_utf16
        else:
            raise NotImplementedError("Only 'ansi' and 'utf16' are implemented")
        return get_str(self._vm, self.get_addr())

    @value.setter
    def value(self, s):
        if self._enc == "ansi":
            set_str = set_str_ansi
        elif self._enc == "utf16":
            set_str = set_str_utf16
        else:
            raise NotImplementedError("Only 'ansi' and 'utf16' are implemented")
        set_str(self._vm, self.get_addr(), s)

    def get_size(self):
        """FIXME Quite unsafe: it reads the string underneath to determine the
        size
        """
        val = self.value
        if self._enc == "ansi":
            return len(val) + 1
        elif self._enc == "utf16":
            # FIXME: real encoding...
            return len(val) * 2 + 2
        else:
            raise NotImplementedError("Only 'ansi' and 'utf16' are implemented")

    def __str__(self):
        raw = self._vm.get_mem(self.get_addr(), self.get_size())
        return raw

    def __repr__(self):
        return "%r(%s): %r" % (self.__class__, self._enc, self.value)


class MemArray(MemStruct):
    _field_type = None

    def __init__(self, vm, addr=None, field_type=None):
        if self._field_type is None:
            self._field_type = field_type
        if self._field_type is None:
            raise NotImplementedError(
                    "Provide field_type to instanciate this class, "
                    "or generate a subclass with mem_array_type.")
        super(MemArray, self).__init__(vm, addr)

    @property
    def field_type(self):
        return self._field_type

    def _normalize_idx(self, idx):
        # Noop for this type
        return idx

    def _normalize_slice(self, slice_):
        start = slice_.start if slice_.start is not None else 0
        stop = slice_.stop if slice_.stop is not None else self.get_size()
        step = slice_.step if slice_.step is not None else 1
        return slice(start, stop, step)

    def _check_bounds(self, idx):
        idx = self._normalize_idx(idx)
        if not isinstance(idx, int) and not isinstance(idx, long):
            raise ValueError("index must be an int or a long")
        if idx < 0:
            raise IndexError("Index %s out of bounds" % idx)

    def index2addr(self, idx):
        self._check_bounds(idx)
        addr = self.get_addr() + idx * self._field_type.size()
        return addr

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            res = []
            idx = self._normalize_slice(idx)
            for i in xrange(idx.start, idx.stop, idx.step):
                res.append(self._field_type.get(self._vm, self.index2addr(i)))
            return res
        else:
            return self._field_type.get(self._vm, self.index2addr(idx))

    def deref_get(self, idx):
        return self._field_type.deref_get(self._vm, self[idx])

    def __setitem__(self, idx, item):
        if isinstance(idx, slice):
            idx = self._normalize_slice(idx)
            if len(item) != len(xrange(idx.start, idx.stop, idx.step)):
                raise ValueError("Mismatched lengths in slice assignment")
            for i, val in zip(xrange(idx.start, idx.stop, idx.step), item):
                self._field_type.set(self._vm, self.index2addr(i), val)
        else:
            self._field_type.set(self._vm, self.index2addr(idx), item)

    def deref_set(self, idx, item):
        self._field_type.deref_set(self._vm, self[idx], item)

    # just a shorthand
    def as_mem_str(self, encoding="ansi"):
        return self.cast(MemStr, encoding)

    @classmethod
    def sizeof(cls):
        raise ValueError("%s is unsized, which makes some operations"
                         " impossible. Use MemSizedArray instead.")

    def __str__(self):
        raise ValueError("%s is unsized, which makes some operations"
                         " impossible. Use MemSizedArray instead.")

    def __repr__(self):
        return "[%r, ...] [%r]" % (self[0], self._field_type)


def mem_array_type(field_type):
    array_type = type('MemArray_%r' % (field_type,),
                      (MemArray,),
                      {'_field_type': field_type})
    return array_type


class MemSizedArray(MemArray):
    _array_len = None

    def __init__(self, vm, addr=None, field_type=None, length=None):
        # Set the length before anything else to allow get_size() to work for
        # allocation
        if self._array_len is None:
            self._array_len = length
        super(MemSizedArray, self).__init__(vm, addr, field_type)
        if self._array_len is None or self._field_type is None:
            raise NotImplementedError(
                    "Provide field_type and length to instanciate this class, "
                    "or generate a subclass with mem_sized_array_type.")

    @property
    def array_len(self):
        return self._array_len

    def sizeof(cls):
        raise ValueError("MemSizedArray is not statically sized. Use "
                         "mem_sized_array_type to generate a type that is.")

    def get_size(self):
        return self._array_len * self._field_type.size()

    def _normalize_idx(self, idx):
        if idx < 0:
            return self.get_size() - idx
        return idx

    def _check_bounds(self, idx):
        if not isinstance(idx, int) and not isinstance(idx, long):
            raise ValueError("index must be an int or a long")
        if idx < 0 or idx >= self.get_size():
            raise IndexError("Index %s out of bounds" % idx)

    def __iter__(self):
        for i in xrange(self._array_len):
            yield self[i]

    def __str__(self):
        return self._vm.get_mem(self.get_addr(), self.get_size())

    def __repr__(self):
        item_reprs = [repr(item) for item in self]
        if self.array_len > 0 and '\n' in item_reprs[0]:
            items = '\n' + indent(',\n'.join(item_reprs), 2) + '\n'
        else:
            items = ', '.join(item_reprs)
        return "[%s] [%r; %s]" % (items, self._field_type, self._array_len)


def mem_sized_array_type(field_type, length):
    @classmethod
    def sizeof(cls):
        return cls._field_type.size() * cls._array_len

    array_type = type('MemSizedArray_%r_%s' % (field_type, length),
                      (MemSizedArray,),
                      {'_array_len': length,
                       '_field_type': field_type,
                       'sizeof': sizeof})
    return array_type


# IDEA: func_args_* functions could return a dynamically generated MemStruct
# class instance
