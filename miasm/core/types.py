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

The `addr` argument can be omitted if an allocator is set, in which case the
structure will be automatically allocated in memory:

    my_heap = miasm.os_dep.common.heap()
    # the allocator is a func(VmMngr) -> integer_address
    set_allocator(my_heap)

Note that some structures (e.g. MemStr or MemArray) do not have a static
size and cannot be allocated automatically.
"""

from builtins import range, zip
from builtins import int as int_types
import itertools
import logging
import struct
from future.utils import PY3
from future.utils import viewitems, with_metaclass

log = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)

# Cache for dynamically generated MemTypes
DYN_MEM_STRUCT_CACHE = {}

def set_allocator(alloc_func):
    """Shorthand to set the default allocator of MemType. See
    MemType.set_allocator doc for more information.
    """
    MemType.set_allocator(alloc_func)


# Helpers

def to_type(obj):
    """If possible, return the Type associated with @obj, otherwise raises
    a ValueError.

    Works with a Type instance (returns obj) or a MemType subclass or instance
    (returns obj.get_type()).
    """
    # obj is a python type
    if isinstance(obj, type):
        if issubclass(obj, MemType):
            if obj.get_type() is None:
                raise ValueError("%r has no static type; use a subclasses "
                                 "with a non null _type or use a "
                                 "Type instance" % obj)
            return obj.get_type()
    # obj is not not a type
    else:
        if isinstance(obj, Type):
            return obj
        elif isinstance(obj, MemType):
            return obj.get_type()
    raise ValueError("%r is not a Type or a MemType" % obj)

def indent(s, size=4):
    """Indent a string with @size spaces"""
    return ' '*size + ('\n' + ' '*size).join(s.split('\n'))


# String generic getter/setter/len-er
# TODO: make miasm.os_dep.common and jitter ones use these ones

def get_str(vm, addr, enc, max_char=None, end=u'\x00'):
    """Get a @end (by default '\\x00') terminated @enc encoded string from a
    VmMngr.

    For example:
        - get_str(vm, addr, "ascii") will read "foo\\x00" in memory and
          return u"foo"
        - get_str(vm, addr, "utf-16le") will read "f\\x00o\\x00o\\x00\\x00\\x00"
          in memory and return u"foo" as well.

    Setting @max_char=<n> and @end='' allows to read non null terminated strings
    from memory.

    @vm: VmMngr instance
    @addr: the address at which to read the string
    @enc: the encoding of the string to read.
    @max_char: max number of bytes to get in memory
    @end: the unencoded ending sequence of the string, by default "\\x00".
        Unencoded here means that the actual ending sequence that this function
        will look for is end.encode(enc), not directly @end.
    """
    s = []
    end_char= end.encode(enc)
    step = len(end_char)
    i = 0
    while max_char is None or i < max_char:
        c = vm.get_mem(addr + i, step)
        if c == end_char:
            break
        s.append(c)
        i += step
    return b''.join(s).decode(enc)

def raw_str(s, enc, end=u'\x00'):
    """Returns a string representing @s as an @end (by default \\x00)
    terminated @enc encoded string.

    @s: the unicode str to serialize
    @enc: the encoding to apply to @s and @end before serialization.
    @end: the ending string/character to append to the string _before encoding_
        and serialization (by default '\\x00')
    """
    return (s + end).encode(enc)

def set_str(vm, addr, s, enc, end=u'\x00'):
    """Encode a string to an @end (by default \\x00) terminated @enc encoded
    string and set it in a VmMngr memory.

    @vm: VmMngr instance
    @addr: start address to serialize the string to
    @s: the unicode str to serialize
    @enc: the encoding to apply to @s and @end before serialization.
    @end: the ending string/character to append to the string _before encoding_
        and serialization (by default '\\x00')
    """
    s = raw_str(s, enc, end=end)
    vm.set_mem(addr, s)

def raw_len(py_unic_str, enc, end=u'\x00'):
    """Returns the length in bytes of @py_unic_str in memory (once @end has been
    added and the full str has been encoded). It returns exactly the room
    necessary to call set_str with similar arguments.

    @py_unic_str: the unicode str to work with
    @enc: the encoding to encode @py_unic_str to
    @end: the ending string/character to append to the string _before encoding_
        (by default \\x00)
    """
    return len(raw_str(py_unic_str, enc))

def enc_triplet(enc, max_char=None, end=u'\x00'):
    """Returns a triplet of functions (get_str_enc, set_str_enc, raw_len_enc)
    for a given encoding (as needed by Str to add an encoding). The prototypes
    are:

        - get_str_end: same as get_str without the @enc argument
        - set_str_end: same as set_str without the @enc argument
        - raw_len_enc: same as raw_len without the @enc argument
    """
    return (
        lambda vm, addr, max_char=max_char, end=end: \
                get_str(vm, addr, enc, max_char=max_char, end=end),
        lambda vm, addr, s, end=end: set_str(vm, addr, s, enc, end=end),
        lambda s, end=end: raw_len(s, enc, end=end),
    )


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
        @addr: the start address in memory to set
        @val: the python value to serialize in @vm at @addr
        """
        raw = self._pack(val)
        vm.set_mem(addr, raw)

    def get(self, vm, addr):
        """Get the python value of a field from a VmMngr memory at @addr."""
        raw = vm.get_mem(addr, self.size)
        return self._unpack(raw)

    @property
    def lval(self):
        """Returns a class with a (vm, addr) constructor that allows to
        interact with this type in memory.

        In compilation terms, it returns a class allowing to instantiate an
        lvalue of this type.

        @return: a MemType subclass.
        """
        if self in DYN_MEM_STRUCT_CACHE:
            return DYN_MEM_STRUCT_CACHE[self]
        pinned_type = self._build_pinned_type()
        DYN_MEM_STRUCT_CACHE[self] = pinned_type
        return pinned_type

    def _build_pinned_type(self):
        """Builds the MemType subclass allowing to interact with this type.

        Called by self.lval when it is not in cache.
        """
        pinned_base_class = self._get_pinned_base_class()
        pinned_type = type(
            "Mem%r" % self,
            (pinned_base_class,),
            {'_type': self}
        )
        return pinned_type

    def _get_pinned_base_class(self):
        """Return the MemType subclass that maps this type in memory"""
        return MemValue

    def _get_self_type(self):
        """Used for the Self trick."""
        return self._self_type

    def _set_self_type(self, self_type):
        """If this field refers to MemSelf/Self, replace it with @self_type
        (a Type instance) when using it. Generally not used outside this
        module.
        """
        self._self_type = self_type

    @property
    def size(self):
        """Return the size in bytes of the serialized version of this field"""
        raise NotImplementedError()

    def __len__(self):
        return self.size

    def __neq__(self, other):
        return not self == other

    def __eq__(self, other):
        raise NotImplementedError("Abstract method")

    def __ne__(self, other):
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

    @property
    def size(self):
        return struct.calcsize(self._fmt)

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, self._fmt)

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self._fmt == other._fmt

    def __ne__(self, other):
        return not self == other

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
        @dst_type: (MemType or Type) the Type this Ptr points to.
            If a Type is given, it is transformed into a MemType with
            TheType.lval.
        *type_args, **type_kwargs: arguments to pass to the the pointed
            MemType when instantiating it (e.g. for MemStr encoding or
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
        if self._dst_type in [MemSelf, SELF_TYPE_INSTANCE]:
            if self._get_self_type() is not None:
                self._dst_type = self._get_self_type()
            else:
                raise ValueError("Unsupported usecase for (Mem)Self, sorry")
        self._dst_type = to_type(self._dst_type)

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
        return self.dst_type.lval(vm, dst_addr,
                                  *self._type_args, **self._type_kwargs)

    def deref_set(self, vm, addr, val):
        """Serializes the @val MemType subclass instance in @vm (VmMngr) at
        @addr. Equivalent to a pointer dereference assignment in C.
        """
        # Sanity check
        if self.dst_type != val.get_type():
            log.warning("Original type was %s, overridden by value of type %s",
                        self._dst_type.__name__, val.__class__.__name__)

        # Actual job
        dst_addr = self.get_val(vm, addr)
        vm.set_mem(dst_addr, bytes(val))

    def _get_pinned_base_class(self):
        return MemPtr

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.dst_type)

    def __eq__(self, other):
        return super(Ptr, self).__eq__(other) and \
                self.dst_type == other.dst_type and \
                self._type_args == other._type_args and \
                self._type_kwargs == other._type_kwargs

    def __ne__(self, other):
        return not self == other

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

    Anonymous Struct, Union or BitField can be used if their field name
    evaluates to False ("" or None). Such anonymous Struct field will generate
    fields to the parent Struct, e.g.:
        bla = Struct("Bla", [
                   ("a", Num("B")),
                   ("", Union([("b1", Num("B")), ("b2", Num("H"))])),
                   ("", Struct("", [("c1", Num("B")), ("c2", Num("B"))])),
               ]
    Will have a b1, b2 and c1, c2 field directly accessible. The anonymous
    fields are renamed to "__anon_<num>", with <num> an incremented number.

    In such case, bla.fields will not contain b1, b2, c1 and c2 (only the 3
    actual fields, with the anonymous ones renamed), but bla.all_fields will
    return the 3 fields + b1, b2, c1 and c2 (and an information telling if it
    has been generated from an anonymous Struct/Union).

    bla.get_field(vm, addr, "b1") will work.
    """

    def __init__(self, name, fields):
        self.name = name
        # generates self._fields and self._fields_desc
        self._gen_fields(fields)

    def _gen_fields(self, fields):
        """Precompute useful metadata on self.fields."""
        self._fields_desc = {}
        offset = 0

        # Build a proper (name, Field()) list, handling cases where the user
        # supplies a MemType subclass instead of a Type instance
        real_fields = []
        uniq_count = 0
        for fname, field in fields:
            field = to_type(field)

            # For reflexion
            field._set_self_type(self)

            # Anonymous Struct/Union
            if not fname and isinstance(field, Struct):
                # Generate field information
                updated_fields = {
                    name: {
                        # Same field type than the anon field subfield
                        'field': fd['field'],
                        # But the current offset is added
                        'offset': fd['offset'] + offset,
                    }
                    for name, fd in viewitems(field._fields_desc)
                }

                # Add the newly generated fields from the anon field
                self._fields_desc.update(updated_fields)
                real_fields += [(name, fld, True)
                                for name, fld in field.fields]

                # Rename the anonymous field
                fname = '__anon_%x' % uniq_count
                uniq_count += 1

            self._fields_desc[fname] = {"field": field, "offset": offset}
            real_fields.append((fname, field, False))
            offset = self._next_offset(field, offset)

        # fields is immutable
        self._fields = tuple(real_fields)

    def _next_offset(self, field, orig_offset):
        return orig_offset + field.size

    @property
    def fields(self):
        """Returns a sequence of (name, field) describing the fields of this
        Struct, in order of offset.

        Fields generated from anonymous Unions or Structs are excluded from
        this sequence.
        """
        return tuple((name, field) for name, field, anon in self._fields
                                   if not anon)

    @property
    def all_fields(self):
        """Returns a sequence of (<name>, <field (Type instance)>, <is_anon>),
        where is_anon is True when a field is generated from an anonymous
        Struct or Union, and False for the fields that have been provided as is.
        """
        return self._fields

    def set(self, vm, addr, val):
        raw = bytes(val)
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

    @property
    def size(self):
        return sum(field.size for _, field in self.fields)

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

    def __ne__(self, other):
        return not self == other

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

    @property
    def size(self):
        return max(field.size for _, field in self.fields)

    def _next_offset(self, field, orig_offset):
        return orig_offset

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
        # Handle both Type instance and MemType subclasses
        self.field_type = to_type(field_type)
        self.array_len = array_len

    def _set_self_type(self, self_type):
        super(Array, self)._set_self_type(self_type)
        self.field_type._set_self_type(self_type)

    def set(self, vm, addr, val):
        # MemSizedArray assignment
        if isinstance(val, MemSizedArray):
            if val.array_len != self.array_len or len(val) != self.size:
                raise ValueError("Size mismatch in MemSizedArray assignment")
            raw = bytes(val)
            vm.set_mem(addr, raw)

        # list assignment
        elif isinstance(val, list):
            if len(val) != self.array_len:
                raise ValueError("Size mismatch in MemSizedArray assignment ")
            offset = 0
            for elt in val:
                self.field_type.set(vm, addr + offset, elt)
                offset += self.field_type.size

        else:
            raise RuntimeError(
                "Assignment only implemented for list and MemSizedArray")

    def get(self, vm, addr):
        return self.lval(vm, addr)

    @property
    def size(self):
        if self.is_sized():
            return self.get_offset(self.array_len)
        else:
            raise ValueError("%s is unsized, use an array with a fixed "
                             "array_len instead." % self)

    def get_offset(self, idx):
        """Returns the offset of the item at index @idx."""
        return self.field_type.size * idx

    def get_item(self, vm, addr, idx):
        """Get the item(s) at index @idx.

        @idx: int, long or slice
        """
        if isinstance(idx, slice):
            res = []
            idx = self._normalize_slice(idx)
            for i in range(idx.start, idx.stop, idx.step):
                res.append(self.field_type.get(vm, addr + self.get_offset(i)))
            return res
        else:
            idx = self._normalize_idx(idx)
            return self.field_type.get(vm, addr + self.get_offset(idx))

    def set_item(self, vm, addr, idx, item):
        """Sets one or multiple items in this array (@idx can be an int, long
        or slice).
        """
        if isinstance(idx, slice):
            idx = self._normalize_slice(idx)
            if len(item) != len(range(idx.start, idx.stop, idx.step)):
                raise ValueError("Mismatched lengths in slice assignment")
            for i, val in zip(range(idx.start, idx.stop, idx.step),
                                         item):
                self.field_type.set(vm, addr + self.get_offset(i), val)
        else:
            idx = self._normalize_idx(idx)
            self.field_type.set(vm, addr + self.get_offset(idx), item)

    def is_sized(self):
        """True if this is a sized array (non None self.array_len), False
        otherwise.
        """
        return self.array_len is not None

    def _normalize_idx(self, idx):
        # Noop for this type
        if self.is_sized():
            if idx < 0:
                idx = self.array_len + idx
            self._check_bounds(idx)
        return idx

    def _normalize_slice(self, slice_):
        start = slice_.start if slice_.start is not None else 0
        stop = slice_.stop if slice_.stop is not None else self.get_size()
        step = slice_.step if slice_.step is not None else 1
        start = self._normalize_idx(start)
        stop = self._normalize_idx(stop)
        return slice(start, stop, step)

    def _check_bounds(self, idx):
        if not isinstance(idx, int_types):
            raise ValueError("index must be an int or a long")
        if idx < 0 or (self.is_sized() and idx >= self.size):
            raise IndexError("Index %s out of bounds" % idx)

    def _get_pinned_base_class(self):
        if self.is_sized():
            return MemSizedArray
        else:
            return MemArray

    def __repr__(self):
        return "[%r; %s]" % (self.field_type, self.array_len or "unsized")

    def __eq__(self, other):
        return self.__class__ == other.__class__ and \
                self.field_type == other.field_type and \
                self.array_len == other.array_len

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.__class__, self.field_type, self.array_len))


class Bits(Type):
    """Helper class for BitField, not very useful on its own. Represents some
    bits of a Num.

    The @backing_num is used to know how to serialize/deserialize data in vm,
    but getting/setting this fields only assign bits from @bit_offset to
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
        num_size = self._num.size * 8

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

    @property
    def size(self):
        return self._num.size

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

    def __ne__(self, other):
        return not self == other

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
        """@backing num: Num instance, @bit_list: [(name, n_bits)]"""
        self._num = backing_num
        fields = []
        offset = 0
        for name, bits in bit_list:
            fields.append((name, Bits(self._num, bits, offset)))
            offset += bits
        if offset > self._num.size * 8:
            raise ValueError("sum of bit lengths is > to the backing num size")
        super(BitField, self).__init__(fields)

    def set(self, vm, addr, val):
        self._num.set(vm, addr, val)

    def _get_pinned_base_class(self):
        return MemBitField

    def __eq__(self, other):
        return self.__class__ == other.__class__ and \
                self._num == other._num and super(BitField, self).__eq__(other)

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((super(BitField, self).__hash__(), self._num))

    def __repr__(self):
        fields_repr = ', '.join("%s: %r" % (name, field.bit_size)
                                for name, field in self.fields)
        return "%s(%s)" % (self.__class__.__name__, fields_repr)


class Str(Type):
    """A string type that handles encoding. This type is unsized (no static
    size).

    The @encoding is passed to the constructor, and is one of the keys of
    Str.encodings, currently:
        - ascii
        - latin1
        - ansi (= latin1)
        - utf8 (= utf-8le)
        - utf16 (= utf-16le, Windows UCS-2 compatible)
    New encodings can be added with Str.add_encoding.
    If an unknown encoding is passed to the constructor, Str will try to add it
    to the available ones with Str.add_encoding.

    Mapped to MemStr.
    """

    # Dict of {name: (getter, setter, raw_len)}
    # Where:
    #   - getter(vm, addr) -> unicode
    #   - setter(vm, addr, unicode)
    #   - raw_len(unicode_str) -> int (length of the str value one encoded in
    #                                  memory)
    # See enc_triplet()
    #
    # NOTE: this appears like it could be implemented only with
    # (getter, raw_str), but this would cause trouble for length-prefixed str
    # encoding (Pascal-style strings).
    encodings = {
        "ascii": enc_triplet("ascii"),
        "latin1": enc_triplet("latin1"),
        "ansi": enc_triplet("latin1"),
        "utf8": enc_triplet("utf8"),
        "utf16": enc_triplet("utf-16le"),
    }

    def __init__(self, encoding="ansi"):
        if encoding not in self.encodings:
            self.add_encoding(encoding)
        self._enc = encoding

    @classmethod
    def add_encoding(cls, enc_name, str_enc=None, getter=None, setter=None,
                     raw_len=None):
        """Add an available Str encoding.

        @enc_name: the name that will be used to designate this encoding in the
            Str constructor
        @str_end: (optional) the actual str encoding name if it differs from
            @enc_name
        @getter: (optional) func(vm, addr) -> unicode, to force usage of this
            function to retrieve the str from memory
        @setter: (optional) func(vm, addr, unicode), to force usage of this
            function to set the str in memory
        @raw_len: (optional) func(unicode_str) -> int (length of the str value
            one encoded in memory), to force usage of this function to compute
            the length of this string once in memory
        """
        default = enc_triplet(str_enc or enc_name)
        actual = (
            getter or default[0],
            setter or default[1],
            raw_len or default[2],
        )
        cls.encodings[enc_name] = actual

    def get(self, vm, addr):
        """Set the string value in memory"""
        get_str = self.encodings[self.enc][0]
        return get_str(vm, addr)

    def set(self, vm, addr, s):
        """Get the string value from memory"""
        set_str = self.encodings[self.enc][1]
        set_str(vm, addr, s)

    @property
    def size(self):
        """This type is unsized."""
        raise ValueError("Str is unsized")

    def value_size(self, py_str):
        """Returns the in-memory size of a @py_str for this Str type (handles
        encoding, i.e. will not return the same size for "utf16" and "ansi").
        """
        raw_len = self.encodings[self.enc][2]
        return raw_len(py_str)

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

    def __ne__(self, other):
        return not self == other

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

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.__class__)

    def __repr__(self):
        return self.__class__.__name__


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

# To avoid reinstantiation when testing equality
SELF_TYPE_INSTANCE = Self()
VOID_TYPE_INSTANCE = Void()


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


class MemType(with_metaclass(_MetaMemType, object)):
    """Base class for classes that allow to map python objects to C types in
    virtual memory. Represents an lvalue of a given type.

    Globally, MemTypes are not meant to be used directly: specialized
    subclasses are generated by Type(...).lval and should be used instead.
    The main exception is MemStruct, which you may want to subclass yourself
    for syntactic ease.
    """

    # allocator is a function(vm, size) -> allocated_address
    allocator = None

    _type = None

    def __init__(self, vm, addr=None, type_=None):
        self._vm = vm
        if addr is None:
            self._addr = self.alloc(vm, self.get_size())
        else:
            self._addr = addr
        if type_ is not None:
            self._type = type_
        if self._type is None:
            raise ValueError("Subclass MemType and define cls._type or pass "
                             "a type to the constructor")

    @classmethod
    def alloc(cls, vm, size):
        """Returns an allocated page of size @size if cls.allocator is set.
        Raises ValueError otherwise.
        """
        if cls.allocator is None:
            raise ValueError("Cannot provide None address to MemType() if"
                             "%s.set_allocator has not been called."
                             % __name__)
        return cls.allocator(vm, size)

    @classmethod
    def set_allocator(cls, alloc_func):
        """Set an allocator for this class; allows to instantiate statically
        sized MemTypes (i.e. sizeof() is implemented) without specifying the
        address (the object is allocated by @alloc_func in the vm).

        You may call set_allocator on specific MemType classes if you want
        to use a different allocator.

        @alloc_func: func(VmMngr) -> integer_address
        """
        cls.allocator = alloc_func

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
        return cls._type.size

    def get_size(self):
        """Return the dynamic size of this structure (e.g. the size of an
        instance). Defaults to sizeof for this base class.

        For example, MemStr defines get_size but not sizeof, as an instance
        has a fixed size (at least its value has), but all the instance do not
        have the same size.
        """
        return self.sizeof()

    def memset(self, byte=b'\x00'):
        """Fill the memory space of this MemType with @byte ('\x00' by
        default). The size is retrieved with self.get_size() (dynamic size).
        """
        # TODO: multibyte patterns
        if not isinstance(byte, bytes) or len(byte) != 1:
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
        if PY3:
            return repr(self)
        return self.__bytes__()

    def __bytes__(self):
        return self.raw()

    def __repr__(self):
        return "Mem%r" % self._type

    def __eq__(self, other):
        return self.__class__ == other.__class__ and \
                self.get_type() == other.get_type() and \
                bytes(self) == bytes(other)

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


class MemStruct(with_metaclass(_MetaMemStruct, MemType)):
    """Base class to easily implement VmMngr backed C-like structures in miasm.
    Represents a structure in virtual memory.

    The mechanism is the following:
        - set a "fields" class field to be a list of
          (<field_name (str)>, <Type_subclass_instance>)
        - instances of this class will have properties to interact with these
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

    @classmethod
    def get_offset(cls, field_name):
        """Shorthand for self.get_type().get_offset(field_name)."""
        return cls.get_type().get_offset(field_name)

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
        for name, _, _ in cls._type.all_fields:
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
        return self.get_type().value_size(val)

    @classmethod
    def from_str(cls, vm, py_str):
        """Allocates a MemStr with the global allocator with value py_str.
        Raises a ValueError if allocator is not set.
        """
        size = cls._type.value_size(py_str)
        addr = cls.alloc(vm, size)
        memstr = cls(vm, addr)
        memstr.val = py_str
        return memstr

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

    @classmethod
    def get_offset(cls, idx):
        """Shorthand for self.get_type().get_offset(idx)."""
        return cls.get_type().get_offset(idx)

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
        return self.get_type().size

    def __iter__(self):
        for i in range(self.get_type().array_len):
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

