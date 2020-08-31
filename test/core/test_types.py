#! /usr/bin/env python2

# miasm.core.types tests

from __future__ import print_function
from builtins import range
import struct

from miasm.core.utils import int_to_byte
from miasm.analysis.machine import Machine
from miasm.core.types import MemStruct, Num, Ptr, Str, \
                              Array, RawStruct, Union, \
                              BitField, Self, Void, Bits, \
                              set_allocator, MemUnion, Struct
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.os_dep.common import heap
from miasm.core.locationdb import LocationDB

# Two structures with some fields
class OtherStruct(MemStruct):
    fields = [
        ("foo", Num("H")),
    ]

class MyStruct(MemStruct):
    fields = [
        # Number field: just struct.pack fields with one value
        ("num", Num("I")),
        ("flags", Num("B")),
        # This field is a pointer to another struct, it has a numeric
        # value (mystruct.other.val) and can be dereferenced to get an
        # OtherStruct instance (mystruct.other.deref)
        ("other", Ptr("I", OtherStruct)),
        # Ptr to a variable length String
        ("s", Ptr("I", Str())),
        ("i", Ptr("I", Num("I"))),
    ]

loc_db = LocationDB()
jitter = Machine("x86_32").jitter(loc_db, "python")
jitter.init_stack()
addr = 0x1000
size = 0x1000
addr_str = 0x1100
addr_str2 = 0x1200
addr_str3 = 0x1300
# Initialize all mem with 0xaa
jitter.vm.add_memory_page(addr, PAGE_READ | PAGE_WRITE, b"\xaa"*size)


# MemStruct tests
## Creation
# Use manual allocation with explicit addr for the first example
mstruct = MyStruct(jitter.vm, addr)
## Fields are read from the virtual memory
assert mstruct.num == 0xaaaaaaaa
assert mstruct.flags == 0xaa

## Field assignment modifies virtual memory
mstruct.num = 3
assert mstruct.num == 3
memval = struct.unpack("I", jitter.vm.get_mem(mstruct.get_addr(), 4))[0]
assert memval == 3

## Memset sets the whole structure
mstruct.memset()
assert mstruct.num == 0
assert mstruct.flags == 0
assert mstruct.other.val == 0
assert mstruct.s.val == 0
assert mstruct.i.val == 0
mstruct.memset(b'\x11')
assert mstruct.num == 0x11111111
assert mstruct.flags == 0x11
assert mstruct.other.val == 0x11111111
assert mstruct.s.val == 0x11111111
assert mstruct.i.val == 0x11111111


# From now, just use heap.vm_alloc
my_heap = heap()
set_allocator(my_heap.vm_alloc)


# Ptr tests
## Setup for Ptr tests
# the addr field can now be omitted since allocator is set
other = OtherStruct(jitter.vm)
other.foo = 0x1234
assert other.foo == 0x1234

## Basic usage
mstruct.other.val = other.get_addr()
# This also works for now:
# mstruct.other = other.get_addr()
assert mstruct.other.val == other.get_addr()
assert mstruct.other.deref == other
assert mstruct.other.deref.foo == 0x1234

## Deref assignment
other2 = OtherStruct(jitter.vm)
other2.foo = 0xbeef
assert mstruct.other.deref != other2
mstruct.other.deref = other2
assert mstruct.other.deref == other2
assert mstruct.other.deref.foo == 0xbeef
assert mstruct.other.val == other.get_addr() # Addr did not change
assert other.foo == 0xbeef # Deref assignment copies by value
assert other2.foo == 0xbeef
assert other.get_addr() != other2.get_addr() # Not the same address
assert other == other2 # But same value

## Same stuff for Ptr to MemField
alloc_addr = my_heap.vm_alloc(jitter.vm,
                              mstruct.get_type().get_field_type("i")
                                     .dst_type.size)
mstruct.i = alloc_addr
mstruct.i.deref.val = 8
assert mstruct.i.deref.val == 8
assert mstruct.i.val == alloc_addr
memval = struct.unpack("I", jitter.vm.get_mem(alloc_addr, 4))[0]
assert memval == 8


# Str tests
## Basic tests
memstr = Str().lval(jitter.vm, addr_str)
memstr.val = ""
assert memstr.val == ""
assert jitter.vm.get_mem(memstr.get_addr(), 1) == b'\x00'
memstr.val = "lala"
assert jitter.vm.get_mem(memstr.get_addr(), memstr.get_size()) == b'lala\x00'
jitter.vm.set_mem(memstr.get_addr(), b'MIAMs\x00')
assert memstr.val == 'MIAMs'

## Ptr(Str()) manipulations
mstruct.s.val = memstr.get_addr()
assert mstruct.s.val == addr_str
assert mstruct.s.deref == memstr
assert mstruct.s.deref.val == 'MIAMs'
mstruct.s.deref.val = "That's all folks!"
assert mstruct.s.deref.val == "That's all folks!"
assert memstr.val == "That's all folks!"

## Other address, same value, same encoding
memstr2 = Str().lval(jitter.vm, addr_str2)
memstr2.val = "That's all folks!"
assert memstr2.get_addr() != memstr.get_addr()
assert memstr2 == memstr

## Same value, other encoding
memstr3 = Str("utf16").lval(jitter.vm, addr_str3)
memstr3.val = "That's all folks!"
assert memstr3.get_addr() != memstr.get_addr()
assert memstr3.get_size() != memstr.get_size() # Size is different
assert bytes(memstr3) != bytes(memstr) # Mem representation is different
assert memstr3 != memstr # Encoding is different, so they are not eq
assert memstr3.val == memstr.val # But the python value is the same


# Array tests
# Construction methods
assert Array(MyStruct) == Array(MyStruct.get_type())
assert Array(MyStruct, 10) == Array(MyStruct.get_type(), 10)
# Allocate buffer manually, since memarray is unsized
alloc_addr = my_heap.vm_alloc(jitter.vm, 0x100)
memarray = Array(Num("I")).lval(jitter.vm, alloc_addr)
memarray[0] = 0x02
assert memarray[0] == 0x02
assert jitter.vm.get_mem(memarray.get_addr(),
                         Num("I").size) == b'\x02\x00\x00\x00'
memarray[2] = 0xbbbbbbbb
assert memarray[2] == 0xbbbbbbbb
assert jitter.vm.get_mem(memarray.get_addr() + 2 * Num("I").size,
                         Num("I").size) == b'\xbb\xbb\xbb\xbb'
try:
    s = bytes(memarray)
    assert False, "Should raise"
except (NotImplementedError, ValueError):
    pass
try:
    s = len(memarray)
    assert False, "Should raise"
except (NotImplementedError, ValueError):
    pass

## Slice assignment
memarray[2:4] = [3, 3]
assert memarray[2] == 3
assert memarray[3] == 3
assert memarray[2:4] == [3, 3]
try:
    memarray[2:4] = [3, 3, 3]
    assert False, "Should raise, mismatched sizes"
except ValueError:
    pass


memsarray = Array(Num("I"), 10).lval(jitter.vm)
# And Array(type, size).lval generates statically sized types
assert memsarray.sizeof() == Num("I").size * 10
memsarray.memset(b'\xcc')
assert memsarray[0] == 0xcccccccc
assert len(memsarray) == 10 * 4
assert bytes(memsarray) == b'\xcc' * (4 * 10)
for val in memsarray:
    assert val == 0xcccccccc
assert list(memsarray) == [0xcccccccc] * 10
memsarray[0] = 2
assert memsarray[0] == 2
assert bytes(memsarray) == b'\x02\x00\x00\x00' + b'\xcc' * (4 * 9)


# Atypical fields (RawStruct and Array)
class MyStruct2(MemStruct):
    fields = [
        ("s1", RawStruct("=BI")),
        ("s2", Array(Num("B"), 10)),
    ]

ms2 = MyStruct2(jitter.vm)
ms2.memset(b'\xaa')
assert len(ms2) == 15

## RawStruct
assert len(ms2.s1) == 2
assert ms2.s1[0] == 0xaa
assert ms2.s1[1] == 0xaaaaaaaa

## Array
### Basic checks
assert len(ms2.s2) == 10
for val in ms2.s2:
    assert val == 0xaa
assert ms2.s2[0] == 0xaa
assert ms2.s2[9] == 0xaa

### Subscript assignment
ms2.s2[3] = 2
assert ms2.s2[3] == 2

### Field assignment (list)
ms2.s2 = [1] * 10
for val in ms2.s2:
    assert val == 1

### Field assignment (MemSizedArray)
array2 = Array(Num("B"), 10).lval(jitter.vm)
jitter.vm.set_mem(array2.get_addr(), b'\x02'*10)
for val in array2:
    assert val == 2
ms2.s2 = array2
for val in ms2.s2:
    assert val == 2


# Inlining a MemType tests
class InStruct(MemStruct):
    fields = [
        ("foo", Num("B")),
        ("bar", Num("B")),
    ]

class ContStruct(MemStruct):
    fields = [
        ("one", Num("B")),
        # Shorthand for: ("instruct", InStruct.get_type()),
        ("instruct", InStruct),
        ("last", Num("B")),
    ]

cont = ContStruct(jitter.vm)
cont.memset()
assert len(cont) == 4
assert len(cont.instruct) == 2
assert cont.one == 0
assert cont.last == 0
assert cont.instruct.foo == 0
assert cont.instruct.bar == 0
cont.memset(b'\x11')
assert cont.one == 0x11
assert cont.last == 0x11
assert cont.instruct.foo == 0x11
assert cont.instruct.bar == 0x11

cont.one = 0x01
cont.instruct.foo = 0x02
cont.instruct.bar = 0x03
cont.last = 0x04
assert cont.one == 0x01
assert cont.instruct.foo == 0x02
assert cont.instruct.bar == 0x03
assert cont.last == 0x04
assert jitter.vm.get_mem(cont.get_addr(), len(cont)) == b'\x01\x02\x03\x04'


# Union test
class UniStruct(MemStruct):
    fields = [
        ("one", Num("B")),
        ("union", Union([
            ("instruct", InStruct),
            ("i", Num(">I")),
        ])),
        ("last", Num("B")),
    ]

uni = UniStruct(jitter.vm)
jitter.vm.set_mem(uni.get_addr(), b''.join(int_to_byte(x) for x in range(len(uni))))
assert len(uni) == 6 # 1 + max(InStruct.sizeof(), 4) + 1
assert uni.one == 0x00
assert uni.union.instruct.foo == 0x01
assert uni.union.instruct.bar == 0x02
assert uni.union.i == 0x01020304
assert uni.last == 0x05
uni.union.instruct.foo = 0x02
assert uni.union.i == 0x02020304
uni.union.i = 0x11223344
assert uni.union.instruct.foo == 0x11
assert uni.union.instruct.bar == 0x22


# BitField test
class BitStruct(MemUnion):
    fields = [
        ("flags_num", Num("H")),
        ("flags", BitField(Num("H"), [
            ("f1_1", 1),
            ("f2_5", 5),
            ("f3_8", 8),
            ("f4_1", 1),
        ])),
    ]

bit = BitStruct(jitter.vm)
bit.memset()
assert bit.flags_num == 0
assert bit.flags.f1_1 == 0
assert bit.flags.f2_5 == 0
assert bit.flags.f3_8 == 0
assert bit.flags.f4_1 == 0
bit.flags.f1_1 = 1
bit.flags.f2_5 = 0b10101
bit.flags.f3_8 = 0b10000001
assert bit.flags_num == 0b0010000001101011
assert bit.flags.f1_1 == 1
assert bit.flags.f2_5 == 0b10101
assert bit.flags.f3_8 == 0b10000001
assert bit.flags.f4_1 == 0
bit.flags_num = 0b1101010101011100
assert bit.flags.f1_1 == 0
assert bit.flags.f2_5 == 0b01110
assert bit.flags.f3_8 == 0b01010101
assert bit.flags.f4_1 == 1

try:
    class BitStruct(MemUnion):
        fields = [
            ("ValueB", BitField(Num("<Q"), [
                ("field_00", 32),
                ("field_01", 32),
            ])),
            ("Value", Num("<Q")),
        ]
except ValueError:
    assert False, "Should not raise"

try:
    class BitStruct(MemUnion):
        fields = [
            ("ValueB", BitField(Num("<Q"), [
                ("field_00", 32),
                ("field_01", 32),
                ("field_02", 1),
            ])),
            ("Value", Num("<Q")),
        ]
    assert False, "Should raise"
except ValueError:
    pass

# Unhealthy ideas
class UnhealthyIdeas(MemStruct):
    fields = [
        ("pastruct", Ptr("I", Array(RawStruct("=Bf")))),
        ("apstr", Array(Ptr("I", Str()), 10)),
        ("pself", Ptr("I", Self())),
        ("apself", Array(Ptr("I", Self()), 2)),
        ("ppself", Ptr("I", Ptr("I", Self()))),
        ("pppself", Ptr("I", Ptr("I", Ptr("I", Self())))),
    ]

p_size = Ptr("I", Void()).size

ideas = UnhealthyIdeas(jitter.vm)
ideas.memset()
ideas.pself = ideas.get_addr()
assert ideas == ideas.pself.deref

ideas.apself[0] = ideas.get_addr()
assert ideas.apself[0].deref == ideas
ideas.apself[1] = my_heap.vm_alloc(jitter.vm, UnhealthyIdeas.sizeof())
ideas.apself[1].deref = ideas
assert ideas.apself[1] != ideas.get_addr()
assert ideas.apself[1].deref == ideas

ideas.ppself = my_heap.vm_alloc(jitter.vm, p_size)
ideas.ppself.deref.val = ideas.get_addr()
assert ideas.ppself.deref.val == ideas.get_addr()
assert ideas.ppself.deref.deref == ideas

ideas.ppself.deref.val = my_heap.vm_alloc(jitter.vm, UnhealthyIdeas.sizeof())
ideas.ppself.deref.deref = ideas
assert ideas.ppself.deref.val != ideas.get_addr()
assert ideas.ppself.deref.deref == ideas

ideas.pppself = my_heap.vm_alloc(jitter.vm, p_size)
ideas.pppself.deref.val = my_heap.vm_alloc(jitter.vm, p_size)
ideas.pppself.deref.deref.val = ideas.get_addr()
assert ideas.pppself.deref.deref.deref == ideas


# Circular dependencies
class A(MemStruct):
    pass

class B(MemStruct):
    fields = [("a", Ptr("I", A)),]

# Gen A's fields after declaration
A.gen_fields([("b", Ptr("I", B)),])

a = A(jitter.vm)
b = B(jitter.vm)
a.b.val = b.get_addr()
b.a.val = a.get_addr()
assert a.b.deref == b
assert b.a.deref == a


# Cast tests
# MemStruct cast
MemInt = Num("I").lval
MemShort = Num("H").lval
dword = MemInt(jitter.vm)
dword.val = 0x12345678
assert isinstance(dword.cast(MemShort), MemShort)
assert dword.cast(MemShort).val == 0x5678

# Field cast
ms2.s2[0] = 0x34
ms2.s2[1] = 0x12
assert ms2.cast_field("s2", MemShort).val == 0x1234

# Other method
assert MemShort(jitter.vm, ms2.get_addr("s2")).val == 0x1234

# Manual cast inside an Array
ms2.s2[4] = 0xcd
ms2.s2[5] = 0xab
assert MemShort(jitter.vm, ms2.s2.get_addr(4)).val == 0xabcd

# void* style cast
MemPtrVoid = Ptr("I", Void()).lval
p = MemPtrVoid(jitter.vm)
p.val = mstruct.get_addr()
assert p.deref.cast(MyStruct) == mstruct
assert p.cast(Ptr("I", MyStruct)).deref == mstruct

# Field equality tests
assert RawStruct("IH") == RawStruct("IH")
assert RawStruct("I") != RawStruct("IH")
assert Num("I") == Num("I")
assert Num(">I") != Num("<I")
assert Ptr("I", MyStruct) == Ptr("I", MyStruct)
assert Ptr(">I", MyStruct) != Ptr("<I", MyStruct)
assert Ptr("I", MyStruct) != Ptr("I", MyStruct2)
assert MyStruct.get_type() == MyStruct.get_type()
assert MyStruct.get_type() != MyStruct2.get_type()
assert Array(Num("H"), 12) == Array(Num("H"), 12)
assert Array(Num("H"), 11) != Array(Num("H"), 12)
assert Array(Num("I"), 12) != Array(Num("H"), 12)
assert Struct("a", [("f1", Num("B")), ("f2", Num("H"))]) == \
        Struct("a", [("f1", Num("B")), ("f2", Num("H"))])
assert Struct("a", [("f2", Num("B")), ("f2", Num("H"))]) != \
        Struct("a", [("f1", Num("B")), ("f2", Num("H"))])
assert Struct("a", [("f1", Num("B")), ("f2", Num("H"))]) != \
        Struct("a", [("f1", Num("I")), ("f2", Num("H"))])
assert Struct("a", [("f1", Num("B")), ("f2", Num("H"))]) != \
        Struct("b", [("f1", Num("B")), ("f2", Num("H"))])
assert Union([("f1", Num("B")), ("f2", Num("H"))]) == \
        Union([("f1", Num("B")), ("f2", Num("H"))])
assert Union([("f2", Num("B")), ("f2", Num("H"))]) != \
        Union([("f1", Num("B")), ("f2", Num("H"))])
assert Union([("f1", Num("B")), ("f2", Num("H"))]) != \
        Union([("f1", Num("I")), ("f2", Num("H"))])
assert Bits(Num("I"), 3, 8) == Bits(Num("I"), 3, 8)
assert (Bits(Num("I"), 3, 8) != Bits(Num("I"), 3, 8)) is False
assert Bits(Num("H"), 2, 8) != Bits(Num("I"), 3, 8)
assert Bits(Num("I"), 3, 7) != Bits(Num("I"), 3, 8)
assert BitField(Num("B"), [("f1", 2), ("f2", 4), ("f3", 1)]) == \
        BitField(Num("B"), [("f1", 2), ("f2", 4), ("f3", 1)])
assert BitField(Num("H"), [("f1", 2), ("f2", 4), ("f3", 1)]) != \
        BitField(Num("B"), [("f1", 2), ("f2", 4), ("f3", 1)])
assert BitField(Num("B"), [("f2", 2), ("f2", 4), ("f3", 1)]) != \
        BitField(Num("B"), [("f1", 2), ("f2", 4), ("f3", 1)])
assert BitField(Num("B"), [("f1", 1), ("f2", 4), ("f3", 1)]) != \
        BitField(Num("B"), [("f1", 2), ("f2", 4), ("f3", 1)])


# Quick MemField.lval/MemField hash test
assert Num("f").lval(jitter.vm, addr) == Num("f").lval(jitter.vm, addr)
# Types are cached
assert Num("f").lval == Num("f").lval
assert Num("d").lval != Num("f").lval
assert Union([("f1", Num("I")), ("f2", Num("H"))]).lval == \
        Union([("f1", Num("I")), ("f2", Num("H"))]).lval
assert Array(Num("B")).lval == Array(Num("B")).lval
assert Array(Num("I")).lval != Array(Num("B")).lval
assert Array(Num("B"), 20).lval == Array(Num("B"), 20).lval
assert Array(Num("B"), 19).lval != Array(Num("B"), 20).lval

# MemStruct unicity test
assert MyStruct == Struct(MyStruct.__name__, MyStruct.fields).lval
assert MyStruct.get_type() == Struct(MyStruct.__name__, MyStruct.fields)

# Anonymous Unions
class Anon(MemStruct):
    fields = [
        ("a", Num("B")),
        # If a field name evaluates to False ("" or None for example) and the
        # field type is a Struct subclass (Struct, Union, BitField), the field
        # is considered as an anonymous struct or union. Therefore, Anon will
        # have b1, b2 and c1, c2 attributes in that case.
        ("", Union([("b1", Num("B")), ("b2", Num("H"))])),
        ("", Struct("", [("c1", Num("B")), ("c2", Num("B"))])),
        ("d", Num("B")),
    ]

anon = Anon(jitter.vm)
anon.memset()
anon.a = 0x07
anon.b2 = 0x0201
anon.c1 = 0x55
anon.c2 = 0x77
anon.d = 0x33
assert anon.a == 0x07
assert anon.b1 == 0x01
assert anon.b2 == 0x0201
assert anon.c1 == 0x55
assert anon.c2 == 0x77
assert anon.d == 0x33

# get_offset
for field, off in (("a", 0), ("b1", 1), ("b2", 1), ("c1", 3), ("c2", 4),
                   ("d", 5)):
    assert Anon.get_offset(field) == Anon.get_type().get_offset(field)
    assert Anon.get_offset(field) == off

arr_t = Array(Num("H"))
for idx, off in ((0, 0), (1, 2), (30, 60)):
    assert arr_t.get_offset(idx) == arr_t.lval.get_offset(idx)
    assert arr_t.get_offset(idx) == off


# Repr tests

print("Some struct reprs:\n")
print(repr(mstruct), '\n')
print(repr(ms2), '\n')
print(repr(cont), '\n')
print(repr(uni), '\n')
print(repr(bit), '\n')
print(repr(ideas), '\n')
print(repr(Array(MyStruct2.get_type(), 2).lval(jitter.vm, addr)), '\n')
print(repr(Num("f").lval(jitter.vm, addr)), '\n')
print(repr(memarray))
print(repr(memsarray))
print(repr(memstr))
print(repr(memstr3))

print("\nOk") # That's all folks!
