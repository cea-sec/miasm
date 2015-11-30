#!/usr/bin/env python

# miasm2.analysis.mem tests

import struct

from miasm2.analysis.machine import Machine
from miasm2.analysis.mem import PinnedStruct, Num, Ptr, Str, \
                                Array, RawStruct, Union, \
                                BitField, Self, Void, Bits, \
                                set_allocator, PinnedUnion, Struct
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.os_dep.common import heap

# Two structures with some fields
class OtherStruct(PinnedStruct):
    fields = [
        ("foo", Num("H")),
    ]

class MyStruct(PinnedStruct):
    fields = [
        # Number field: just struct.pack fields with one value
        ("num", Num("I")),
        ("flags", Num("B")),
        # TODO: comment
        ("other", Ptr("I", OtherStruct)),
        # Ptr to a variable length String
        ("s", Ptr("I", Str())),
        ("i", Ptr("I", Num("I"))),
    ]

jitter = Machine("x86_32").jitter("python")
jitter.init_stack()
addr = 0x1000
size = 0x1000
addr_str = 0x1100
addr_str2 = 0x1200
addr_str3 = 0x1300
# Initialize all mem with 0xaa
jitter.vm.add_memory_page(addr, PAGE_READ | PAGE_WRITE, "\xaa"*size)


# PinnedStruct tests
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

## Pinnedset sets the whole structure
mstruct.memset()
assert mstruct.num == 0
assert mstruct.flags == 0
assert mstruct.other.val == 0
assert mstruct.s.val == 0
assert mstruct.i.val == 0
mstruct.memset('\x11')
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
# the addr field can now be omited since allocator is set
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

## Same stuff for Ptr to PinnedField
alloc_addr = my_heap.vm_alloc(jitter.vm,
                              mstruct.get_type().get_field_type("i")
                                     .dst_type.sizeof())
mstruct.i = alloc_addr
mstruct.i.deref.val = 8
assert mstruct.i.deref.val == 8
assert mstruct.i.val == alloc_addr
memval = struct.unpack("I", jitter.vm.get_mem(alloc_addr, 4))[0]
assert memval == 8


# Str tests
## Basic tests
memstr = Str().pinned(jitter.vm, addr_str)
memstr.val = ""
assert memstr.val == ""
assert jitter.vm.get_mem(memstr.get_addr(), 1) == '\x00'
memstr.val = "lala"
assert jitter.vm.get_mem(memstr.get_addr(), memstr.get_size()) == 'lala\x00'
jitter.vm.set_mem(memstr.get_addr(), 'MIAMs\x00')
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
memstr2 = Str().pinned(jitter.vm, addr_str2)
memstr2.val = "That's all folks!"
assert memstr2.get_addr() != memstr.get_addr()
assert memstr2 == memstr

## Same value, other encoding
memstr3 = Str("utf16").pinned(jitter.vm, addr_str3)
memstr3.val = "That's all folks!"
assert memstr3.get_addr() != memstr.get_addr()
assert memstr3.get_size() != memstr.get_size() # Size is different
assert str(memstr3) != str(memstr) # Pinned representation is different
assert memstr3 != memstr # Encoding is different, so they are not eq
assert memstr3.val == memstr.val # But the python value is the same


# Array tests
# Allocate buffer manually, since memarray is unsized
alloc_addr = my_heap.vm_alloc(jitter.vm, 0x100)
memarray = Array(Num("I")).pinned(jitter.vm, alloc_addr)
memarray[0] = 0x02
assert memarray[0] == 0x02
assert jitter.vm.get_mem(memarray.get_addr(),
                         Num("I").size()) == '\x02\x00\x00\x00'
memarray[2] = 0xbbbbbbbb
assert memarray[2] == 0xbbbbbbbb
assert jitter.vm.get_mem(memarray.get_addr() + 2 * Num("I").size(),
                         Num("I").size()) == '\xbb\xbb\xbb\xbb'
try:
    s = str(memarray)
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


memsarray = Array(Num("I"), 10).pinned(jitter.vm)
# And Array(type, size).pinned generates statically sized types
assert memsarray.sizeof() == Num("I").size() * 10
memsarray.memset('\xcc')
assert memsarray[0] == 0xcccccccc
assert len(memsarray) == 10 * 4
assert str(memsarray) == '\xcc' * (4 * 10)
for val in memsarray:
    assert val == 0xcccccccc
assert list(memsarray) == [0xcccccccc] * 10
memsarray[0] = 2
assert memsarray[0] == 2
assert str(memsarray) == '\x02\x00\x00\x00' + '\xcc' * (4 * 9)


# Atypical fields (RawStruct and Array)
class MyStruct2(PinnedStruct):
    fields = [
        ("s1", RawStruct("=BI")),
        ("s2", Array(Num("B"), 10)),
    ]

ms2 = MyStruct2(jitter.vm)
ms2.memset('\xaa')
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

### Field assignment (PinnedSizedArray)
array2 = Array(Num("B"), 10).pinned(jitter.vm)
jitter.vm.set_mem(array2.get_addr(), '\x02'*10)
for val in array2:
    assert val == 2
ms2.s2 = array2
for val in ms2.s2:
    assert val == 2


# Inlining a PinnedType tests
class InStruct(PinnedStruct):
    fields = [
        ("foo", Num("B")),
        ("bar", Num("B")),
    ]

class ContStruct(PinnedStruct):
    fields = [
        ("one", Num("B")),
        ("instruct", InStruct.get_type()),
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
cont.memset('\x11')
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
assert jitter.vm.get_mem(cont.get_addr(), len(cont)) == '\x01\x02\x03\x04'


# Union test
class UniStruct(PinnedStruct):
    fields = [
        ("one", Num("B")),
        ("union", Union([
            ("instruct", InStruct.get_type()),
            ("i", Num(">I")),
        ])),
        ("last", Num("B")),
    ]

uni = UniStruct(jitter.vm)
jitter.vm.set_mem(uni.get_addr(), ''.join(chr(x) for x in xrange(len(uni))))
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
class BitStruct(PinnedUnion):
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


# Unhealthy ideas
class UnhealthyIdeas(PinnedStruct):
    fields = [
        ("pastruct", Ptr("I", Array(RawStruct("=Bf")))),
        ("apstr", Array(Ptr("I", Str()), 10)),
        ("pself", Ptr("I", Self())),
        ("apself", Array(Ptr("I", Self()), 2)),
        ("ppself", Ptr("I", Ptr("I", Self()))),
        ("pppself", Ptr("I", Ptr("I", Ptr("I", Self())))),
    ]

p_size = Ptr("I", Void()).size()

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
class A(PinnedStruct):
    pass

class B(PinnedStruct):
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
# PinnedStruct cast
PinnedInt = Num("I").pinned
PinnedShort = Num("H").pinned
dword = PinnedInt(jitter.vm)
dword.val = 0x12345678
assert isinstance(dword.cast(PinnedShort), PinnedShort)
assert dword.cast(PinnedShort).val == 0x5678

# Field cast
ms2.s2[0] = 0x34
ms2.s2[1] = 0x12
assert ms2.cast_field("s2", PinnedShort).val == 0x1234

# Other method
assert PinnedShort(jitter.vm, ms2.get_addr("s2")).val == 0x1234

# Manual cast inside an Array
ms2.s2[4] = 0xcd
ms2.s2[5] = 0xab
assert PinnedShort(jitter.vm, ms2.s2.get_addr(4)).val == 0xabcd

# void* style cast
PinnedPtrVoid = Ptr("I", Void()).pinned
p = PinnedPtrVoid(jitter.vm)
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
assert Bits(Num("I"), 3, 8) != Bits(Num("I"), 3, 8)
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


# Quick PinnedField.pinned/PinnedField hash test
assert Num("f").pinned(jitter.vm, addr) == Num("f").pinned(jitter.vm, addr)
# Types are cached
assert Num("f").pinned == Num("f").pinned
assert Num("d").pinned != Num("f").pinned
assert Union([("f1", Num("I")), ("f2", Num("H"))]).pinned == \
        Union([("f1", Num("I")), ("f2", Num("H"))]).pinned
assert Array(Num("B")).pinned == Array(Num("B")).pinned
assert Array(Num("I")).pinned != Array(Num("B")).pinned
assert Array(Num("B"), 20).pinned == Array(Num("B"), 20).pinned
assert Array(Num("B"), 19).pinned != Array(Num("B"), 20).pinned


# Repr tests

print "Some struct reprs:\n"
print repr(mstruct), '\n'
print repr(ms2), '\n'
print repr(cont), '\n'
print repr(uni), '\n'
print repr(bit), '\n'
print repr(ideas), '\n'
print repr(Array(MyStruct2.get_type(), 2).pinned(jitter.vm, addr)), '\n'
print repr(Num("f").pinned(jitter.vm, addr)), '\n'
print repr(memarray)
print repr(memsarray)
print repr(memstr)
print repr(memstr3)

print "\nOk" # That's all folks!
