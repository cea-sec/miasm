#!/usr/bin/env python

# miasm2.analysis.mem tests


from miasm2.analysis.machine import Machine
from miasm2.analysis.mem import *
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE

# Two structures with some fields
class OtherStruct(MemStruct):
    fields = [
        ("foo", Num("H")),
    ]

class MyStruct(MemStruct):
    fields = [
        # Integer field: just struct.pack fields with one value
        ("num", Num("I")),
        ("flags", Num("B")),
        # Ptr fields are Int, but they can also be dereferenced
        # (self.deref_<field>). Deref can be read and set.
        ("other", Ptr("I", OtherStruct)),
        # Ptr to a variable length String
        ("s", Ptr("I", MemStr)),
        ("i", Ptr("I", Num("I"))),
    ]

jitter = Machine("x86_32").jitter("python")
jitter.init_stack()
addr = 0x1000
addr2 = 0x1100
addr3 = 0x1200
addr_str = 0x1300
addr_str2 = 0x1400
addr_str3 = 0x1500
addr4 = 0x1600
addr5 = 0x1700
addr6 = 0x1800
addr7 = 0x1900
addr8 = 0x2000
addr9 = 0x2100
addr10 = 0x2200
addr11 = 0x2300
size = 0x2000
# Initialize all mem with 0xaa
jitter.vm.add_memory_page(addr, PAGE_READ | PAGE_WRITE, "\xaa"*size)


# MemStruct tests
## Creation
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
assert mstruct.other == 0
assert mstruct.s == 0
assert mstruct.i == 0
mstruct.memset('\x11')
assert mstruct.num == 0x11111111
assert mstruct.flags == 0x11
assert mstruct.other == 0x11111111
assert mstruct.s == 0x11111111
assert mstruct.i == 0x11111111


# Ptr tests
## Setup for Ptr tests
other = OtherStruct(jitter.vm, addr2)
other.foo = 0x1234
assert other.foo == 0x1234

## Basic usage
mstruct.other = other.get_addr()
assert mstruct.other == addr2
assert mstruct.deref_other == other
assert mstruct.deref_other.foo == 0x1234

## Deref assignment
other2 = OtherStruct(jitter.vm, addr3)
other2.foo = 0xbeef
assert mstruct.deref_other != other2
mstruct.deref_other = other2
assert mstruct.deref_other == other2
assert mstruct.deref_other.foo == 0xbeef
assert mstruct.other == addr2 # Addr did not change
assert other.foo == 0xbeef # Deref assignment copies by value
assert other2.foo == 0xbeef
assert other.get_addr() != other2.get_addr() # Not the same address
assert other == other2 # But same value

## Same stuff for Ptr to MemField
mstruct.i = addr7
mstruct.deref_i.value = 8
assert mstruct.deref_i.value == 8
assert mstruct.i == addr7
memval = struct.unpack("I", jitter.vm.get_mem(addr7, 4))[0]
assert memval == 8


# Str tests
## Basic tests
memstr = MemStr(jitter.vm, addr_str)
memstr.value = ""
assert memstr.value == ""
assert jitter.vm.get_mem(memstr.get_addr(), 1) == '\x00'
memstr.value = "lala"
assert jitter.vm.get_mem(memstr.get_addr(), memstr.get_size()) == 'lala\x00'
jitter.vm.set_mem(memstr.get_addr(), 'MIAMs\x00')
assert memstr.value == 'MIAMs'

## Ptr(MemStr) manipulations
mstruct.s = memstr.get_addr()
assert mstruct.s == addr_str
assert mstruct.deref_s == memstr
assert mstruct.deref_s.value == 'MIAMs'
mstruct.deref_s.value = "That's all folks!"
assert mstruct.deref_s.value == "That's all folks!"
assert memstr.value == "That's all folks!"

## Other address, same value, same encoding
memstr2 = MemStr(jitter.vm, addr_str2)
memstr2.value = "That's all folks!"
assert memstr2.get_addr() != memstr.get_addr()
assert memstr2 == memstr

## Same value, other encoding
memstr3 = MemStr(jitter.vm, addr_str3, "utf16")
memstr3.value = "That's all folks!"
assert memstr3.get_addr() != memstr.get_addr()
assert memstr3.get_size() != memstr.get_size() # Size is different
assert str(memstr3) != str(memstr) # Mem representation is different
assert memstr3 != memstr # Encoding is different, so they are not eq
assert memstr3.value == memstr.value # But the python value is the same


# MemArray tests
memarray = MemArray(jitter.vm, addr6, Num("I"))
# This also works:
_memarray = mem_array_type(Num("I"))(jitter.vm, addr6)
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
except (ValueError):
    pass

try:
    memarray[1, 2]
    assert False, "Should raise, mismatched sizes"
except (ValueError):
    pass


# MemSizedArray tests
memsarray = MemSizedArray(jitter.vm, addr6, Num("I"), 10)
# This also works:
_memsarray = mem_sized_array_type(Num("I"), 10)(jitter.vm, addr6)
# And mem_sized_array_type generates statically sized types
assert _memsarray.sizeof() == len(memsarray)
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


# Atypical fields (Struct and Array)
class MyStruct2(MemStruct):
    fields = [
        ("s1", Struct("=BI")),
        ("s2", Array(Num("B"), 10)),
    ]

ms2 = MyStruct2(jitter.vm, addr5)
ms2.memset('\xaa')
assert len(ms2) == 15

## Struct
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
jitter.vm.set_mem(addr4, '\x02'*10)
array2 = MemSizedArray(jitter.vm, addr4, Num("B"), 10)
for val in array2:
    assert val == 2
ms2.s2 = array2
for val in ms2.s2:
    assert val == 2


# Inline tests
class InStruct(MemStruct):
    fields = [
        ("foo", Num("B")),
        ("bar", Num("B")),
    ]

class ContStruct(MemStruct):
    fields = [
        ("one", Num("B")),
        ("instruct", Inline(InStruct)),
        ("last", Num("B")),
    ]

cont = ContStruct(jitter.vm, addr4)
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

# Quick mem(MemField) test:
assert mem(Num("f"))(jitter.vm, addr) == mem(Num("f"))(jitter.vm, addr)


# Union test
class UniStruct(MemStruct):
    fields = [
        ("one", Num("B")),
        ("union", Union([
            ("instruct", Inline(InStruct)),
            ("i", Num(">I")),
        ])),
        ("last", Num("B")),
    ]

uni = UniStruct(jitter.vm, addr8)
jitter.vm.set_mem(addr8, ''.join(chr(x) for x in xrange(len(uni))))
assert len(uni) == 6 # 1 + max(InStruct.sizeof(), 4) + 1
assert uni.one == 0x00
assert uni.instruct.foo == 0x01
assert uni.instruct.bar == 0x02
assert uni.i == 0x01020304
assert uni.last == 0x05
uni.instruct.foo = 0x02
assert uni.i == 0x02020304
uni.i = 0x11223344
assert uni.instruct.foo == 0x11
assert uni.instruct.bar == 0x22


# BitField test
class BitStruct(MemStruct):
    fields = [
        ("flags", BitField(Num("H"), [
            ("f1_1", 1),
            ("f2_5", 5),
            ("f3_8", 8),
            ("f4_1", 1),
        ])),
    ]

bit = BitStruct(jitter.vm, addr9)
bit.memset()
assert bit.flags == 0
assert bit.f1_1 == 0
assert bit.f2_5 == 0
assert bit.f3_8 == 0
assert bit.f4_1 == 0
bit.f1_1 = 1
bit.f2_5 = 0b10101
bit.f3_8 = 0b10000001
assert bit.flags == 0b0010000001101011
assert bit.f1_1 == 1
assert bit.f2_5 == 0b10101
assert bit.f3_8 == 0b10000001
assert bit.f4_1 == 0
bit.flags = 0b1101010101011100
assert bit.f1_1 == 0
assert bit.f2_5 == 0b01110
assert bit.f3_8 == 0b01010101
assert bit.f4_1 == 1


# Unhealthy ideas
class UnhealthyIdeas(MemStruct):
    fields = [
        ("f1", Ptr("I", MemArray, Struct("=Bf"))),
        ("f2", Array(Ptr("I", MemStr), 10)),
        ("f3", Ptr("I", MemSelf)),
        ("f4", Array(Ptr("I", MemSelf), 2)),
        ("f5", Ptr("I", Ptr("I", MemSelf))),
    ]

# Other way to handle self dependency and circular dependencies
# NOTE: in this case, MemSelf would have been fine
UnhealthyIdeas.fields.append(
    ("f6", Ptr("I", Ptr("I", Ptr("I", UnhealthyIdeas)))))
# Regen all fields
UnhealthyIdeas.gen_fields()

ideas = UnhealthyIdeas(jitter.vm, addr7)
ideas.memset()
ideas.f3 = ideas.get_addr()
assert ideas == ideas.deref_f3

ideas.f4[0] = ideas.get_addr()
assert ideas.f4.deref_get(0) == ideas
ideas.f4[1] = addr6
ideas.f4.deref_set(1, ideas)
assert ideas.f4[1] != ideas.get_addr()
assert ideas.f4.deref_get(1) == ideas

ideas.f5 = addr2
ideas.deref_f5.value = ideas.get_addr()
assert ideas.deref_f5.value == ideas.get_addr()
assert ideas.deref_f5.deref_value == ideas

ideas.deref_f5.value = addr3
ideas.deref_f5.deref_value = ideas
assert ideas.deref_f5.value != ideas.get_addr()
assert ideas.deref_f5.deref_value == ideas

ideas.f6 = addr4
ideas.deref_f6.value = addr5
ideas.deref_f6.deref_value.value = ideas.get_addr()
assert ideas.deref_f6.deref_value.deref_value == ideas

# Cast tests
# MemStruct cast
MemInt = mem(Num("I"))
MemShort = mem(Num("H"))
dword = MemInt(jitter.vm, addr10)
dword.value = 0x12345678
assert isinstance(dword.cast(MemShort), MemShort)
assert dword.cast(MemShort).value == 0x5678

# Field cast
ms2.s2[0] = 0x34
ms2.s2[1] = 0x12
assert ms2.cast_field("s2", MemShort).value == 0x1234

# Other method
assert MemShort(jitter.vm, ms2.get_addr("s2")).value == 0x1234

# Manual cast inside an Array
ms2.s2[4] = 0xcd
ms2.s2[5] = 0xab
assert MemShort(jitter.vm, ms2.s2.index2addr(4)).value == 0xabcd

# void* style cast
MemPtrVoid = mem(Ptr("I", MemVoid))
MemPtrMyStruct = mem(Ptr("I", MyStruct))
p = MemPtrVoid(jitter.vm, addr11)
p.value = mstruct.get_addr()
assert p.deref_value.cast(MyStruct) == mstruct
assert p.cast(MemPtrMyStruct).deref_value == mstruct

print "Some struct reprs:\n"
print repr(mstruct), '\n'
print repr(ms2), '\n'
print repr(cont), '\n'
print repr(uni), '\n'
print repr(bit), '\n'
print repr(bit), '\n'
print repr(ideas), '\n'
print repr(mem(Array(Inline(MyStruct2), 2))(jitter.vm, addr)), '\n'
print repr(mem(Num("f"))(jitter.vm, addr)), '\n'
print repr(memarray)
print repr(memsarray)
print repr(memstr)
print repr(memstr3)

print "Ok" # That's all folks!
