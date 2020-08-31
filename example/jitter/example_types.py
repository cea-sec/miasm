#! /usr/bin/env python2
"""This script is just a short example of common usages for miasm.core.types.
For a more complete view of what is possible, tests/core/types.py covers
most of the module possibilities, and the module doc gives useful information
as well.
"""
from __future__ import print_function

from miasm.core.utils import iterbytes
from miasm.analysis.machine import Machine
from miasm.core.types import MemStruct, Self, Void, Str, Array, Ptr, \
                              Num, Array, set_allocator
from miasm.os_dep.common import heap
from miasm.core.locationdb import LocationDB

loc_db = LocationDB()

# Instantiate a heap
my_heap = heap()
# And set it as the default memory allocator, to avoid manual allocation and
# explicit address passing to the MemType subclasses (like MemStruct)
# constructor
set_allocator(my_heap.vm_alloc)

# Let's reimplement a simple C generic linked list mapped on a VmMngr.

# All the structures and methods will use the python objects but all the data
# is in fact stored in the VmMngr

class ListNode(MemStruct):
    fields = [
        # The "<I" is the struct-like format of the pointer in memory, in this
        # case a Little Endian 32 bits unsigned int.
        # One way to handle reference to ListNode in ListNode is to use the
        # special marker Self().
        # You could also generate ListNode's fields with ListNode.gen_field
        # after the class declaration, so that the ListNode is defined when
        # fields are generated.
        ("next", Ptr("<I", Self())),
        # Ptr(_, Void()) is analogous to void*, Void() is a kind of "empty type"
        ("data", Ptr("<I", Void())),
    ]

    def get_next(self):
        if self.next.val == 0:
            return None
        return self.next.deref

    def get_data(self, data_type=None):
        if data_type is not None:
            return self.data.deref.cast(data_type)
        else:
            return self.data.deref


class LinkedList(MemStruct):
    fields = [
        # For convenience, either a Type instance (like Self() or Num("I") or a
        # MemStruct subclass can be passed to the Ptr constructor.
        ("head", Ptr("<I", ListNode)),
        ("tail", Ptr("<I", ListNode)),
        # Num can take any one-field struct-like format, including floats and
        # doubles
        ("size", Num("<I")),
    ]

    def get_head(self):
        """Returns the head ListNode instance"""
        if self.head == 0:
            return None
        return self.head.deref

    def get_tail(self):
        """Returns the tail ListNode instance"""
        if self.tail == 0:
            return None
        return self.tail.deref

    def push(self, data):
        """Push a data (MemType instance) to the linked list."""
        # Allocate a new node
        node = ListNode(self._vm)

        # Set the data pointer
        node.data = data.get_addr()

        # re-link
        if self.head != 0:
            # get the head ListNode
            head = self.get_head()
            node.next = head.get_addr()

        # pointer to head assigned to the new node address
        self.head = node.get_addr()

        # Do not forget the tail :)
        if self.tail == 0:
            self.tail = node.get_addr()

        self.size += 1

    def pop(self, data_type=None):
        """Pop one data from the LinkedList."""
        # Nothing to pop
        if self.head == 0:
            return None

        node = self.get_head()
        self.head = node.next

        # empty
        if self.head == 0:
            self.tail = 0

        self.size -= 1

        return node.get_data(data_type)

    def empty(self):
        """True if the list is empty."""
        return self.head == 0

    def __iter__(self):
        if not self.empty():
            cur = self.get_head()
            while cur is not None:
                yield cur.data.deref
                cur = cur.get_next()


# Some data types to put in the LinkedList and play with:

class DataArray(MemStruct):
    fields = [
        ("val1", Num("B")),
        ("val2", Num("B")),
        # Ptr can also be instantiated with a Type instance as an argument, the
        # corresponding Memtype will be returned when dereferencing
        # Here, data_array.array.deref will allow to access an Array
        ("arrayptr", Ptr("<I", Array(Num("B"), 16))),
        # Array of 10 uint8
        ("array", Array(Num("B"), 16)),
    ]

class DataStr(MemStruct):
    fields = [
        ("valshort", Num("<H")),
        # Pointer to an utf16 null terminated string
        ("data", Ptr("<I", Str("utf16"))),
    ]


print("This script demonstrates a LinkedList implementation using the types ")
print("module in the first part, and how to play with some casts in the second.")
print()

# A random jitter
# You can also use miasm.jitter.VmMngr.Vm(), but it does not happen in real
# life scripts, so here is the usual way:
jitter = Machine("x86_32").jitter(loc_db, "python")
vm = jitter.vm

# Auto-allocated by my_heap. If you allocate memory at `addr`,
# `link = LinkedList(vm, addr)` will use this allocation. If you just want
# to read/modify existing struct, you may want to use the (vm, addr) syntax.
link = LinkedList(vm)
# memset the struct (with '\x00' by default)
link.memset()

# Push three uninitialized structures
link.push(DataArray(vm))
link.push(DataArray(vm))
link.push(DataArray(vm))

# Size has been updated
assert link.size == 3
# If you get it directly from the VM, it is updated as well
raw_size = vm.get_mem(link.get_addr("size"), link.get_type()
                                                 .get_field_type("size").size)
assert raw_size == b'\x03\x00\x00\x00'

print("The linked list just built:")
print(repr(link), '\n')

print("Its uninitialized data elements:")
for data in link:
    # __iter__ returns MemVoids here, just cast them to the real data type
    real_data = data.cast(DataArray)
    print(repr(real_data))
print()

# Now let's play with one data
data = link.pop(DataArray)
assert link.size == 2
# Make the Array Ptr point to the data's array field
# Note: this is equivalent to data.arrayptr.val = ...
data.arrayptr = data.get_addr("array")
# Now the pointer dereference is equal to the array field's value
assert data.arrayptr.deref == data.array

# Let's say that it is a DataStr:
datastr = data.cast(DataStr)

print("First element casted to DataStr:")
print(repr(datastr))
print()

# data and datastr really share the same memory:
data.val1 = 0x34
data.val2 = 0x12
assert datastr.valshort == 0x1234
datastr.valshort = 0x1122
assert data.val1 == 0x22 and data.val2 == 0x11

# Let's play with strings
memstr = datastr.data.deref
# Note that memstr is Str("utf16")
memstr.val = 'Miams'

print("Cast data.array to MemStr and set the string value:")
print(repr(memstr))
print()

# If you followed, memstr and data.array point to the same object, so:
raw_miams = 'Miams'.encode('utf-16le') + b'\x00'*2
raw_miams_array = [ord(c) for c in iterbytes(raw_miams)]
assert list(data.array)[:len(raw_miams_array)] == raw_miams_array
assert data.array.cast(Str("utf16")) == memstr
# Default is "ansi"
assert data.array.cast(Str()) != memstr
assert data.array.cast(Str("utf16")).val == memstr.val

print("See that the original array has been modified:")
print(repr(data))
print()

# Some type manipulation examples, for example let's construct an argv for
# a program:
# Let's say that we have two arguments, +1 for the program name and +1 for the
# final null ptr in argv, the array has 4 elements:
argv_t = Array(Ptr("<I", Str()), 4)
print("3 arguments argv type:", argv_t)

# alloc argv somewhere
argv = argv_t.lval(vm)

# Auto alloc with the MemStr.from_str helper
MemStrAnsi = Str().lval
argv[0].val = MemStrAnsi.from_str(vm, "./my-program").get_addr()
argv[1].val = MemStrAnsi.from_str(vm, "arg1").get_addr()
argv[2].val = MemStrAnsi.from_str(vm, "27").get_addr()
argv[3].val = 0

# If you changed your mind on the second arg, you could do:
argv[2].deref.val = "42"

print("An argv instance:", repr(argv))
print("argv values:", repr([val.deref.val for val in argv[:-1]]))
print()

print("See test/core/types.py and the miasm.core.types module doc for ")
print("more information.")

