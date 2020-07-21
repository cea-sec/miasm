from __future__ import print_function

from miasm.core.modint import *

a = uint8(0x42)
b = uint8(0xFF)
c = uint8(0x4)

d = uint1(0)
e = uint1(1)

f = uint8(0x1)
g = int8(-3)

print(a, b, c)
print(a + b, a + c, b + c)
print(a == a, a == b, a == 0x42, a == 0x78)
print(a != b, a != a)
print(d, e)
print(d + e, d + d, e + e, e + e + e, e + 0x11)

assert(f == 1)
assert(f + 1 == 2)
assert(2 == f + 1)
assert(f + 0xff == 0)
assert(f & 0 == 0)
assert(f & 0xff == f)
assert(0xff & f == f)
assert(f // 1 == f)
assert(1 // f == f)
assert(int(f) == 1)
assert(int(f) == 1)
assert(~f == 0xfe)
assert(f << 1 == 2)
assert(f << 8 == 0)
assert(1 << f == 2)
assert(0x80 << f == 0)
assert(f % 2 == f)
assert(f % 1 == 0)
assert(2 % f == 0)
assert(f * 2 == 2)
assert(2 * f == 2)
assert(f * f == 1)
assert(f * uint8(0x80) == 0x80)
assert(-f == 0xff)
assert(f | f == f)
assert(f | 0 == f)
assert(2 | f == 3)
assert(f >> 0 == f)
assert(f >> 1 == 0)
assert(0x10 >> f == 0x8)
assert(0x100 >> f == 0x80)  # XXXX
assert(0x1000 >> f == 0x0)  # XXXX
assert(f ^ f == 0)
assert(f ^ 0 == f)
assert(0 ^ f == f)
assert(1 ^ f == 0)
assert(c // g == -1)
assert(c // -3 == -1)
assert(c % g == 1)
assert(c % -3 == 1)

print(e + c, c + e, c - e, e - c)
print(1000 * a)
print(hex(a))

define_int(128)
define_uint(128)
h = uint128(0x11223344556677889900AABBCCDDEEFF)
i = int128(-0x9900AABBCCDDEEFF1122334455667788)

assert(i //h == 6)
assert(i % h == 0x3221aa32bb43cd58d9cc54dd65ee7e)

