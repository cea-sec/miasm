from miasm.analysis.data_flow import State
from miasm.expression.expression import *

"""
Test memory interferences

A memory interference may appear when two ExprMem objects relate to the same area of memory: editing one may impact the other.
"""

a32 = ExprId('a', 32)
b32 = ExprId('b', 32)

a64 = ExprId('a', 64)
b64 = ExprId('b', 64)

mem_a32_32 = ExprMem(a32, 32)
mem_b32_32 = ExprMem(b32, 32)

mem_a64_32 = ExprMem(a64, 32)

mem_a32_m1_8 = ExprMem(a32 + ExprInt(-1, 32), 8)
mem_a32_p0_8 = ExprMem(a32, 8)
mem_a32_p1_8 = ExprMem(a32 + ExprInt(1, 32), 8)
mem_a32_p2_8 = ExprMem(a32 + ExprInt(2, 32), 8)
mem_a32_p3_8 = ExprMem(a32 + ExprInt(3, 32), 8)
mem_a32_p4_8 = ExprMem(a32 + ExprInt(4, 32), 8)


mem_a32_m4_32 = ExprMem(a32 + ExprInt(-4, 32), 32)
mem_a32_m3_32 = ExprMem(a32 + ExprInt(-3, 32), 32)
mem_a32_m2_32 = ExprMem(a32 + ExprInt(-2, 32), 32)
mem_a32_m1_32 = ExprMem(a32 + ExprInt(-1, 32), 32)
mem_a32_p0_32 = ExprMem(a32, 32)
mem_a32_p1_32 = ExprMem(a32 + ExprInt(1, 32), 32)
mem_a32_p2_32 = ExprMem(a32 + ExprInt(2, 32), 32)
mem_a32_p3_32 = ExprMem(a32 + ExprInt(3, 32), 32)
mem_a32_p4_32 = ExprMem(a32 + ExprInt(4, 32), 32)


mem_a64_m4_32 = ExprMem(a64 + ExprInt(-4, 64), 32)
mem_a64_m3_32 = ExprMem(a64 + ExprInt(-3, 64), 32)
mem_a64_m2_32 = ExprMem(a64 + ExprInt(-2, 64), 32)
mem_a64_m1_32 = ExprMem(a64 + ExprInt(-1, 64), 32)
mem_a64_p0_32 = ExprMem(a64, 32)
mem_a64_p1_32 = ExprMem(a64 + ExprInt(1, 64), 32)
mem_a64_p2_32 = ExprMem(a64 + ExprInt(2, 64), 32)
mem_a64_p3_32 = ExprMem(a64 + ExprInt(3, 64), 32)
mem_a64_p4_32 = ExprMem(a64 + ExprInt(4, 64), 32)


state = State()


assert state.may_interfer(set([mem_a32_32]), mem_b32_32) == True
assert state.may_interfer(set([mem_b32_32]), mem_a32_32) == True

# Test 8 bit accesses
assert state.may_interfer(set([mem_a32_m1_8]), mem_a32_32) == False
assert state.may_interfer(set([mem_a32_p0_8]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_p1_8]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_p2_8]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_p3_8]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_p4_8]), mem_a32_32) == False

assert state.may_interfer(set([mem_a32_32]), mem_a32_m1_8) == False
assert state.may_interfer(set([mem_a32_32]), mem_a32_p0_8) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_p1_8) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_p2_8) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_p3_8) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_p4_8) == False


# Test 32 bit accesses
assert state.may_interfer(set([mem_a32_m4_32]), mem_a32_32) == False
assert state.may_interfer(set([mem_a32_m3_32]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_m2_32]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_m1_32]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_p0_32]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_p1_32]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_p2_32]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_p3_32]), mem_a32_32) == True
assert state.may_interfer(set([mem_a32_p4_32]), mem_a32_32) == False

assert state.may_interfer(set([mem_a32_32]), mem_a32_m4_32) == False
assert state.may_interfer(set([mem_a32_32]), mem_a32_m3_32) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_m2_32) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_m1_32) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_p0_32) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_p1_32) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_p2_32) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_p3_32) == True
assert state.may_interfer(set([mem_a32_32]), mem_a32_p4_32) == False

# Test 32 bit accesses with 64 bit memory address
assert state.may_interfer(set([mem_a64_m4_32]), mem_a64_32) == False
assert state.may_interfer(set([mem_a64_m3_32]), mem_a64_32) == True
assert state.may_interfer(set([mem_a64_m2_32]), mem_a64_32) == True
assert state.may_interfer(set([mem_a64_m1_32]), mem_a64_32) == True
assert state.may_interfer(set([mem_a64_p0_32]), mem_a64_32) == True
assert state.may_interfer(set([mem_a64_p1_32]), mem_a64_32) == True
assert state.may_interfer(set([mem_a64_p2_32]), mem_a64_32) == True
assert state.may_interfer(set([mem_a64_p3_32]), mem_a64_32) == True
assert state.may_interfer(set([mem_a64_p4_32]), mem_a64_32) == False

assert state.may_interfer(set([mem_a64_32]), mem_a64_m4_32) == False
assert state.may_interfer(set([mem_a64_32]), mem_a64_m3_32) == True
assert state.may_interfer(set([mem_a64_32]), mem_a64_m2_32) == True
assert state.may_interfer(set([mem_a64_32]), mem_a64_m1_32) == True
assert state.may_interfer(set([mem_a64_32]), mem_a64_p0_32) == True
assert state.may_interfer(set([mem_a64_32]), mem_a64_p1_32) == True
assert state.may_interfer(set([mem_a64_32]), mem_a64_p2_32) == True
assert state.may_interfer(set([mem_a64_32]), mem_a64_p3_32) == True
assert state.may_interfer(set([mem_a64_32]), mem_a64_p4_32) == False
