from __future__ import print_function

import time
from pdb import pm
from miasm.core.utils import decode_hex, encode_hex
from miasm.arch.msp430.arch import *
from miasm.core.locationdb import LocationDB

loc_db = LocationDB()

def h2i(s):
    return decode_hex(s.replace(' ', ''))


def u16swap(i):
    return struct.unpack('<H', struct.pack('>H', i))[0]


reg_tests_msp = [
    ("4456    mov.w      SP, R4",
     "0441"),
    ("4d4f    mov.b      R13, R15",
     "4f4d"),
    ("49fe    mov.w      @R13, R9",
     "294d"),
    ("4982    mov.w      0x10(R14), R13",
     "1d4e1000"),
    ("4972    mov.w      R14, 0x0(SP)",
     "814e0000"),
    ("46de    mov.w      0x2(R14), 0x2(R13)",
     "9d4e02000200"),
    ("469e    mov.w      @0x2400, R11",
     "1b420024"),
    ("4c14    mov.w      0x4A96, R15",
     "3f40964a"),
    ("47c0    mov.w      0x1, R8",
     "1843"),
    ("48fc    mov.w      0x2, R10",
     "2a43"),
    ("44fe    mov.w      0x4, R7",
     "2742"),
    ("4a28    mov.w      0xFFFF, R15",
     "3f43"),
    ("4416    mov.w      R5, @0x15C",
     "82455c01"),

    ("4a22    add.w      R11, R15",
     "0f5b"),
    ("448e    sub.w      R15, SP",
     "018f"),
    ("4474    cmp.b      @R15, R13",
     "6d9f"),
    ("46a8    bit.w      0x1, R13",
     "1db3"),
    ("440a    bis.w      0x5A08, R5",
     "35d0085a"),
    ("4c1a    xor.w      R15, R10",
     "0aef"),
    ("4408    and.b      0xFF, R5",
     "75f3"),


    ("4cf0    push.w     SR",
     "0212"),
    ("4d6e    push.w     0x0",
     "0312"),
    ("45dc    push.w     0x2(R11)",
     "1b120200"),
    ("49cc    push.w     R11",
     "0b12"),

    ("443a    call       0x4B66",
     "b012664b"),

    ("4442    jmp        0xFFFC",
     "fd3f"),
    ("4422    jnz        0xFFF4",
     "f923"),

    ("xxxx    mov.b      @R13+, 0x0(R14)",
     "fe4d0000"),

    ("4a36    mov.w      @SP+, PC",
     "3041"),


]

ts = time.time()

for s, l in reg_tests_msp:
    print("-" * 80)
    s = s[8:]
    b = h2i((l))
    print(repr(b))
    mn = mn_msp430.dis(b, None)
    print([str(x) for x in mn.args])
    print(s)
    print(mn)
    assert(str(mn) == s)
    l = mn_msp430.fromstring(s, loc_db, None)
    assert(str(l) == s)
    a = mn_msp430.asm(l)
    print([x for x in a])
    print(repr(b))
    assert(b in a)
    print(l.to_html())
