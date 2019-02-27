from __future__ import print_function
from miasm.arch.x86.arch import mn_x86
from miasm.arch.x86.regs import EDX
from miasm.core.locationdb import LocationDB

loc_db = LocationDB()
l = mn_x86.fromstring('MOV EAX, EBX', loc_db, 32)
print("instruction:", l)
print("arg:", l.args[0])
x = mn_x86.asm(l)
print(x)
l.args[0] = EDX
y = mn_x86.asm(l)
print(y)
print(mn_x86.dis(y[0], 32))
