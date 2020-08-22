import sys
from miasm.core.locationdb import LocationDB

from miasm.analysis.machine import Machine
machine = Machine("x86_64")
loc_db = LocationDB()
jitter = machine.jitter(loc_db, sys.argv[1])

jitter.cpu.RAX = 16565615892967251934
assert jitter.cpu.RAX == 16565615892967251934

jitter.cpu.RAX = -1
assert jitter.cpu.RAX == 0xffffffffffffffff

jitter.cpu.RAX = -2
assert jitter.cpu.RAX == 0xfffffffffffffffe

jitter.cpu.EAX = -2
assert jitter.cpu.EAX == 0xfffffffe

jitter.cpu.RAX = -0xffffffffffffffff
assert jitter.cpu.RAX == 1

try:
        jitter.cpu.RAX = 0x1ffffffffffffffff
except TypeError:
        pass
else:
        raise Exception("Should see that 0x1ffffffffffffffff is too big for RAX")

try:
        jitter.cpu.RAX = 0x10000000000000000
except TypeError:
        pass
else:
        raise Exception("Should see that 0x10000000000000000 is too big for RAX")

jitter.cpu.EAX = -0xefffffff
assert jitter.cpu.EAX == 0x10000001

jitter.cpu.EAX = -0xFFFFFFFF
assert jitter.cpu.EAX == 1

try:
        jitter.cpu.EAX = -0x1ffffffff
except TypeError:
        pass
else:
        raise Exception("Should see that -0x1ffffffff is too big for EAX")
