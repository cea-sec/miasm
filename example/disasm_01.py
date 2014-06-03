from miasm2.arch.x86.arch import mn_x86
from miasm2.arch.x86.regs import *

l = mn_x86.fromstring('MOV EAX, EBX', 32)
print "instruction:", l
print "arg:", l.args[0]
x = mn_x86.asm(l)
print x
l.args[0] = EDX
y = mn_x86.asm(l)
print y
print mn_x86.dis(y[0], 32)
