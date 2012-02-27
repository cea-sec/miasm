from miasm.arch.ia32_sem import *
from miasm.expression.expression_helper import *

print 'simple expression simplification demo'
print

a = ExprId('eax')
b = ExprId('ebx')
c = a + b
d = c - a
print d
# ((eax + ebx) - eax)
print "=>", expr_simp(d)
print
# ebx
e = ExprInt(uint32(0x12)) + ExprInt(uint32(0x30)) - a
print e
# ((0x12 + 0x30) - eax)
print "=>",  expr_simp(e)
# (0x42 - eax)
