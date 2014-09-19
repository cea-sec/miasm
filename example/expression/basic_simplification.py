from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp

print """
Simple expression simplification demo
"""


a = ExprId('eax')
b = ExprId('ebx')

exprs = [a + b - a,
         ExprInt32(0x12) + ExprInt32(0x30) - a,
         ExprCompose([(a[:8], 0, 8),
                      (a[8:16], 8, 16)])]

for e in exprs:
    print '*' * 40
    print 'original expression:', e
    print "simplified:", expr_simp(e)
