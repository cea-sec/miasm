from __future__ import print_function
from miasm.expression.expression import *

print("""
Simple expression manipulation demo
""")

# define 2 ID
a = ExprId('eax', 32)
b = ExprId('ebx', 32)
print(a, b)
# eax ebx

# add those ID
c = ExprOp('+', a, b)
print(c)
# (eax + ebx)

# + automatically generates ExprOp('+', a, b)
c = a + b
print(c)
# (eax + ebx)

# ax is a slice of eax
ax = a[:16]
print(ax)
# eax[0:16]

# memory deref
d = ExprMem(c, 32)
print(d)
# @32[(eax + ebx)]
