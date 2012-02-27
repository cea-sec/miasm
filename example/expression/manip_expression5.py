from miasm.expression.expression import *

print 'simple expression canonization demo'

# define 2 ID
a = ExprId('eax', 32)
b = ExprId('ebx', 32)
print a, b
# eax ebx

# add those ID
c = ExprOp('+', a, b)
print c
# (eax + ebx)

# + automaticaly generates ExprOp('+', a, b)
c = a + b
print c
# (eax + ebx)

# ax is a slice of eax
ax = a[:16]
print ax
# eax[0:16]

#memory deref
d = ExprMem(c, 32)
print d
# @32[(eax + ebx)]

print (a+b).canonize()
print (b+a).canonize()

m = ExprMem(a)

print (a+m).canonize()
print (m+a).canonize()

s = a[:8]

print (a+s).canonize()
print (s+a).canonize()

print (m+s).canonize()
print (s+m).canonize()

i1 = ExprInt(uint32(0x1))
i2 = ExprInt(uint32(0x2))

print (i1+i2).canonize()
print (i2+i1).canonize()

print (a+i2).canonize()
print (i2+a).canonize()

print (m+i2).canonize()
print (i2+m).canonize()

print (s+i2).canonize()
print (i2+s).canonize()

cc = ExprCond(a, b, c)

o = ExprCompose([ExprSliceTo(a[:8], 8, 16),
                 ExprSliceTo(a[8:16], 0, 8)])
print o
print o.canonize()

o = ExprCompose([ExprSliceTo(a[8:16], 0, 8),
                 ExprSliceTo(a[:8], 8, 16)])
print o
print o.canonize()

print ExprMem(o).canonize()

l = [a, b, c, m, s, i1, i2, o]
print l
print ExprOp('+', *l).canonize()
l.reverse()
print l
print ExprOp('+', *l).canonize()

