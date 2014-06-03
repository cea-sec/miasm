from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp
from pdb import pm
import os

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

print """
Expression simplification demo.
(and regression test)
"""


a = ExprId('a')
b = ExprId('b')
c = ExprId('c')
d = ExprId('d')
e = ExprId('e')

m = ExprMem(a)
s = a[:8]

i1 = ExprInt(uint32(0x1))
i2 = ExprInt(uint32(0x2))
cc = ExprCond(a, b, c)

o = ExprCompose([(a[:8], 8, 16),
                 (a[8:16], 0, 8)])

o2 = ExprCompose([(a[8:16], 0, 8),
                 (a[:8], 8, 16)])

l = [a[:8], b[:8], c[:8], m[:8], s, i1[:8], i2[:8], o[:8]]
l2 = l[::-1]


x = ExprMem(a + b + ExprInt32(0x42))


def replace_expr(e):
    # print 'visit', e
    dct = {c + ExprInt32(0x42): d,
           a + b: c, }
    if e in dct:
        return dct[e]
    return e


print x
y = x.visit(replace_expr)
print y
print x.copy()
print y.copy()
print y == y.copy()
print repr(y), repr(y.copy())


z = ExprCompose([(a[5:5 + 8], 0, 8), (b[:16], 8, 24), (x[:8], 24, 32)])
print z
print z.copy()
print z[:31].copy().visit(replace_expr)

print 'replace'
print x.replace_expr({c + ExprInt32(0x42): d,
                      a + b: c, })
print z.replace_expr({c + ExprInt32(0x42): d,
                      a + b: c, })


u = z.copy()
print u
