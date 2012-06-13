from miasm.expression.expression import *
from miasm.expression.expression_helper import *
import os

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

a = ExprId('a')
b = ExprId('b')
c = ExprId('c')
d = ExprId('d')


x = ExprMem(a+b+ExprInt32(0x42))

def replace_expr(e):
    #print 'visit', e
    dct = {c+ExprInt32(0x42):d,
           a+b:c,}
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


z = ExprCompose([(a[5:9], 0, 8), (b, 8, 24), (x, 24, 32)])
print z
print z.copy()
print z[:31].copy().visit(replace_expr)

print 'replace'
print x.replace_expr({c+ExprInt32(0x42):d,
                      a+b:c,})
print z.replace_expr({c+ExprInt32(0x42):d,
                      a+b:c,})


u = z.copy()
print u
u.args[-1][0].arg.args[1].arg = uint32(0x45)
print u
print z
print u == z

to_test = [(ExprInt32(5)+c+a+b-a+ExprInt32(1)-ExprInt32(5)),
           a+b+c-a-b-c+a,
           a+a+b+c-(a+(b+c)),
           c^b^a^c^b,
           a^ExprInt32(0),
           (a+b)-b,
           -(ExprInt32(0)-((a+b)-b)),

           ExprOp('<<<', a, ExprInt32(32)),
           ExprOp('>>>', a, ExprInt32(32)),
           ExprOp('>>>', a, ExprInt32(0)),
           ExprOp('<<', a, ExprInt32(0)),

           ExprOp('<<<', a, ExprOp('<<<', b, c)),
           ExprOp('<<<', ExprOp('<<<', a, b), c),
           ExprOp('<<<', ExprOp('>>>', a, b), c),
           ExprOp('>>>', ExprOp('<<<', a, b), c),
           ExprOp('>>>', ExprOp('<<<', a, b), b),


           ExprOp('>>>', ExprOp('<<<', a, ExprInt32(10)), ExprInt32(2)),

           ExprOp('>>>', ExprOp('<<<', a, ExprInt32(10)), ExprInt32(2)) ^ ExprOp('>>>', ExprOp('<<<', a, ExprInt32(10)), ExprInt32(2)),
           ExprOp(">>", (a & ExprInt32(0xF)), ExprInt32(0x15)),
           ExprOp("==", ExprInt32(12), ExprInt32(10)),
           ExprOp("==", ExprInt32(12), ExprInt32(12)),
           ExprOp("==", a|ExprInt32(12), ExprInt32(0)),
           ExprOp("==", a|ExprInt32(12), ExprInt32(14)),
           ExprOp("parity", ExprInt32(0xf)),
           ExprOp("parity", ExprInt32(0xe)),
           ExprInt32(0x4142)[:32],
           ExprInt32(0x4142)[:8],
           ExprInt32(0x4142)[8:16],
           a[:32],
           a[:8][:8],
           a[:16][:8],
           a[8:16][:8],
           a[8:32][:8],
           a[:16][8:16],
           ExprCompose([(a, 0, 32)]),
           ExprCompose([(a[:16], 0, 16)]),
           ExprCompose([(a[:16], 0, 16), (a, 16, 32)]),
           ExprCompose([(a[:16], 0, 16), (a[16:32], 16, 32)]),

           ExprMem(a)[:32],
           ExprMem(a)[:16],
           ]


for e in to_test:
    print "#"*80
    print e
    print e.visit(expr_simp)

