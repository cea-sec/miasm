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

to_test = [(ExprInt32(1)-ExprInt32(1), ExprInt32(0)),
           ((ExprInt32(5)+c+a+b-a+ExprInt32(1)-ExprInt32(5)),b+c+ExprInt32(1)),
           (a+b+c-a-b-c+a,a),
           (a+a+b+c-(a+(b+c)),a),
           (c^b^a^c^b,a),
           (a^ExprInt32(0),a),
           ((a+b)-b,a),
           (-(ExprInt32(0)-((a+b)-b)),a),

           (ExprOp('<<<', a, ExprInt32(32)),a),
           (ExprOp('>>>', a, ExprInt32(32)),a),
           (ExprOp('>>>', a, ExprInt32(0)),a),
           (ExprOp('<<', a, ExprInt32(0)),a),

           (ExprOp('<<<', a, ExprOp('<<<', b, c)),
            ExprOp('<<<', a, ExprOp('<<<', b, c))),
           (ExprOp('<<<', ExprOp('<<<', a, b), c),
            ExprOp('<<<', ExprOp('<<<', a, b), c)),
           (ExprOp('<<<', ExprOp('>>>', a, b), c),
            ExprOp('<<<', ExprOp('>>>', a, b), c)),
           (ExprOp('>>>', ExprOp('<<<', a, b), c),
            ExprOp('>>>', ExprOp('<<<', a, b), c)),
           (ExprOp('>>>', ExprOp('<<<', a, b), b),
            ExprOp('>>>', ExprOp('<<<', a, b), b)),


           (ExprOp('>>>', ExprOp('<<<', a, ExprInt32(10)), ExprInt32(2)),
            ExprOp('<<<', a, ExprInt32(8))),

           (ExprOp('>>>', ExprOp('<<<', a, ExprInt32(10)), ExprInt32(2)) ^ ExprOp('>>>', ExprOp('<<<', a, ExprInt32(10)), ExprInt32(2)),
            ExprInt32(0)),
           (ExprOp(">>", (a & ExprInt32(0xF)), ExprInt32(0x15)),
            ExprInt32(0)),
           (ExprOp("==", ExprInt32(12), ExprInt32(10)), ExprInt32(0)),
           (ExprOp("==", ExprInt32(12), ExprInt32(12)), ExprInt32(1)),
           (ExprOp("==", a|ExprInt32(12), ExprInt32(0)),ExprInt32(0)),
           (ExprOp("==", a|ExprInt32(12), ExprInt32(14)),
            ExprOp("==", a|ExprInt32(12), ExprInt32(14))),
           (ExprOp("parity", ExprInt32(0xf)), ExprInt32(1)),
           (ExprOp("parity", ExprInt32(0xe)), ExprInt32(0)),
           (ExprInt32(0x4142)[:32],ExprInt32(0x4142)),
           (ExprInt32(0x4142)[:8],ExprInt8(0x42)),
           (ExprInt32(0x4142)[8:16],ExprInt8(0x41)),
           (a[:32], a),
           (a[:8][:8],a[:8]),
           (a[:16][:8],a[:8]),
           (a[8:16][:8],a[8:16]),
           (a[8:32][:8],a[8:16]),
           (a[:16][8:16],a[8:16]),
           (ExprCompose([(a, 0, 32)]),a),
           (ExprCompose([(a[:16], 0, 16)]), a[:16]),
           (ExprCompose([(a[:16], 0, 16), (a, 16, 32)]),
            ExprCompose([(a[:16], 0, 16), (a, 16, 32)]),),
           (ExprCompose([(a[:16], 0, 16), (a[16:32], 16, 32)]), a),

           (ExprMem(a)[:32], ExprMem(a)),
           (ExprMem(a)[:16], ExprMem(a, size=16)),

           (ExprCond(ExprInt32(1), a, b), a),
           (ExprCond(ExprInt32(0), b, a), a),

           (ExprInt32(0x80000000)[31:32], ExprInt32(1)),
           (ExprCompose([(ExprInt16(0x1337)[:8], 0, 8),(ExprInt16(0x1337)[8:16], 8, 16)]),
            ExprInt16(0x1337)),

           (ExprCompose([(ExprInt32(0x1337beef)[8:16], 8, 16),
                        (ExprInt32(0x1337beef)[:8], 0, 8),
                        (ExprInt32(0x1337beef)[16:32], 16, 32)]),
            ExprInt32(0x1337BEEF)),


           ]


for e, e_check in to_test[:]:
    #
    print "#"*80
    e_check = expr_simp(e_check)
    print "#"*80
    print str(e), str(e_check)
    e_new = expr_simp(e)
    print "orig", str(e), "new", str(e_new), "check", str(e_check)
    rez = e_new == e_check
    if not rez:
        fdsfds
