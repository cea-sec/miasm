#
# Expression simplification regression tests  #
#
from pdb import pm
from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp, ExpressionSimplifier
from miasm2.expression.simplifications_cond import ExprOp_inf_signed, ExprOp_inf_unsigned, ExprOp_equal

# Define example objects
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

# Define tests: (expression to simplify, expected value)
to_test = [(ExprInt32(1) - ExprInt32(1), ExprInt32(0)),
           ((ExprInt32(5) + c + a + b - a + ExprInt32(1) - ExprInt32(5)),
            b + c + ExprInt32(1)),
           (a + b + c - a - b - c + a, a),
           (a + a + b + c - (a + (b + c)), a),
           (c ^ b ^ a ^ c ^ b, a),
           (a ^ ExprInt32(0), a),
           ((a + b) - b, a),
           (-(ExprInt32(0) - ((a + b) - b)), a),

           (ExprOp('<<<', a, ExprInt32(32)), a),
           (ExprOp('>>>', a, ExprInt32(32)), a),
           (ExprOp('>>>', a, ExprInt32(0)), a),
           (ExprOp('<<', a, ExprInt32(0)), a),

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
           (ExprOp(">>", (ExprInt32(0x12345678)), ExprInt32(0x4)),
            ExprInt32(0x1234567)),
           (ExprOp("a>>", (ExprInt32(0x12345678)), ExprInt32(0x4)),
            ExprInt32(0x1234567)),
           (ExprOp("a>>", (ExprInt32(0xF1234567)), ExprInt32(0x4)),
            ExprInt32(0xFF123456)),
           (ExprOp("a>>", (ExprInt32(0xF1234567)), ExprInt32(28)),
            ExprInt32(0xFFFFFFFF)),
           (ExprOp("parity", ExprInt32(0xf)), ExprInt1(1)),
           (ExprOp("parity", ExprInt32(0xe)), ExprInt1(0)),
           (ExprInt32(0x4142)[:32], ExprInt32(0x4142)),
           (ExprInt32(0x4142)[:8], ExprInt8(0x42)),
           (ExprInt32(0x4142)[8:16], ExprInt8(0x41)),
           (a[:32], a),
           (a[:8][:8], a[:8]),
           (a[:16][:8], a[:8]),
           (a[8:16][:8], a[8:16]),
           (a[8:32][:8], a[8:16]),
           (a[:16][8:16], a[8:16]),
           (ExprCompose([(a, 0, 32)]), a),
           (ExprCompose([(a[:16], 0, 16)]), a[:16]),
           (ExprCompose([(a[:16], 0, 16), (a[:16], 16, 32)]),
            ExprCompose([(a[:16], 0, 16), (a[:16], 16, 32)]),),
           (ExprCompose([(a[:16], 0, 16), (a[16:32], 16, 32)]), a),

           (ExprMem(a)[:32], ExprMem(a)),
           (ExprMem(a)[:16], ExprMem(a, size=16)),

           (ExprCond(ExprInt32(1), a, b), a),
           (ExprCond(ExprInt32(0), b, a), a),

           (ExprInt32(0x80000000)[31:32], ExprInt1(1)),
           (ExprCompose([
               (ExprInt16(0x1337)[
                   :8], 0, 8), (ExprInt16(0x1337)[8:16], 8, 16)]),
            ExprInt16(0x1337)),

           (ExprCompose([(ExprInt32(0x1337beef)[8:16], 8, 16),
                        (ExprInt32(0x1337beef)[:8], 0, 8),
                        (ExprInt32(0x1337beef)[16:32], 16, 32)]),
            ExprInt32(0x1337BEEF)),
           (ExprCond(a,
                     ExprCond(a,
                              b,
                              c),
                     d), ExprCond(a, b, d)),
           ((a & b & ExprInt32(0x12))[31:32], ExprInt1(0)),

           (ExprCompose([
               (ExprCond(a, ExprInt16(0x10), ExprInt16(0x20)), 0, 16),
    (ExprInt16(0x1337), 16, 32)]),
               ExprCond(a, ExprInt32(0x13370010), ExprInt32(0x13370020))),
    (ExprCond(ExprCond(a, ExprInt1(0), ExprInt1(1)), b, c),
     ExprCond(a, c, b)),
    (ExprCond(a, ExprInt32(0x10), ExprInt32(0x20)) + ExprInt32(0x13370000),
     ExprCond(a, ExprInt32(0x13370010), ExprInt32(0x13370020))),

    (ExprCond(a, ExprInt32(0x10), ExprInt32(0x20)) + ExprCond(a, ExprInt32(0x13370000), ExprInt32(0x13380000)),
     ExprCond(a, ExprInt32(0x13370010), ExprInt32(0x13380020))),
    (-ExprCond(a, ExprInt32(0x1), ExprInt32(0x2)),
     ExprCond(a, ExprInt32(-0x1), ExprInt32(-0x2))),
    (ExprOp('*', a, b, c, ExprInt32(0x12))[0:17],
     ExprOp(
     '*', a[0:17], b[0:17], c[0:17], ExprInt(mod_size2uint[17](0x12)))),
    (ExprOp('*', a, ExprInt32(0xffffffff)),
     -a),
    (ExprOp('*', -a, -b, c, ExprInt32(0x12)),
     ExprOp('*', a, b, c, ExprInt32(0x12))),
    (ExprOp('*', -a, -b, -c, ExprInt32(0x12)),
     ExprOp('*', -a, b, c, ExprInt32(0x12))),
    (a | ExprInt32(0xffffffff),
     ExprInt32(0xffffffff)),
    (ExprCond(a, ExprInt32(1), ExprInt32(2)) * ExprInt32(4),
     ExprCond(a, ExprInt32(4), ExprInt32(8))),
    (ExprCond(a, b, c) + ExprCond(a, d, e),
     ExprCond(a, b + d, c + e)),
    (ExprCond(a, b, c) * ExprCond(a, d, e),
     ExprCond(a, b * d, c * e)),

    (ExprCond(a, ExprInt32(8), ExprInt32(4)) >> ExprInt32(1),
     ExprCond(a, ExprInt32(4), ExprInt32(2))),

    (ExprCond(a, b, c) >> ExprCond(a, d, e),
     ExprCond(a, b >> d, c >> e)),

    (a & b & ExprInt_fromsize(a.size, -1), a & b),
    (a | b | ExprInt_fromsize(a.size, -1),
     ExprInt_fromsize(a.size, -1)),
]

for e, e_check in to_test[:]:
    #
    print "#" * 80
    e_check = expr_simp(e_check)
    # print str(e), str(e_check)
    e_new = expr_simp(e)
    print "original: ", str(e), "new: ", str(e_new)
    rez = e_new == e_check
    if not rez:
        raise ValueError(
            'bug in expr_simp simp(%s) is %s and should be %s' % (e, e_new, e_check))

# Test conds

to_test = [
    (((a - b) ^ ((a ^ b) & ((a - b) ^ a))).msb(),
     ExprOp_inf_signed(a, b)),
    ((((a - b) ^ ((a ^ b) & ((a - b) ^ a))) ^ a ^ b).msb(),
     ExprOp_inf_unsigned(a, b)),
    (ExprOp_inf_unsigned(ExprInt32(-1), ExprInt32(3)), ExprInt1(0)),
    (ExprOp_inf_signed(ExprInt32(-1), ExprInt32(3)), ExprInt1(1)),
    (ExprOp_inf_unsigned(a, b) ^ (a ^ b).msb(), ExprOp_inf_signed(a, b)),
    (ExprOp_inf_signed(a, b) ^ (a ^ b).msb(), ExprOp_inf_unsigned(a, b)),
    (ExprOp_equal(ExprInt32(12), ExprInt32(10)), ExprInt1(0)),
    (ExprOp_equal(ExprInt32(12), ExprInt32(12)), ExprInt1(1)),
    (ExprOp_equal(ExprInt32(12), ExprInt32(-12)), ExprInt1(0)),
    (ExprCond(a - b, ExprInt1(0), ExprInt1(1)), ExprOp_equal(a, b)),
    (ExprCond(a + b, ExprInt1(0), ExprInt1(1)), ExprOp_equal(a, -b)),
]

expr_simp_cond = ExpressionSimplifier()
expr_simp.enable_passes(ExpressionSimplifier.PASS_COND)


for e, e_check in to_test[:]:
    #
    print "#" * 80
    e_check = expr_simp(e_check)
    # print str(e), str(e_check)
    e_new = expr_simp(e)
    print "original: ", str(e), "new: ", str(e_new)
    rez = e_new == e_check
    if not rez:
        raise ValueError(
            'bug in expr_simp simp(%s) is %s and should be %s' % (e, e_new, e_check))



x = ExprId('x')
y = ExprId('y')
z = ExprId('z')
a = ExprId('a')
b = ExprId('b')
c = ExprId('c')


jra = ExprId('jra')
jrb = ExprId('jrb')
jrint1 = ExprId('jrint1')


e1 = ExprMem((a & ExprInt32(0xFFFFFFFC)) + ExprInt32(0x10), 32)
e2 = ExprMem((a & ExprInt32(0xFFFFFFFC)) + b, 32)
e3 = (a ^ b ^ ((a ^ b) & (b ^ (b - a))) ^ (b - a)).canonize()

match_tests = [
    (MatchExpr(ExprInt32(12), a, [a]), {a: ExprInt32(12)}),
    (MatchExpr(x, a, [a]), {a: x}),
    (MatchExpr(x + y, a, [a]), {a: x + y}),
    (MatchExpr(x + y, a + y, [a]), {a: x}),
    (MatchExpr(x + y, x + a, [a]), {a: y}),
    (MatchExpr(x + y, a + b, [a, b]), {a: x, b: y}),
    (MatchExpr(x + ExprInt32(12), a + b, [a, b]), {a: x, b: ExprInt32(12)}),
    (MatchExpr(ExprMem(x), a, [a]), {a: ExprMem(x)}),
    (MatchExpr(ExprMem(x), ExprMem(a), [a]), {a: x}),
    (MatchExpr(x[0:8], a, [a]), {a: x[0:8]}),
    (MatchExpr(x[0:8], a[0:8], [a]), {a: x}),
    (MatchExpr(ExprCond(x, y, z), a, [a]), {a: ExprCond(x, y, z)}),
    (MatchExpr(ExprCond(x, y, z),
               ExprCond(a, b, c), [a, b, c]),
     {a: x, b: y, c: z}),
    (MatchExpr(ExprCompose([(x[:8], 0, 8), (y[:8], 8, 16)]), a, [a]),
     {a: ExprCompose([(x[:8], 0, 8), (y[:8], 8, 16)])}),
    (MatchExpr(ExprCompose([(x[:8], 0, 8), (y[:8], 8, 16)]),
               ExprCompose([(a[:8], 0, 8), (b[:8], 8, 16)]), [a, b]),
     {a: x, b: y}),
    (MatchExpr(e1, e2, [b]), {b: ExprInt32(0x10)}),
    (MatchExpr(e3,
               (((jra ^ jrb) & (jrb ^ jrint1))
                ^ jra ^ jrb ^ jrint1).canonize(),
               [jra, jrb, jrint1]),
     {jra: a, jrb: b, jrint1: b - a}),
]

for test, res in match_tests:
    assert(test == res)


get_tests = [
    (ExprAff(ExprMem(a), ExprMem(b)).get_r(True), set([a, b, ExprMem(b)])),
    (ExprAff(ExprMem(a), ExprMem(b)).get_w(), set([ExprMem(a)])),
    (ExprAff(ExprMem(ExprMem(a)), ExprMem(b))
     .get_r(True), set([a, b, ExprMem(b), ExprMem(a)])),
]


for test, res in get_tests:
    assert(test == res)


to_test = [(a + b, b + a),
           (a + m, m + a),
           ((a[:8] + s), (s + a[:8])),
           ((m[:8] + s), (s + m[:8])),
           ((i1 + i2), (i2 + i1)),
           ((a + i2), (i2 + a)),
           ((m + i2), (i2 + m)),
           ((s + i2[:8]), (i2[:8] + s)),
           (o, o2),
           (ExprOp('+', *l), ExprOp('+', *l2)),
           ]

for x, y in to_test:
    x, y = x.canonize(), y.canonize()

    assert(x == y)
    assert(str(x) == str(y))
    print x

print 'all tests ok'
