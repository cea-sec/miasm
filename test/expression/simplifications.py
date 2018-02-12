#
# Expression simplification regression tests  #
#
from pdb import pm
from miasm2.expression.expression import *
from miasm2.expression.expression_helper import expr_cmpu, expr_cmps
from miasm2.expression.simplifications import expr_simp, ExpressionSimplifier
from miasm2.expression.simplifications_cond import ExprOp_inf_signed, ExprOp_inf_unsigned, ExprOp_equal

# Define example objects
a = ExprId('a')
b = ExprId('b')
c = ExprId('c')
d = ExprId('d')
e = ExprId('e')
f = ExprId('f', size=64)

m = ExprMem(a)
s = a[:8]

i0 = ExprInt(0, 32)
i1 = ExprInt(1, 32)
i2 = ExprInt(2, 32)
icustom = ExprInt(0x12345678, 32)
cc = ExprCond(a, b, c)

o = ExprCompose(a[8:16], a[:8])

o2 = ExprCompose(a[8:16], a[:8])

l = [a[:8], b[:8], c[:8], m[:8], s, i1[:8], i2[:8], o[:8]]
l2 = l[::-1]


x = ExprMem(a + b + ExprInt(0x42, 32))

# Define tests: (expression to simplify, expected value)
to_test = [(ExprInt(1, 32) - ExprInt(1, 32), ExprInt(0, 32)),
           ((ExprInt(5, 32) + c + a + b - a + ExprInt(1, 32) - ExprInt(5, 32)),
            ExprOp('+', b, c, ExprInt(1, 32))),
           (a + b + c - a - b - c + a, a),
           (a + a + b + c - (a + (b + c)), a),
           (c ^ b ^ a ^ c ^ b, a),
           (a ^ ExprInt(0, 32), a),
           ((a + b) - b, a),
           (-(ExprInt(0, 32) - ((a + b) - b)), a),

           (ExprOp('<<<', a, ExprInt(32, 32)), a),
           (ExprOp('>>>', a, ExprInt(32, 32)), a),
           (ExprOp('>>>', a, ExprInt(0, 32)), a),
           (ExprOp('<<', a, ExprInt(0, 32)), a),

           (ExprOp('<<<', a, ExprOp('<<<', b, c)),
            ExprOp('<<<', a, ExprOp('<<<', b, c))),
           (ExprOp('<<<', ExprOp('<<<', a, b), c),
            ExprOp('<<<', a, (b+c))),
           (ExprOp('<<<', ExprOp('>>>', a, b), c),
            ExprOp('>>>', a, (b-c))),
           (ExprOp('>>>', ExprOp('<<<', a, b), c),
            ExprOp('<<<', a, (b-c))),
           (ExprOp('>>>', ExprOp('<<<', a, b), b),
            a),
           (ExprOp(">>>", ExprInt(0x1000, 16), ExprInt(0x11, 16)),
            ExprInt(0x800, 16)),
           (ExprOp("<<<", ExprInt(0x1000, 16), ExprInt(0x11, 16)),
            ExprInt(0x2000, 16)),

           (ExprOp('>>>', ExprOp('<<<', a, ExprInt(10, 32)), ExprInt(2, 32)),
            ExprOp('<<<', a, ExprInt(8, 32))),

           (ExprOp('>>>', ExprOp('<<<', a, ExprInt(10, 32)), ExprInt(2, 32)) ^ ExprOp('>>>', ExprOp('<<<', a, ExprInt(10, 32)), ExprInt(2, 32)),
            ExprInt(0, 32)),
           (ExprOp(">>", (a & ExprInt(0xF, 32)), ExprInt(0x15, 32)),
            ExprInt(0, 32)),
           (ExprOp(">>", (ExprInt(0x12345678, 32)), ExprInt(0x4, 32)),
            ExprInt(0x1234567, 32)),
           (ExprOp("a>>", (ExprInt(0x12345678, 32)), ExprInt(0x4, 32)),
            ExprInt(0x1234567, 32)),
           (ExprOp("a>>", (ExprInt(0xF1234567, 32)), ExprInt(0x4, 32)),
            ExprInt(0xFF123456, 32)),
           (ExprOp("a>>", (ExprInt(0xF1234567, 32)), ExprInt(28, 32)),
            ExprInt(0xFFFFFFFF, 32)),
           (ExprOp("parity", ExprInt(0xf, 32)), ExprInt(1, 1)),
           (ExprOp("parity", ExprInt(0xe, 32)), ExprInt(0, 1)),
           (ExprInt(0x4142, 32)[:32], ExprInt(0x4142, 32)),
           (ExprInt(0x4142, 32)[:8], ExprInt(0x42, 8)),
           (ExprInt(0x4142, 32)[8:16], ExprInt(0x41, 8)),
           (a[:32], a),
           (a[:8][:8], a[:8]),
           (a[:16][:8], a[:8]),
           (a[8:16][:8], a[8:16]),
           (a[8:32][:8], a[8:16]),
           (a[:16][8:16], a[8:16]),
           (ExprCompose(a), a),
           (ExprCompose(a[:16]), a[:16]),
           (ExprCompose(a[:16], a[:16]),
            ExprCompose(a[:16], a[:16]),),
           (ExprCompose(a[:16], a[16:32]), a),

           (ExprMem(a)[:32], ExprMem(a)),
           (ExprMem(a)[:16], ExprMem(a, size=16)),

           (ExprCond(ExprInt(1, 32), a, b), a),
           (ExprCond(ExprInt(0, 32), b, a), a),

           (ExprInt(0x80000000, 32)[31:32], ExprInt(1, 1)),
           (ExprCompose(ExprInt(0x1337, 16)[:8], ExprInt(0x1337, 16)[8:16]),
            ExprInt(0x1337, 16)),

           (ExprCompose(ExprInt(0x1337beef, 32)[:8],
                        ExprInt(0x1337beef, 32)[8:16],
                        ExprInt(0x1337beef, 32)[16:32]),
            ExprInt(0x1337BEEF, 32)),
           (ExprCond(a,
                     ExprCond(a,
                              b,
                              c),
                     d), ExprCond(a, b, d)),
           ((a & b & ExprInt(0x12, 32))[31:32], ExprInt(0, 1)),

           (ExprCompose(
               ExprCond(a, ExprInt(0x10, 16), ExprInt(0x20, 16)),
               ExprInt(0x1337, 16)),
               ExprCond(a, ExprInt(0x13370010, 32), ExprInt(0x13370020, 32))),
    (ExprCond(ExprCond(a, ExprInt(0, 1), ExprInt(1, 1)), b, c),
     ExprCond(a, c, b)),
    (ExprCond(a, ExprInt(0x10, 32), ExprInt(0x20, 32)) + ExprInt(0x13370000, 32),
     ExprCond(a, ExprInt(0x13370010, 32), ExprInt(0x13370020, 32))),

    (ExprCond(a, ExprInt(0x10, 32), ExprInt(0x20, 32)) + ExprCond(a, ExprInt(0x13370000, 32), ExprInt(0x13380000, 32)),
     ExprCond(a, ExprInt(0x13370010, 32), ExprInt(0x13380020, 32))),
    (-ExprCond(a, ExprInt(0x1, 32), ExprInt(0x2, 32)),
     ExprCond(a, ExprInt(-0x1, 32), ExprInt(-0x2, 32))),
    (ExprOp('*', a, b, c, ExprInt(0x12, 32))[0:17],
     ExprOp(
     '*', a[0:17], b[0:17], c[0:17], ExprInt(0x12, 17))),
    (ExprOp('*', a, ExprInt(0x0, 32)),
     ExprInt(0x0, 32)),
    (ExprOp('&', a, ExprInt(0x0, 32)),
     ExprInt(0x0, 32)),
    (ExprOp('*', a, ExprInt(0xffffffff, 32)),
     -a),
    (ExprOp('*', -a, -b, c, ExprInt(0x12, 32)),
     ExprOp('*', a, b, c, ExprInt(0x12, 32))),
    (ExprOp('*', -a, -b, -c, ExprInt(0x12, 32)),
     - ExprOp('*', a, b, c, ExprInt(0x12, 32))),
     (ExprOp('**', ExprInt(2, 32), ExprInt(8, 32)), ExprInt(0x100, 32)),
     (ExprInt(2, 32)**ExprInt(8, 32), ExprInt(256, 32)),
    (a | ExprInt(0xffffffff, 32),
     ExprInt(0xffffffff, 32)),
    (ExprCond(a, ExprInt(1, 32), ExprInt(2, 32)) * ExprInt(4, 32),
     ExprCond(a, ExprInt(4, 32), ExprInt(8, 32))),
    (ExprCond(a, b, c) + ExprCond(a, d, e),
     ExprCond(a, b + d, c + e)),
    (ExprCond(a, b, c) * ExprCond(a, d, e),
     ExprCond(a, b * d, c * e)),

    (ExprCond(a, ExprInt(8, 32), ExprInt(4, 32)) >> ExprInt(1, 32),
     ExprCond(a, ExprInt(4, 32), ExprInt(2, 32))),

    (ExprCond(a, b, c) >> ExprCond(a, d, e),
     ExprCond(a, b >> d, c >> e)),

    (a & b & ExprInt(-1, a.size), a & b),
    (a | b | ExprInt(-1, a.size),
     ExprInt(-1, a.size)),
    (ExprOp('-', ExprInt(1, 8), ExprInt(0, 8)),
     ExprInt(1, 8)),

    (ExprCompose(a, ExprInt(0, 32)) << ExprInt(0x20, 64),
     ExprCompose(ExprInt(0, 32), a)),
    (ExprCompose(a, ExprInt(0, 32)) << ExprInt(0x10, 64),
     ExprCompose(ExprInt(0, 16), a, ExprInt(0, 16))),
    (ExprCompose(a, ExprInt(0, 32)) << ExprInt(0x30, 64),
     ExprCompose(ExprInt(0, 48), a[:0x10])),
    (ExprCompose(a, ExprInt(0, 32)) << ExprInt(0x11, 64),
     ExprCompose(ExprInt(0, 0x11), a, ExprInt(0, 0xF))),
    (ExprCompose(a, ExprInt(0, 32)) << ExprInt(0x40, 64),
     ExprInt(0, 64)),
    (ExprCompose(a, ExprInt(0, 32)) << ExprInt(0x50, 64),
     ExprInt(0, 64)),

    (ExprCompose(ExprInt(0, 32), a) >> ExprInt(0x20, 64),
     ExprCompose(a, ExprInt(0, 32))),
    (ExprCompose(ExprInt(0, 32), a) >> ExprInt(0x10, 64),
     ExprCompose(ExprInt(0, 16), a, ExprInt(0, 16))),
    (ExprCompose(ExprInt(0, 32), a) >> ExprInt(0x30, 64),
     ExprCompose(a[0x10:], ExprInt(0, 48))),
    (ExprCompose(ExprInt(0, 32), a) >> ExprInt(0x11, 64),
     ExprCompose(ExprInt(0, 0xf), a, ExprInt(0, 0x11))),
    (ExprCompose(ExprInt(0, 32), a) >> ExprInt(0x40, 64),
     ExprInt(0, 64)),
    (ExprCompose(ExprInt(0, 32), a) >> ExprInt(0x50, 64),
     ExprInt(0, 64)),


    (ExprCompose(a, b) << ExprInt(0x20, 64),
     ExprCompose(ExprInt(0, 32), a)),
    (ExprCompose(a, b) << ExprInt(0x10, 64),
     ExprCompose(ExprInt(0, 16), a, b[:16])),

    (ExprCompose(a, b) | ExprCompose(c, d),
     ExprCompose(a|c, b|d)),
    (ExprCompose(a, ExprInt(0, 32)) | ExprCompose(ExprInt(0, 32), d),
     ExprCompose(a, d)),
    (ExprCompose(f[:32], ExprInt(0, 32)) | ExprCompose(ExprInt(0, 32), f[32:]),
     f),
    ((ExprCompose(a, ExprInt(0, 32)) * ExprInt(0x123, 64))[32:64],
     (ExprCompose(a, ExprInt(0, 32)) * ExprInt(0x123, 64))[32:64]),

    (ExprInt(0x12, 32),
     ExprInt(0x12L, 32)),


    (ExprCompose(a, b, c)[:16],
     a[:16]),
    (ExprCompose(a, b, c)[16:32],
     a[16:]),
    (ExprCompose(a, b, c)[32:48],
     b[:16]),
    (ExprCompose(a, b, c)[48:64],
     b[16:]),
    (ExprCompose(a, b, c)[64:80],
     c[:16]),
    (ExprCompose(a, b, c)[80:],
     c[16:]),
    (ExprCompose(a, b, c)[80:82],
     c[16:18]),
    (ExprCompose(a, b, c)[16:48],
     ExprCompose(a[16:], b[:16])),
    (ExprCompose(a, b, c)[48:80],
     ExprCompose(b[16:], c[:16])),

    (ExprCompose(a[0:8], b[8:16], ExprInt(0x0L, 48))[12:32],
     ExprCompose(b[12:16], ExprInt(0, 16))
       ),

    (ExprCompose(ExprCompose(a[:8], ExprInt(0x0L, 56))[8:32]
                  &
                  ExprInt(0x1L, 24),
                  ExprInt(0x0L, 40)),
     ExprInt(0, 64)),

    (ExprCompose(ExprCompose(a[:8], ExprInt(0x0L, 56))[:8]
                 &
                 ExprInt(0x1L, 8),
                 (ExprInt(0x0L, 56))),
     ExprCompose(a[:8]&ExprInt(1, 8), ExprInt(0, 56))),

    (ExprCompose(ExprCompose(a[:8],
                             ExprInt(0x0L, 56))[:32]
                 &
                 ExprInt(0x1L, 32),
                 ExprInt(0x0L, 32)),
     ExprCompose(ExprCompose(ExprSlice(a, 0, 8),
                             ExprInt(0x0L, 24))
                 &
                 ExprInt(0x1L, 32),
                 ExprInt(0x0L, 32))
       ),
    (ExprCompose(a[:16], b[:16])[8:32],
     ExprCompose(a[8:16], b[:16])),
    ((a >> ExprInt(16, 32))[:16],
     a[16:32]),
    ((a >> ExprInt(16, 32))[8:16],
     a[24:32]),
    ((a << ExprInt(16, 32))[16:32],
     a[:16]),
    ((a << ExprInt(16, 32))[24:32],
     a[8:16]),
    (expr_cmpu(ExprInt(0, 32), ExprInt(0, 32)),
     ExprInt(0, 1)),
    (expr_cmpu(ExprInt(10, 32), ExprInt(0, 32)),
     ExprInt(1, 1)),
    (expr_cmpu(ExprInt(10, 32), ExprInt(5, 32)),
     ExprInt(1, 1)),
    (expr_cmpu(ExprInt(5, 32), ExprInt(10, 32)),
     ExprInt(0, 1)),
    (expr_cmpu(ExprInt(-1, 32), ExprInt(0, 32)),
     ExprInt(1, 1)),
    (expr_cmpu(ExprInt(-1, 32), ExprInt(-1, 32)),
     ExprInt(0, 1)),
    (expr_cmpu(ExprInt(0, 32), ExprInt(-1, 32)),
     ExprInt(0, 1)),
    (expr_cmps(ExprInt(0, 32), ExprInt(0, 32)),
     ExprInt(0, 1)),
    (expr_cmps(ExprInt(10, 32), ExprInt(0, 32)),
     ExprInt(1, 1)),
    (expr_cmps(ExprInt(10, 32), ExprInt(5, 32)),
     ExprInt(1, 1)),
    (expr_cmps(ExprInt(5, 32), ExprInt(10, 32)),
     ExprInt(0, 1)),
    (expr_cmps(ExprInt(-1, 32), ExprInt(0, 32)),
     ExprInt(0, 1)),
    (expr_cmps(ExprInt(-1, 32), ExprInt(-1, 32)),
     ExprInt(0, 1)),
    (expr_cmps(ExprInt(0, 32), ExprInt(-1, 32)),
     ExprInt(1, 1)),
    (expr_cmps(ExprInt(-5, 32), ExprInt(-10, 32)),
     ExprInt(1, 1)),
    (expr_cmps(ExprInt(-10, 32), ExprInt(-5, 32)),
     ExprInt(0, 1)),

    (ExprOp("<<<c_rez", i1, i0, i0),
     i1),
    (ExprOp("<<<c_rez", i1, i1, i0),
     ExprInt(2, 32)),
    (ExprOp("<<<c_rez", i1, i1, i1),
     ExprInt(3, 32)),
    (ExprOp(">>>c_rez", icustom, i0, i0),
     icustom),
    (ExprOp(">>>c_rez", icustom, i1, i0),
     ExprInt(0x91A2B3C, 32)),
    (ExprOp(">>>c_rez", icustom, i1, i1),
     ExprInt(0x891A2B3C, 32)),
    (ExprOp("idiv", ExprInt(0x0123, 16), ExprInt(0xfffb, 16))[:8],
     ExprInt(0xc6, 8)),
    (ExprOp("imod", ExprInt(0x0123, 16), ExprInt(0xfffb, 16))[:8],
     ExprInt(0x01, 8)),

    (ExprCompose(ExprInt(0x0123, 16), ExprMem(a + ExprInt(0x40, a.size), 16),
                 ExprMem(a + ExprInt(0x42, a.size), 16), ExprInt(0x0321, 16)),
     ExprCompose(ExprInt(0x0123, 16), ExprMem(a + ExprInt(0x40, a.size), 32),
                 ExprInt(0x0321, 16))),
    (ExprCompose(ExprCond(a, i1, i0), ExprCond(a, i1, i2)),
     ExprCond(a, ExprInt(0x100000001, 64), ExprInt(0x200000000, 64))),
    ((ExprMem(ExprCond(a, b, c)),ExprCond(a, ExprMem(b), ExprMem(c)))),
    (ExprCond(a, i0, i1) + ExprCond(a, i0, i1), ExprCond(a, i0, i2)),

]

for e, e_check in to_test[:]:
    #
    print "#" * 80
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
    (ExprOp_inf_unsigned(ExprInt(-1, 32), ExprInt(3, 32)), ExprInt(0, 1)),
    (ExprOp_inf_signed(ExprInt(-1, 32), ExprInt(3, 32)), ExprInt(1, 1)),
    (ExprOp_inf_unsigned(a, b) ^ (a ^ b).msb(), ExprOp_inf_signed(a, b)),
    (ExprOp_inf_signed(a, b) ^ (a ^ b).msb(), ExprOp_inf_unsigned(a, b)),
    (ExprOp_equal(ExprInt(12, 32), ExprInt(10, 32)), ExprInt(0, 1)),
    (ExprOp_equal(ExprInt(12, 32), ExprInt(12, 32)), ExprInt(1, 1)),
    (ExprOp_equal(ExprInt(12, 32), ExprInt(-12, 32)), ExprInt(0, 1)),
    (ExprCond(a - b, ExprInt(0, 1), ExprInt(1, 1)), ExprOp_equal(a, b)),
    (ExprCond(a + b, ExprInt(0, 1), ExprInt(1, 1)), ExprOp_equal(a, -b)),
    (ExprOp_inf_signed(ExprInt(-2, 32), ExprInt(3, 32)), ExprInt(1, 1)),
    (ExprOp_inf_signed(ExprInt(3, 32), ExprInt(-3, 32)), ExprInt(0, 1)),
    (ExprOp_inf_signed(ExprInt(2, 32), ExprInt(3, 32)), ExprInt(1, 1)),
    (ExprOp_inf_signed(ExprInt(-3, 32), ExprInt(-2, 32)), ExprInt(1, 1)),
    (ExprOp_inf_signed(ExprInt(0, 32), ExprInt(2, 32)), ExprInt(1, 1)),
    (ExprOp_inf_signed(ExprInt(-3, 32), ExprInt(0, 32)), ExprInt(1, 1)),
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


e1 = ExprMem((a & ExprInt(0xFFFFFFFC, 32)) + ExprInt(0x10, 32), 32)
e2 = ExprMem((a & ExprInt(0xFFFFFFFC, 32)) + b, 32)
e3 = (a ^ b ^ ((a ^ b) & (b ^ (b - a))) ^ (b - a)).canonize()

match_tests = [
    (match_expr(ExprInt(12, 32), a, [a]), {a: ExprInt(12, 32)}),
    (match_expr(x, a, [a]), {a: x}),
    (match_expr(x + y, a, [a]), {a: x + y}),
    (match_expr(x + y, a + y, [a]), {a: x}),
    (match_expr(x + y, x + a, [a]), {a: y}),
    (match_expr(x + y, a + b, [a, b]), {a: x, b: y}),
    (match_expr(x + ExprInt(12, 32), a + b, [a, b]), {a: x, b: ExprInt(12, 32)}),
    (match_expr(ExprMem(x), a, [a]), {a: ExprMem(x)}),
    (match_expr(ExprMem(x), ExprMem(a), [a]), {a: x}),
    (match_expr(x[0:8], a, [a]), {a: x[0:8]}),
    (match_expr(x[0:8], a[0:8], [a]), {a: x}),
    (match_expr(ExprCond(x, y, z), a, [a]), {a: ExprCond(x, y, z)}),
    (match_expr(ExprCond(x, y, z),
               ExprCond(a, b, c), [a, b, c]),
     {a: x, b: y, c: z}),
    (match_expr(ExprCompose(x[:8], y[:8]), a, [a]),
     {a: ExprCompose(x[:8], y[:8])}),
    (match_expr(ExprCompose(x[:8], y[:8]),
               ExprCompose(a[:8], b[:8]), [a, b]),
     {a: x, b: y}),
    (match_expr(e1, e2, [b]), {b: ExprInt(0x10, 32)}),
    (match_expr(e3,
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
