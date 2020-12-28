from __future__ import print_function
#
# Expression simplification regression tests  #
#
from pdb import pm
from argparse import ArgumentParser
import logging

from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp, expr_simp_explicit, \
    ExpressionSimplifier, log_exprsimp

from miasm.expression.simplifications_cond import ExprOp_inf_signed, ExprOp_inf_unsigned, ExprOp_equal

parser = ArgumentParser("Expression simplification regression tests")
parser.add_argument("--z3", action="store_true", help="Enable check against z3")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose simplify")
args = parser.parse_args()

if args.verbose:
    log_exprsimp.setLevel(logging.DEBUG)

# Additional imports and definitions
if args.z3:
    import z3
    from miasm.ir.translators import Translator
    trans = Translator.to_language("z3")

    def check(expr_in, expr_out):
        """Check that expr_in is always equals to expr_out"""
        print("Ensure %s = %s" % (expr_in, expr_out))
        solver = z3.Solver()
        solver.add(trans.from_expr(expr_in) != trans.from_expr(expr_out))

        result = solver.check()

        if result != z3.unsat:
            print("ERROR: a counter-example has been founded:")
            model = solver.model()
            print(model)

            print("Reinjecting in the simplifier:")
            to_rep = {}
            expressions = expr_in.get_r().union(expr_out.get_r())
            for expr in expressions:
                value = model.eval(trans.from_expr(expr))
                if hasattr(value, "as_long"):
                    new_val = ExprInt(value.as_long(), expr.size)
                else:
                    raise RuntimeError("Unable to reinject %r" % value)

                to_rep[expr] = new_val

            new_expr_in = expr_in.replace_expr(to_rep)
            new_expr_out = expr_out.replace_expr(to_rep)

            print("Check %s = %s" % (new_expr_in, new_expr_out))
            simp_in = expr_simp_explicit(new_expr_in)
            simp_out =  expr_simp_explicit(new_expr_out)
            print("[%s] %s = %s" % (simp_in == simp_out, simp_in, simp_out))

            # Either the simplification does not stand, either the test is wrong
            raise RuntimeError("Bad simplification")

else:
    # Dummy 'check' method to avoid checking the '--z3' argument each time
    check = lambda expr_in, expr_out: None


# Define example objects
a = ExprId('a', 32)
b = ExprId('b', 32)
c = ExprId('c', 32)
d = ExprId('d', 32)
e = ExprId('e', 32)
f = ExprId('f', size=64)

b_msb_null = b[:31].zeroExtend(32)
c_msb_null = c[:31].zeroExtend(32)

a31 = ExprId('a31', 31)
b31 = ExprId('b31', 31)
c31 = ExprId('c31', 31)
b31_msb_null = ExprId('b31', 31)[:30].zeroExtend(31)
c31_msb_null = ExprId('c31', 31)[:30].zeroExtend(31)

a8 = ExprId('a8', 8)
b8 = ExprId('b8', 8)
c8 = ExprId('c8', 8)
d8 = ExprId('d8', 8)
e8 = ExprId('e8', 8)


m = ExprMem(a, 32)
s = a[:8]

i0 = ExprInt(0, 32)
i1 = ExprInt(1, 32)
i2 = ExprInt(2, 32)
i3 = ExprInt(3, 32)
im1 = ExprInt(-1, 32)
im2 = ExprInt(-2, 32)

bi0 = ExprInt(0, 1)
bi1 = ExprInt(1, 1)


icustom = ExprInt(0x12345678, 32)
cc = ExprCond(a, b, c)

o = ExprCompose(a[8:16], a[:8])

o2 = ExprCompose(a[8:16], a[:8])

l = [a[:8], b[:8], c[:8], m[:8], s, i1[:8], i2[:8], o[:8]]
l2 = l[::-1]


x = ExprMem(a + b + ExprInt(0x42, 32), 32)

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
           (ExprOp('<<<', a31, ExprInt(31, 31)), a31),
           (ExprOp('>>>', a31, ExprInt(31, 31)), a31),
           (ExprOp('>>>', a31, ExprInt(0, 31)), a31),
           (ExprOp('<<', a31, ExprInt(0, 31)), a31),

           (ExprOp('<<<', a31, ExprOp('<<<', b31, c31)),
            ExprOp('<<<', a31, ExprOp('<<<', b31, c31))),
           (ExprOp('<<<', ExprOp('>>>', a31, b31), c31),
            ExprOp('<<<', ExprOp('>>>', a31, b31), c31)),
           (ExprOp('>>>', ExprOp('<<<', a31, b31), c31),
            ExprOp('>>>', ExprOp('<<<', a31, b31), c31)),
           (ExprOp('>>>', ExprOp('<<<', a31, b31), b31),
            a31),
           (ExprOp('<<<', ExprOp('>>>', a31, b31), b31),
            a31),
           (ExprOp('>>>', ExprOp('>>>', a31, b31), b31),
            ExprOp('>>>', ExprOp('>>>', a31, b31), b31)),
           (ExprOp('<<<', ExprOp('<<<', a31, b31), b31),
            ExprOp('<<<', ExprOp('<<<', a31, b31), b31)),

           (ExprOp('>>>', ExprOp('<<<', a31, ExprInt(0x1234, 31)), ExprInt(0x1111, 31)),
            ExprOp('>>>', a31, ExprInt(0x13, 31))),
           (ExprOp('<<<', ExprOp('>>>', a31, ExprInt(0x1234, 31)), ExprInt(0x1111, 31)),
            ExprOp('<<<', a31, ExprInt(0x13, 31))),
           (ExprOp('>>>', ExprOp('<<<', a31, ExprInt(-1, 31)), ExprInt(0x1111, 31)),
            ExprOp('>>>', a31, ExprInt(0x1c, 31))),
           (ExprOp('<<<', ExprOp('>>>', a31, ExprInt(-1, 31)), ExprInt(0x1111, 31)),
            ExprOp('<<<', a31, ExprInt(0x1c, 31))),

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
           (ExprOp('>>', ExprOp('<<', a, ExprInt(0x4, 32)), ExprInt(0x4, 32)),
            ExprOp('&', a, ExprInt(0x0FFFFFFF, 32))),
           (ExprOp('<<', ExprOp('>>', a, ExprInt(0x4, 32)), ExprInt(0x4, 32)),
            ExprOp('&', a, ExprInt(0xFFFFFFF0, 32))),

           (ExprCompose(ExprId("a", 8), ExprId("b", 24)) & ExprInt(0xFF, 32), ExprCompose(ExprId("a", 8), ExprInt(0x0, 24))),
           (ExprCompose(ExprId("a", 8), ExprInt(0x12, 8), ExprId("b", 16)) & ExprInt(0xFFFF, 32), ExprCompose(ExprId("a", 8), ExprInt(0x12, 24))),
           (ExprCompose(ExprId("a", 8), ExprInt(0x1234, 16), ExprId("b", 8)) & ExprInt(0xFFFF, 32), ExprCompose(ExprId("a", 8), ExprInt(0x34, 24))),

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

           (ExprMem(a, 32)[:32], ExprMem(a, 32)),
           (ExprMem(a, 32)[:16], ExprMem(a, size=16)),

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
    (ExprOp('*', a, b, ExprInt(0x0, 32)),
     ExprInt(0x0, 32)),
    (ExprOp('&', a, b, ExprInt(0x0, 32)),
     ExprInt(0x0, 32)),
    (ExprOp('*', a, ExprInt(0xffffffff, 32)),
     -a),
    (ExprOp('*', -a, -b, c, ExprInt(0x12, 32)),
     ExprOp('*', a, b, c, ExprInt(0x12, 32))),
    (ExprOp('*', -a, -b, -c, ExprInt(0x12, 32)),
     ExprOp('*', a, b, c, ExprInt(-0x12, 32))),
    (a | ExprInt(0xffffffff, 32),
     ExprInt(0xffffffff, 32)),
    (ExprCond(a, ExprInt(1, 32), ExprInt(2, 32)) * ExprInt(4, 32),
     ExprCond(a, ExprInt(4, 32), ExprInt(8, 32))),
    (ExprCond(a, b, c) + ExprCond(a, d, e),
     ExprCond(a, b + d, c + e)),
    (ExprCond(a8, b8, c8) * ExprCond(a8, d8, e8),
     ExprCond(a8, b8 * d8, c8 * e8)),

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
     ExprInt(0x12, 32)),


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

    (ExprCompose(a[0:8], b[8:16], ExprInt(0x0, 48))[12:32],
     ExprCompose(b[12:16], ExprInt(0, 16))
       ),

    (ExprCompose(ExprCompose(a[:8], ExprInt(0x0, 56))[8:32]
                  &
                  ExprInt(0x1, 24),
                  ExprInt(0x0, 40)),
     ExprInt(0, 64)),

    (ExprCompose(ExprCompose(a[:8], ExprInt(0x0, 56))[:8]
                 &
                 ExprInt(0x1, 8),
                 (ExprInt(0x0, 56))),
     ExprCompose(a[:8]&ExprInt(1, 8), ExprInt(0, 56))),

    (ExprCompose(ExprCompose(a[:8],
                             ExprInt(0x0, 56))[:32]
                 &
                 ExprInt(0x1, 32),
                 ExprInt(0x0, 32)),
     ExprCompose(ExprCompose(ExprSlice(a, 0, 8),
                             ExprInt(0x0, 24))
                 &
                 ExprInt(0x1, 32),
                 ExprInt(0x0, 32))
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
    (expr_is_unsigned_greater(ExprInt(0, 32), ExprInt(0, 32)),
     ExprInt(0, 1)),
    (expr_is_unsigned_greater(ExprInt(10, 32), ExprInt(0, 32)),
     ExprInt(1, 1)),
    (expr_is_unsigned_greater(ExprInt(10, 32), ExprInt(5, 32)),
     ExprInt(1, 1)),
    (expr_is_unsigned_greater(ExprInt(5, 32), ExprInt(10, 32)),
     ExprInt(0, 1)),
    (expr_is_unsigned_greater(ExprInt(-1, 32), ExprInt(0, 32)),
     ExprInt(1, 1)),
    (expr_is_unsigned_greater(ExprInt(-1, 32), ExprInt(-1, 32)),
     ExprInt(0, 1)),
    (expr_is_unsigned_greater(ExprInt(0, 32), ExprInt(-1, 32)),
     ExprInt(0, 1)),
    (expr_is_signed_greater(ExprInt(0, 32), ExprInt(0, 32)),
     ExprInt(0, 1)),
    (expr_is_signed_greater(ExprInt(10, 32), ExprInt(0, 32)),
     ExprInt(1, 1)),
    (expr_is_signed_greater(ExprInt(10, 32), ExprInt(5, 32)),
     ExprInt(1, 1)),
    (expr_is_signed_greater(ExprInt(5, 32), ExprInt(10, 32)),
     ExprInt(0, 1)),
    (expr_is_signed_greater(ExprInt(-1, 32), ExprInt(0, 32)),
     ExprInt(0, 1)),
    (expr_is_signed_greater(ExprInt(-1, 32), ExprInt(-1, 32)),
     ExprInt(0, 1)),
    (expr_is_signed_greater(ExprInt(0, 32), ExprInt(-1, 32)),
     ExprInt(1, 1)),
    (expr_is_signed_greater(ExprInt(-5, 32), ExprInt(-10, 32)),
     ExprInt(1, 1)),
    (expr_is_signed_greater(ExprInt(-10, 32), ExprInt(-5, 32)),
     ExprInt(0, 1)),

    (ExprOp("sdiv", ExprInt(0x0123, 16), ExprInt(0xfffb, 16))[:8],
     ExprInt(0xc6, 8)),
    (ExprOp("smod", ExprInt(0x0123, 16), ExprInt(0xfffb, 16))[:8],
     ExprInt(0x01, 8)),
    (ExprOp("cnttrailzeros", ExprInt(0x2, 32)),
     ExprInt(0x1, 32)),
    (ExprOp("cnttrailzeros", ExprInt(0x0, 32)),
     ExprInt(0x20, 32)),
    (ExprOp("cntleadzeros", ExprInt(0x2, 32)),
     ExprInt(30, 32)),
    (ExprOp("cntleadzeros", ExprInt(0x0, 32)),
     ExprInt(0x20, 32)),


    (ExprCompose(ExprInt(0x0123, 16), ExprMem(a + ExprInt(0x40, a.size), 16),
                 ExprMem(a + ExprInt(0x42, a.size), 16), ExprInt(0x0321, 16)),
     ExprCompose(ExprInt(0x0123, 16), ExprMem(a + ExprInt(0x40, a.size), 32),
                 ExprInt(0x0321, 16))),
    (ExprCompose(ExprCond(a, i1, i0), ExprCond(a, i1, i2)),
     ExprCond(a, ExprInt(0x100000001, 64), ExprInt(0x200000000, 64))),
    ((ExprMem(ExprCond(a, b, c), 4),ExprCond(a, ExprMem(b, 4), ExprMem(c, 4)))),
    (ExprCond(a, i0, i1) + ExprCond(a, i0, i1), ExprCond(a, i0, i2)),

    (a << b << c, a << b << c), # Left unmodified
    (a << b_msb_null << c_msb_null,
     a << (ExprCompose(b[:31], ExprInt(0, 1)) + ExprCompose(c[:31], ExprInt(0, 1)))),
    (a >> b >> c, a >> b >> c), # Left unmodified
    (a >> b_msb_null >> c_msb_null,
     a >> (ExprCompose(b[:31], ExprInt(0, 1)) + ExprCompose(c[:31], ExprInt(0, 1)))),

    # Degenerated case from fuzzing, which had previously raised bugs
    (ExprCompose(ExprInt(0x7, 3), ExprMem(ExprInt(0x39E21, 19), 1), ExprMem(ExprInt(0x39E21, 19), 1)),
     ExprCompose(ExprInt(0x7, 3), ExprMem(ExprInt(0x39E21, 19), 1), ExprMem(ExprInt(0x39E21, 19), 1))),
    (ExprOp('>>', ExprInt(0x5E580475, 92), ExprInt(0x7D800000000000000331720, 92)),
     ExprInt(0x0, 92)),
    (ExprOp('a>>', ExprInt(0x5E580475, 92), ExprInt(0x7D800000000000000331720, 92)),
     ExprInt(0x0, 92)),
    (ExprOp('a>>', ExprInt(-0x5E580475, 92), ExprInt(0x7D800000000000000331720, 92)),
     ExprInt(-1, 92)),

    (ExprOp("zeroExt_16", ExprInt(0x8, 8)), ExprInt(0x8, 16)),
    (ExprOp("zeroExt_16", ExprInt(0x88, 8)), ExprInt(0x88, 16)),
    (ExprOp("signExt_16", ExprInt(0x8, 8)), ExprInt(0x8, 16)),
    (ExprOp("signExt_16", ExprInt(-0x8, 8)), ExprInt(-0x8, 16)),

    (ExprCond(a8.zeroExtend(32), a, b), ExprCond(a8, a, b)),
    (ExprCond(a8, bi1, bi0).zeroExtend(32), ExprCond(a8, i1, i0)),


    (- (i2*a), a * im2),
    (a + a, a * i2),
    (ExprOp('+', a, a), a * i2),
    (ExprOp('+', a, a, a), a * i3),
    ((a<<i1) - a, a),
    ((a<<i1) - (a<<i2), a*im2),
    ((a<<i1) - a - a, i0),
    ((a<<i2) - (a<<i1) - (a<<i1), i0),
    ((a<<i2) - a*i3, a),
    (((a+b) * i3) - (a + b), (a+b) * i2),
    (((a+b) * i2) + a + b, (a+b) * i3),
    (((a+b) * i3) - a - b, (a+b) * i2),
    (((a+b) * i2) - a - b, a+b),
    (((a+b) * i2) - i2 * a - i2 * b, i0),


]

for e_input, e_check in to_test:
    print("#" * 80)
    e_new = expr_simp_explicit(e_input)
    print("original: ", str(e_input), "new: ", str(e_new))
    rez = e_new == e_check
    if not rez:
        raise ValueError(
            'bug in expr_simp_explicit simp(%s) is %s and should be %s' % (e_input, e_new, e_check)
        )
    check(e_input, e_check)


# Test high level op
to_test = [
    (ExprOp(TOK_EQUAL, a+i2, i1), ExprOp(TOK_EQUAL, a+i1, i0)),
    (ExprOp(TOK_INF_SIGNED, a+i2, i1), ExprOp(TOK_INF_SIGNED, a+i2, i1)),
    (ExprOp(TOK_INF_UNSIGNED, a+i2, i1), ExprOp(TOK_INF_UNSIGNED, a+i2, i1)),

    (
        ExprOp(TOK_EQUAL, ExprCompose(a8, ExprInt(0, 24)), im1),
        ExprOp(TOK_EQUAL, a8, ExprInt(0xFF, 8))
    ),

    (
        ExprOp(TOK_EQUAL, i2, a + i1),
        ExprOp(TOK_EQUAL, a , i1)
    ),

    (
        ExprOp(TOK_EQUAL, a ^ i1, i2),
        ExprOp(TOK_EQUAL, a , i3)
    ),

    (
        ExprOp(TOK_EQUAL, i2, a ^ i1),
        ExprOp(TOK_EQUAL, a , i3)
    ),


    (
        ExprOp(TOK_EQUAL, ExprOp("^", a, b, i2), i1),
        ExprOp(TOK_EQUAL, a^b , i3)
    ),


    (
        ExprOp(TOK_EQUAL, a ^ b, a ^ c),
        ExprOp(TOK_EQUAL, b , c)
    ),

    (
        ExprOp(TOK_EQUAL, a + b, a + c),
        ExprOp(TOK_EQUAL, b , c)
    ),

    (
        ExprOp(TOK_EQUAL, a + b, a),
        ExprOp(TOK_EQUAL, b , i0)
    ),

    (
        ExprOp(TOK_EQUAL, a, a + b),
        ExprOp(TOK_EQUAL, b , i0)
    ),


    (
        ExprOp(TOK_EQUAL, ExprOp("+", a, b, c), a),
        ExprOp(TOK_EQUAL, b+c , i0)
    ),

    (
        ExprOp(TOK_EQUAL, a, ExprOp("+", a, b, c)),
        ExprOp(TOK_EQUAL, b+c , i0)
    ),


    (ExprOp(TOK_INF_SIGNED, i1, i2), ExprInt(1, 1)),
    (ExprOp(TOK_INF_UNSIGNED, i1, i2), ExprInt(1, 1)),
    (ExprOp(TOK_INF_EQUAL_SIGNED, i1, i2), ExprInt(1, 1)),
    (ExprOp(TOK_INF_EQUAL_UNSIGNED, i1, i2), ExprInt(1, 1)),

    (ExprOp(TOK_INF_SIGNED, i2, i1), ExprInt(0, 1)),
    (ExprOp(TOK_INF_UNSIGNED, i2, i1), ExprInt(0, 1)),
    (ExprOp(TOK_INF_EQUAL_SIGNED, i2, i1), ExprInt(0, 1)),
    (ExprOp(TOK_INF_EQUAL_UNSIGNED, i2, i1), ExprInt(0, 1)),

    (ExprOp(TOK_INF_SIGNED, i1, i1), ExprInt(0, 1)),
    (ExprOp(TOK_INF_UNSIGNED, i1, i1), ExprInt(0, 1)),
    (ExprOp(TOK_INF_EQUAL_SIGNED, i1, i1), ExprInt(1, 1)),
    (ExprOp(TOK_INF_EQUAL_UNSIGNED, i1, i1), ExprInt(1, 1)),


    (ExprOp(TOK_INF_SIGNED, im1, i1), ExprInt(1, 1)),
    (ExprOp(TOK_INF_UNSIGNED, im1, i1), ExprInt(0, 1)),
    (ExprOp(TOK_INF_EQUAL_SIGNED, im1, i1), ExprInt(1, 1)),
    (ExprOp(TOK_INF_EQUAL_UNSIGNED, im1, i1), ExprInt(0, 1)),

    (ExprOp(TOK_INF_SIGNED, i1, im1), ExprInt(0, 1)),
    (ExprOp(TOK_INF_UNSIGNED, i1, im1), ExprInt(1, 1)),
    (ExprOp(TOK_INF_EQUAL_SIGNED, i1, im1), ExprInt(0, 1)),
    (ExprOp(TOK_INF_EQUAL_UNSIGNED, i1, im1), ExprInt(1, 1)),

    (ExprOp(TOK_EQUAL, a8.zeroExtend(32), b8.zeroExtend(32)), ExprOp(TOK_EQUAL, a8, b8)),
    (ExprOp(TOK_EQUAL, a8.signExtend(32), b8.signExtend(32)), ExprOp(TOK_EQUAL, a8, b8)),

    (ExprOp(TOK_INF_EQUAL_SIGNED, a8.zeroExtend(32), i0), ExprOp(TOK_EQUAL, a8, ExprInt(0, 8))),

    ((a8.zeroExtend(32) + b8.zeroExtend(32) + ExprInt(1, 32))[0:8], a8 + b8 + ExprInt(1, 8)),

    (ExprCond(a8.zeroExtend(32), a, b), ExprCond(a8, a, b)),
    (ExprCond(a8.signExtend(32), a, b), ExprCond(a8, a, b)),


    (
        ExprOp(
            TOK_EQUAL,
            a8.zeroExtend(32) & b8.zeroExtend(32) & ExprInt(0x12, 32),
            i1
        ),
        ExprOp(
            TOK_EQUAL,
            a8 & b8 & ExprInt(0x12, 8),
            ExprInt(1, 8)
        )
    ),

    (
        ExprCond(
            ExprOp(
                TOK_EQUAL,
                a & b & ExprInt(0x80, 32),
                ExprInt(0x80, 32)
            ), a, b
        ),
        ExprCond(a & b & ExprInt(0x80, 32), a, b)
    ),



    (
        ExprCond(
            a8.zeroExtend(32) & b8.zeroExtend(32) & ExprInt(0x12, 32),
            a, b
        ),
        ExprCond(
            a8 & b8 & ExprInt(0x12, 8),
            a, b
        ),
    ),


    (a8.zeroExtend(32)[:8], a8),
    (a.zeroExtend(64)[:32], a),
    (a.zeroExtend(64)[:8], a[:8]),
    (a8.zeroExtend(32)[:16], a8.zeroExtend(16)),

    (
        ExprCond(
            a & ExprInt(0x80000000, 32),
            a, b
        ),
        ExprCond(
            ExprOp(TOK_INF_SIGNED, a, ExprInt(0, 32) ),
            a, b
        )
    ),



    (
        ExprCond(
            a8.signExtend(32) & ExprInt(0x80000000, 32),
            a, b
        ),
        ExprCond(
            ExprOp(TOK_INF_SIGNED, a8, ExprInt(0, 8) ),
            a, b
        )
    ),


    (
        ExprCond(
            ExprOp(TOK_INF_SIGNED, a8.signExtend(32), ExprInt(0x10, 32) ),
            a, b
        ),
        ExprCond(
            ExprOp(TOK_INF_SIGNED, a8, ExprInt(0x10, 8) ),
            a, b
        )
    ),

    (
        ExprCond(
            ExprOp(TOK_INF_SIGNED, a8.signExtend(32), ExprInt(-0x10, 32) ),
            a, b
        ),
        ExprCond(
            ExprOp(TOK_INF_SIGNED, a8, ExprInt(-0x10, 8) ),
            a, b
        )
    ),


    (
        ExprCond(
            ExprOp(TOK_INF_UNSIGNED, a8.zeroExtend(32), ExprInt(0x10, 32) ),
            a, b
        ),
        ExprCond(
            ExprOp(TOK_INF_UNSIGNED, a8, ExprInt(0x10, 8) ),
            a, b
        )
    ),



    (
        ExprCond(
            ExprOp(TOK_INF_SIGNED, a8.signExtend(32), ExprInt(0x200, 32) ),
            a, b
        ),
        a
    ),


    (
        ExprCond(
            ExprOp(TOK_INF_UNSIGNED, a8.zeroExtend(32), ExprInt(0x200, 32) ),
            a, b
        ),
        a
    ),



    (
        ExprCond(
            ExprOp(TOK_INF_SIGNED, a8.zeroExtend(32), ExprInt(0x10, 32) ),
            a, b
        ),
        ExprCond(
            ExprOp(TOK_INF_UNSIGNED, a8, ExprInt(0x10, 8) ),
            a, b
        )
    ),

    (
        ExprCond(
            ExprOp(TOK_INF_EQUAL_SIGNED, a8.zeroExtend(32), ExprInt(0x10, 32) ),
            a, b
        ),
        ExprCond(
            ExprOp(TOK_INF_EQUAL_UNSIGNED, a8, ExprInt(0x10, 8) ),
            a, b
        )
    ),


    (
        ExprCond(
            ExprOp(TOK_INF_SIGNED, a8.zeroExtend(32), ExprInt(-1, 32) ),
            a, b
        ),
        b
    ),

    (
        ExprCond(
            ExprOp(TOK_INF_EQUAL_SIGNED, a8.zeroExtend(32), ExprInt(-1, 32) ),
            a, b
        ),
        b
    ),


    (a8.zeroExtend(32)[2:5], a8[2:5]),


    (
        ExprCond(a + b, a, b),
        ExprCond(ExprOp(TOK_EQUAL, a, -b), b, a)
    ),

    (
        ExprCond(a + i1, a, b),
        ExprCond(ExprOp(TOK_EQUAL, a, im1), b, a)
    ),


    (
        ExprCond(ExprOp(TOK_EQUAL, a, i1), bi1, bi0),
        ExprOp(TOK_EQUAL, a, i1)
    ),

    (
        ExprCond(ExprOp(TOK_INF_SIGNED, a, i1), bi1, bi0),
        ExprOp(TOK_INF_SIGNED, a, i1)
    ),

    (
        ExprOp(TOK_INF_EQUAL_UNSIGNED, a, i0),
        ExprOp(TOK_EQUAL, a, i0)
    ),


    (
        ExprCond(
            ExprOp("CC_U<", a[0:1]),
            b, c
        ),
        ExprCond(
            a[0:1],
            b, c
        ),
    ),

    (
        ExprCond(
            ExprOp("CC_U>=", a[0:1]),
            b, c
        ),
        ExprCond(
            a[0:1],
            c, b
        ),
    ),

    (
        ExprCond(
            ExprOp("FLAG_SUB_CF", a, b),
            c, d
        ),
        ExprCond(
            ExprOp("<u", a, b),
            c, d
        ),
    ),



]

for e_input, e_check in to_test:
    print("#" * 80)
    e_check = expr_simp(e_check)
    e_new = expr_simp(e_input)
    print("original: ", str(e_input), "new: ", str(e_new))
    rez = e_new == e_check
    if not rez:
        raise ValueError(
            'bug in expr_simp simp(%s) is %s and should be %s' % (e_input, e_new, e_check)
        )


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

expr_simp.enable_passes(ExpressionSimplifier.PASS_COND)


for e_input, e_check in to_test:
    print("#" * 80)
    e_check = expr_simp(e_check)
    e_new = expr_simp(e_input)
    print("original: ", str(e_input), "new: ", str(e_new))
    rez = e_new == e_check
    if not rez:
        raise ValueError(
            'bug in expr_simp simp(%s) is %s and should be %s' % (e_input, e_new, e_check)
        )


if args.z3:
    # This check is done on 32 bits, but the size is not use by Miasm formulas, so
    # it should be OK for any size > 0
    x1 = ExprId("x1", 32)
    x2 = ExprId("x2", 32)
    i1_tmp = ExprInt(1, 1)

    x1_z3 = trans.from_expr(x1)
    x2_z3 = trans.from_expr(x2)
    i1_z3 = trans.from_expr(i1_tmp)

    # (Assumptions, function(arg1, arg2) -> True/False (= i1/i0) to check)
    tests = [
        (x1_z3 == x2_z3, expr_is_equal),
        (x1_z3 != x2_z3, expr_is_not_equal),
        (z3.UGT(x1_z3, x2_z3), expr_is_unsigned_greater),
        (z3.UGE(x1_z3, x2_z3), expr_is_unsigned_greater_or_equal),
        (z3.ULT(x1_z3, x2_z3), expr_is_unsigned_lower),
        (z3.ULE(x1_z3, x2_z3), expr_is_unsigned_lower_or_equal),
        (x1_z3 > x2_z3, expr_is_signed_greater),
        (x1_z3 >= x2_z3, expr_is_signed_greater_or_equal),
        (x1_z3 < x2_z3, expr_is_signed_lower),
        (x1_z3 <= x2_z3, expr_is_signed_lower_or_equal),
    ]

    for assumption, func in tests:
        solver = z3.Solver()
        solver.add(assumption)
        solver.add(trans.from_expr(func(x1, x2)) != i1_z3)
        assert solver.check() == z3.unsat


x = ExprId('x', 32)
y = ExprId('y', 32)
z = ExprId('z', 32)
a = ExprId('a', 32)
b = ExprId('b', 32)
c = ExprId('c', 32)


jra = ExprId('jra', 32)
jrb = ExprId('jrb', 32)
jrint1 = ExprId('jrint1', 32)


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
    (match_expr(ExprMem(x, 32), a, [a]), {a: ExprMem(x, 32)}),
    (match_expr(ExprMem(x, 32), ExprMem(a, 32), [a]), {a: x}),
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
    (ExprAssign(ExprMem(a, 32), ExprMem(b, 32)).get_r(True), set([a, b, ExprMem(b, 32)])),
    (ExprAssign(ExprMem(a, 32), ExprMem(b, 32)).get_w(), set([ExprMem(a, 32)])),
    (ExprAssign(ExprMem(ExprMem(a, 32), 32), ExprMem(b, 32))
     .get_r(True), set([a, b, ExprMem(b, 32), ExprMem(a, 32)])),
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
    print(x)

print('all tests ok')
