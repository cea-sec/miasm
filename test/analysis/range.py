from miasm2.expression.expression import *
from miasm2.analysis.expression_range import expr_range
from miasm2.ir.translators import Translator
import z3

trans = Translator.to_language("z3")
a = ExprId("a", 8)
b = ExprId("b", 32)

for expr in [
        a,
        b,
        b[4:6],
        a + ExprInt8(4),
        ExprInt8(5) + ExprInt8(4),
        a.zeroExtend(32) + ExprInt32(0x100),
        (a.zeroExtend(32) * ExprInt32(3)) + ExprInt32(0x100),
        (a.zeroExtend(32) + ExprInt32(0x80)) * ExprInt32(3),
        ExprCond(b, a.zeroExtend(32) + ExprInt32(0x100),
                 a.zeroExtend(32) + ExprInt32(0x500)),
        ExprCond(b[1:2], a.zeroExtend(32), a.zeroExtend(32) + ExprInt32(0x1000)) + \
        ExprCond(b[0:1], a.zeroExtend(32) + ExprInt32(0x5000), a.zeroExtend(32) + ExprInt32(0x10000)),
        - a,
        - ExprInt8(4),
        b[:8].zeroExtend(16) - ExprInt16(4),
        a[4:6].zeroExtend(32) + ExprInt32(-1),
        a >> ExprInt8(4),
        a << ExprInt8(4),
        ExprOp("a>>", a, ExprInt8(4)),
        ExprInt8(4) >> a,
        ExprInt8(4) << a,
        ExprOp("a>>", ExprInt8(4), a),
        a >> a,
        a << a,
        ExprOp("a>>", a, a),
        ExprInt8(4) >> ExprCond(b[0:1], ExprInt8(1), ExprInt8(10)),
        ExprInt8(4) << ExprCond(b[0:1], ExprInt8(1), ExprInt8(10)),
        ExprOp("a>>", ExprInt8(4), ExprCond(b[0:1], ExprInt8(1), ExprInt8(10))),
        a | ExprInt8(4),
        a[3:5] | a[6:8],
        ExprInt8(0) | a,
        ExprInt8(0xF) | ExprInt8(0xC),
        ExprCond(a[0:1], ExprInt8(5), ExprInt8(18)) | a[5:7].zeroExtend(8),
        a & ExprInt8(4),
        a[3:5] & a[6:8],
        ExprInt8(8) & a,
        ExprInt8(0xF) & ExprInt8(0xC),
        ExprCond(a[0:1], ExprInt8(5), ExprInt8(18)) & (a[4:7].zeroExtend(8) << ExprInt8(2)),
        a ^ ExprInt8(4),
        a[3:5] ^ a[6:8],
        ExprInt8(0xF) ^ a,
        ExprInt8(0xF) ^ ExprInt8(0xC),
        ExprCond(a[0:1], ExprInt8(5), ExprInt8(18)) ^ (a[4:7].zeroExtend(8) << ExprInt8(2)),
        a % ExprInt8(8),
        ExprInt8(33) % ExprInt8(8),
        a % a,
        a[:2].zeroExtend(8) + ExprInt8(0xF) % ExprCond(a[0:1], ExprInt8(5), ExprInt8(18)),
        ExprOp("<<<", ExprInt8(4), ExprInt8(1)),
        ExprOp("<<<", ExprInt8(4), ExprInt8(14)),
        ExprOp("<<<", ExprInt8(4), a),
        ExprOp("<<<", a, ExprInt8(4)),
        ExprOp("<<<", a, a),
        ExprOp("<<<", a[1:2].zeroExtend(8) + ExprInt8(1), ExprCond(a[0:1], ExprInt8(5), ExprInt8(18))),
        ExprOp(">>>", ExprInt8(4), ExprInt8(1)),
        ExprOp(">>>", ExprInt8(4), ExprInt8(14)),
        ExprOp(">>>", ExprInt8(4), a),
        ExprOp(">>>", a, ExprInt8(4)),
        ExprOp(">>>", a, a),
        ExprOp(">>>", a[1:2].zeroExtend(8) + ExprInt8(1), ExprCond(a[0:1], ExprInt8(5), ExprInt8(18))),

        # Fuzzed by ExprRandom, with previous bug
        ExprSlice(ExprSlice(ExprOp('<<<', ExprInt(0x7FBE84D6, 51), ExprId('WYBZj', 51)), 6, 48), 3, 35),
        ExprOp('>>>', ExprOp('-', ExprOp('&', ExprInt(0x347384F7, 32), ExprId('oIkka', 32), ExprId('jSfOB', 32), ExprId('dUXBp', 32), ExprInt(0x7169DEAA, 32))), ExprId('kMVuR', 32)),
        ExprOp('|', ExprInt(0x94A3AB47, 32), ExprCompose(ExprId('dTSkf', 21), ExprOp('>>', ExprInt(0x24, 8), ExprId('HTHES', 8)), ExprId('WHNIZ', 1), ExprMem(ExprInt(0x100, 9), 1), ExprId('kPQck', 1))),
        ExprOp('<<<', ExprOp('<<<', ExprCompose(ExprId('OOfuB', 6), ExprInt(0x24, 11), ExprInt(0xE8C, 12), ExprId('jbUWR', 1), ExprInt(0x2, 2)), ExprId('mLlTH', 32)), ExprInt(0xE600B6B2, 32)),

]:
    computed_range = expr_range(expr)
    print expr, computed_range

    # Trivia checks
    assert all(x[1] < (1 << expr.size) for x in computed_range)

    # Check against z3
    s = z3.Solver()
    cond = []

    ## Constraint expr to be in computed intervals
    z3_expr = trans.from_expr(expr)
    for mini, maxi in computed_range:
        cond.append(z3.And(z3.ULE(mini, z3_expr),
                           z3.ULE(z3_expr, maxi)))

    ## Ask for a solution outside intervals (should not exists)
    s.add(z3.Not(z3.Or(*cond)))
    assert s.check() == z3.unsat
