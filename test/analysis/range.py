from __future__ import print_function
from miasm.expression.expression import *
from miasm.analysis.expression_range import expr_range
from miasm.ir.translators import Translator
import z3

trans = Translator.to_language("z3")
a = ExprId("a", 8)
b = ExprId("b", 32)

for expr in [
        a,
        b,
        b[4:6],
        a + ExprInt(4, 8),
        ExprInt(5, 8) + ExprInt(4, 8),
        a.zeroExtend(32) + ExprInt(0x100, 32),
        (a.zeroExtend(32) * ExprInt(3, 32)) + ExprInt(0x100, 32),
        (a.zeroExtend(32) + ExprInt(0x80, 32)) * ExprInt(3, 32),
        ExprCond(b, a.zeroExtend(32) + ExprInt(0x100, 32),
                 a.zeroExtend(32) + ExprInt(0x500, 32)),
        ExprCond(b[1:2], a.zeroExtend(32), a.zeroExtend(32) + ExprInt(0x1000, 32)) + \
        ExprCond(b[0:1], a.zeroExtend(32) + ExprInt(0x5000, 32), a.zeroExtend(32) + ExprInt(0x10000, 32)),
        - a,
        - ExprInt(4, 8),
        b[:8].zeroExtend(16) - ExprInt(4, 16),
        a[4:6].zeroExtend(32) + ExprInt(-1, 32),
        a >> ExprInt(4, 8),
        a << ExprInt(4, 8),
        ExprOp("a>>", a, ExprInt(4, 8)),
        ExprInt(4, 8) >> a,
        ExprInt(4, 8) << a,
        ExprOp("a>>", ExprInt(4, 8), a),
        a >> a,
        a << a,
        ExprOp("a>>", a, a),
        ExprInt(4, 8) >> ExprCond(b[0:1], ExprInt(1, 8), ExprInt(10, 8)),
        ExprInt(4, 8) << ExprCond(b[0:1], ExprInt(1, 8), ExprInt(10, 8)),
        ExprOp("a>>", ExprInt(4, 8), ExprCond(b[0:1], ExprInt(1, 8), ExprInt(10, 8))),
        a | ExprInt(4, 8),
        a[3:5] | a[6:8],
        ExprInt(0, 8) | a,
        ExprInt(0xF, 8) | ExprInt(0xC, 8),
        ExprCond(a[0:1], ExprInt(5, 8), ExprInt(18, 8)) | a[5:7].zeroExtend(8),
        a & ExprInt(4, 8),
        a[3:5] & a[6:8],
        ExprInt(8, 8) & a,
        ExprInt(0xF, 8) & ExprInt(0xC, 8),
        ExprCond(a[0:1], ExprInt(5, 8), ExprInt(18, 8)) & (a[4:7].zeroExtend(8) << ExprInt(2, 8)),
        a ^ ExprInt(4, 8),
        a[3:5] ^ a[6:8],
        ExprInt(0xF, 8) ^ a,
        ExprInt(0xF, 8) ^ ExprInt(0xC, 8),
        ExprCond(a[0:1], ExprInt(5, 8), ExprInt(18, 8)) ^ (a[4:7].zeroExtend(8) << ExprInt(2, 8)),
        a % ExprInt(8, 8),
        ExprInt(33, 8) % ExprInt(8, 8),
        a % a,
        a[:2].zeroExtend(8) + ExprInt(0xF, 8) % ExprCond(a[0:1], ExprInt(5, 8), ExprInt(18, 8)),
        ExprInt(33, 8) * ExprInt(8, 8),
        a * a,
        a * ExprInt(0, 8),
        ExprInt(4, 8) * a,
        (a[:2].zeroExtend(8) + ExprInt(0xF, 8)) * ExprCond(a[0:1], ExprInt(5, 8), ExprInt(18, 8)),
        ExprOp("<<<", ExprInt(4, 8), ExprInt(1, 8)),
        ExprOp("<<<", ExprInt(4, 8), ExprInt(14, 8)),
        ExprOp("<<<", ExprInt(4, 8), a),
        ExprOp("<<<", a, ExprInt(4, 8)),
        ExprOp("<<<", a, a),
        ExprOp("<<<", a[1:2].zeroExtend(8) + ExprInt(1, 8), ExprCond(a[0:1], ExprInt(5, 8), ExprInt(18, 8))),
        ExprOp(">>>", ExprInt(4, 8), ExprInt(1, 8)),
        ExprOp(">>>", ExprInt(4, 8), ExprInt(14, 8)),
        ExprOp(">>>", ExprInt(4, 8), a),
        ExprOp(">>>", a, ExprInt(4, 8)),
        ExprOp(">>>", a, a),
        ExprOp(">>>", a[1:2].zeroExtend(8) + ExprInt(1, 8), ExprCond(a[0:1], ExprInt(5, 8), ExprInt(18, 8))),

        # Fuzzed by ExprRandom, with previous bug
        ExprSlice(ExprSlice(ExprOp('<<<', ExprInt(0x7FBE84D6, 51), ExprId('WYBZj', 51)), 6, 48), 3, 35),
        ExprOp('>>>', ExprOp('-', ExprOp('&', ExprInt(0x347384F7, 32), ExprId('oIkka', 32), ExprId('jSfOB', 32), ExprId('dUXBp', 32), ExprInt(0x7169DEAA, 32))), ExprId('kMVuR', 32)),
        ExprOp('|', ExprInt(0x94A3AB47, 32), ExprCompose(ExprId('dTSkf', 21), ExprOp('>>', ExprInt(0x24, 8), ExprId('HTHES', 8)), ExprId('WHNIZ', 1), ExprMem(ExprInt(0x100, 9), 1), ExprId('kPQck', 1))),
        ExprOp('<<<', ExprOp('<<<', ExprCompose(ExprId('OOfuB', 6), ExprInt(0x24, 11), ExprInt(0xE8C, 12), ExprId('jbUWR', 1), ExprInt(0x2, 2)), ExprId('mLlTH', 32)), ExprInt(0xE600B6B2, 32)),

]:
    computed_range = expr_range(expr)
    print(expr, computed_range)

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
