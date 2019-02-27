from __future__ import print_function
import pickle
from miasm.expression.expression import ExprInt, ExprAssign, ExprId, \
    Expr, ExprCompose, ExprMem


a = ExprId("test", 8)
b = ExprInt(1338, 8)
c = a + b
d = ExprCompose(a, b)
e = ExprMem(a, 32)
f = a[:8]
aff = ExprAssign(a, b)


print('Pickling')
out = pickle.dumps((a, b, c, d, e, f, aff))
print('Unpickling')
new_a, new_b, new_c, new_d, new_e, new_f, new_aff = pickle.loads(out)
print('Result')
print(a, b, c, aff)
print(id(a), id(b), id(c), id(d), id(e), id(f), id(aff))
print(new_a, new_b, new_c, new_d, new_e, new_f, new_aff)
print(id(new_a), id(new_b), id(new_c), id(new_d), id(new_e), id(new_f), id(new_aff))

assert a == new_a
assert b == new_b
assert c == new_c
assert d == new_d
assert e == new_e
assert f == new_f
assert aff == new_aff
assert new_a + new_b == a + b


assert a is new_a
assert b is new_b
assert c is new_c
assert d is new_d
assert e is new_e
assert f is new_f
assert aff is new_aff
assert new_a + new_b is a + b

Expr.use_singleton = False

new_a, new_b, new_c, new_d, new_e, new_f, new_aff = pickle.loads(out)


assert a is not new_a
assert b is not new_b
assert c is not new_c
assert d is not new_d
assert e is not new_e
assert f is not new_f
assert aff is not new_aff
assert new_a + new_b is not a + b


assert a == new_a
assert b == new_b
assert c == new_c
assert d == new_d
assert e == new_e
assert f == new_f
assert aff == new_aff
assert new_a + new_b == a + b
