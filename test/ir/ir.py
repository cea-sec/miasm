from future.utils import viewitems

from miasm.expression.expression import *
from miasm.ir.ir import AssignBlock
from miasm.expression.simplifications import expr_simp

id_a = ExprId("a", 32)
id_b = ExprId("b", 32)
int0 = ExprInt(0, id_a.size)

# Test AssignBlock
## Constructors
assignblk1 = AssignBlock([ExprAssign(id_a, id_b)])
assignblk2 = AssignBlock({id_a: id_b})

## Equality
assignblk1_bis = AssignBlock([ExprAssign(id_a, id_b)])
assert assignblk1 == assignblk1_bis
assert assignblk1 == assignblk2

## Immutability
try:
    assignblk1[id_a] = id_a
except RuntimeError:
    pass
else:
    raise RuntimeError("An error was expected")
try:
    del assignblk1[id_a]
except RuntimeError:
    pass
else:
    raise RuntimeError("An error was expected")

## Basic APIs
assert assignblk1.get_r() == set([id_b])
assert assignblk1.get_w() == set([id_a])
assert assignblk1.get_rw() == {id_a: set([id_b])}
assert list(assignblk1) == [id_a]
assert dict(assignblk1) == {id_a: id_b}
assert assignblk1[id_a] == id_b
assert list(viewitems(assignblk1)) == list(viewitems(assignblk1))
assert set(assignblk1.iteritems()) == set(assignblk1.items())

## Simplify
assignblk3 = AssignBlock({id_a: id_b - id_b})
assert assignblk3[id_a] != int0
assignblk4 = assignblk3.simplify(expr_simp)
assert assignblk3[id_a] != int0
assert assignblk4[id_a] == int0
