from __future__ import print_function

from miasm.expression.expression import *

print("Simple Expression grapher demo")

a = ExprId("A", 32)
b = ExprId("B", 32)
c = ExprId("C", 32)
d = ExprId("D", 32)
m = ExprMem(a + b + c + a, 32)

e1 = ExprCompose(a + b - ((c * a) // m) | b, a + m)
e2 = ExprInt(15, 64)
e = ExprCond(d, e1, e2)[0:32]

print("[+] Expression:")
print(e)

g = e.graph()
print("[+] Graph:")
print(g.dot())
