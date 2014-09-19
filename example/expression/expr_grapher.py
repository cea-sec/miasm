from miasm2.core.graph import DiGraph
from miasm2.expression.expression import *

print "Simple Expression grapher demo"

a = ExprId("A")
b = ExprId("B")
c = ExprId("C")
d = ExprId("D")
m = ExprMem(a + b + c + a)

e1 = ExprCompose([(a + b - (c * a) / m | b, 0, 32), (a + m, 32, 64)])
e2 = ExprInt64(15)
e = ExprCond(d, e1, e2)[0:32]

print "[+] Expression:"
print e

g = e.graph()
print "[+] Graph:"
print g.dot()
