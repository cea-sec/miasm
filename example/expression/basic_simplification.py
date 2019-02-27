from __future__ import print_function
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp

print("""
Simple expression simplification demo
""")


a = ExprId('eax', 32)
b = ExprId('ebx', 32)

exprs = [a + b - a,
         ExprInt(0x12, 32) + ExprInt(0x30, 32) - a,
         ExprCompose(a[:8], a[8:16])]

for e in exprs:
    print('*' * 40)
    print('original expression:', e)
    print("simplified:", expr_simp(e))
