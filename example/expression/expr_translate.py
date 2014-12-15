import random

from miasm2.expression.expression import ExprId
from miasm2.expression.expression_helper import ExprRandom
from miasm2.ir.translators import Translator


class ExprRandom_OpSubRange(ExprRandom):
    operations_by_args_number = {1: ["-"],
                                 2: ["<<", ">>",],
                                 "2+": ["+", "*", "&", "|", "^"],
                                 }


print "[+] Compute a random expression:"
expr = ExprRandom_OpSubRange.get(depth=8)
print "-> %s" % expr
print ""

print "[+] Translate in Python:"
exprPython = Translator.to_language("Python").from_expr(expr)
print exprPython
print ""

print "[+] Translate in C:"
exprC = Translator.to_language("C").from_expr(expr)
print exprC
print ""

print "[+] Eval in Python:"
def memory(addr, size):
    ret = random.randint(0, (1 << size) - 1)
    print "Memory access: @0x%x -> 0x%x" % (addr, ret)
    return ret

for expr_id in expr.get_r(mem_read=True):
    if isinstance(expr_id, ExprId):
        value = random.randint(0, (1 << expr_id.size) - 1)
        print "Declare var: %s = 0x%x" % (expr_id.name, value)
        globals()[expr_id.name] = value

print "-> 0x%x" % eval(exprPython)
