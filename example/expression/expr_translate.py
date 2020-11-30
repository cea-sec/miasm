from __future__ import print_function
import random

from future.utils import viewitems

from miasm.expression.expression import *
from miasm.expression.expression_helper import ExprRandom
from miasm.ir.translators import Translator

random.seed(0)

class ExprRandom_OpSubRange(ExprRandom):
    operations_by_args_number = {1: ["-"],
                                 2: ["<<", ">>",],
                                 "2+": ["+", "*", "&", "|", "^"],
                                 }


print("[+] Compute a random expression:")
expr = ExprRandom_OpSubRange.get(depth=8)
print("-> %s" % expr)
print()

target_exprs = {lang:Translator.to_language(lang).from_expr(expr)
                for lang in Translator.available_languages()}
for target_lang, target_expr in viewitems(target_exprs):
    print("[+] Translate in %s:" % target_lang)
    print(target_expr)
    print()

print("[+] Eval in Python:")
def memory(addr, size):
    ret = random.randint(0, (1 << size) - 1)
    print("Memory access: @0x%x -> 0x%x" % (addr, ret))
    return ret

for expr_id in expr.get_r(mem_read=True):
    if isinstance(expr_id, ExprId):
        value = random.randint(0, (1 << expr_id.size) - 1)
        print("Declare var: %s = 0x%x" % (expr_id.name, value))
        globals()[expr_id.name] = value

print("-> 0x%x" % eval(target_exprs["Python"]))

print("[+] Validate the Miasm syntax rebuilding")
exprRebuild = eval(target_exprs["Miasm"])
assert(expr == exprRebuild)


a = ExprId("a", 32)
b = ExprId("b", 32)
cst1 = ExprInt(1, 32)
eq_test = ExprOp("==", a, b + cst1)

for lang in Translator.available_languages():
    translator = Translator.to_language(lang)
    print("Translate to %s:" % lang)
    print(translator.from_expr(eq_test))
