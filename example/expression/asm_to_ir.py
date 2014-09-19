from miasm2.core.cpu import parse_ast, ast_id2expr
from miasm2.arch.x86.arch import mn_x86, base_expr
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmbloc
from miasm2.arch.x86.ira import ir_a_x86_32
from pdb import pm


def my_ast_int2expr(a):
    return ExprInt32(a)

my_var_parser = parse_ast(ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)


# First, asm code
blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 32, '''
main:
   MOV    EAX, 1
   MOV    EBX, 2
   MOV    ECX, 2
   MOV    DX, 2

loop:
   INC    EBX
   CMOVZ  EAX, EBX
   ADD    EAX, ECX
   JZ     loop
   RET
''')

blocs = blocs[0]

symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)
for b in blocs:
    print b


print "symbols:"
print symbol_pool
resolved_b, patches = asmbloc.asm_resolve_final(mn_x86, 32, blocs, symbol_pool)

# Translate to IR
ir_arch = ir_a_x86_32(symbol_pool)
for b in blocs:
    print 'add bloc'
    print b
    ir_arch.add_bloc(b)

# Display IR
for lbl, b in ir_arch.blocs.items():
    print b

# Dead propagation
ir_arch.gen_graph()
out = ir_arch.graph()
open('graph.txt', 'w').write(out)
print '*' * 80
ir_arch.dead_simp()
out2 = ir_arch.graph()
open('graph2.txt', 'w').write(out2)

# Display new IR
print 'new ir blocs'
for lbl, b in ir_arch.blocs.items():
    print b
