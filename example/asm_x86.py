#! /usr/bin/env python

from miasm2.core.cpu import parse_ast
from miasm2.arch.x86.arch import mn_x86, base_expr, variable
from miasm2.core import parse_asm
from miasm2.expression.expression import *
from miasm2.core import asmbloc
from elfesteem.strpatchwork import StrPatchwork

reg_and_id = dict(mn_x86.regs.all_regs_ids_byname)


def my_ast_int2expr(a):
    return ExprInt32(a)


def my_ast_id2expr(t):
    return reg_and_id.get(t, ExprId(t, size=32))

my_var_parser = parse_ast(my_ast_id2expr, my_ast_int2expr)
base_expr.setParseAction(my_var_parser)

blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 32, '''
main:
   PUSH EBP
   MOV  EBP, ESP
   SUB  ESP, 0x100
   MOV  EAX, 0x1337
   ; test ptr manip
   LEA  ESI, DWORD PTR [mystr^toto]
   CALL toto
mystr:
.string "test string"
 toto:
   POP  EDI

   PUSH EDI
   ; test scasb
   XOR  EAX, EAX
   XOR  ECX, ECX
   DEC  ECX
   REPNE SCASB
   NOT  ECX
   DEC  ECX

   ; test movsb
   POP  ESI
   LEA  EDI, DWORD PTR [EBP-0x100]
   REPE  MOVSB

   ; test float
   PUSH 0
   FLD1
   FLD1
   FADD ST, ST(1)
   FIST  DWORD PTR [ESP]
   POP  EAX

   ; test cond mnemo
   NOP
   NOP
   CMOVZ EAX, EBX
   ; test shr
   NOP
   SHR EAX, 1
   NOP
   NOP
   SHR EAX, CL
   NOP

   MOV  ESP, EBP
   POP  EBP
   RET


''')

# fix shellcode addr
symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)
s = StrPatchwork()
resolved_b, patches = asmbloc.asm_resolve_final(
    mn_x86, '32', blocs[0], symbol_pool)
for offset, raw in patches.items():
    s[offset] = raw

print patches

open('demo_x86_32.bin', 'wb').write(str(s))
