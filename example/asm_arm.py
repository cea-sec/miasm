#! /usr/bin/env python

from miasm.arch.arm_arch import arm_mn
from miasm.core.bin_stream import  bin_stream
from miasm.core import parse_asm
from miasm.core import asmbloc
import struct

my_mn = arm_mn


####filelogger sc####

all_bloc, symbol_pool = parse_asm.parse_txt(my_mn,r'''
toto:
    STMFD  SP!, {R0-R12, LR}^
    MOV    R11, LR
    MOV    R11, R0, ROR 4
    STC    P2,C3, [R5, 24]!
    MOV    R1, R0
    LDR    R2, [PC, R0 ROR 0x2]
    CMP    R2, R3
    BLE    tutu
    ORR    R0, R1, R2
    ORRLE  R0, R0, R0
    ORR    R0, R0, R0
    LDR    R3, [R11, 0x98]
    LDR    R3, [R11, -0x98]
    STMFD  SP!, {R4-R6,R11,R12,LR,PC}
    STMFD  SP!, {R0-R12, SP, LR, PC}
    LDMIA  R9, {R9, R12}
    BLE    tutu
    LDMFD  SP, {R4-R8,R11,SP,PC}
     
tutu:
    LDMFD  SP!, {R0-R12, LR}
    BX     LR
''')

g = asmbloc.bloc2graph(all_bloc[0])
open("graph.txt" , "w").write(g)



for b in all_bloc[0]:
    print b
symbol_pool.add_label('base_address', 0x0)
symbol_pool.getby_name("toto").offset = 0x0

resolved_b, patches = asmbloc.asm_resolve_final(my_mn, all_bloc[0], symbol_pool)
print patches

f = open('uu.bin', 'w')
for p, v in patches.items():
    f.seek(p)
    f.write(v)

f.close()

print 'DISASSEMBLE FILE'
data = open('uu.bin', 'rb').read()
in_str = bin_stream(data)
job_done = set()
symbol_pool = asmbloc.asm_symbol_pool()
all_bloc = asmbloc.dis_bloc_all(my_mn, in_str, 0, job_done, symbol_pool, follow_call = False, lines_wd = 20)
g = asmbloc.bloc2graph(all_bloc)
open("graph2.txt" , "w").write(g)

