from miasm2.arch.x86.arch import mn_x86
from miasm2.expression.expression import get_rw
from miasm2.arch.x86.ira import ir_a_x86_32


print """
Simple expression manipulation demo.
Get read/written registers for a given instruction
"""

arch = mn_x86
ir_arch = ir_a_x86_32()

l = arch.fromstring('LODSB', 32)
l.offset, l.l = 0, 15
ir_arch.add_instr(l)

print '*' * 80
for lbl, b in ir_arch.blocks.items():
    print b
    for irs in b.irs:
        o_r, o_w = get_rw(irs)
        print 'read:   ', [str(x) for x in o_r]
        print 'written:', [str(x) for x in o_w]
        print

open('graph_instr.dot', 'w').write(ir_arch.graph.dot())
