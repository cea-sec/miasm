from miasm.arch.ia32_sem import *

print 'simple expression use demo: get read/written stuff for instruction:'
print 'add eax, [ebx]'
print

def get_rw(exprs):
    o_r = set()
    o_w = set()
    for e in exprs:
        o_r.update(e.get_r(mem_read=True))
    for e in exprs:
        o_w.update(e.get_w())
    return o_r, o_w

a = ExprId('eax')
b = ExprMem(ExprId('ebx'), 32)

exprs = add(ia32info(), a, b)
o_r, o_w = get_rw(exprs)
# read ID
print 'r:', [str(x) for x in o_r]
# ['eax', '@32[ebx]', 'ebx']

# written ID
print 'w:', [str(x) for x in o_w]
# ['eax', 'pf', 'af', 'of', 'zf', 'cf', 'nf']
