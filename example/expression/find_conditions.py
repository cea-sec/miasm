import sys
from miasm.arch.ia32_arch import *
from miasm.tools.emul_helper import *
from miasm.core.bin_stream import bin_stream
from miasm.tools.to_c_helper import *
from optparse import OptionParser



"""
Symbolic execute a function, and generate conditions list used to
explore whole binary control flow

python  find_conditions.py -a 0   simple_tests
"""

parser = OptionParser(usage = "usage: %prog [options] file")
parser.add_option('-a', "--address", dest="address", metavar="ADDRESS",
                  help="address to disasemble", default="0")


(options, args) = parser.parse_args(sys.argv[1:])
if not args:
    parser.print_help()
    sys.exit(0)
fname = args[0]
ad_to_dis = options.address

data = (open(fname).read())
in_str = bin_stream(data)
symbol_pool = asmbloc.asm_symbol_pool()

def add_bloc_to_disasm(ad, all_blocs, job_done):
    b = asmbloc.dis_bloc_all(x86_mn, in_str, ad, set(),
                             symbol_pool, bloc_wd = 1)[0]
    all_blocs[ad] = b


def get_bloc(ad, all_blocs, job_done):
    if not ad in all_blocs:
        add_bloc_to_disasm(ad, all_blocs, job_done)
    return all_blocs[ad]

init_state = x86_machine().pool
def print_state(state):
    to_out= []
    for r in [eax, ebx, ecx, edx, esi, edi, esp, ebp]:
        if state[r] == init_state[r]:
            continue
        to_out.append((r, state[r]))
    for k, v in state.items():
        if isinstance(k, ExprMem):
            to_out.append((k, v))
    for k, v in to_out:
        print k, '=', v

def emul_mn(states_todo, states_done, all_blocs, job_done):
    while states_todo:
        ad, pool = states_todo.pop()
        if (ad, pool) in states_done:
            print 'skip', ad
            continue
        states_done.add((ad, pool))
        machine = x86_machine()
        machine.pool = pool.copy()
        ad = int(ad.arg)
        b = get_bloc(ad, all_blocs, job_done)
        ad = emul_bloc(machine, b)
        print_state(machine.pool)
        if isinstance(ad, ExprCond):
            # Create 2 states, each including complementary conditions
            p1 = machine.pool.copy()
            p2 = machine.pool.copy()
            c1 = {ad.cond: ExprInt(uint32(0))}
            c2 = {ad.cond: ExprInt(uint32(1))}
            p1[ad.cond] = ExprInt(uint32(0))
            p2[ad.cond] = ExprInt(uint32(1))
            ad1 = machine.eval_expr(ad.reload_expr(c1), {})
            ad2 = machine.eval_expr(ad.reload_expr(c2), {})
            if not (isinstance(ad1, ExprInt) and isinstance(ad2, ExprInt)):
                print str(ad1), str(ad2)
                raise ValueError("zarb condition")
            states_todo.add((ad1, p1))
            states_todo.add((ad2, p2))
        elif isinstance(ad, ExprInt):
            pass
        elif ad == ret_addr:
            continue
        else:
            raise ValueError("zarb eip")

all_blocs = {}
job_done = set()
machine = x86_machine()

argc = ExprId('argc')
argv = ExprId('argv')
ret_addr = ExprId('ret_addr')

machine.eval_instr(push(('u32', 'u32'), argv))
machine.eval_instr(push(('u32', 'u32'), argc))
machine.eval_instr(push(('u32', 'u32'), ret_addr))

ad = int(ad_to_dis, 16)
print 'disasm', hex(ad)

states_todo = set()
states_todo.add((ExprInt(uint32(ad)), machine.pool))
states_done = set()
emul_mn(states_todo, states_done, all_blocs, job_done)

all_info = set()
print '*'*40, 'conditions to match', '*'*40
for ad, pool in states_done:
    for k, v in pool.items():
        t = (k, v)
        # filter conditions which are argc aware
        if argc in k:
            all_info.add(t)

machine = x86_machine()
for k, v in list(all_info):
    print machine.eval_expr(k.reload_expr({}), {}), "=", v
