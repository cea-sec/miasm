"""
Example of "constant expression" propagation.
A "constant expression" is an expression based on constants or init regs.

"""

from argparse import ArgumentParser

from miasm2.arch.x86.disasm import dis_x86_32 as dis_engine
from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from miasm2.analysis.cst_propag import propagate_cst_expr
from miasm2.analysis.data_flow import dead_simp
from miasm2.expression.simplifications import expr_simp


parser = ArgumentParser("Constant expression propagation")
parser.add_argument('filename', help="File to analyze")
parser.add_argument('address', help="Starting address for disassembly engine")
parser.add_argument('-s', "--simplify", action="store_true",
                    help="Apply simplifications rules (liveness, graph simplification, ...)")

args = parser.parse_args()


machine = Machine("x86_32")

cont = Container.from_stream(open(args.filename))
ira, dis_engine = machine.ira, machine.dis_engine
mdis = dis_engine(cont.bin_stream)
ir_arch = ira(mdis.symbol_pool)
addr = int(args.address, 0)


asmcfg = mdis.dis_multiblock(addr)
for block in asmcfg.blocks:
    ir_arch.add_block(block)


init_infos = ir_arch.arch.regs.regs_init
cst_propag_link = propagate_cst_expr(ir_arch, addr, init_infos)

if args.simplify:
    ir_arch.simplify(expr_simp)
    modified = True
    while modified:
        modified = False
        modified |= dead_simp(ir_arch)
        modified |= ir_arch.remove_empty_assignblks()
        modified |= ir_arch.remove_jmp_blocks()
        modified |= ir_arch.merge_blocks()


open("%s.propag.dot" % args.filename, 'w').write(ir_arch.graph.dot())
