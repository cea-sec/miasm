"""

This example demonstrates the recovering of possible C types for an arbitrary
variable in an assembly code (the types are inferred from the function
argument types). It also displays the C code used to access this variable.

Input:
* definitions of the C types that can be used by the code
* layout of structures (packed/not packed)
* prototype of the analyzed function

Algorithm:
The DepGraph of the target variable is computed, which gives possible
expressions for this variable. For each DepGraph solution, if the expression
depends on typed arguments, the code infers the variable type and displays the C
code to access this variable.


Here be dragons:
For the moment, Miasm can infer C types (and generate C) for simple expressions.
To summarize, Miasm only supports accesses that do not involve arithmetic or
conditional expressions such as the following:
* var1.field
* var1[12][4]
* *(var1.field->tab[4])

Unsupported forms:
* var1 + var2
* var1[var2+4]
* var1?var2->field:6

In the following example, we have an explicit cast for "age", from uint16_t to
uint64_t, and for "height", from uint32_t to uint64_t. We are adding a naive
reduction rule to support such a cast.

First, in the type inference engine:
ExprCompose(int, 0) => int
Then, in the C generator:
ExprCompose(var1, 0) => var1

"""


import sys

from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from miasm2.expression.expression import ExprOp, ExprCompose, ExprId, ExprInt
from miasm2.analysis.depgraph import DependencyGraph

from miasm2.arch.x86.ctype import CTypeAMD64_unk

from miasm2.core.objc import ExprToAccessC, CHandler
from miasm2.core.objc import CTypesManagerNotPacked
from miasm2.core.ctypesmngr import CAstTypes, CTypePtr, CTypeStruct

def find_call(ircfg):
    """Returns (irb, index) which call"""

    for irb in ircfg.blocks.values():
        out = set()
        if len(irb) < 2:
            continue
        assignblk = irb[-2]
        for src in assignblk.itervalues():
            if not isinstance(src, ExprOp):
                continue
            if not src.op.startswith('call_func'):
                continue
            out.add((irb, len(irb) - 2))
        if len(out) != 1:
            continue
        irb, index = out.pop()
        yield irb, index


class MyExprToAccessC(ExprToAccessC):
    """Custom ExprToAccessC to complete expression traduction to C"""

    def reduce_compose(self, node, **kwargs):
        """Custom reduction rule: {XXX, 0} -> XXX"""
        if not (isinstance(node.expr, ExprCompose) and
                len(node.expr.args) == 2 and
                node.expr.args[1].is_int(0)):
            return None
        found = []
        for subcgenobj in node.args[0].info:
            found.append(subcgenobj)
        return found

    reduction_rules = ExprToAccessC.reduction_rules + [reduce_compose]


def get_funcs_arg0(ctx, ira, ircfg, lbl_head):
    """Compute DependencyGraph on the func @lbl_head"""
    g_dep = DependencyGraph(ircfg, follow_call=False)
    element = ira.arch.regs.RSI

    for irb, index in find_call(ircfg):
        instr = irb[index].instr
        print 'Analysing references from:', hex(instr.offset), instr
        g_list = g_dep.get(irb.loc_key, set([element]), index, set([lbl_head]))
        for dep in g_list:
            emul_result = dep.emul(ira, ctx)
            value = emul_result[element]
            yield value


class MyCHandler(CHandler):
    """Custom CHandler to add complementary C handling rules"""

    exprToAccessC_cls = MyExprToAccessC



data = open(sys.argv[1]).read()
# Digest C information
text = """
struct human {
        unsigned short age;
        unsigned int height;
        char name[50];
};

struct ll_human {
        struct ll_human* next;
        struct human human;
};
"""

base_types = CTypeAMD64_unk()
types_ast = CAstTypes()
types_ast.add_c_decl(text)

types_mngr = CTypesManagerNotPacked(types_ast, base_types)

# Analyze binary
cont = Container.fallback_container(data, None, addr=0)

machine = Machine("x86_64")
dis_engine, ira = machine.dis_engine, machine.ira

mdis = dis_engine(cont.bin_stream, loc_db=cont.loc_db)
addr_head = 0
asmcfg = mdis.dis_multiblock(addr_head)
lbl_head = mdis.loc_db.get_offset_location(addr_head)

ir_arch_a = ira(mdis.loc_db)
ircfg = ir_arch_a.new_ircfg_from_asmcfg(asmcfg)

open('graph_irflow.dot', 'w').write(ircfg.dot())

# Main function's first argument's type is "struct ll_human*"
ptr_llhuman = types_mngr.get_objc(CTypePtr(CTypeStruct('ll_human')))
arg0 = ExprId('ptr', 64)
ctx = {ir_arch_a.arch.regs.RDI: arg0}
expr_types = {arg0: (ptr_llhuman,),
              ExprInt(0x8A, 64): (ptr_llhuman,)}

mychandler = MyCHandler(types_mngr, expr_types)

for expr in get_funcs_arg0(ctx, ir_arch_a, ircfg, lbl_head):
    print "Access:", expr
    for c_str, ctype in mychandler.expr_to_c_and_types(expr):
        print '\taccess:', c_str
        print '\tc type:', ctype
