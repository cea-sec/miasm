import sys

from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from miasm2.expression.expression import ExprOp, ExprCompose, ExprId
from miasm2.analysis.depgraph import DependencyGraph

from miasm2.arch.x86.ctype import CTypeAMD64_unk

from miasm2.core.objc import CTypeAnalyzer, ExprToAccessC, CHandler
from miasm2.core.objc import ObjCPtr
from miasm2.core.ctypesmngr import CTypesManagerNotPacked


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

def find_call(ira):
    """Returns (irb, index) which call"""

    for irb in ira.blocks.values():
        out = set()
        if len(irb.irs) < 2:
            continue
        assignblk = irb.irs[-2]
        for src in assignblk.itervalues():
            if not isinstance(src, ExprOp):
                continue
            if not src.op.startswith('call_func'):
                continue
            out.add((irb, len(irb.irs) - 2))
        if len(out) != 1:
            continue
        irb, index = out.pop()
        yield irb, index


class MyCTypeAnalyzer(CTypeAnalyzer):

    def reduce_compose(self, node, _):
        """Custom reduction rule: {XXX, 0} -> typeof(XXX)"""
        if not (isinstance(node.expr, ExprCompose) and
                len(node.expr.args) == 2 and
                node.expr.args[1].is_int(0)):
            return None
        return node.args[0].info

    reduction_rules = CTypeAnalyzer.reduction_rules + [reduce_compose]


class MyExprToAccessC(ExprToAccessC):

    def reduce_compose(self, node, _):
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


def get_funcs_arg0(ctx, ira, lbl_head):
    g_dep = DependencyGraph(ira, follow_call=False)
    element = ira.arch.regs.RSI

    for irb, index in find_call(ira):
        line = irb.lines[index]
        print 'Analysing references from:', hex(line.offset), line
        g_list = g_dep.get(irb.label, set([element]), index, set([lbl_head]))
        for dep in g_list:
            emul_result = dep.emul(ctx)
            value = emul_result[element]
            yield value


class MyCHandler(CHandler):
    cTypeAnalyzer_cls = MyCTypeAnalyzer
    exprToAccessC_cls = MyExprToAccessC


def test(data):
    # Digest C informations
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

    my_types = CTypeAMD64_unk()
    types_mngr = CTypesManagerNotPacked(my_types.types)

    types_mngr.add_c_decl(text)

    # Analyze binary
    cont = Container.fallback_container(data, None, addr=0)

    machine = Machine("x86_64")
    dis_engine, ira = machine.dis_engine, machine.ira

    mdis = dis_engine(cont.bin_stream, symbol_pool=cont.symbol_pool)
    addr_head = 0
    blocks = mdis.dis_multibloc(addr_head)
    lbl_head = mdis.symbol_pool.getby_offset(addr_head)

    ir_arch_a = ira(mdis.symbol_pool)
    for block in blocks:
        ir_arch_a.add_bloc(block)

    open('graph_irflow.dot', 'w').write(ir_arch_a.graph.dot())

    # Main function's first argument's type is "struct ll_human*"
    void_ptr = types_mngr.void_ptr
    ll_human = types_mngr.get_type(('ll_human',))
    ptr_llhuman = ObjCPtr('noname', ll_human,
                          void_ptr.align, void_ptr.size)

    arg0 = ExprId('ptr', 64)
    ctx = {ir_arch_a.arch.regs.RDI: arg0}
    expr_types = {arg0.name: ptr_llhuman}

    mychandler = MyCHandler(types_mngr, expr_types)

    for expr in get_funcs_arg0(ctx, ir_arch_a, lbl_head):
        print "Access:", expr
        target_types = mychandler.expr_to_types(expr)
        for target_type in target_types:
            print '\tType:', target_type
        c_strs = mychandler.expr_to_c(expr)
        for c_str in c_strs:
            print "\tC access:", c_str
        print


if __name__ == '__main__':
    data = open(sys.argv[1]).read()
    test(data)
