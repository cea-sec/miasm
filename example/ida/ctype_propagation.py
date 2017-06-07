import os
import tempfile

from miasm2.core.bin_stream_ida import bin_stream_ida
from miasm2.expression import expression as m2_expr

from miasm2.expression.simplifications import expr_simp
from miasm2.analysis.depgraph import DependencyGraph
from miasm2.ir.ir import IRBlock, AssignBlock

from utils import guess_machine

from miasm2.arch.x86.ctype import CTypeAMD64_unk
from miasm2.expression.expression import ExprId

from miasm2.core.objc import CTypesManagerNotPacked, CTypeAnalyzer, ExprToAccessC, CHandler
from miasm2.core.ctypesmngr import CAstTypes
from miasm2.expression.expression import ExprMem, ExprId, ExprInt, ExprOp, ExprAff
from miasm2.ir.symbexec_types import SymbExecCType

from miasm2.expression.parser import str_to_expr


class TypePropagationForm(Form):

    def __init__(self, ira):

        self.ira = ira
        self.stk_unalias_force = False

        default_types_info = r"""ExprId("RDX", 64): char *
"""
        archs = ["AMD64_unk", "X86_32_unk"]

        Form.__init__(self,
r"""BUTTON YES* Launch
BUTTON CANCEL NONE
Dependency Graph Settings
<##Header file :{headerFile}>
<Architecture/complator:{cbReg}>
<Types informations:{strTypesInfo}>
<Unalias stack:{rUnaliasStack}>{cMethod}>
""", {
    'headerFile': Form.FileInput(swidth=20, open=True),
    'cbReg': Form.DropdownListControl(
        items=archs,
        readonly=False,
        selval=archs[0]),
    'strTypesInfo': Form.MultiLineTextControl(text=default_types_info,
                                              flags=Form.MultiLineTextControl.TXTF_FIXEDFONT),
    'cMethod': Form.ChkGroupControl(("rUnaliasStack",)),
    })
        self.Compile()

    @property
    def unalias_stack(self):
        return self.cMethod.value & 1 or self.stk_unalias_force


def get_block(ir_arch, mdis, addr):
    """Get IRBlock at address @addr"""
    mdis.job_done.clear()
    lbl = ir_arch.get_label(addr)
    if not lbl in ir_arch.blocks:
        block = mdis.dis_bloc(lbl.offset)
        ir_arch.add_bloc(block)
    irblock = ir_arch.get_bloc(lbl)
    if irblock is None:
        raise LookupError('No block found at that address: %s' % lbl)
    return irblock


def get_types_mngr(headerFile):
    text = open(headerFile).read()
    base_types = CTypeAMD64_unk()
    types_ast = CAstTypes()

    # Add C types definition
    types_ast.add_c_decl(text)

    types_mngr = CTypesManagerNotPacked(types_ast, base_types)
    return types_mngr



# add stack alignment simpl
def simp_stack_align(expr_simp, expr):
    if not expr.is_op("&"):
        return expr
    if len(expr.args) != 2:
        return expr
    if not expr.args[1].is_int(0xFFFFFFF0):
        return expr
    if expr.args[0] != ir_arch.arch.regs.ESP_init:
        return expr
    return expr.args[0]

expr_simp.enable_passes({m2_expr.ExprOp: [simp_stack_align]})

# Init
machine = guess_machine()
mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira

bs = bin_stream_ida()
mdis = dis_engine(bs, dont_dis_nulstart_bloc=True)
ir_arch = ira(mdis.symbol_pool)

# Get the current function
func = idaapi.get_func(ScreenEA())
addr = func.startEA
blocks = mdis.dis_multibloc(addr)
# Generate IR
for block in blocks:
    ir_arch.add_bloc(block)


class MyCTypeAnalyzer(CTypeAnalyzer):
    allow_none_result = True


class MyExprToAccessC(ExprToAccessC):
    allow_none_result = True


class MyCHandler(CHandler):
    cTypeAnalyzer_cls = MyCTypeAnalyzer
    exprToAccessC_cls = MyExprToAccessC


# Get settings
settings = TypePropagationForm(ir_arch)
ret = settings.Execute()
if ret:

    ir_arch = ir_arch


    types_mngr = get_types_mngr(settings.headerFile.value)
    mychandler = MyCHandler(types_mngr, {})

    #print 'Expr', settings.iStr1.value
    #print 'Type', settings.iStr2.value
    #print 'Header', settings.headerFile.value
    print 'InfoTypes', settings.strTypesInfo.value
    infos_types = {}
    for line in settings.strTypesInfo.value.split('\n'):
        if not line:
            continue
        expr_str, ctype_str = line.split(':')
        expr_str, ctype_str = expr_str.strip(), ctype_str.strip()
        expr = str_to_expr(expr_str)
        ast = mychandler.type_analyzer.types_mngr.types_ast.parse_c_type(ctype_str)
        ctype = mychandler.type_analyzer.types_mngr.types_ast.ast_parse_declaration(ast.ext[0])
        objc = types_mngr.get_objc(ctype)
        print '='*20
        print expr, objc
        infos_types[expr] = objc

    # Add fake head
    lbl_real_start = ir_arch.symbol_pool.getby_offset(addr)
    lbl_head = ir_arch.symbol_pool.getby_name_create("start")

    first_block = blocks.label2block(lbl_real_start)

    assignblk_head = AssignBlock([ExprAff(ir_arch.IRDst, ExprId(lbl_real_start, ir_arch.IRDst.size)),
                                  ExprAff(ir_arch.sp, ir_arch.arch.regs.regs_init[ir_arch.sp])
                                 ], first_block.lines[0])
    irb_head = IRBlock(lbl_head, [assignblk_head])
    ir_arch.blocks[lbl_head] = irb_head
    ir_arch.graph.add_uniq_edge(lbl_head, lbl_real_start)

    class Engine(SymbExecCType):
        def __init__(self, state):
            mychandler = MyCHandler(types_mngr, state.infos_types)
            super(Engine, self).__init__(ir_arch,
                                         state.symbols,
                                         state.infos_types,
                                         mychandler)


    def add_state(todo, states, addr, state):
        addr = ir_arch.get_label(addr)
        if addr not in states:
            states[addr] = state
            todo.add(addr)
        else:
            todo.add(addr)
            states[addr] = states[addr].merge(state)


    state = Engine.StateEngine(infos_types, infos_types)
    states = {lbl_head:state}
    todo = set([lbl_head])
    done = set()

    while todo:
        lbl = todo.pop()
        state = states[lbl]
        if (lbl, state) in done:
            continue
        done.add((lbl, state))
        symbexec_engine = Engine(state)

        get_block(ir_arch, mdis, lbl)

        addr = symbexec_engine.emul_ir_block(lbl)
        symbexec_engine.del_mem_above_stack(ir_arch.sp)

        ir_arch._graph = None
        sons = ir_arch.graph.successors(lbl)
        for son in sons:
            if son.offset is None:
                continue
            add_state(todo, states, son.offset, symbexec_engine.get_state())


    class SymbExecCTypeFix(SymbExecCType):
        def emulbloc(self, irb, step=False):
            """
            Symbolic execution of the @irb on the current state
            @irb: irblock instance
            @step: display intermediate steps
            """
            offset2cmt = {}
            for assignblk in irb.irs:
                instr = assignblk.instr
                tmp_rw = assignblk.get_rw()
                for dst, src in assignblk.iteritems():
                    for arg in set(instr.args).union(set([src])):
                        if arg in tmp_rw and arg not in tmp_rw.values():
                            continue
                        objc = self.eval_expr(arg)
                        if objc is None:
                            continue
                        if self.is_type_offset(objc):
                            continue
                        offset2cmt.setdefault(instr.offset, set()).add("%s: %s" % (arg, str(objc)))
                self.eval_ir(assignblk)

            for offset, value in offset2cmt.iteritems():
                idc.MakeComm(offset, '\n'.join(value))

            return self.eval_expr(self.ir_arch.IRDst)


    class Engine(SymbExecCTypeFix):
        def __init__(self, state):
            mychandler = MyCHandler(types_mngr, state.infos_types)
            super(Engine, self).__init__(ir_arch,
                                         state.symbols,
                                         state.infos_types,
                                         mychandler)


    for lbl, state in states.iteritems():
        symbexec_engine = Engine(state)
        addr = symbexec_engine.emul_ir_block(lbl)
        symbexec_engine.del_mem_above_stack(ir_arch.sp)








