import ida_kernwin
import idc
import ida_funcs

from miasm2.core.bin_stream_ida import bin_stream_ida
from miasm2.expression import expression as m2_expr
from miasm2.expression.simplifications import expr_simp
from miasm2.ir.ir import IRBlock, AssignBlock
from miasm2.arch.x86.ctype import CTypeAMD64_unk, CTypeX86_unk
from miasm2.arch.msp430.ctype import CTypeMSP430_unk
from miasm2.core.objc import CTypesManagerNotPacked, ExprToAccessC, CHandler
from miasm2.core.ctypesmngr import CAstTypes
from miasm2.expression.expression import ExprId, ExprInt, ExprOp, ExprAff
from miasm2.ir.symbexec_types import SymbExecCType
from miasm2.expression.parser import str_to_expr
from miasm2.analysis.cst_propag import add_state, propagate_cst_expr

from utils import guess_machine

class TypePropagationForm(ida_kernwin.Form):

    def __init__(self, ira):

        self.ira = ira

        default_types_info = r"""ExprId("RDX", 64): char *"""
        archs = ["AMD64_unk", "X86_32_unk", "msp430_unk"]

        ida_kernwin.Form.__init__(self,
                      r"""BUTTON YES* Launch
BUTTON CANCEL NONE
Type Propagation Settings
<##Header file :{headerFile}>
<Architecture/compilator:{arch}>
<Types informations:{strTypesInfo}>
<Unalias stack:{rUnaliasStack}>{cUnalias}>
""", {
                          'headerFile': ida_kernwin.Form.FileInput(swidth=20, open=True),
                          'arch': ida_kernwin.Form.DropdownListControl(
                              items=archs,
                              readonly=False,
                              selval=archs[0]),
                          'strTypesInfo': ida_kernwin.Form.MultiLineTextControl(text=default_types_info,
                                                                    flags=ida_kernwin.Form.MultiLineTextControl.TXTF_FIXEDFONT),
                          'cUnalias': ida_kernwin.Form.ChkGroupControl(("rUnaliasStack",)),
                      })
        form, args = self.Compile()
        form.rUnaliasStack.checked = True


def get_types_mngr(headerFile, arch):
    text = open(headerFile).read()
    if arch == "AMD64_unk":
        base_types = CTypeAMD64_unk()
    elif arch =="X86_32_unk":
        base_types = CTypeX86_unk()
    elif arch =="msp430_unk":
        base_types = CTypeMSP430_unk()
    else:
        raise NotImplementedError("Unsupported arch")
    types_ast = CAstTypes()

    # Add C types definition
    types_ast.add_c_decl(text)

    types_mngr = CTypesManagerNotPacked(types_ast, base_types)
    return types_mngr


class MyExprToAccessC(ExprToAccessC):
    allow_none_result = True


class MyCHandler(CHandler):
    exprToAccessC_cls = MyExprToAccessC


class TypePropagationEngine(SymbExecCType):

    def __init__(self, ir_arch, types_mngr, state):
        mychandler = MyCHandler(types_mngr, state.symbols)
        super(TypePropagationEngine, self).__init__(ir_arch,
                                                    state.symbols,
                                                    mychandler)


class SymbExecCTypeFix(SymbExecCType):

    def __init__(self, ir_arch,
                 symbols, chandler,
                 cst_propag_link,
                 func_read=None, func_write=None,
                 sb_expr_simp=expr_simp):
        super(SymbExecCTypeFix, self).__init__(ir_arch,
                                               symbols,
                                               chandler,
                                               func_read=func_read,
                                               func_write=func_write,
                                               sb_expr_simp=expr_simp)

        self.cst_propag_link = cst_propag_link

    def eval_updt_irblock(self, irb, step=False):
        """
        Symbolic execution of the @irb on the current state
        @irb: irblock instance
        @step: display intermediate steps
        """

        offset2cmt = {}
        for index, assignblk in enumerate(irb):
            if set(assignblk) == set([self.ir_arch.IRDst, self.ir_arch.pc]):
                # Don't display on jxx
                continue
            instr = assignblk.instr
            tmp_r = assignblk.get_r()
            tmp_w = assignblk.get_w()

            todo = set()

            # Replace PC with value to match IR args
            pc_fixed = {self.ir_arch.pc: m2_expr.ExprInt(instr.offset + instr.l, self.ir_arch.pc.size)}
            inputs = tmp_r
            inputs.update(arg for arg in tmp_w if arg.is_mem())
            for arg in inputs:
                arg = expr_simp(arg.replace_expr(pc_fixed))
                if arg in tmp_w and not arg.is_mem():
                    continue
                todo.add(arg)

            for expr in todo:
                if expr.is_int():
                    continue
                for c_str, c_type in self.chandler.expr_to_c_and_types(expr, self.symbols):
                    expr = self.cst_propag_link.get((irb.label, index), {}).get(expr, expr)
                    offset2cmt.setdefault(instr.offset, set()).add(
                        "\n%s: %s\n%s" % (expr, c_str, c_type))

            self.eval_updt_assignblk(assignblk)
        for offset, value in offset2cmt.iteritems():
            idc.MakeComm(offset, '\n'.join(value))
            print "%x\n" % offset, '\n'.join(value)

        return self.eval_expr(self.ir_arch.IRDst)


class CTypeEngineFixer(SymbExecCTypeFix):

    def __init__(self, ir_arch, types_mngr, state, cst_propag_link):
        mychandler = MyCHandler(types_mngr, state.symbols)
        super(CTypeEngineFixer, self).__init__(ir_arch,
                                               state.symbols,
                                               mychandler,
                                               cst_propag_link)


def get_ira_call_fixer(ira):

    class iraCallStackFixer(ira):

        def call_effects(self, ad, instr):
            print hex(instr.offset), instr
            stk_before = idc.GetSpd(instr.offset)
            stk_after = idc.GetSpd(instr.offset + instr.l)
            stk_diff = stk_after - stk_before
            print hex(stk_diff)
            return [AssignBlock([ExprAff(self.ret_reg, ExprOp('call_func_ret', ad)),
                                 ExprAff(self.sp, self.sp + ExprInt(stk_diff, self.sp.size))
                                 ],
                                instr
                                )]

    return iraCallStackFixer


def analyse_function():

    # Init
    machine = guess_machine()
    mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira

    bs = bin_stream_ida()
    mdis = dis_engine(bs, dont_dis_nulstart_bloc=True)


    iraCallStackFixer = get_ira_call_fixer(ira)
    ir_arch = iraCallStackFixer(mdis.symbol_pool)


    # Get the current function
    func = ida_funcs.get_func(idc.ScreenEA())
    addr = func.startEA
    blocks = mdis.dis_multiblock(addr)
    # Generate IR
    for block in blocks:
        ir_arch.add_block(block)


    # Get settings
    settings = TypePropagationForm(ir_arch)
    ret = settings.Execute()
    if not ret:
        return

    cst_propag_link = {}
    if settings.cUnalias.value:
        init_infos = {ir_arch.sp: ir_arch.arch.regs.regs_init[ir_arch.sp] }
        cst_propag_link = propagate_cst_expr(ir_arch, addr, init_infos)


    types_mngr = get_types_mngr(settings.headerFile.value, settings.arch.value)
    mychandler = MyCHandler(types_mngr, {})
    infos_types = {}
    for line in settings.strTypesInfo.value.split('\n'):
        if not line:
            continue
        expr_str, ctype_str = line.split(':')
        expr_str, ctype_str = expr_str.strip(), ctype_str.strip()
        expr = str_to_expr(expr_str)
        ast = mychandler.types_mngr.types_ast.parse_c_type(
            ctype_str)
        ctype = mychandler.types_mngr.types_ast.ast_parse_declaration(ast.ext[0])
        objc = types_mngr.get_objc(ctype)
        print '=' * 20
        print expr, objc
        infos_types[expr] = set([objc])

    # Add fake head
    lbl_real_start = ir_arch.symbol_pool.getby_offset(addr)
    lbl_head = ir_arch.symbol_pool.getby_name_create("start")

    first_block = blocks.label2block(lbl_real_start)

    assignblk_head = AssignBlock([ExprAff(ir_arch.IRDst, ExprId(lbl_real_start, ir_arch.IRDst.size)),
                                  ExprAff(
                                      ir_arch.sp, ir_arch.arch.regs.regs_init[ir_arch.sp])
                                  ], first_block.lines[0])
    irb_head = IRBlock(lbl_head, [assignblk_head])
    ir_arch.blocks[lbl_head] = irb_head
    ir_arch.graph.add_uniq_edge(lbl_head, lbl_real_start)

    state = TypePropagationEngine.StateEngine(infos_types)
    states = {lbl_head: state}
    todo = set([lbl_head])
    done = set()

    while todo:
        lbl = todo.pop()
        state = states[lbl]
        if (lbl, state) in done:
            continue
        done.add((lbl, state))
        if lbl not in ir_arch.blocks:
            continue

        symbexec_engine = TypePropagationEngine(ir_arch, types_mngr, state)
        addr = symbexec_engine.run_block_at(lbl)
        symbexec_engine.del_mem_above_stack(ir_arch.sp)

        ir_arch._graph = None
        sons = ir_arch.graph.successors(lbl)
        for son in sons:
            add_state(ir_arch, todo, states, son,
                      symbexec_engine.get_state())

    for lbl, state in states.iteritems():
        if lbl not in ir_arch.blocks:
            continue
        symbexec_engine = CTypeEngineFixer(ir_arch, types_mngr, state, cst_propag_link)
        addr = symbexec_engine.run_block_at(lbl)
        symbexec_engine.del_mem_above_stack(ir_arch.sp)


if __name__ == "__main__":
    analyse_function()
