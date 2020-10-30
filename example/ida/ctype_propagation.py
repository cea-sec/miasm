from __future__ import print_function
import ida_kernwin
import idc
import ida_funcs

from future.utils import viewitems

from miasm.core.bin_stream_ida import bin_stream_ida
from miasm.expression import expression as m2_expr
from miasm.expression.simplifications import expr_simp
from miasm.ir.ir import IRBlock, AssignBlock
from miasm.arch.x86.ctype import CTypeAMD64_unk, CTypeX86_unk
from miasm.arch.msp430.ctype import CTypeMSP430_unk
from miasm.core.objc import CTypesManagerNotPacked, ExprToAccessC, CHandler
from miasm.core.ctypesmngr import CAstTypes
from miasm.expression.expression import ExprLoc, ExprInt, ExprOp, ExprAssign
from miasm.ir.symbexec_types import SymbExecCType
from miasm.expression.parser import str_to_expr
from miasm.analysis.cst_propag import add_state, propagate_cst_expr
from miasm.core.locationdb import LocationDB

from utils import guess_machine

class TypePropagationForm(ida_kernwin.Form):

    def __init__(self):

        default_types_info = r"""ExprId("RDX", 64): char *"""
        archs = ["AMD64_unk", "X86_32_unk", "msp430_unk"]

        func = ida_funcs.get_func(idc.get_screen_ea())
        func_addr = func.start_ea

        start_addr = idc.read_selection_start()
        if start_addr == idc.BADADDR:
            start_addr = idc.get_screen_ea()
        end_addr = idc.read_selection_end()

        ida_kernwin.Form.__init__(self,
                      r"""BUTTON YES* Launch
BUTTON CANCEL NONE
Type Propagation Settings

{FormChangeCb}
Analysis scope:
<Whole function:{rFunction}>
<From an address to the end of function:{rAddr}>
<Between two addresses:{r2Addr}>{cScope}>

<Target function:{functionAddr}>
<Start address  :{startAddr}>
<End address    :{endAddr}>

<Architecture/compilator :{arch}>

<##Header file          :{headerFile}>
<Use a file for type information:{rTypeFile}>{cTypeFile}>
<##Types information   :{typeFile}>
<Types information     :{strTypesInfo}>

<Unalias stack:{rUnaliasStack}>{cUnalias}>
""", {
                          'FormChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange),
                          'cScope': ida_kernwin.Form.RadGroupControl(
                              ("rFunction", "rAddr", "r2Addr")),
                          'functionAddr': ida_kernwin.Form.NumericInput(
                              tp=ida_kernwin.Form.FT_RAWHEX,
                              value=func_addr),
                          'startAddr': ida_kernwin.Form.NumericInput(
                              tp=ida_kernwin.Form.FT_RAWHEX,
                              value=start_addr),
                          'endAddr': ida_kernwin.Form.NumericInput(
                              tp=ida_kernwin.Form.FT_RAWHEX,
                              value=end_addr),
                          'arch': ida_kernwin.Form.DropdownListControl(
                              items=archs,
                              readonly=False,
                              selval=archs[0]),
                          'headerFile': ida_kernwin.Form.FileInput(swidth=20, open=True),
                          'cTypeFile': ida_kernwin.Form.ChkGroupControl(("rTypeFile",)),
                          'typeFile': ida_kernwin.Form.FileInput(swidth=20, open=True),
                          'strTypesInfo': ida_kernwin.Form.MultiLineTextControl(text=default_types_info,
                                                                    flags=ida_kernwin.Form.MultiLineTextControl.TXTF_FIXEDFONT),
                          'cUnalias': ida_kernwin.Form.ChkGroupControl(("rUnaliasStack",)),
                      })
        form, args = self.Compile()
        form.rUnaliasStack.checked = True
        form.rTypeFile.checked = True

    def OnFormChange(self, fid):
        if fid == -1: # INIT
            self.EnableField(self.functionAddr, True)
            self.EnableField(self.startAddr, False)
            self.EnableField(self.endAddr, False)
            self.EnableField(self.strTypesInfo, False)
            self.EnableField(self.typeFile, True)
        elif fid == self.cTypeFile.id:
            if self.GetControlValue(self.cTypeFile) == 0:
                self.EnableField(self.strTypesInfo, True)
                self.EnableField(self.typeFile, False)
            elif self.GetControlValue(self.cTypeFile) == 1:
                self.EnableField(self.strTypesInfo, False)
                self.EnableField(self.typeFile, True)
        elif fid == self.cScope.id:
            # "Whole function" scope
            if self.GetControlValue(self.cScope) == 0:
                self.EnableField(self.functionAddr, True)
                self.EnableField(self.startAddr, False)
                self.EnableField(self.endAddr, False)
            # "From an address" scope
            elif self.GetControlValue(self.cScope) == 1:
                self.EnableField(self.functionAddr, False)
                self.EnableField(self.startAddr, True)
                self.EnableField(self.endAddr, False)
            # "Between two addresses" scope
            elif self.GetControlValue(self.cScope) == 2:
                self.EnableField(self.functionAddr, False)
                self.EnableField(self.startAddr, True)
                self.EnableField(self.endAddr, True)
        return 1

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
                 sb_expr_simp=expr_simp):
        super(SymbExecCTypeFix, self).__init__(ir_arch,
                                               symbols,
                                               chandler,
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
                    expr = self.cst_propag_link.get((irb.loc_key, index), {}).get(expr, expr)
                    offset2cmt.setdefault(instr.offset, set()).add(
                        "\n%s: %s\n%s" % (expr, c_str, c_type)
                    )
            self.eval_updt_assignblk(assignblk)
        for offset, value in viewitems(offset2cmt):
            idc.set_cmt(offset, '\n'.join(value), 0)
            print("%x\n" % offset, '\n'.join(value))

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
            print(hex(instr.offset), instr)
            stk_before = idc.get_spd(instr.offset)
            stk_after = idc.get_spd(instr.offset + instr.l)
            stk_diff = stk_after - stk_before
            print(hex(stk_diff))
            call_assignblk = AssignBlock(
                [
                    ExprAssign(self.ret_reg, ExprOp('call_func_ret', ad)),
                    ExprAssign(self.sp, self.sp + ExprInt(stk_diff, self.sp.size))
                ],
                instr
            )
            return [call_assignblk], []

    return iraCallStackFixer


def analyse_function():
    # Get settings
    settings = TypePropagationForm()
    ret = settings.Execute()
    if not ret:
        return


    end = None
    if settings.cScope.value == 0:
        addr = settings.functionAddr.value
    else:
        addr = settings.startAddr.value
        if settings.cScope.value == 2:
            end = settings.endAddr

    # Init
    machine = guess_machine(addr=addr)
    mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira

    bs = bin_stream_ida()
    loc_db = LocationDB()

    mdis = dis_engine(bs, loc_db=loc_db, dont_dis_nulstart_bloc=True)
    if end is not None:
        mdis.dont_dis = [end]


    iraCallStackFixer = get_ira_call_fixer(ira)
    ir_arch = iraCallStackFixer(loc_db)

    asmcfg = mdis.dis_multiblock(addr)
    # Generate IR
    ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

    cst_propag_link = {}
    if settings.cUnalias.value:
        init_infos = {ir_arch.sp: ir_arch.arch.regs.regs_init[ir_arch.sp] }
        cst_propag_link = propagate_cst_expr(ir_arch, ircfg, addr, init_infos)


    types_mngr = get_types_mngr(settings.headerFile.value, settings.arch.value)
    mychandler = MyCHandler(types_mngr, {})
    infos_types = {}
    infos_types_raw = []

    if settings.cTypeFile.value:
        infos_types_raw = open(settings.typeFile.value).read().split('\n')
    else:
        infos_types_raw = settings.strTypesInfo.value.split('\n')

    for line in infos_types_raw:
        if not line:
            continue
        expr_str, ctype_str = line.split(':')
        expr_str, ctype_str = expr_str.strip(), ctype_str.strip()
        expr = str_to_expr(expr_str)
        ast = mychandler.types_mngr.types_ast.parse_c_type(
            ctype_str
        )
        ctype = mychandler.types_mngr.types_ast.ast_parse_declaration(ast.ext[0])
        objc = types_mngr.get_objc(ctype)
        print('=' * 20)
        print(expr, objc)
        infos_types[expr] = set([objc])

    # Add fake head
    lbl_real_start = loc_db.get_offset_location(addr)
    lbl_head = loc_db.get_or_create_name_location("start")

    first_block = asmcfg.label2block(lbl_real_start)

    assignblk_head = AssignBlock(
        [
            ExprAssign(ir_arch.IRDst, ExprLoc(lbl_real_start, ir_arch.IRDst.size)),
            ExprAssign(ir_arch.sp, ir_arch.arch.regs.regs_init[ir_arch.sp])
        ],
        first_block.lines[0]
    )
    irb_head = IRBlock(lbl_head, [assignblk_head])
    ircfg.blocks[lbl_head] = irb_head
    ircfg.add_uniq_edge(lbl_head, lbl_real_start)

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
        if lbl not in ircfg.blocks:
            continue
        symbexec_engine = TypePropagationEngine(ir_arch, types_mngr, state)
        symbexec_engine.run_block_at(ircfg, lbl)
        symbexec_engine.del_mem_above_stack(ir_arch.sp)

        sons = ircfg.successors(lbl)
        for son in sons:
            add_state(
                ircfg, todo, states, son,
                symbexec_engine.get_state()
            )

    for lbl, state in viewitems(states):
        if lbl not in ircfg.blocks:
            continue
        symbexec_engine = CTypeEngineFixer(ir_arch, types_mngr, state, cst_propag_link)
        symbexec_engine.run_block_at(ircfg, lbl)
        symbexec_engine.del_mem_above_stack(ir_arch.sp)


if __name__ == "__main__":
    analyse_function()
