import operator

import idaapi
import idc
from miasm2.expression.expression_helper import Variables_Identifier
from miasm2.expression.expression import ExprAff

from utils import expr2colorstr, translatorForm


class symbolicexec_t(idaapi.simplecustviewer_t):

    def add(self, key, value):
        self.AddLine("%s = %s" % (expr2colorstr(self.machine.mn.regs.all_regs_ids, key),
                                  expr2colorstr(self.machine.mn.regs.all_regs_ids, value)))

    def expand(self, linenum):
        element = self.line2eq[linenum]
        expanded = Variables_Identifier(element[1],
                                        var_prefix="%s_v" % element[0])
        self.line2eq = self.line2eq[0:linenum] + \
            expanded.vars.items() + \
            [(element[0], expanded.equation)] + \
            self.line2eq[linenum + 1:]

    def print_lines(self):
        self.ClearLines()

        for element in self.line2eq:
            self.add(*element)

        self.Refresh()

    def translate_expr(self, line_nb):
        element = self.line2eq[line_nb]
        expr = ExprAff(*element)
        form = translatorForm(expr)
        form.Compile()
        form.Execute()

    def Create(self, equations, machine, *args, **kwargs):
        if not super(symbolicexec_t, self).Create(*args, **kwargs):
            return False

        self.machine = machine
        self.line2eq = sorted(equations.items(), key=operator.itemgetter(0))
        self.lines_expanded = set()

        self.print_lines()

        self.menu_expand = self.AddPopupMenu("Expand [E]")
        self.menu_translate = self.AddPopupMenu("Translate [T]")
        return True

    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_expand:
            self.expand(self.GetLineNo())
            self.print_lines()
        if menu_id == self.menu_translate:
            self.translate_expr(self.GetLineNo())
        return True

    def OnKeydown(self, vkey, shift):
        # ESCAPE
        if vkey == 27:
            self.Close()
            return True
        # E (expand)
        if vkey == 69:
            self.OnPopupMenu(self.menu_expand)
        # T (translate)
        if vkey == 84:
            self.OnPopupMenu(self.menu_translate)
        return False


def symbolic_exec():
    from miasm2.ir.symbexec import symbexec
    from miasm2.core.bin_stream_ida import bin_stream_ida

    from utils import guess_machine

    bs = bin_stream_ida()
    machine = guess_machine()

    mdis = machine.dis_engine(bs)
    start, end = SelStart(), SelEnd()

    mdis.dont_dis = [end]
    blocs = mdis.dis_multibloc(start)
    ira = machine.ira()
    for bloc in blocs:
        ira.add_bloc(bloc)

    print "Run symbolic execution..."
    sb = symbexec(ira, machine.mn.regs.regs_init)
    sb.emul_ir_blocs(ira, start)

    modified = {}
    for ident in sb.symbols.symbols_id:
        if ident in sb.ir_arch.arch.regs.regs_init and \
                ident in sb.symbols.symbols_id and \
                sb.symbols.symbols_id[ident] == sb.ir_arch.arch.regs.regs_init[ident]:
            continue
        modified[ident] = sb.symbols.symbols_id[ident]

    for ident in sb.symbols.symbols_mem:
        modified[sb.symbols.symbols_mem[ident][0]] = sb.symbols.symbols_mem[ident][1]


    view = symbolicexec_t()
    if not view.Create(modified, machine,
                       "Symbolic Execution - 0x%x to 0x%x" % (start, end)):
        return

    view.Show()

idaapi.CompileLine('static key_F3() { RunPythonStatement("symbolic_exec()"); }')
idc.AddHotkey("F3", "key_F3")

print "=" * 50
print """Available commands:
    symbolic_exec() - F3: Symbolic execution of current selection
"""
