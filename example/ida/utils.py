from __future__ import print_function
from builtins import map
import idaapi
from idc import *

from miasm.analysis.machine import Machine
from miasm.ir.translators import Translator
import miasm.expression.expression as m2_expr

def guess_machine(addr=None):
    "Return an instance of Machine corresponding to the IDA guessed processor"

    processor_name = get_inf_attr(INF_PROCNAME)
    info = idaapi.get_inf_structure()

    if info.is_64bit():
        size = 64
    elif info.is_32bit():
        size = 32
    else:
        size = None

    if processor_name == "metapc":
        size2machine = {
            64: "x86_64",
            32: "x86_32",
            None: "x86_16",
        }

        machine = Machine(size2machine[size])

    elif processor_name == "ARM":
        # TODO ARM/thumb
        # hack for thumb: set armt = True in globals :/
        # set bigendiant = True is bigendian
        # Thumb, size, endian
        info2machine = {(True, 32, True): "armtb",
                        (True, 32, False): "armtl",
                        (False, 32, True): "armb",
                        (False, 32, False): "arml",
                        (False, 64, True): "aarch64b",
                        (False, 64, False): "aarch64l",
                        }

        # Get T reg to detect arm/thumb function
        # Default is arm
        is_armt = False
        if addr is not None:
            t_reg = get_sreg(addr, "T")
            is_armt = t_reg == 1

        is_bigendian = info.is_be()
        infos = (is_armt, size, is_bigendian)
        if not infos in info2machine:
            raise NotImplementedError('not fully functional')
        machine = Machine(info2machine[infos])

        from miasm.analysis.disasm_cb import guess_funcs, guess_multi_cb
        from miasm.analysis.disasm_cb import arm_guess_subcall, arm_guess_jump_table
        guess_funcs.append(arm_guess_subcall)
        guess_funcs.append(arm_guess_jump_table)

    elif processor_name == "msp430":
        machine = Machine("msp430")
    elif processor_name == "mipsl":
        machine = Machine("mips32l")
    elif processor_name == "mipsb":
        machine = Machine("mips32b")
    elif processor_name == "PPC":
        machine = Machine("ppc32b")
    else:
        print(repr(processor_name))
        raise NotImplementedError('not fully functional')

    return machine


class TranslatorIDA(Translator):
    """Translate a Miasm expression to a IDA colored string"""

    # Implemented language
    __LANG__ = "ida_w_color"

    def __init__(self, loc_db=None, **kwargs):
        super(TranslatorIDA, self).__init__(**kwargs)
        self.loc_db = loc_db

    def str_protected_child(self, child, parent):
        return ("(%s)" % (
            self.from_expr(child)) if m2_expr.should_parenthesize_child(child, parent)
                else self.from_expr(child)
        )

    def from_ExprInt(self, expr):
        return idaapi.COLSTR(str(expr), idaapi.SCOLOR_NUMBER)

    def from_ExprId(self, expr):
        out = idaapi.COLSTR(str(expr), idaapi.SCOLOR_REG)
        return out

    def from_ExprLoc(self, expr):
        if self.loc_db is not None:
            out = self.loc_db.pretty_str(expr.loc_key)
        else:
            out = str(expr)
        out = idaapi.COLSTR(out, idaapi.SCOLOR_REG)
        return out

    def from_ExprMem(self, expr):
        ptr = self.from_expr(expr.ptr)
        size = idaapi.COLSTR('@' + str(expr.size), idaapi.SCOLOR_RPTCMT)
        out = '%s[%s]' % (size, ptr)
        return out

    def from_ExprSlice(self, expr):
        base = self.from_expr(expr.arg)
        start = idaapi.COLSTR(str(expr.start), idaapi.SCOLOR_RPTCMT)
        stop = idaapi.COLSTR(str(expr.stop), idaapi.SCOLOR_RPTCMT)
        out = "(%s)[%s:%s]" % (base, start, stop)
        return out

    def from_ExprCompose(self, expr):
        out = "{"
        out += ", ".join(["%s, %s, %s" % (self.from_expr(subexpr),
                                          idaapi.COLSTR(str(idx), idaapi.SCOLOR_RPTCMT),
                                          idaapi.COLSTR(str(idx + subexpr.size), idaapi.SCOLOR_RPTCMT))
                          for idx, subexpr in expr.iter_args()])
        out += "}"
        return out

    def from_ExprCond(self, expr):
        cond = self.str_protected_child(expr.cond, expr)
        src1 = self.from_expr(expr.src1)
        src2 = self.from_expr(expr.src2)
        out = "%s?(%s,%s)" % (cond, src1, src2)
        return out

    def from_ExprOp(self, expr):
        if expr._op == '-':		# Unary minus
            return '-' + self.str_protected_child(expr._args[0], expr)
        if expr.is_associative() or expr.is_infix():
            return (' ' + expr._op + ' ').join([self.str_protected_child(arg, expr)
                                                for arg in expr._args])
        return (expr._op + '(' +
                ', '.join(
                    self.from_expr(arg)
                    for arg in expr._args
                ) + ')')

    def from_ExprAssign(self, expr):
        return "%s = %s" % tuple(map(expr.from_expr, (expr.dst, expr.src)))



def expr2colorstr(expr, loc_db):
    """Colorize an Expr instance for IDA
    @expr: Expr instance to colorize
    @loc_db: LocationDB instance
    """

    translator = TranslatorIDA(loc_db=loc_db)
    return translator.from_expr(expr)


class translatorForm(idaapi.Form):
    """Translator Form.

    Offer a ComboBox with available languages (ie. IR translators) and the
    corresponding translation."""

    flags = (idaapi.Form.MultiLineTextControl.TXTF_FIXEDFONT | \
                 idaapi.Form.MultiLineTextControl.TXTF_READONLY)

    def __init__(self, expr):
        "@expr: Expr instance"

        # Init
        self.languages = list(Translator.available_languages())
        self.expr = expr

        # Initial translation
        text = Translator.to_language(self.languages[0]).from_expr(self.expr)

        # Create the Form
        idaapi.Form.__init__(self, r"""STARTITEM 0
Python Expression
{FormChangeCb}
<Language:{cbLanguage}>
<Translation:{result}>
""", {
            'result': idaapi.Form.MultiLineTextControl(text=text,
                                                       flags=translatorForm.flags),
            'cbLanguage': idaapi.Form.DropdownListControl(
                    items=self.languages,
                    readonly=True,
                    selval=0),
            'FormChangeCb': idaapi.Form.FormChangeCb(self.OnFormChange),
        })

    def OnFormChange(self, fid):
        if fid == self.cbLanguage.id:
            # Display the Field (may be hide)
            self.ShowField(self.result, True)

            # Translate the expression
            dest_lang = self.languages[self.GetControlValue(self.cbLanguage)]
            try:
                text = Translator.to_language(dest_lang).from_expr(self.expr)
            except Exception as error:
                self.ShowField(self.result, False)
                return -1

            # Update the form
            self.SetControlValue(self.result,
                                 idaapi.textctrl_info_t(text=str(text),
                                                        flags=translatorForm.flags))
        return 1
