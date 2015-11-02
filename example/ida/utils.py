import idaapi
from idc import *

from miasm2.analysis.machine import Machine
from miasm2.ir.translators import Translator
import miasm2.expression.expression as m2_expr

def max_size_to_size(max_size):
    for size in [16, 32, 64]:
        if (1 << size) - 1 == max_size:
            return size
    return None

def guess_machine():
    "Return an instance of Machine corresponding to the IDA guessed processor"

    processor_name = GetLongPrm(INF_PROCNAME)
    max_size = GetLongPrm(INF_START_SP)
    size = max_size_to_size(max_size)

    if processor_name == "metapc":

        # HACK: check 32/64 using INF_START_SP
        if max_size == 0x80:  # TODO XXX check
            machine = Machine("x86_16")
        elif size == 32:
            machine = Machine("x86_32")
        elif size == 64:
            machine = Machine("x86_64")
        else:
            raise ValueError('cannot guess 32/64 bit! (%x)' % max_size)
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
        is_armt = globals().get('armt', False)
        is_bigendian = globals().get('bigendian', False)
        infos = (is_armt, size, is_bigendian)
        if not infos in info2machine:
            raise NotImplementedError('not fully functional')
        machine = Machine(info2machine[infos])

        from miasm2.analysis.disasm_cb import guess_funcs, guess_multi_cb
        from miasm2.analysis.disasm_cb import arm_guess_subcall, arm_guess_jump_table
        guess_funcs.append(arm_guess_subcall)
        guess_funcs.append(arm_guess_jump_table)

    elif processor_name == "msp430":
        machine = Machine("msp430")
    elif processor_name == "mipsl":
        machine = Machine("mips32l")
    elif processor_name == "mipsb":
        machine = Machine("mips32b")
    else:
        print repr(processor_name)
        raise NotImplementedError('not fully functional')

    return machine


def expr2colorstr(regs_ids, expr):
    """Colorize an Expr instance for IDA
    @regs_ids: list of ExprId corresponding to available registers
    @expr: Expr instance to colorize
    """

    if isinstance(expr, m2_expr.ExprId):
        s = str(expr)
        if expr in regs_ids:
            s = idaapi.COLSTR(s, idaapi.SCOLOR_REG)
    elif isinstance(expr, m2_expr.ExprInt):
        s = str(expr)
        s = idaapi.COLSTR(s, idaapi.SCOLOR_NUMBER)
    elif isinstance(expr, m2_expr.ExprMem):
        s = '%s[%s]' % (idaapi.COLSTR('@' + str(expr.size),
                                      idaapi.SCOLOR_RPTCMT),
                         expr2colorstr(regs_ids, expr.arg))
    elif isinstance(expr, m2_expr.ExprOp):
        out = []
        for a in expr.args:
            s = expr2colorstr(regs_ids, a)
            if isinstance(a, m2_expr.ExprOp):
                s = "(%s)" % s
            out.append(s)
        if len(out) == 1:
            s = "%s %s" % (expr.op, str(out[0]))
        else:
            s = (" " + expr.op + " ").join(out)
    elif isinstance(expr, m2_expr.ExprAff):
        s = "%s = %s" % (
            expr2colorstr(regs_ids, expr.dst), expr2colorstr(regs_ids, expr.src))
    elif isinstance(expr, m2_expr.ExprCond):
        cond = expr2colorstr(regs_ids, expr.cond)
        src1 = expr2colorstr(regs_ids, expr.src1)
        src2 = expr2colorstr(regs_ids, expr.src2)
        s = "(%s?%s:%s)" % (cond, src1, src2)
    elif isinstance(expr, m2_expr.ExprSlice):
        s = "(%s)[%s:%s]" % (expr2colorstr(regs_ids, expr.arg),
                             idaapi.COLSTR(str(expr.start),
                                           idaapi.SCOLOR_RPTCMT),
                             idaapi.COLSTR(str(expr.stop),
                                           idaapi.SCOLOR_RPTCMT))
    elif isinstance(expr, m2_expr.ExprCompose):
        s = "{"
        s += ", ".join(["%s, %s, %s" % (expr2colorstr(regs_ids, subexpr),
                                        idaapi.COLSTR(str(start),
                                                      idaapi.SCOLOR_RPTCMT),
                                        idaapi.COLSTR(str(stop),
                                                      idaapi.SCOLOR_RPTCMT))
                        for subexpr, start, stop in expr.args])
        s += "}"
    else:
        s = str(expr)

    return s


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
            except Exception, error:
                self.ShowField(self.result, False)
                return -1

            # Update the form
            self.SetControlValue(self.result,
                                 idaapi.textctrl_info_t(text=str(text),
                                                        flags=translatorForm.flags))
        return 1
