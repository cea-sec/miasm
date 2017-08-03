import idaapi
from idc import *

from miasm2.analysis.machine import Machine
from miasm2.ir.translators import Translator
from miasm2.expression.expression import ExprInt, ExprId, ExprSlice, ExprMem, \
    ExprCond, ExprCompose, ExprOp, ExprAff

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


class ExprInt_ida(ExprInt):
    def __str__(self):
        return idaapi.COLSTR(super(ExprInt_ida, self).__str__(), idaapi.SCOLOR_NUMBER)

class ExprId_ida(ExprId):
    def __str__(self):
        out = super(ExprId_ida, self).__str__()
        expr = ExprId(self.name, self.size)
        if expr in self.regs_ids:
            return idaapi.COLSTR(out, idaapi.SCOLOR_REG)
        else:
            return out

class ExprSlice_ida(ExprSlice):
    def __str__(self):
        s = "%s[%s:%s]" % (self.arg._str_sub_expr(self),
                           idaapi.COLSTR(str(self.start),
                                         idaapi.SCOLOR_RPTCMT),
                           idaapi.COLSTR(str(self.stop),
                                         idaapi.SCOLOR_RPTCMT))
        return s

class ExprMem_ida(ExprMem):
    def __str__(self):
        return '%s[%s]' % (idaapi.COLSTR('@' + str(self.size),
                                         idaapi.SCOLOR_RPTCMT),
                           self.arg)

class ExprCond_ida(ExprCond):
    pass

class ExprCompose_ida(ExprCompose):
    def __str__(self):
        s = '{'
        s += ", ".join("%s, %s, %s" % (subexpr,
                                       idaapi.COLSTR(str(idx),
                                                     idaapi.SCOLOR_RPTCMT),
                                       idaapi.COLSTR(str(idx + subexpr.size),
                                                     idaapi.SCOLOR_RPTCMT))
                       for idx, subexpr in self.iter_args())
        s += '}'
        return s

class ExprOp_ida(ExprOp):
    pass

class ExprAff_ida(ExprAff):
    pass

def expr2exprida(regs_ids, expr):
    """Translate an Expr into an ExprIda
    @regs_ids: list of ExprId corresponding to available registers
    @expr: Expr instance to transform
    """

    if expr.is_int():
        new_expr = ExprInt_ida(expr.arg, expr.size)
    elif expr.is_id():
        new_expr =  ExprId_ida(expr.name, expr.size)
    elif expr.is_slice():
        new_expr =  ExprSlice_ida(expr2exprida(regs_ids, expr.arg), expr.start, expr.stop)
    elif expr.is_mem():
        new_expr =  ExprMem_ida(expr2exprida(regs_ids, expr.arg), expr.size)
    elif expr.is_cond():
        new_expr =  ExprCond_ida(expr2exprida(regs_ids, expr.cond),
                                 expr2exprida(regs_ids, expr.src1),
                                 expr2exprida(regs_ids, expr.src2))
    elif expr.is_compose():
        new_expr =  ExprCompose_ida(*[expr2exprida(regs_ids, arg) for arg in expr.args])
    elif expr.is_op():
        new_expr =  ExprOp_ida(expr.op, *[expr2exprida(regs_ids, arg) for arg in expr.args])
    elif expr.is_aff():
        new_expr =  ExprMem_ida(expr2exprida(regs_ids, expr.dst),
                                expr2exprida(regs_ids, expr.src))
    new_expr.regs_ids = regs_ids
    return new_expr

def expr2colorstr(regs_ids, expr):
    """Colorize an Expr instance for IDA
    @regs_ids: list of ExprId corresponding to available registers
    @expr: Expr instance to colorize
    """
    return str(expr2exprida(regs_ids, expr))

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
