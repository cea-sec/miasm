from miasm2.ir.translators.translator import Translator


class TranslatorMiasm(Translator):
    "Translate a Miasm expression to its Python building form"

    __LANG__ = "Miasm"

    @classmethod
    def from_ExprId(cls, expr):
        return "ExprId(%s, size=%d)" % (repr(expr.name), expr.size)

    @classmethod
    def from_ExprInt(cls, expr):
        return "ExprInt_fromsize(%d, 0x%x)" % (expr.size, int(expr.arg))

    @classmethod
    def from_ExprCond(cls, expr):
        return "ExprCond(%s, %s, %s)" % (cls.from_expr(expr.cond),
                                         cls.from_expr(expr.src1),
                                         cls.from_expr(expr.src2))

    @classmethod
    def from_ExprSlice(cls, expr):
        return "ExprSlice(%s, %d, %d)" % (cls.from_expr(expr.arg),
                                          expr.start,
                                          expr.stop)

    @classmethod
    def from_ExprOp(cls, expr):
        return "ExprOp(%s, %s)" % (repr(expr.op),
                                   ", ".join(map(cls.from_expr, expr.args)))

    @classmethod
    def from_ExprCompose(cls, expr):
        args = ["(%s, %d, %d)" % (cls.from_expr(arg), start, stop)
                for arg, start, stop in expr.args]
        return "ExprCompose([%s])" % ", ".join(args)

    @classmethod
    def from_ExprAff(cls, expr):
        return "ExprAff(%s, %s)" % (cls.from_expr(expr.dst),
                                    cls.from_expr(expr.src))

    @classmethod
    def from_ExprMem(cls, expr):
        return "ExprMem(%s, size=%d)" % (cls.from_expr(expr.arg), expr.size)


# Register the class
Translator.register(TranslatorMiasm)
