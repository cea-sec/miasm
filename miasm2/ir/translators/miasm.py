from miasm2.ir.translators.translator import Translator


class TranslatorMiasm(Translator):
    "Translate a Miasm expression to its Python building form"

    __LANG__ = "Miasm"

    def from_ExprId(self, expr):
        return "ExprId(%s, size=%d)" % (repr(expr.name), expr.size)

    def from_ExprInt(self, expr):
        return "ExprInt_fromsize(%d, 0x%x)" % (expr.size, int(expr.arg))

    def from_ExprCond(self, expr):
        return "ExprCond(%s, %s, %s)" % (self.from_expr(expr.cond),
                                         self.from_expr(expr.src1),
                                         self.from_expr(expr.src2))

    def from_ExprSlice(self, expr):
        return "ExprSlice(%s, %d, %d)" % (self.from_expr(expr.arg),
                                          expr.start,
                                          expr.stop)

    def from_ExprOp(self, expr):
        return "ExprOp(%s, %s)" % (repr(expr.op),
                                   ", ".join(map(self.from_expr, expr.args)))

    def from_ExprCompose(self, expr):
        args = ["(%s, %d, %d)" % (self.from_expr(arg), start, stop)
                for arg, start, stop in expr.args]
        return "ExprCompose([%s])" % ", ".join(args)

    def from_ExprAff(self, expr):
        return "ExprAff(%s, %s)" % (self.from_expr(expr.dst),
                                    self.from_expr(expr.src))

    def from_ExprMem(self, expr):
        return "ExprMem(%s, size=%d)" % (self.from_expr(expr.arg), expr.size)


# Register the class
Translator.register(TranslatorMiasm)
