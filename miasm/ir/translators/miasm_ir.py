from builtins import map
from miasm.ir.translators.translator import Translator


class TranslatorMiasm(Translator):
    "Translate a Miasm expression to its Python building form"

    __LANG__ = "Miasm"

    def from_ExprId(self, expr):
        return "ExprId(%s, size=%d)" % (repr(expr.name), expr.size)

    def from_ExprInt(self, expr):
        return "ExprInt(0x%x, %d)" % (int(expr), expr.size)

    def from_ExprCond(self, expr):
        return "ExprCond(%s, %s, %s)" % (self.from_expr(expr.cond),
                                         self.from_expr(expr.src1),
                                         self.from_expr(expr.src2))

    def from_ExprSlice(self, expr):
        return "ExprSlice(%s, %d, %d)" % (self.from_expr(expr.arg),
                                          expr.start,
                                          expr.stop)

    def from_ExprOp(self, expr):
        return "ExprOp(%s, %s)" % (
            repr(expr.op),
            ", ".join(map(self.from_expr, expr.args))
        )

    def from_ExprCompose(self, expr):
        args = ["%s" % self.from_expr(arg) for arg in expr.args]
        return "ExprCompose(%s)" % ", ".join(args)

    def from_ExprAssign(self, expr):
        return "ExprAssign(%s, %s)" % (self.from_expr(expr.dst),
                                    self.from_expr(expr.src))

    def from_ExprMem(self, expr):
        return "ExprMem(%s, size=%d)" % (self.from_expr(expr.ptr), expr.size)


# Register the class
Translator.register(TranslatorMiasm)
