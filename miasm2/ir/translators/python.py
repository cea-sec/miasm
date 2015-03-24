from miasm2.ir.translators.translator import Translator


class TranslatorPython(Translator):
    """Translate a Miasm expression to an equivalent Python code

    Memory is abstracted using the unimplemented function:
    int memory(int address, int size)
    """

    # Implemented language
    __LANG__ = "Python"
    # Operations translation
    op_no_translate = ["+", "-", "/", "%", ">>", "<<", "&", "^", "|", "*"]

    def from_ExprInt(self, expr):
        return str(expr)

    def from_ExprId(self, expr):
        return str(expr)

    def from_ExprMem(self, expr):
        return "memory(%s, 0x%x)" % (self.from_expr(expr.arg),
                                     expr.size / 8)

    def from_ExprSlice(self, expr):
        out = self.from_expr(expr.arg)
        if expr.start != 0:
            out = "(%s >> %d)" % (out, expr.start)
        return "(%s & 0x%x)" % (out, (1 << (expr.stop - expr.start)) - 1)

    def from_ExprCompose(self, expr):
        out = []
        for subexpr, start, stop in expr.args:
            out.append("((%s & 0x%x) << %d)" % (self.from_expr(subexpr),
                                                 (1 << (stop - start)) - 1,
                                                 start))
        return "(%s)" % ' | '.join(out)

    def from_ExprCond(self, expr):
        return "(%s if (%s) else %s)" % (self.from_expr(expr.src1),
                                         self.from_expr(expr.cond),
                                         self.from_expr(expr.src2))

    def from_ExprOp(self, expr):
        if expr.op in self.op_no_translate:
            args = map(self.from_expr, expr.args)
            if len(expr.args) == 1:
                return "((%s %s) & 0x%x)" % (expr.op,
                                             args[0],
                                             (1 << expr.size) - 1)
            else:
                return "((%s) & 0x%x)" % ((" %s " % expr.op).join(args),
                                        (1 << expr.size) - 1)
        elif expr.op == "parity":
            return "(%s & 0x1)" % self.from_expr(expr.args[0])

        raise NotImplementedError("Unknown operator: %s" % expr.op)

    def from_ExprAff(self, expr):
        return "%s = %s" % tuple(map(self.from_expr, (expr.dst, expr.src)))


# Register the class
Translator.register(TranslatorPython)
