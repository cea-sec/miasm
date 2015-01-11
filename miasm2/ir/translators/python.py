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

    @classmethod
    def from_ExprInt(cls, expr):
        return str(expr)

    @classmethod
    def from_ExprId(cls, expr):
        return str(expr)

    @classmethod
    def from_ExprMem(cls, expr):
        return "memory(%s, 0x%x)" % (cls.from_expr(expr.arg),
                                     expr.size / 8)

    @classmethod
    def from_ExprSlice(cls, expr):
        out = cls.from_expr(expr.arg)
        if expr.start != 0:
            out = "(%s >> %d)" % (out, expr.start)
        return "(%s & 0x%x)" % (out, (1 << (expr.stop - expr.start)) - 1)

    @classmethod
    def from_ExprCompose(cls, expr):
        out = []
        for subexpr, start, stop in expr.args:
            out.append("((%s & 0x%x) << %d)" % (cls.from_expr(subexpr),
                                                 (1 << (stop - start)) - 1,
                                                 start))
        return "(%s)" % ' | '.join(out)

    @classmethod
    def from_ExprCond(cls, expr):
        return "(%s if (%s) else %s)" % (cls.from_expr(expr.src1),
                                         cls.from_expr(expr.cond),
                                         cls.from_expr(expr.src2))

    @classmethod
    def from_ExprOp(cls, expr):
        if expr.op in cls.op_no_translate:
            args = map(cls.from_expr, expr.args)
            if len(expr.args) == 1:
                return "((%s %s) & 0x%x)" % (expr.op,
                                             args[0],
                                             (1 << expr.size) - 1)
            else:
                return "((%s) & 0x%x)" % ((" %s " % expr.op).join(args),
                                        (1 << expr.size) - 1)
        elif expr.op == "parity":
            return "(%s & 0x1)" % cls.from_expr(expr.args[0])

        raise NotImplementedError("Unknown operator: %s" % expr.op)

    @classmethod
    def from_ExprAff(cls, expr):
        return "%s = %s" % tuple(map(cls.from_expr, (expr.dst, expr.src)))


# Register the class
Translator.register(TranslatorPython)
