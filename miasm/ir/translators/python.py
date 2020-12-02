from builtins import map
from miasm.expression.expression import ExprInt
from miasm.ir.translators.translator import Translator
from miasm.expression.expression import ExprCond, ExprInt


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

    def from_ExprLoc(self, expr):
        return str(expr)

    def from_ExprMem(self, expr):
        return "memory(%s, 0x%x)" % (
            self.from_expr(expr.ptr),
            expr.size // 8
        )

    def from_ExprSlice(self, expr):
        out = self.from_expr(expr.arg)
        if expr.start != 0:
            out = "(%s >> %d)" % (out, expr.start)
        return "(%s & 0x%x)" % (out, (1 << (expr.stop - expr.start)) - 1)

    def from_ExprCompose(self, expr):
        out = []
        for index, arg in expr.iter_args():
            out.append(
                "((%s & 0x%x) << %d)" % (
                    self.from_expr(arg),
                    (1 << arg.size) - 1,
                    index
                )
            )
        return "(%s)" % ' | '.join(out)

    def from_ExprCond(self, expr):
        return "(%s if (%s) else %s)" % (
            self.from_expr(expr.src1),
            self.from_expr(expr.cond),
            self.from_expr(expr.src2)
        )

    def from_ExprOp(self, expr):
        if expr.op in self.op_no_translate:
            args = list(map(self.from_expr, expr.args))
            if len(expr.args) == 1:
                return "((%s %s) & 0x%x)" % (
                    expr.op,
                    args[0],
                    (1 << expr.size) - 1
                )
            else:
                return "((%s) & 0x%x)" % (
                    (" %s " % expr.op).join(args),
                    (1 << expr.size) - 1
                )
        elif expr.op == "parity":
            return "(%s & 0x1)" % self.from_expr(expr.args[0])
        elif expr.op == "==":
            return self.from_expr(
                ExprCond(expr.args[0] - expr.args[1], ExprInt(0, 1), ExprInt(1, 1))
            )

        elif expr.op in ["<<<", ">>>"]:
            amount_raw = expr.args[1]
            amount = expr.args[1] % ExprInt(amount_raw.size, expr.size)
            amount_inv = ExprInt(expr.size, expr.size) - amount
            if expr.op == "<<<":
                amount, amount_inv = amount_inv, amount
            part1 = "(%s >> %s)"% (self.from_expr(expr.args[0]),
                                   self.from_expr(amount))
            part2 = "(%s << %s)"% (self.from_expr(expr.args[0]),
                                         self.from_expr(amount_inv))

            return "((%s | %s) &0x%x)" % (part1, part2, int(expr.mask))

        raise NotImplementedError("Unknown operator: %s" % expr.op)

    def from_ExprAssign(self, expr):
        return "%s = %s" % (
            self.from_expr(expr.dst),
            self.from_expr(expr.src)
        )


# Register the class
Translator.register(TranslatorPython)
