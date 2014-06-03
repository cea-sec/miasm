from miasm2.expression.expression import *


"""
Quick implementation of miasm traduction to stp langage
TODO XXX: finish
"""


def ExprInt_strcst(self):
    b = bin(int(self.arg))[2::][::-1]
    b += "0" * self.size
    b = b[:self.size][::-1]
    return "0bin" + b


def ExprId_strcst(self):
    return self.name


def genop(op, size, a, b):
    return op + '(' + str(size) + ',' + a + ', ' + b + ')'


def genop_nosize(op, size, a, b):
    return op + '(' + a + ', ' + b + ')'


def ExprOp_strcst(self):
    op = self.op
    op_dct = {"|": " | ",
              "&": " & "}
    if op in op_dct:
        return '(' + op_dct[op].join([x.strcst() for x in self.args]) + ')'
    op_dct = {"-": "BVUMINUS"}
    if op in op_dct:
        return op_dct[op] + '(' + self.args[0].strcst() + ')'
    op_dct = {"^": ("BVXOR", genop_nosize),
              "+": ("BVPLUS", genop)}
    if not op in op_dct:
        raise ValueError('implement op', op)
    op, f = op_dct[op]
    args = [x.strcst() for x in self.args][::-1]
    a = args.pop()
    b = args.pop()
    size = self.args[0].size
    out = f(op, size, a, b)
    while args:
        out = f(op, size, out, args.pop())
    return out


def ExprSlice_strcst(self):
    return '(' + self.arg.strcst() + ')[%d:%d]' % (self.stop - 1, self.start)


def ExprCond_strcst(self):
    cond = self.cond.strcst()
    src1 = self.src1.strcst()
    src2 = self.src2.strcst()
    return "(IF %s=(%s) THEN %s ELSE %s ENDIF)" % (
        "0bin%s" % ('0' * self.cond.size), cond, src2, src1)

ExprInt.strcst = ExprInt_strcst
ExprId.strcst = ExprId_strcst
ExprOp.strcst = ExprOp_strcst
ExprCond.strcst = ExprCond_strcst
ExprSlice.strcst = ExprSlice_strcst
