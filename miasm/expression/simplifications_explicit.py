from miasm.core.utils import size2mask
from miasm.expression.expression import ExprInt, ExprCond, ExprCompose, \
    TOK_EQUAL


def simp_ext(_, expr):
    if expr.op.startswith('zeroExt_'):
        arg = expr.args[0]
        if expr.size == arg.size:
            return arg
        return ExprCompose(arg, ExprInt(0, expr.size - arg.size))

    if expr.op.startswith("signExt_"):
        arg = expr.args[0]
        add_size = expr.size - arg.size
        new_expr = ExprCompose(
            arg,
            ExprCond(
                arg.msb(),
                ExprInt(size2mask(add_size), add_size),
                ExprInt(0, add_size)
            )
        )
        return new_expr
    return expr


def simp_flags(_, expr):
    args = expr.args

    if expr.is_op("FLAG_EQ"):
        return ExprCond(args[0], ExprInt(0, 1), ExprInt(1, 1))

    elif expr.is_op("FLAG_EQ_AND"):
        op1, op2 = args
        return ExprCond(op1 & op2, ExprInt(0, 1), ExprInt(1, 1))

    elif expr.is_op("FLAG_SIGN_SUB"):
        return (args[0] - args[1]).msb()

    elif expr.is_op("FLAG_EQ_CMP"):
        return ExprCond(
            args[0] - args[1],
            ExprInt(0, 1),
            ExprInt(1, 1),
        )

    elif expr.is_op("FLAG_ADD_CF"):
        op1, op2 = args
        res = op1 + op2
        return (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (~(op1 ^ op2)))).msb()

    elif expr.is_op("FLAG_SUB_CF"):
        op1, op2 = args
        res = op1 - op2
        return (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))).msb()

    elif expr.is_op("FLAG_ADD_OF"):
        op1, op2 = args
        res = op1 + op2
        return (((op1 ^ res) & (~(op1 ^ op2)))).msb()

    elif expr.is_op("FLAG_SUB_OF"):
        op1, op2 = args
        res = op1 - op2
        return (((op1 ^ res) & (op1 ^ op2))).msb()

    elif expr.is_op("FLAG_EQ_ADDWC"):
        op1, op2, op3 = args
        return ExprCond(
            op1 + op2 + op3.zeroExtend(op1.size),
            ExprInt(0, 1),
            ExprInt(1, 1),
        )

    elif expr.is_op("FLAG_ADDWC_OF"):
        op1, op2, op3 = args
        res = op1 + op2 + op3.zeroExtend(op1.size)
        return (((op1 ^ res) & (~(op1 ^ op2)))).msb()

    elif expr.is_op("FLAG_SUBWC_OF"):
        op1, op2, op3 = args
        res = op1 - (op2 + op3.zeroExtend(op1.size))
        return (((op1 ^ res) & (op1 ^ op2))).msb()

    elif expr.is_op("FLAG_ADDWC_CF"):
        op1, op2, op3 = args
        res = op1 + op2 + op3.zeroExtend(op1.size)
        return (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (~(op1 ^ op2)))).msb()

    elif expr.is_op("FLAG_SUBWC_CF"):
        op1, op2, op3 = args
        res = op1 - (op2 + op3.zeroExtend(op1.size))
        return (((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))).msb()

    elif expr.is_op("FLAG_SIGN_ADDWC"):
        op1, op2, op3 = args
        return (op1 + op2 + op3.zeroExtend(op1.size)).msb()

    elif expr.is_op("FLAG_SIGN_SUBWC"):
        op1, op2, op3 = args
        return (op1 - (op2 + op3.zeroExtend(op1.size))).msb()


    elif expr.is_op("FLAG_EQ_SUBWC"):
        op1, op2, op3 = args
        res = op1 - (op2 + op3.zeroExtend(op1.size))
        return ExprCond(res, ExprInt(0, 1), ExprInt(1, 1))

    elif expr.is_op("CC_U<="):
        op_cf, op_zf = args
        return op_cf | op_zf

    elif expr.is_op("CC_U>="):
        op_cf, = args
        return ~op_cf

    elif expr.is_op("CC_S<"):
        op_nf, op_of = args
        return op_nf ^ op_of

    elif expr.is_op("CC_S>"):
        op_nf, op_of, op_zf = args
        return ~(op_zf | (op_nf ^ op_of))

    elif expr.is_op("CC_S<="):
        op_nf, op_of, op_zf = args
        return op_zf | (op_nf ^ op_of)

    elif expr.is_op("CC_S>="):
        op_nf, op_of = args
        return ~(op_nf ^ op_of)

    elif expr.is_op("CC_U>"):
        op_cf, op_zf = args
        return ~(op_cf | op_zf)

    elif expr.is_op("CC_U<"):
        op_cf, = args
        return op_cf

    elif expr.is_op("CC_NEG"):
        op_nf, = args
        return op_nf

    elif expr.is_op("CC_EQ"):
        op_zf, = args
        return op_zf

    elif expr.is_op("CC_NE"):
        op_zf, = args
        return ~op_zf

    elif expr.is_op("CC_POS"):
        op_nf, = args
        return ~op_nf

    return expr

