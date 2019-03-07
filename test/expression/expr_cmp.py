#
# Expression comparison regression tests  #
#
from pdb import pm
from miasm.expression.expression import ExprInt, expr_is_unsigned_greater,\
    expr_is_unsigned_greater_or_equal, expr_is_unsigned_lower,\
    expr_is_unsigned_lower_or_equal, expr_is_signed_greater,\
    expr_is_signed_greater_or_equal, expr_is_signed_lower, \
    expr_is_signed_lower_or_equal, expr_is_equal, expr_is_not_equal
from miasm.expression.simplifications import expr_simp

int_0 = ExprInt(0, 32)
int_1 = ExprInt(1, 32)
int_m1 = ExprInt(-1, 32)
int_m2 = ExprInt(-2, 32)

b0 = ExprInt(0, 1)
b1 = ExprInt(1, 1)

tests = [
    # unsigned
    (b1, expr_is_unsigned_greater, int_1, int_0),
    (b1, expr_is_unsigned_lower, int_0, int_1),

    (b0, expr_is_unsigned_greater, int_0, int_1),
    (b0, expr_is_unsigned_lower, int_1, int_0),

    (b1, expr_is_unsigned_greater_or_equal, int_1, int_0),
    (b1, expr_is_unsigned_lower_or_equal, int_0, int_1),

    (b0, expr_is_unsigned_greater_or_equal, int_0, int_1),
    (b0, expr_is_unsigned_lower_or_equal, int_1, int_0),

    (b1, expr_is_unsigned_greater_or_equal, int_1, int_1),
    (b1, expr_is_unsigned_lower_or_equal, int_1, int_1),

    (b1, expr_is_unsigned_greater, int_m1, int_0),
    (b1, expr_is_unsigned_lower, int_0, int_m1),

    (b0, expr_is_unsigned_greater, int_0, int_m1),
    (b0, expr_is_unsigned_lower, int_m1, int_0),


    # signed
    (b1, expr_is_signed_greater, int_1, int_0),
    (b1, expr_is_signed_lower, int_0, int_1),

    (b0, expr_is_signed_greater, int_0, int_1),
    (b0, expr_is_signed_lower, int_1, int_0),

    (b1, expr_is_signed_greater_or_equal, int_1, int_0),
    (b1, expr_is_signed_lower_or_equal, int_0, int_1),

    (b0, expr_is_signed_greater_or_equal, int_0, int_1),
    (b0, expr_is_signed_lower_or_equal, int_1, int_0),

    (b1, expr_is_signed_greater_or_equal, int_1, int_1),
    (b1, expr_is_signed_lower_or_equal, int_1, int_1),

    (b0, expr_is_signed_greater, int_m1, int_0),
    (b0, expr_is_signed_lower, int_0, int_m1),

    (b1, expr_is_signed_greater, int_0, int_m1),
    (b1, expr_is_signed_lower, int_m1, int_0),


    # greater lesser, neg
    (b1, expr_is_signed_greater, int_1, int_m1),
    (b1, expr_is_signed_lower, int_m1, int_1),

    (b0, expr_is_signed_greater, int_m1, int_1),
    (b0, expr_is_signed_lower, int_1, int_m1),

    (b1, expr_is_signed_greater_or_equal, int_1, int_m1),
    (b1, expr_is_signed_lower_or_equal, int_m1, int_1),

    (b0, expr_is_signed_greater_or_equal, int_m1, int_1),
    (b0, expr_is_signed_lower_or_equal, int_1, int_m1),

    (b1, expr_is_signed_greater_or_equal, int_m1, int_m1),
    (b1, expr_is_signed_lower_or_equal, int_m1, int_m1),


    (b1, expr_is_signed_greater, int_m1, int_m2),
    (b1, expr_is_signed_lower, int_m2, int_m1),

    (b0, expr_is_signed_greater, int_m2, int_m1),
    (b0, expr_is_signed_lower, int_m1, int_m2),

    (b1, expr_is_signed_greater_or_equal, int_m1, int_m2),
    (b1, expr_is_signed_lower_or_equal, int_m2, int_m1),

    (b0, expr_is_signed_greater_or_equal, int_m2, int_m1),
    (b0, expr_is_signed_lower_or_equal, int_m1, int_m2),

    # eq/neq
    (b1, expr_is_equal, int_1, int_1),
    (b1, expr_is_not_equal, int_0, int_1),

    (b0, expr_is_equal, int_1, int_0),
    (b0, expr_is_not_equal, int_0, int_0),


]

for result, func, arg1, arg2 in tests:
    assert result == expr_simp(func(arg1, arg2))
