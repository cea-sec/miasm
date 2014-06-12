################################################################################
#
# By choice, Miasm2 does not handle comparaison as a single operation, but with
# operations corresponding to comparaison computation.
# One may want to detect those comparaison; this library is designed to add them
# in Miasm2 engine thanks to :
# - Conditions computation in ExprOp
# - Simplifications to catch known condition forms
#
# Conditions currently supported :
# <u, <s
#
# Authors : Fabrice DESCLAUX (CEA/DAM), Camille MOUGEY (CEA/DAM)
#
################################################################################

import itertools
import miasm2.expression.expression as m2_expr

# Define tokens
TOK_INF = "<"
TOK_INF_SIGNED = TOK_INF + "s"
TOK_INF_UNSIGNED = TOK_INF + "u"
TOK_INF_EQUAL = "<="
TOK_INF_EQUAL_SIGNED = TOK_INF_EQUAL + "s"
TOK_INF_EQUAL_UNSIGNED = TOK_INF_EQUAL + "u"
TOK_EQUAL = "=="
TOK_POS = "pos"
TOK_POS_STRICT = "Spos"

# Jokers for expression matching

jok1 = m2_expr.ExprId("jok1")
jok2 = m2_expr.ExprId("jok2")
jok3 = m2_expr.ExprId("jok3")

# Constructors

def __ExprOp_cond(op, arg1, arg2):
    "Return an ExprOp standing for arg1 op arg2 with size to 1"
    ec = m2_expr.ExprOp(op, arg1, arg2)
    ec._size = 1
    return ec


def ExprOp_inf_signed(arg1, arg2):
    "Return an ExprOp standing for arg1 <s arg2"
    return __ExprOp_cond(TOK_INF_SIGNED, arg1, arg2)


def ExprOp_inf_unsigned(arg1, arg2):
    "Return an ExprOp standing for arg1 <s arg2"
    return __ExprOp_cond(TOK_INF_UNSIGNED, arg1, arg2)


# Catching conditions forms

def __check_msb(e):
    """If @e stand for the most significant bit of its arg, return the arg;
    False otherwise"""

    if not isinstance(e, m2_expr.ExprSlice):
        return False

    arg = e.arg
    if e.start != (arg.size - 1) or e.stop != arg.size:
        return False

    return arg

def __MatchExprWrap(e, to_match, jok_list):
    "Wrapper around MatchExpr to canonize pattern"

    to_match = to_match.canonize()

    r = m2_expr.MatchExpr(e, to_match, jok_list)
    if r is False:
        return False

    if r == {}:
        return False

    return r

def expr_simp_inf_signed(expr_simp, e):
    "((x - y) ^ ((x ^ y) & ((x - y) ^ x))) [31:32] == x <s y"

    arg = __check_msb(e)
    if arg is False:
        return e

    # We want jok3 = jok1 - jok2
    to_match = jok3 ^ ((jok1 ^ jok2) & (jok3 ^ jok1))
    r = __MatchExprWrap(arg,
                        to_match,
                        [jok1, jok2, jok3])

    if r is False:
        return e

    new_j3 = expr_simp(r[jok3])
    sub = expr_simp(r[jok1] - r[jok2])

    if new_j3 == sub:
        return ExprOp_inf_signed(r[jok1], r[jok2])
    else:
        return e

def expr_simp_inf_unsigned_inversed(expr_simp, e):
    "((x - y) ^ ((x ^ y) & ((x - y) ^ x))) ^ x ^ y [31:32] == x <u y"

    arg = __check_msb(e)
    if arg is False:
        return e

    # We want jok3 = jok1 - jok2
    to_match = jok3 ^ ((jok1 ^ jok2) & (jok3 ^ jok1)) ^ jok1 ^ jok2
    r = __MatchExprWrap(arg,
                        to_match,
                        [jok1, jok2, jok3])

    if r is False:
        return e

    new_j3 = expr_simp(r[jok3])
    sub = expr_simp(r[jok1] - r[jok2])

    if new_j3 == sub:
        return ExprOp_inf_unsigned(r[jok1], r[jok2])
    else:
        return e

def expr_simp_inverse(expr_simp, e):
    """(x <u y) ^ ((x ^ y) [31:32]) == x <s y,
    (x <s y) ^ ((x ^ y) [31:32]) == x <u y"""

    if e.op != '^' or len(e.args) != 2:
        return e

    return e # TODO: Not Implemented

# Compute conditions

def exec_inf_unsigned(expr_simp, e):
    "Compute x <u y"
    if e.op != TOK_INF_UNSIGNED:
        return e

    arg1, arg2 = e.args

    if isinstance(arg1, m2_expr.ExprInt) and isinstance(arg2, m2_expr.ExprInt):
        return m2_expr.ExprInt1(1) if (arg1.arg < arg2.arg) else m2_expr.ExprInt1(0)
    else:
        return e


def __comp_signed(arg1, arg2):
    """Return ExprInt1(1) if arg1 <s arg2 else ExprInt1(0)
    @arg1, @arg2: ExprInt"""

    val1 = arg1.arg
    if val1 >> (arg1.size - 1) == 1:
        val1 = - (arg1.mask.arg ^ val1 + 1)

    val2 = arg2.arg
    if val2 >> (arg2.size - 1) == 1:
        val2 = - (arg2.mask.arg ^ val2 + 1)

    return m2_expr.ExprInt1(1) if (val1 < val2) else m2_expr.ExprInt1(0)

def exec_inf_signed(expr_simp, e):
    "Compute x <s y"
    if e.op != TOK_INF_SIGNED:
        return e

    arg1, arg2 = e.args

    if isinstance(arg1, m2_expr.ExprInt) and isinstance(arg2, m2_expr.ExprInt):
        return __comp_signed(arg1, arg2)
    else:
        return e
