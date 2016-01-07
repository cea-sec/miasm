# Helper functions for the generation of SMT2 expressions
# The SMT2 expressions will be returned as a string.
# The expressions are divided as follows
#
# - generic SMT2 operations
# - definitions of SMT2 structures
# - bit vector operations
# - array operations

# generic SMT2 operations

def smt2_eq(a, b):
    """
    Assignment: a = b
    """
    return "(= {} {})".format(a, b)


def smt2_implies(a, b):
    """
    Implication: a => b
    """
    return "(=> {} {})".format(a, b)


def smt2_and(*args):
    """
    Conjunction: a and b and c ...
    """
    # transform args into strings
    args = [str(arg) for arg in args]
    return "(and {})".format(' '.join(args))


def smt2_or(*args):
    """
    Disjunction: a or b or c ...
    """
    # transform args into strings
    args = [str(arg) for arg in args]
    return "(or {})".format(' '.join(args))


def smt2_ite(cond, a, b):
    """
    If-then-else: cond ? a : b
    """
    return "(ite {} {} {})".format(cond, a, b)


def smt2_distinct(*args):
    """
    Distinction: a != b != c != ...
    """
    # transform args into strings
    args = [str(arg) for arg in args]
    return "(distinct {})".format(' '.join(args))


def smt2_assert(expr):
    """
    Assertion that @expr holds
    """
    return "(assert {})".format(expr)


# definitions

def declare_bv(bv, size):
    """
    Declares an bit vector @bv of size @size
    """
    return "(declare-fun {} () {})".format(bv, bit_vec(size))


def declare_array(a, bv1, bv2):
    """
    Declares an SMT2 array represented as a map
    from a bit vector to another bit vector.
    :param a: array name
    :param bv1: SMT2 bit vector
    :param bv2: SMT2 bit vector
    """
    return "(declare-fun {} () (Array {} {}))".format(a, bv1, bv2)


def bit_vec_val(v, size):
    """
    Declares a bit vector value
    :param v: int, value of the bit vector
    :param size: size of the bit vector
    """
    return "(_ bv{} {})".format(v, size)


def bit_vec(size):
    """
    Returns a bit vector of size @size
    """
    return "(_ BitVec {})".format(size)


# bit vector operations

def bvadd(a, b):
    """
    Addition: a + b
    """
    return "(bvadd {} {})".format(a, b)


def bvsub(a, b):
    """
    Subtraction: a - b
    """
    return "(bvsub {} {})".format(a, b)


def bvmul(a, b):
    """
    Multiplication: a * b
    """
    return "(bvmul {} {})".format(a, b)


def bvand(a, b):
    """
    Bitwise AND: a & b
    """
    return "(bvand {} {})".format(a, b)


def bvor(a, b):
    """
    Bitwise OR: a | b
    """
    return "(bvor {} {})".format(a, b)


def bvxor(a, b):
    """
    Bitwise XOR: a ^ b
    """
    return "(bvxor {} {})".format(a, b)


def bvneg(bv):
    """
    Unary minus: - bv
    """
    return "(bvneg {})".format(bv)


def bvsdiv(a, b):
    """
    Signed division: a / b
    """
    return "(bvsdiv {} {})".format(a, b)


def bvudiv(a, b):
    """
    Unsigned division: a / b
    """
    return "(bvudiv {} {})".format(a, b)


def bvsmod(a, b):
    """
    Signed modulo: a mod b
    """
    return "(bvsmod {} {})".format(a, b)


def bvurem(a, b):
    """
    Unsigned modulo: a mod b
    """
    return "(bvurem {} {})".format(a, b)


def bvshl(a, b):
    """
    Shift left: a << b
    """
    return "(bvshl {} {})".format(a, b)


def bvlshr(a, b):
    """
    Logical shift right: a >> b
    """
    return "(bvlshr {} {})".format(a, b)


def bvashr(a, b):
    """
    Arithmetic shift right: a a>> b
    """
    return "(bvashr {} {})".format(a, b)


def bv_rotate_left(a, b, size):
    """
    Rotates bits of a to the left b times: a <<< b

    Since ((_ rotate_left b) a) does not support
    symbolic values for b, the implementation is
    based on a C implementation.

    Therefore, the rotation will be computed as
    a << (b & (size - 1))) | (a >> (size - (b & (size - 1))))

    :param a: bit vector
    :param b: bit vector
    :param size: size of a
    """

    # define constant
    s = bit_vec_val(size, size)

    # shift = b & (size  - 1)
    shift = bvand(b, bvsub(s, bit_vec_val(1, size)))

    # (a << shift) | (a >> size - shift)
    rotate = bvor(bvshl(a, shift),
                  bvlshr(a, bvsub(s, shift)))

    return rotate


def bv_rotate_right(a, b, size):
    """
    Rotates bits of a to the right b times: a >>> b

    Since ((_ rotate_right b) a) does not support
    symbolic values for b, the implementation is
    based on a C implementation.

    Therefore, the rotation will be computed as
    a >> (b & (size - 1))) | (a << (size - (b & (size - 1))))

    :param a: bit vector
    :param b: bit vector
    :param size: size of a
    """

    # define constant
    s = bit_vec_val(size, size)

    # shift = b & (size  - 1)
    shift = bvand(b, bvsub(s, bit_vec_val(1, size)))

    # (a >> shift) | (a << size - shift)
    rotate = bvor(bvlshr(a, shift),
                  bvshl(a, bvsub(s, shift)))

    return rotate


def bv_extract(high, low, bv):
    """
    Extracts bits from a bit vector
    :param high: end bit
    :param low: start bit
    :param bv: bit vector
    """
    return "((_ extract {} {}) {})".format(high, low, bv)


def bv_concat(a, b):
    """
    Concatenation of two SMT2 expressions
    """
    return "(concat {} {})".format(a, b)


# array operations

def array_select(array, index):
    """
    Reads from an SMT2 array at index @index
    :param array: SMT2 array
    :param index: SMT2 expression, index of the array
    """
    return "(select {} {})".format(array, index)


def array_store(array, index, value):
    """
    Writes an value into an SMT2 array at address @index
    :param array: SMT array
    :param index: SMT2 expression, index of the array
    :param value: SMT2 expression, value to write
    """
    return "(store {} {} {})".format(array, index, value)
