from builtins import range
from random import shuffle, seed

from miasm.core.interval import interval
from miasm.analysis.modularintervals import ModularIntervals
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp


def gen_all_intervals(size):
    """Return every possible interval for element of @size bit
    -> 2**(2**size) (number of partition)
    """
    nb_elements = 1 << size
    for bvec in range(1 << nb_elements):
        # Bit vector: if bit i is on, i is in the interval
        to_ret = interval()
        for i in range(nb_elements):
            if bvec & i == i:
                to_ret += [(i, i)]
        yield to_ret

def interval_elements(interv):
    """Generator on element of an interval"""
    for sub_range in interv:
        for i in range(sub_range[0], sub_range[1] + 1):
            yield i

size = 4
left, right = list(gen_all_intervals(size)), list(gen_all_intervals(size))
right_int = list(range(1 << size))
mask = (1 << size) - 1

def test(left, right):
    """Launch tests on left OP right"""
    global size, mask

    for left_i in left:
        left_i = ModularIntervals(size, left_i)
        left_values = list(interval_elements(left_i))

        # Check operations without other arguments
        ## Check NEG
        result = - left_i
        for x in left_values:
            rez = (- x) & mask
            assert rez in result

        # Check operations on intervals
        for right_i in right:
            right_i = ModularIntervals(size, right_i)
            right_values = list(interval_elements(right_i))

            # Check operations available only on integer
            if len(right_values) == 1:
                # Check mod
                value = right_values[0]
                # Avoid division by zero
                if value != 0:
                    result = left_i % value
                    for x in left_values:
                        rez = (x % value) & mask
                        assert rez in result

            # Check ADD
            result = left_i + right_i
            for x in left_values:
                for y in right_values:
                    rez = (x + y) & mask
                    assert rez in result

            # Check OR
            result = left_i | right_i
            for x in left_values:
                for y in right_values:
                    rez = (x | y) & mask
                    assert rez in result

            # Check AND
            result = left_i & right_i
            for x in left_values:
                for y in right_values:
                    rez = (x & y) & mask
                    assert rez in result

            # Check XOR
            result = left_i ^ right_i
            for x in left_values:
                for y in right_values:
                    rez = (x ^ y) & mask
                    assert rez in result

            # Check MUL
            result = left_i * right_i
            for x in left_values:
                for y in right_values:
                    rez = (x * y) & mask
                    assert rez in result

            # Check >>
            result = left_i >> right_i
            for x in left_values:
                for y in right_values:
                    rez = (x >> y) & mask
                    assert rez in result

            # Check <<
            result = left_i << right_i
            for x in left_values:
                for y in right_values:
                    rez = (x << y) & mask
                    assert rez in result

            # Check a>>
            result = left_i.arithmetic_shift_right(right_i)
            for x in left_values:
                x = ExprInt(x, size)
                for y in right_values:
                    y = ExprInt(y, size)
                    rez = int(expr_simp(ExprOp('a>>', x, y)))
                    assert rez in result

            # Check >>>
            result = left_i.rotation_right(right_i)
            for x in left_values:
                x = ExprInt(x, size)
                for y in right_values:
                    y = ExprInt(y, size)
                    rez = int(expr_simp(ExprOp('>>>', x, y)))
                    assert rez in result

            # Check <<<
            result = left_i.rotation_left(right_i)
            for x in left_values:
                x = ExprInt(x, size)
                for y in right_values:
                    y = ExprInt(y, size)
                    rez = int(expr_simp(ExprOp('<<<', x, y)))
                    assert rez in result



# Following tests take around 10 minutes with PyPy, but too long for Python
# interval_uniq = [interval([(i, i)]) for i in xrange(1 << size)]
# test(left, interval_uniq)
# test(interval_uniq, right)

# Uncomment the following line for a full test over intervals, which may take
# several hours
# test(left, right)

# Random pick for tests
seed(0)
shuffle(left)
shuffle(right)

test(left[:100], right[:100])
