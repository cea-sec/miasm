"""Naive range analysis for expression"""

from future.builtins import zip
from functools import reduce

from miasm.analysis.modularintervals import ModularIntervals

_op_range_handler = {
    "+": lambda x, y: x + y,
    "&": lambda x, y: x & y,
    "|": lambda x, y: x | y,
    "^": lambda x, y: x ^ y,
    "*": lambda x, y: x * y,
    "a>>": lambda x, y: x.arithmetic_shift_right(y),
    "<<": lambda x, y: x << y,
    ">>": lambda x, y: x >> y,
    ">>>": lambda x, y: x.rotation_right(y),
    "<<<": lambda x, y: x.rotation_left(y),
}

def expr_range(expr):
    """Return a ModularIntervals containing the range of possible values of
    @expr"""
    max_bound = (1 << expr.size) - 1
    if expr.is_int():
        return ModularIntervals(expr.size, [(int(expr), int(expr))])
    elif expr.is_id() or expr.is_mem():
        return ModularIntervals(expr.size, [(0, max_bound)])
    elif expr.is_slice():
        interval_mask = ((1 << expr.start) - 1) ^ ((1 << expr.stop) - 1)
        arg = expr_range(expr.arg)
        # Mask for possible range, and shift range
        return ((arg & interval_mask) >> expr.start).size_update(expr.size)
    elif expr.is_compose():
        sub_ranges = [expr_range(arg) for arg in expr.args]
        args_idx = [info[0] for info in expr.iter_args()]

        # No shift for the first one
        ret = sub_ranges[0].size_update(expr.size)

        # Doing it progressively (2 by 2)
        for shift, sub_range in zip(args_idx[1:], sub_ranges[1:]):
            ret |= sub_range.size_update(expr.size) << shift
        return ret
    elif expr.is_op():
        # A few operation are handled with care
        # Otherwise, overapproximate (ie. full range interval)
        if expr.op in _op_range_handler:
            sub_ranges = [expr_range(arg) for arg in expr.args]
            return reduce(
                _op_range_handler[expr.op],
                (sub_range for sub_range in sub_ranges[1:]),
                sub_ranges[0]
            )
        elif expr.op == "-":
            assert len(expr.args) == 1
            return - expr_range(expr.args[0])
        elif expr.op == "%":
            assert len(expr.args) == 2
            op, mod = [expr_range(arg) for arg in expr.args]
            if mod.intervals.length == 1:
                # Modulo intervals is not supported
                return op % mod.intervals.hull()[0]

        # Operand not handled, return the full domain
        return ModularIntervals(expr.size, [(0, max_bound)])
    elif expr.is_cond():
        return expr_range(expr.src1).union(expr_range(expr.src2))
    else:
        raise TypeError("Unsupported type: %s" % expr.__class__)
