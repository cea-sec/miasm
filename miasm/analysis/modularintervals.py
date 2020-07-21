"""Intervals with a maximum size, supporting modular arithmetic"""

from future.builtins import range
from builtins import int as int_types
from itertools import product

from miasm.core.interval import interval
from miasm.core.utils import size2mask

class ModularIntervals(object):
    """Intervals with a maximum size, supporting modular arithmetic"""

    def __init__(self, size, intervals=None):
        """Instantiate a ModularIntervals of size @size
        @size: maximum size of elements
        @intervals: (optional) interval instance, or any type  supported by
                    interval initialisation; element of the current instance
        """
        # Create or cast @intervals argument
        if intervals is None:
            intervals = interval()
        if not isinstance(intervals, interval):
            intervals = interval(intervals)
        self.intervals = intervals
        self.size = size

        # Sanity check
        start, end = intervals.hull()
        if start is not None:
            assert start >= 0
        if end is not None:
            assert end <= self.mask

    # Helpers
    def _range2interval(func):
        """Convert a function taking 2 ranges to a function taking a ModularIntervals
        and applying to the current instance"""
        def ret_func(self, target):
            ret = interval()
            for left_i, right_i in product(self.intervals, target.intervals):
                ret += func(self, left_i[0], left_i[1], right_i[0],
                            right_i[1])
            return self.__class__(self.size, ret)
        return ret_func

    def _range2integer(func):
        """Convert a function taking 1 range and optional arguments to a function
        applying to the current instance"""
        def ret_func(self, *args):
            ret = interval()
            for x_min, x_max in self.intervals:
                ret += func(self, x_min, x_max, *args)
            return self.__class__(self.size, ret)
        return ret_func

    def _promote(func):
        """Check and promote the second argument from integer to
        ModularIntervals with one value"""
        def ret_func(self, target):
            if isinstance(target, int_types):
                target = ModularIntervals(self.size, interval([(target, target)]))
            if not isinstance(target, ModularIntervals):
                raise TypeError("Unsupported operation with %s" % target.__class__)
            if target.size != self.size:
                raise TypeError("Size are not the same: %s vs %s" % (self.size,
                                                                     target.size))
            return func(self, target)
        return ret_func

    def _unsigned2signed(self, value):
        """Return the signed value of @value, based on self.size"""
        if (value & (1 << (self.size - 1))):
            return -(self.mask ^ value) - 1
        else:
            return value

    def _signed2unsigned(self, value):
        """Return the unsigned value of @value, based on self.size"""
        return value & self.mask

    # Operation internals
    #
    # Naming convention:
    # _range_{op}: takes 2 interval bounds and apply op
    # _range_{op}_uniq: takes 1 interval bounds and apply op
    # _interval_{op}: apply op on an ModularIntervals
    # _integer_{op}: apply op on itself with possible arguments

    def _range_add(self, x_min, x_max, y_min, y_max):
        """Bounds interval for x + y, with
         - x, y of size 'self.size'
         - @x_min <= x <= @x_max
         - @y_min <= y <= @y_max
         - operations are considered unsigned
        From Hacker's Delight: Chapter 4
        """
        max_bound = self.mask
        if (x_min + y_min <= max_bound and
            x_max + y_max >= max_bound + 1):
            # HD returns 0, max_bound; but this is because it cannot handle multiple
            # interval.
            # x_max + y_max can only overflow once, so returns
            # [result_min, overflow] U [0, overflow_rest]
            return interval([(x_min + y_min, max_bound),
                             (0, (x_max + y_max) & max_bound)])
        else:
            return interval([((x_min + y_min) & max_bound,
                              (x_max + y_max) & max_bound)])

    _interval_add = _range2interval(_range_add)

    def _range_minus_uniq(self, x_min, x_max):
        """Bounds interval for -x, with
         - x of size self.size
         - @x_min <= x <= @x_max
         - operations are considered unsigned
        From Hacker's Delight: Chapter 4
        """
        max_bound = self.mask
        if (x_min == 0 and x_max != 0):
            # HD returns 0, max_bound; see _range_add
            return interval([(0, 0), ((- x_max) & max_bound, max_bound)])
        else:
            return interval([((- x_max) & max_bound, (- x_min) & max_bound)])

    _interval_minus = _range2integer(_range_minus_uniq)

    def _range_or_min(self, x_min, x_max, y_min, y_max):
        """Interval min for x | y, with
         - x, y of size self.size
         - @x_min <= x <= @x_max
         - @y_min <= y <= @y_max
         - operations are considered unsigned
        From Hacker's Delight: Chapter 4
        """
        max_bit = 1 << (self.size - 1)
        while max_bit:
            if ~x_min & y_min & max_bit:
                temp = (x_min | max_bit) & - max_bit
                if temp <= x_max:
                    x_min = temp
                    break
            elif x_min & ~y_min & max_bit:
                temp = (y_min | max_bit) & - max_bit
                if temp <= y_max:
                    y_min = temp
                    break
            max_bit >>= 1
        return x_min | y_min

    def _range_or_max(self, x_min, x_max, y_min, y_max):
        """Interval max for x | y, with
         - x, y of size self.size
         - @x_min <= x <= @x_max
         - @y_min <= y <= @y_max
         - operations are considered unsigned
        From Hacker's Delight: Chapter 4
        """
        max_bit = 1 << (self.size - 1)
        while max_bit:
            if x_max & y_max & max_bit:
                temp = (x_max - max_bit) | (max_bit - 1)
                if temp >= x_min:
                    x_max = temp
                    break
                temp = (y_max - max_bit) | (max_bit - 1)
                if temp >= y_min:
                    y_max = temp
                    break
            max_bit >>= 1
        return x_max | y_max

    def _range_or(self, x_min, x_max, y_min, y_max):
        """Interval bounds for x | y, with
         - x, y of size self.size
         - @x_min <= x <= @x_max
         - @y_min <= y <= @y_max
         - operations are considered unsigned
        From Hacker's Delight: Chapter 4
        """
        return interval([(self._range_or_min(x_min, x_max, y_min, y_max),
                          self._range_or_max(x_min, x_max, y_min, y_max))])

    _interval_or = _range2interval(_range_or)

    def _range_and_min(self, x_min, x_max, y_min, y_max):
        """Interval min for x & y, with
         - x, y of size self.size
         - @x_min <= x <= @x_max
         - @y_min <= y <= @y_max
         - operations are considered unsigned
        From Hacker's Delight: Chapter 4
        """
        max_bit = (1 << (self.size - 1))
        while max_bit:
            if ~x_min & ~y_min & max_bit:
                temp = (x_min | max_bit) & - max_bit
                if temp <= x_max:
                    x_min = temp
                    break
                temp = (y_min | max_bit) & - max_bit
                if temp <= y_max:
                    y_min = temp
                    break
            max_bit >>= 1
        return x_min & y_min

    def _range_and_max(self, x_min, x_max, y_min, y_max):
        """Interval max for x & y, with
         - x, y of size self.size
         - @x_min <= x <= @x_max
         - @y_min <= y <= @y_max
         - operations are considered unsigned
        From Hacker's Delight: Chapter 4
        """
        max_bit = (1 << (self.size - 1))
        while max_bit:
            if x_max & ~y_max & max_bit:
                temp = (x_max & ~max_bit) | (max_bit - 1)
                if temp >= x_min:
                    x_max = temp
                    break
            elif ~x_max & y_max & max_bit:
                temp = (y_max & ~max_bit) | (max_bit - 1)
                if temp >= y_min:
                    y_max = temp
                    break
            max_bit >>= 1
        return x_max & y_max

    def _range_and(self, x_min, x_max, y_min, y_max):
        """Interval bounds for x & y, with
         - x, y of size @size
         - @x_min <= x <= @x_max
         - @y_min <= y <= @y_max
         - operations are considered unsigned
        From Hacker's Delight: Chapter 4
        """
        return interval([(self._range_and_min(x_min, x_max, y_min, y_max),
                          self._range_and_max(x_min, x_max, y_min, y_max))])

    _interval_and = _range2interval(_range_and)

    def _range_xor(self, x_min, x_max, y_min, y_max):
        """Interval bounds for x ^ y, with
         - x, y of size self.size
         - @x_min <= x <= @x_max
         - @y_min <= y <= @y_max
         - operations are considered unsigned
        From Hacker's Delight: Chapter 4
        """
        not_size = lambda x: x ^ self.mask
        min_xor = self._range_and_min(x_min, x_max, not_size(y_max), not_size(y_min)) | self._range_and_min(not_size(x_max), not_size(x_min), y_min, y_max)
        max_xor = self._range_or_max(0,
                                     self._range_and_max(x_min, x_max, not_size(y_max), not_size(y_min)),
                                     0,
                                     self._range_and_max(not_size(x_max), not_size(x_min), y_min, y_max))
        return interval([(min_xor, max_xor)])

    _interval_xor = _range2interval(_range_xor)

    def _range_mul(self, x_min, x_max, y_min, y_max):
        """Interval bounds for x * y, with
         - x, y of size self.size
         - @x_min <= x <= @x_max
         - @y_min <= y <= @y_max
         - operations are considered unsigned
        This is a naive version, going to TOP on overflow"""
        max_bound = self.mask
        if y_max * x_max > max_bound:
            return interval([(0, max_bound)])
        else:
            return interval([(x_min * y_min, x_max * y_max)])

    _interval_mul = _range2interval(_range_mul)

    def _range_mod_uniq(self, x_min, x_max, mod):
        """Interval bounds for x % @mod, with
         - x, @mod of size self.size
         - @x_min <= x <= @x_max
         - operations are considered unsigned
        """
        if (x_max - x_min) >= mod:
            return interval([(0, mod - 1)])
        x_max = x_max % mod
        x_min = x_min % mod
        if x_max < x_min:
            return interval([(0, x_max), (x_min, mod - 1)])
        else:
            return interval([(x_min, x_max)])

    _integer_modulo = _range2integer(_range_mod_uniq)

    def _range_shift_uniq(self, x_min, x_max, shift, op):
        """Bounds interval for x @op @shift with
         - x of size self.size
         - @x_min <= x <= @x_max
         - operations are considered unsigned
         - shift <= self.size
        """
        assert shift <= self.size
        # Shift operations are monotonic, and overflow results in 0
        max_bound = self.mask

        if op == "<<":
            obtain_max = x_max << shift
            if obtain_max > max_bound:
                # Overflow at least on max, best-effort
                # result '0' often happen, include it
                return interval([(0, 0), ((1 << shift) - 1, max_bound)])
            else:
                return interval([(x_min << shift, obtain_max)])
        elif op == ">>":
            return interval([((x_min >> shift) & max_bound,
                              (x_max >> shift) & max_bound)])
        elif op == "a>>":
            # The Miasm2 version (Expr or ModInt) could have been used, but
            # introduce unnecessary dependencies for this module
            # Python >> is the arithmetic one
            ashr = lambda x, y: self._signed2unsigned(self._unsigned2signed(x) >> y)
            end_min, end_max = ashr(x_min, shift), ashr(x_max, shift)
            end_min, end_max = min(end_min, end_max), max(end_min, end_max)
            return interval([(end_min, end_max)])
        else:
            raise ValueError("%s is not a shifter" % op)

    def _interval_shift(self, operation, shifter):
        """Apply the shifting operation @operation with a shifting
        ModularIntervals @shifter on the current instance"""
        # Work on a copy of shifter intervals
        shifter = interval(shifter.intervals)
        if (shifter.hull()[1] >= self.size):
            shifter += interval([(self.size, self.size)])
        shifter &= interval([(0, self.size)])
        ret = interval()
        for shift_range in shifter:
            for shift in range(shift_range[0], shift_range[1] + 1):
                for x_min, x_max in self.intervals:
                    ret += self._range_shift_uniq(x_min, x_max, shift, operation)
        return self.__class__(self.size, ret)

    def _range_rotate_uniq(self, x_min, x_max, shift, op):
        """Bounds interval for x @op @shift with
         - x of size self.size
         - @x_min <= x <= @x_max
         - operations are considered unsigned
         - shift <= self.size
        """
        assert shift <= self.size
        # Divide in sub-operations: a op b: a left b | a right (size - b)
        if op == ">>>":
            left, right = ">>", "<<"
        elif op == "<<<":
            left, right = "<<", ">>"
        else:
            raise ValueError("Not a rotator: %s" % op)

        left_intervals = self._range_shift_uniq(x_min, x_max, shift, left)
        right_intervals = self._range_shift_uniq(x_min, x_max,
                                                 self.size - shift, right)

        result = self.__class__(self.size, left_intervals) | self.__class__(self.size, right_intervals)
        return result.intervals

    def _interval_rotate(self, operation, shifter):
        """Apply the rotate operation @operation with a shifting
        ModularIntervals @shifter on the current instance"""
        # Consider only rotation without repetition, and enumerate
        # -> apply a '% size' on shifter
        shifter %= self.size
        ret = interval()
        for shift_range in shifter:
            for shift in range(shift_range[0], shift_range[1] + 1):
                for x_min, x_max in self.intervals:
                    ret += self._range_rotate_uniq(x_min, x_max, shift,
                                                   operation)

        return self.__class__(self.size, ret)

    # Operation wrappers

    @_promote
    def __add__(self, to_add):
        """Add @to_add to the current intervals
        @to_add: ModularInstances or integer
        """
        return self._interval_add(to_add)

    @_promote
    def __or__(self, to_or):
        """Bitwise OR @to_or to the current intervals
        @to_or: ModularInstances or integer
        """
        return self._interval_or(to_or)

    @_promote
    def __and__(self, to_and):
        """Bitwise AND @to_and to the current intervals
        @to_and: ModularInstances or integer
        """
        return self._interval_and(to_and)

    @_promote
    def __xor__(self, to_xor):
        """Bitwise XOR @to_xor to the current intervals
        @to_xor: ModularInstances or integer
        """
        return self._interval_xor(to_xor)

    @_promote
    def __mul__(self, to_mul):
        """Multiply @to_mul to the current intervals
        @to_mul: ModularInstances or integer
        """
        return self._interval_mul(to_mul)

    @_promote
    def __rshift__(self, to_shift):
        """Logical shift right the current intervals of @to_shift
        @to_shift: ModularInstances or integer
        """
        return self._interval_shift('>>', to_shift)

    @_promote
    def __lshift__(self, to_shift):
        """Logical shift left the current intervals of @to_shift
        @to_shift: ModularInstances or integer
        """
        return self._interval_shift('<<', to_shift)

    @_promote
    def arithmetic_shift_right(self, to_shift):
        """Arithmetic shift right the current intervals of @to_shift
        @to_shift: ModularInstances or integer
        """
        return self._interval_shift('a>>', to_shift)

    def __neg__(self):
        """Negate the current intervals"""
        return self._interval_minus()

    def __mod__(self, modulo):
        """Apply % @modulo on the current intervals
        @modulo: integer
        """

        if not isinstance(modulo, int_types):
            raise TypeError("Modulo with %s is not supported" % modulo.__class__)
        return self._integer_modulo(modulo)

    @_promote
    def rotation_right(self, to_rotate):
        """Right rotate the current intervals of @to_rotate
        @to_rotate: ModularInstances or integer
        """
        return self._interval_rotate('>>>', to_rotate)

    @_promote
    def rotation_left(self, to_rotate):
        """Left rotate the current intervals of @to_rotate
        @to_rotate: ModularInstances or integer
        """
        return self._interval_rotate('<<<', to_rotate)

    # Instance operations

    @property
    def mask(self):
        """Return the mask corresponding to the instance size"""
        return size2mask(self.size)

    def __iter__(self):
        return iter(self.intervals)

    @property
    def length(self):
        return self.intervals.length

    def __contains__(self, other):
        if isinstance(other, ModularIntervals):
            other = other.intervals
        return other in self.intervals

    def __str__(self):
        return "%s (Size: %s)" % (self.intervals, self.size)

    def size_update(self, new_size):
        """Update the instance size to @new_size
        The size of elements must be <= @new_size"""

        # Increasing size is always safe
        if new_size < self.size:
            # Check that current values are indeed included in the new range
            assert self.intervals.hull()[1] <= size2mask(new_size)

        self.size = new_size

        # For easy chainning
        return self

    # Mimic Python's set operations

    @_promote
    def union(self, to_union):
        """Union set operation with @to_union
        @to_union: ModularIntervals instance"""
        return ModularIntervals(self.size, self.intervals + to_union.intervals)

    @_promote
    def update(self, to_union):
        """Union set operation in-place with @to_union
        @to_union: ModularIntervals instance"""
        self.intervals += to_union.intervals

    @_promote
    def intersection(self, to_intersect):
        """Intersection set operation with @to_intersect
        @to_intersect: ModularIntervals instance"""
        return ModularIntervals(self.size, self.intervals & to_intersect.intervals)

    @_promote
    def intersection_update(self, to_intersect):
        """Intersection set operation in-place with @to_intersect
        @to_intersect: ModularIntervals instance"""
        self.intervals &= to_intersect.intervals
