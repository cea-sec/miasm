#!/usr/bin/env python
#-*- coding:utf-8 -*-

class moduint(object):

    def __init__(self, arg):
        if isinstance(arg, moduint):
            arg = arg.arg
        self.arg = arg % self.__class__.limit
        assert(self.arg >= 0 and self.arg < self.__class__.limit)

    def __repr__(self):
        return self.__class__.__name__ + '(' + hex(self.arg) + ')'

    def __hash__(self):
        return hash(self.arg)

    @classmethod
    def maxcast(cls, c2):
        c2 = c2.__class__
        if cls.size > c2.size:
            return cls
        else:
            return c2

    def __cmp__(self, y):
        if isinstance(y, moduint):
            return cmp(self.arg, y.arg)
        else:
            return cmp(self.arg, y)

    def __add__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg + y.arg)
        else:
            return self.__class__(self.arg + y)

    def __and__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg & y.arg)
        else:
            return self.__class__(self.arg & y)

    def __div__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg / y.arg)
        else:
            return self.__class__(self.arg / y)

    def __int__(self):
        return int(self.arg)

    def __long__(self):
        return long(self.arg)

    def __invert__(self):
        return self.__class__(~self.arg)

    def __lshift__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg << y.arg)
        else:
            return self.__class__(self.arg << y)

    def __mod__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg % y.arg)
        else:
            return self.__class__(self.arg % y)

    def __mul__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg * y.arg)
        else:
            return self.__class__(self.arg * y)

    def __neg__(self):
        return self.__class__(-self.arg)

    def __or__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg | y.arg)
        else:
            return self.__class__(self.arg | y)

    def __radd__(self, y):
        return self.__add__(y)

    def __rand__(self, y):
        return self.__and__(y)

    def __rdiv__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(y.arg / self.arg)
        else:
            return self.__class__(y / self.arg)

    def __rlshift__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(y.arg << self.arg)
        else:
            return self.__class__(y << self.arg)

    def __rmod__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(y.arg % self.arg)
        else:
            return self.__class__(y % self.arg)

    def __rmul__(self, y):
        return self.__mul__(y)

    def __ror__(self, y):
        return self.__or__(y)

    def __rrshift__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(y.arg >> self.arg)
        else:
            return self.__class__(y >> self.arg)

    def __rshift__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg >> y.arg)
        else:
            return self.__class__(self.arg >> y)

    def __rsub__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(y.arg - self.arg)
        else:
            return self.__class__(y - self.arg)

    def __rxor__(self, y):
        return self.__xor__(y)

    def __sub__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg - y.arg)
        else:
            return self.__class__(self.arg - y)

    def __xor__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(self.arg ^ y.arg)
        else:
            return self.__class__(self.arg ^ y)

    def __hex__(self):
        return hex(self.arg)

    def __abs__(self):
        return abs(self.arg)

    def __rpow__(self, v):
        return v ** self.arg

    def __pow__(self, v):
        return self.__class__(self.arg ** v)


class modint(moduint):

    def __init__(self, arg):
        if isinstance(arg, moduint):
            arg = arg.arg
        a = arg % self.__class__.limit
        if a >= self.__class__.limit / 2:
            a -= self.__class__.limit
        self.arg = a
        assert(self.arg >= -self.__class__.limit /
               2 and self.arg < self.__class__.limit)


def is_modint(a):
    return isinstance(a, moduint)


def size2mask(size):
    return (1 << size) - 1

mod_size2uint = {}
mod_size2int = {}

mod_uint2size = {}
mod_int2size = {}


def define_common_int():
    "Define common int: ExprInt1, ExprInt2, .."
    global mod_size2int, mod_int2size, mod_size2uint, mod_uint2size

    common_int = xrange(1, 257)

    for i in common_int:
        name = 'uint%d' % i
        c = type(name, (moduint,), {"size": i, "limit": 1 << i})
        globals()[name] = c
        mod_size2uint[i] = c
        mod_uint2size[c] = i

    for i in common_int:
        name = 'int%d' % i
        c = type(name, (modint,), {"size": i, "limit": 1 << i})
        globals()[name] = c
        mod_size2int[i] = c
        mod_int2size[c] = i

define_common_int()
