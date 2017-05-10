#-*- coding:utf-8 -*-

class moduint(object):

    def __init__(self, arg):
        self.arg = long(arg) % self.__class__.limit
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
        # Python: 8 / -7 == -2 (C-like: -1)
        # int(float) trick cannot be used, due to information loss
        den = int(y)
        num = int(self)
        result_sign = 1 if (den * num) >= 0 else -1
        cls = self.__class__
        if isinstance(y, moduint):
            cls = self.maxcast(y)
        return ((abs(num) / abs(den)) * result_sign)

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
        # See __div__ for implementation choice
        cls = self.__class__
        if isinstance(y, moduint):
            cls = self.maxcast(y)
        return cls(self.arg - (y * (self / y)))

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

def define_int(size):
    """Build the 'modint' instance corresponding to size @size"""
    global mod_size2int, mod_int2size

    name = 'int%d' % size
    cls = type(name, (modint,), {"size": size, "limit": 1 << size})
    globals()[name] = cls
    mod_size2int[size] = cls
    mod_int2size[cls] = size
    return cls

def define_uint(size):
    """Build the 'moduint' instance corresponding to size @size"""
    global mod_size2uint, mod_uint2size

    name = 'uint%d' % size
    cls = type(name, (moduint,), {"size": size, "limit": 1 << size})
    globals()[name] = cls
    mod_size2uint[size] = cls
    mod_uint2size[cls] = size
    return cls

def define_common_int():
    "Define common int"
    common_int = xrange(1, 257)

    for i in common_int:
        define_int(i)

    for i in common_int:
        define_uint(i)

define_common_int()
