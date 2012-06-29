import os

class moduint(object):
    def __init__(self, arg):
        if isinstance(arg, moduint):
            arg = arg.arg
        self.arg = arg%self.__class__.limit
        assert(self.arg >= 0 and self.arg < self.__class__.limit)
    def __repr__(self):
        return self.__class__.__name__+'('+hex(self.arg)+')'
    def __hash__(self):
        return hash(self.arg)
    @classmethod
    def maxcast(c1, c2):
        c2 = c2.__class__
        if c1.size > c2.size:
            return c1
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
            return cls(y.arg % self.arg )
        else:
            return self.__class__(y % self.arg)
    def __rmul__(self, y):
        return self.__mul__(y)
    def __ror__(self, y):
        return self.__or__(y)
    def __rrshift__(self, y):
        if isinstance(y, moduint):
            cls = self.maxcast(y)
            return cls(y.arg >> self.arg )
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
        return v**self.arg
    def __pow__(self, v):
        return self.__class__(self.arg**v)

class modint(moduint):
    def __init__(self, arg):
        if isinstance(arg, moduint):
            arg = arg.arg
        a = arg%self.__class__.limit
        if a >= self.__class__.limit/2:
            a -= self.__class__.limit
        self.arg = a
        assert(self.arg >= -self.__class__.limit/2 and self.arg < self.__class__.limit)


class uint1(moduint):
    size = 1
    limit = 1<<size

class uint8(moduint):
    size = 8
    limit = 1<<size

class uint16(moduint):
    size = 16
    limit = 1<<size

class uint32(moduint):
    size = 32
    limit = 1<<size

class uint64(moduint):
    size = 64
    limit = 1<<size

class uint128(moduint):
    size = 128
    limit = 1<<size

class int8(modint):
    size = 8
    limit = 1<<size

class int16(modint):
    size = 16
    limit = 1<<size

class int32(modint):
    size = 32
    limit = 1<<size

class int64(modint):
    size = 64
    limit = 1<<size

class int128(modint):
    size = 128
    limit = 1<<size



if __name__ == "__main__":
    a = uint8(0x42)
    b = uint8(0xFF)
    c = uint8(0x4)

    d = uint1(0)
    e = uint1(1)

    f = uint8(0x1)


    print a, b, c
    print a+b, a+c, b+c
    print a == a, a == b, a == 0x42, a == 0x78
    print a != b, a != a
    print d, e
    print d+e, d+d, e+e, e+e+e, e+0x11

    assert(f == 1)
    assert(f+1 == 2)
    assert(2 == f+1)
    assert(f+0xff==0)
    assert(f&0==0)
    assert(f&0xff==f)
    assert(0xff&f==f)
    assert(f/1==f)
    assert(1/f==f)
    assert(int(f)==1)
    assert(long(f)==1)
    assert(~f==0xfe)
    assert(f<<1==2)
    assert(f<<8==0)
    assert(1<<f==2)
    assert(0x80<<f==0)
    assert(f%2==f)
    assert(f%1==0)
    assert(2%f==0)
    assert(f*2==2)
    assert(2*f==2)
    assert(f*f==1)
    assert(f*uint8(0x80)==0x80)
    assert(-f==0xff)
    assert(f|f==f)
    assert(f|0==f)
    assert(2|f==3)
    assert(f>>0==f)
    assert(f>>1==0)
    assert(0x10>>f==0x8)
    assert(0x100>>f==0x80) # XXXX
    assert(0x1000>>f==0x0) # XXXX
    assert(f^f==0)
    assert(f^0==f)
    assert(0^f==f)
    assert(1^f==0)

    print e+c, c+e, c-e, e-c
    print 1000*a
    print hex(a)
