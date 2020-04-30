#! /usr/bin/env python

from __future__ import print_function
import re
import struct

from miasm.core.utils import force_bytes
from future.utils import PY3, viewitems, with_metaclass

type2realtype = {}
size2type = {}
size2type_s = {}

for t in 'B', 'H', 'I', 'Q':
    s = struct.calcsize(t)
    type2realtype[t] = s * 8
    size2type[s * 8] = t

for t in 'b', 'h', 'i', 'q':
    s = struct.calcsize(t)
    type2realtype[t] = s * 8
    size2type_s[s * 8] = t

type2realtype['u08'] = size2type[8]
type2realtype['u16'] = size2type[16]
type2realtype['u32'] = size2type[32]
type2realtype['u64'] = size2type[64]

type2realtype['s08'] = size2type_s[8]
type2realtype['s16'] = size2type_s[16]
type2realtype['s32'] = size2type_s[32]
type2realtype['s64'] = size2type_s[64]

type2realtype['d'] = 'd'
type2realtype['f'] = 'f'
type2realtype['q'] = 'q'
type2realtype['ptr'] = 'ptr'

sex_types = {0: '<', 1: '>'}


def fix_size(fields, wsize):
    out = []
    for name, v in fields:
        if v.endswith("s"):
            pass
        elif v == "ptr":
            v = size2type[wsize]
        elif not v in type2realtype:
            raise ValueError("unknown Cstruct type", v)
        else:
            v = type2realtype[v]
        out.append((name, v))
    fields = out
    return fields


def real_fmt(fmt, wsize):
    if fmt == "ptr":
        v = size2type[wsize]
    elif fmt in type2realtype:
        v = type2realtype[fmt]
    else:
        v = fmt
    return v

all_cstructs = {}


class Cstruct_Metaclass(type):
    field_suffix = "_value"

    def __new__(cls, name, bases, dct):
        for fields in dct['_fields']:
            fname = fields[0]
            if fname in ['parent', 'parent_head']:
                raise ValueError('field name will confuse internal structs',
                                 repr(fname))
            dct[fname] = property(dct.pop("get_" + fname,
                                          lambda self, fname=fname: getattr(
                                              self, fname + self.__class__.field_suffix)),
                                  dct.pop("set_" + fname,
                                          lambda self, v, fname=fname: setattr(
                                              self, fname + self.__class__.field_suffix, v)),
                                  dct.pop("del_" + fname, None))

        o = super(Cstruct_Metaclass, cls).__new__(cls, name, bases, dct)
        if name != "CStruct":
            all_cstructs[name] = o
        return o

    def unpack_l(cls, s, off=0, parent_head=None, _sex=None, _wsize=None):
        if _sex is None and _wsize is None:
            # get sex and size from parent
            if parent_head is not None:
                _sex = parent_head._sex
                _wsize = parent_head._wsize
            else:
                _sex = 0
                _wsize = 32
        c = cls(_sex=_sex, _wsize=_wsize)
        if parent_head is None:
            parent_head = c
        c.parent_head = parent_head

        of1 = off
        for field in c._fields:
            cpt = None
            if len(field) == 2:
                fname, ffmt = field
            elif len(field) == 3:
                fname, ffmt, cpt = field
            if ffmt in type2realtype or (isinstance(ffmt, str) and re.match(r'\d+s', ffmt)):
                # basic types
                if cpt:
                    value = []
                    i = 0
                    while i < cpt(c):
                        fmt = real_fmt(ffmt, _wsize)
                        of2 = of1 + struct.calcsize(fmt)
                        value.append(struct.unpack(c.sex + fmt, s[of1:of2])[0])
                        of1 = of2
                        i += 1
                else:
                    fmt = real_fmt(ffmt, _wsize)
                    of2 = of1 + struct.calcsize(fmt)
                    if not (0 <= of1 < len(s) and 0 <= of2 < len(s)):
                        raise RuntimeError("not enough data")
                    value = struct.unpack(c.sex + fmt, s[of1:of2])[0]
            elif ffmt == "sz":  # null terminated special case
                of2 = s.find(b'\x00', of1)
                if of2 == -1:
                    raise ValueError('no null char in string!')
                of2 += 1
                value = s[of1:of2 - 1]
            elif ffmt in all_cstructs:
                of2 = of1
                # sub structures
                if cpt:
                    value = []
                    i = 0
                    while i < cpt(c):
                        v, l = all_cstructs[ffmt].unpack_l(
                            s, of1, parent_head, _sex, _wsize)
                        v.parent = c
                        value.append(v)
                        of2 = of1 + l
                        of1 = of2
                        i += 1
                else:
                    value, l = all_cstructs[ffmt].unpack_l(
                        s, of1, parent_head, _sex, _wsize)
                    value.parent = c
                    of2 = of1 + l
            elif isinstance(ffmt, tuple):
                f_get, f_set = ffmt
                value, of2 = f_get(c, s, of1)
            else:
                raise ValueError('unknown class', ffmt)
            of1 = of2
            setattr(c, fname + c.__class__.field_suffix, value)

        return c, of2 - off

    def unpack(cls, s, off=0, parent_head=None, _sex=None, _wsize=None):
        c, l = cls.unpack_l(s, off=off,
                            parent_head=parent_head, _sex=_sex, _wsize=_wsize)
        return c


class CStruct(with_metaclass(Cstruct_Metaclass, object)):
    _packformat = ""
    _fields = []

    def __init__(self, parent_head=None, _sex=None, _wsize=None, **kargs):
        self.parent_head = parent_head
        self._size = None
        kargs = dict(kargs)
        # if not sex or size: get the one of the parent
        if _sex == None and _wsize == None:
            if parent_head:
                _sex = parent_head._sex
                _wsize = parent_head._wsize
            else:
                # else default sex & size
                _sex = 0
                _wsize = 32
        # _sex is 0 or 1, sex is '<' or '>'
        self._sex = _sex
        self._wsize = _wsize
        if self._packformat:
            self.sex = self._packformat
        else:
            self.sex = sex_types[_sex]
        for f in self._fields:
            setattr(self, f[0] + self.__class__.field_suffix, None)
        if kargs:
            for k, v in viewitems(kargs):
                self.__dict__[k + self.__class__.field_suffix] = v

    def pack(self):
        out = b''
        for field in self._fields:
            cpt = None
            if len(field) == 2:
                fname, ffmt = field
            elif len(field) == 3:
                fname, ffmt, cpt = field

            value = getattr(self, fname + self.__class__.field_suffix)
            if ffmt in type2realtype or (isinstance(ffmt, str) and re.match(r'\d+s', ffmt)):
                # basic types
                fmt = real_fmt(ffmt, self._wsize)
                if cpt == None:
                    if value == None:
                        o = struct.calcsize(fmt) * b"\x00"
                    elif ffmt.endswith('s'):
                        new_value = force_bytes(value)
                        o = struct.pack(self.sex + fmt, new_value)
                    else:
                        o = struct.pack(self.sex + fmt, value)
                else:
                    o = b""
                    for v in value:
                        if value == None:
                            o += struct.calcsize(fmt) * b"\x00"
                        else:
                            o += struct.pack(self.sex + fmt, v)

            elif ffmt == "sz":  # null terminated special case
                o = value + b'\x00'
            elif ffmt in all_cstructs:
                # sub structures
                if cpt == None:
                    o = bytes(value)
                else:
                    o = b""
                    for v in value:
                        o += bytes(v)
            elif isinstance(ffmt, tuple):
                f_get, f_set = ffmt
                o = f_set(self, value)

            else:
                raise ValueError('unknown class', ffmt)
            out += o

        return out

    def __bytes__(self):
        return self.pack()

    def __str__(self):
        if PY3:
            return repr(self)
        return self.__bytes__()

    def __len__(self):
        return len(self.pack())

    def __repr__(self):
        return "<%s=%s>" % (self.__class__.__name__, "/".join(
            repr(getattr(self, x[0])) for x in self._fields)
        )

    def __getitem__(self, item):  # to work with format strings
        return getattr(self, item)
